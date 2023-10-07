// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/xarray.h>

#include "ksmbd_ida.h"
#include "user_session.h"
#include "user_config.h"
#include "tree_connect.h"
#include "share_config.h"
#include "../transport_ipc.h"
#include "../connection.h"
#include "../vfs_cache.h"
#include "../misc.h"
#include "../stats.h"

static DEFINE_IDA(session_ida);

#define SESSION_HASH_BITS		3
static DEFINE_HASHTABLE(sessions_table, SESSION_HASH_BITS);
static DECLARE_RWSEM(sessions_table_lock);

struct ksmbd_session_rpc {
	int			id;
	unsigned int		method;
};

#ifdef CONFIG_PROC_FS

static const struct ksmbd_const_name ksmbd_sess_cap_const_names[] = {
	{SMB2_GLOBAL_CAP_DFS, "dfs"},
	{SMB2_GLOBAL_CAP_LEASING, "lease"},
	{SMB2_GLOBAL_CAP_LARGE_MTU, "large-mtu"},
	{SMB2_GLOBAL_CAP_MULTI_CHANNEL, "multi-channel"},
	{SMB2_GLOBAL_CAP_PERSISTENT_HANDLES, "persistent-handles"},
	{SMB2_GLOBAL_CAP_DIRECTORY_LEASING, "dir-lease"},
	{SMB2_GLOBAL_CAP_ENCRYPTION, "encryption"}
};

static const struct ksmbd_const_name ksmbd_cipher_const_names[] = {
	{le16_to_cpu(SMB2_ENCRYPTION_AES128_CCM), "aes128-ccm"},
	{le16_to_cpu(SMB2_ENCRYPTION_AES128_GCM), "aes128-gcm"},
	{le16_to_cpu(SMB2_ENCRYPTION_AES256_CCM), "aes256-ccm"},
	{le16_to_cpu(SMB2_ENCRYPTION_AES256_GCM), "aes256-gcm"},
};

static const struct ksmbd_const_name ksmbd_signing_const_names[] = {
	{le16_to_cpu(SIGNING_ALG_HMAC_SHA256), "hmac-sha256"},
	{le16_to_cpu(SIGNING_ALG_AES_CMAC), "aes-cmac"},
	{le16_to_cpu(SIGNING_ALG_AES_GMAC), "aes-gmac"},
};

static const char *session_state_string(struct ksmbd_session *session)
{
	if (session->state == SMB2_SESSION_VALID)
		return "valid";
	else if (session->state == SMB2_SESSION_IN_PROGRESS)
		return "progress";
	else if (session->state == SMB2_SESSION_EXPIRED)
		return "expired";
	else
		return "";
}

static const char *session_user_name(struct ksmbd_session *session)
{
	if (user_guest(session->user))
		return "(Guest)";
	else if (user_anonymous(session->user))
		return "(Anonymous)";
	return session->user->name;
}

static int show_proc_session(struct seq_file *m, void *v)
{
	struct ksmbd_session *sess;
	struct ksmbd_tree_connect *tree_conn;
	struct ksmbd_share_config *share_conf;
	struct channel *chan;
	unsigned long id;
	int i = 0;

	sess = (struct ksmbd_session *)m->private;
	get_session(sess);

	seq_printf(m, "%-20s\t%s\n", "client", sess->conn->client_name);
	seq_printf(m, "%-20s\t%s\n", "user", session_user_name(sess));
	seq_printf(m, "%-20s\t%s\n", "state", session_state_string(sess));

	seq_printf(m, "%-20s\t", "capabilities");
	ksmbd_proc_show_flag_names(m,
				   ksmbd_sess_cap_const_names,
				   ARRAY_SIZE(ksmbd_sess_cap_const_names),
				   sess->conn->vals->capabilities);

	if (sess->sign) {
		seq_printf(m, "%-20s\t", "signing");
		ksmbd_proc_show_const_name(m, "%s\n",
					   ksmbd_signing_const_names,
					   ARRAY_SIZE(ksmbd_signing_const_names),
					   le16_to_cpu(sess->conn->signing_algorithm));
	} else if (sess->enc) {
		seq_printf(m, "%-20s\t", "encryption");
		ksmbd_proc_show_const_name(m, "%s\n",
					   ksmbd_cipher_const_names,
					   ARRAY_SIZE(ksmbd_cipher_const_names),
					   le16_to_cpu(sess->conn->cipher_type));
	}

	i = 0;
	list_for_each_entry(chan, &sess->ksmbd_chann_list, chann_list) {
		i++;
	}
	seq_printf(m, "%-20s\t%d\n", "channels", i);

	i = 0;
	xa_for_each(&sess->tree_conns, id, tree_conn) {
		share_conf = tree_conn->share_conf;
		seq_printf(m, "%-20s\t%s\t%8d", "share",
			   share_conf->name, tree_conn->id);
		if (test_share_config_flag(share_conf, KSMBD_SHARE_FLAG_PIPE))
			seq_printf(m, " %s ", "pipe");
		else
			seq_printf(m, " %s ", "disk");
		seq_putc(m, '\n');
	}

	put_session(sess);
	return 0;
}

static int create_proc_session(struct ksmbd_session *sess)
{
	char name[30];

	snprintf(name, sizeof(name), "sessions/%llu", sess->id);
	sess->proc_entry = ksmbd_proc_create(name, show_proc_session, sess);
	return 0;
}

static void delete_proc_session(struct ksmbd_session *sess)
{
	if (sess->proc_entry)
		proc_remove(sess->proc_entry);
}

static int show_proc_sessions(struct seq_file *m, void *v)
{
	struct ksmbd_session *session;
	int i;

	seq_printf(m, "#%-10s %-40s %-15s %-10s\n",
		 "<id>", "<address>", "<user>", "<state>");

	down_read(&sessions_table_lock);
	hash_for_each(sessions_table, i, session, hlist) {
		get_session(session);

		seq_printf(m, " %-10llu %-40s %-15s %-10s\n",
			   session->id,
			   session->conn->client_name,
			   session_user_name(session),
			   session_state_string(session));

		put_session(session);
	}
	up_read(&sessions_table_lock);
	return 0;
}

static int create_proc_sessions(void)
{
	if (ksmbd_proc_create("sessions/sessions",
			      show_proc_sessions, NULL) == NULL)
		return -ENOMEM;
	return 0;
}
#else
static int create_proc_sessions(void) { return 0; }
static int create_proc_session(struct ksmbd_session *sess) { return 0; }
static void delete_proc_session(struct ksmbd_session *sess) {}
#endif

static void free_channel_list(struct ksmbd_session *sess)
{
	struct channel *chann;
	unsigned long index;

	xa_for_each(&sess->ksmbd_chann_list, index, chann) {
		xa_erase(&sess->ksmbd_chann_list, index);
		kfree(chann);
	}

	xa_destroy(&sess->ksmbd_chann_list);
}

static void __session_rpc_close(struct ksmbd_session *sess,
				struct ksmbd_session_rpc *entry)
{
	struct ksmbd_rpc_command *resp;

	resp = ksmbd_rpc_close(sess, entry->id);
	if (!resp)
		pr_err("Unable to close RPC pipe %d\n", entry->id);

	kvfree(resp);
	ksmbd_rpc_id_free(entry->id);
	kfree(entry);
}

static void ksmbd_session_rpc_clear_list(struct ksmbd_session *sess)
{
	struct ksmbd_session_rpc *entry;
	long index;

	xa_for_each(&sess->rpc_handle_list, index, entry) {
		xa_erase(&sess->rpc_handle_list, index);
		__session_rpc_close(sess, entry);
	}

	xa_destroy(&sess->rpc_handle_list);
}

static int __rpc_method(char *rpc_name)
{
	if (!strcmp(rpc_name, "\\srvsvc") || !strcmp(rpc_name, "srvsvc"))
		return KSMBD_RPC_SRVSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\wkssvc") || !strcmp(rpc_name, "wkssvc"))
		return KSMBD_RPC_WKSSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "LANMAN") || !strcmp(rpc_name, "lanman"))
		return KSMBD_RPC_RAP_METHOD;

	if (!strcmp(rpc_name, "\\samr") || !strcmp(rpc_name, "samr"))
		return KSMBD_RPC_SAMR_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\lsarpc") || !strcmp(rpc_name, "lsarpc"))
		return KSMBD_RPC_LSARPC_METHOD_INVOKE;

	pr_err("Unsupported RPC: %s\n", rpc_name);
	return 0;
}

int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name)
{
	struct ksmbd_session_rpc *entry;
	struct ksmbd_rpc_command *resp;
	int method;

	method = __rpc_method(rpc_name);
	if (!method)
		return -EINVAL;

	entry = kzalloc(sizeof(struct ksmbd_session_rpc), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->method = method;
	entry->id = ksmbd_ipc_id_alloc();
	if (entry->id < 0)
		goto free_entry;
	xa_store(&sess->rpc_handle_list, entry->id, entry, GFP_KERNEL);

	resp = ksmbd_rpc_open(sess, entry->id);
	if (!resp)
		goto free_id;

	kvfree(resp);
	return entry->id;
free_id:
	xa_erase(&sess->rpc_handle_list, entry->id);
	ksmbd_rpc_id_free(entry->id);
free_entry:
	kfree(entry);
	return -EINVAL;
}

void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id)
{
	struct ksmbd_session_rpc *entry;

	entry = xa_erase(&sess->rpc_handle_list, id);
	if (entry)
		__session_rpc_close(sess, entry);
}

int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id)
{
	struct ksmbd_session_rpc *entry;

	entry = xa_load(&sess->rpc_handle_list, id);
	return entry ? entry->method : 0;
}

void ksmbd_session_destroy(struct ksmbd_session *sess)
{
	if (!sess)
		return;

	delete_proc_session(sess);

	if (sess->user)
		ksmbd_free_user(sess->user);

	ksmbd_tree_conn_session_logoff(sess);
	ksmbd_destroy_file_table(&sess->file_table);
	ksmbd_session_rpc_clear_list(sess);
	free_channel_list(sess);
	kfree(sess->Preauth_HashValue);
	ksmbd_release_id(&session_ida, sess->id);
	kfree(sess);
}

static struct ksmbd_session *__session_lookup(unsigned long long id)
{
	struct ksmbd_session *sess;

	hash_for_each_possible(sessions_table, sess, hlist, id) {
		if (id == sess->id) {
			sess->last_active = jiffies;
			return sess;
		}
	}
	return NULL;
}

static void ksmbd_expire_session(struct ksmbd_conn *conn)
{
	unsigned long id;
	struct ksmbd_session *sess;

	down_write(&sessions_table_lock);
	xa_for_each(&conn->sessions, id, sess) {
		if (sess->state != SMB2_SESSION_VALID ||
		    time_after(jiffies,
			       sess->last_active + SMB2_SESSION_TIMEOUT)) {
			xa_erase(&conn->sessions, sess->id);
#ifdef CONFIG_SMB_INSECURE_SERVER
			if (hash_hashed(&sess->hlist))
				hash_del(&sess->hlist);
#else
			hash_del(&sess->hlist);
#endif
			ksmbd_session_destroy(sess);
			continue;
		}
	}
	up_write(&sessions_table_lock);
}

int ksmbd_session_register(struct ksmbd_conn *conn,
			   struct ksmbd_session *sess)
{
	sess->dialect = conn->dialect;
	memcpy(sess->ClientGUID, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);
	ksmbd_expire_session(conn);
	return xa_err(xa_store(&conn->sessions, sess->id, sess, GFP_KERNEL));
}

static int ksmbd_chann_del(struct ksmbd_conn *conn, struct ksmbd_session *sess)
{
	struct channel *chann;

	chann = xa_erase(&sess->ksmbd_chann_list, (long)conn);
	if (!chann)
		return -ENOENT;

	kfree(chann);
	return 0;
}

void ksmbd_sessions_deregister(struct ksmbd_conn *conn)
{
	struct ksmbd_session *sess;
	unsigned long id;

	down_write(&sessions_table_lock);
	if (conn->binding) {
		int bkt;
		struct hlist_node *tmp;

		hash_for_each_safe(sessions_table, bkt, tmp, sess, hlist) {
			if (!ksmbd_chann_del(conn, sess) &&
			    xa_empty(&sess->ksmbd_chann_list)) {
#ifdef CONFIG_SMB_INSECURE_SERVER
			if (hash_hashed(&sess->hlist))
				hash_del(&sess->hlist);
#else
				hash_del(&sess->hlist);
#endif
				ksmbd_session_destroy(sess);
			}
		}
	}

	xa_for_each(&conn->sessions, id, sess) {
		unsigned long chann_id;
		struct channel *chann;

		xa_for_each(&sess->ksmbd_chann_list, chann_id, chann) {
			if (chann->conn != conn)
				ksmbd_conn_set_exiting(chann->conn);
		}

		ksmbd_chann_del(conn, sess);
		if (xa_empty(&sess->ksmbd_chann_list)) {
			xa_erase(&conn->sessions, sess->id);
#ifdef CONFIG_SMB_INSECURE_SERVER
			if (hash_hashed(&sess->hlist))
				hash_del(&sess->hlist);
#else
			hash_del(&sess->hlist);
#endif
			ksmbd_session_destroy(sess);
		}
	}
	up_write(&sessions_table_lock);
}

struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
					   unsigned long long id)
{
	struct ksmbd_session *sess;

	sess = xa_load(&conn->sessions, id);
	if (sess)
		sess->last_active = jiffies;
	return sess;
}

struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id)
{
	struct ksmbd_session *sess;

	down_read(&sessions_table_lock);
	sess = __session_lookup(id);
	if (sess)
		sess->last_active = jiffies;
	up_read(&sessions_table_lock);

	return sess;
}

struct ksmbd_session *ksmbd_session_lookup_all(struct ksmbd_conn *conn,
					       unsigned long long id)
{
	struct ksmbd_session *sess;

	sess = ksmbd_session_lookup(conn, id);
	if (!sess && conn->binding)
		sess = ksmbd_session_lookup_slowpath(id);
	if (sess && sess->state != SMB2_SESSION_VALID)
		sess = NULL;
	return sess;
}

struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,
						    u64 sess_id)
{
	struct preauth_session *sess;

	sess = kmalloc(sizeof(struct preauth_session), GFP_KERNEL);
	if (!sess)
		return NULL;

	sess->id = sess_id;
	memcpy(sess->Preauth_HashValue, conn->preauth_info->Preauth_HashValue,
	       PREAUTH_HASHVALUE_SIZE);
	list_add(&sess->preauth_entry, &conn->preauth_sess_table);

	return sess;
}

static bool ksmbd_preauth_session_id_match(struct preauth_session *sess,
					   unsigned long long id)
{
	return sess->id == id;
}

struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,
						     unsigned long long id)
{
	struct preauth_session *sess = NULL;

	list_for_each_entry(sess, &conn->preauth_sess_table, preauth_entry) {
		if (ksmbd_preauth_session_id_match(sess, id))
			return sess;
	}
	return NULL;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
static int __init_smb1_session(struct ksmbd_session *sess)
{
	int id = ksmbd_acquire_smb1_uid(&session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}
#endif

static int __init_smb2_session(struct ksmbd_session *sess)
{
	int id = ksmbd_acquire_smb2_uid(&session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}

static struct ksmbd_session *__session_create(int protocol)
{
	struct ksmbd_session *sess;
	int ret;

	sess = kzalloc(sizeof(struct ksmbd_session), GFP_KERNEL);
	if (!sess)
		return NULL;

	if (ksmbd_init_file_table(&sess->file_table))
		goto error;

	sess->last_active = jiffies;
	sess->state = SMB2_SESSION_IN_PROGRESS;
	set_session_flag(sess, protocol);
	xa_init(&sess->tree_conns);
	xa_init(&sess->ksmbd_chann_list);
	xa_init(&sess->rpc_handle_list);
	sess->sequence_number = 1;

	switch (protocol) {
#ifdef CONFIG_SMB_INSECURE_SERVER
	case CIFDS_SESSION_FLAG_SMB1:
		ret = __init_smb1_session(sess);
		break;
#endif
	case CIFDS_SESSION_FLAG_SMB2:
		ret = __init_smb2_session(sess);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		goto error;

	ida_init(&sess->tree_conn_ida);

	if (protocol == CIFDS_SESSION_FLAG_SMB2) {
		down_write(&sessions_table_lock);
		hash_add(sessions_table, &sess->hlist, sess->id);
		up_write(&sessions_table_lock);
	}

	create_proc_session(sess);
	ksmbd_counter_inc(KSMBD_COUNTER_SESSIONS);
	return sess;

error:
	ksmbd_session_destroy(sess);
	return NULL;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
struct ksmbd_session *ksmbd_smb1_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB1);
}
#endif

struct ksmbd_session *ksmbd_smb2_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB2);
}

int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess)
{
	int id = -EINVAL;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		id = ksmbd_acquire_smb1_tid(&sess->tree_conn_ida);
#endif
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		id = ksmbd_acquire_smb2_tid(&sess->tree_conn_ida);

	return id;
}

void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id)
{
	if (id >= 0)
		ksmbd_release_id(&sess->tree_conn_ida, id);
}

int ksmbd_sessions_init(void)
{
	create_proc_sessions();
	return 0;
}
