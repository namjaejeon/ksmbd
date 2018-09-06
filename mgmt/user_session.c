/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rwsem.h>

#include "cifsd_ida.h"
#include "user_session.h"
#include "tree_connect.h"
#include "../transport_ipc.h"
#include "../transport_tcp.h"
#include "../buffer_pool.h"
#include "../cifsd_server.h" /* FIXME */

static struct cifsd_ida *session_ida;

#define SESSION_HASH_BITS		3
static DEFINE_HASHTABLE(sessions_table, SESSION_HASH_BITS);
static DECLARE_RWSEM(sessions_table_lock);

struct cifsd_session_rpc {
	int			id;
	unsigned int		method;
	struct list_head	list;
};

static void free_channel_list(struct cifsd_session *sess)
{
	struct channel *chann;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &sess->cifsd_chann_list) {
		chann = list_entry(tmp, struct channel, chann_list);
		if (chann) {
			list_del(&chann->chann_list);
			kfree(chann);
		}
	}
}

static void __kill_smb1_session(struct cifsd_session *sess)
{

}

static void __kill_smb2_session(struct cifsd_session *sess)
{
	destroy_fidtable(sess);
}

static void __session_rpc_close(struct cifsd_session *sess,
				struct cifsd_session_rpc *entry)
{
	struct cifsd_rpc_command *resp;

	resp = cifsd_rpc_close(sess, entry->id);
	if (!resp)
		pr_err("Unable to close RPC pipe %d\n", entry->id);

	cifsd_free(resp);
	cifsd_rpc_id_free(entry->id);
	cifsd_free(entry);
}

static void cifsd_session_rpc_clear_list(struct cifsd_session *sess)
{
	struct cifsd_session_rpc *entry;

	while (!list_empty(&sess->rpc_handle_list)) {
		entry = list_entry(sess->rpc_handle_list.next,
				   struct cifsd_session_rpc,
				   list);

		list_del(&entry->list);
		__session_rpc_close(sess, entry);
	}
}

static int __rpc_method(char *rpc_name)
{
	if (!strcmp(rpc_name, "\\srvsvc") || !strcmp(rpc_name, "srvsvc"))
		return CIFSD_RPC_SRVSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\wkssvc") || !strcmp(rpc_name, "wkssvc"))
		return CIFSD_RPC_WKSSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "LANMAN") || !strcmp(rpc_name, "lanman"))
		return CIFSD_RPC_RAP_METHOD;
	return 0;
}

int cifsd_session_rpc_open(struct cifsd_session *sess, char *rpc_name)
{
	struct cifsd_session_rpc *entry;
	struct cifsd_rpc_command *resp;
	int method;

	method = __rpc_method(rpc_name);
	if (!method)
		return -EINVAL;

	entry = cifsd_alloc(sizeof(struct cifsd_session_rpc));
	if (!entry)
		return -EINVAL;

	list_add(&entry->list, &sess->rpc_handle_list);
	entry->method = method;
	entry->id = cifsd_ipc_id_alloc();
	if (entry->id < 0)
		goto error;

	resp = cifsd_rpc_open(sess, entry->id);
	if (!resp)
		goto error;

	cifsd_free(resp);
	return entry->id;
error:
	list_del(&entry->list);
	cifsd_free(entry);
	return -EINVAL;
}

void cifsd_session_rpc_close(struct cifsd_session *sess, int id)
{
	struct cifsd_session_rpc *entry;

	list_for_each_entry(entry, &sess->rpc_handle_list, list) {
		if (entry->id == id) {
			list_del(&entry->list);
			__session_rpc_close(sess, entry);
			break;
		}
	}
}

int cifsd_session_rpc_method(struct cifsd_session *sess, int id)
{
	struct cifsd_session_rpc *entry;

	list_for_each_entry(entry, &sess->rpc_handle_list, list) {
		if (entry->id == id)
			return entry->method;
	}
	return 0;
}

void cifsd_session_destroy(struct cifsd_session *sess)
{
	if (!sess)
		return;

	cifsd_session_rpc_clear_list(sess);
	free_channel_list(sess);
	kfree(sess->Preauth_HashValue);
	cifds_release_id(session_ida, sess->id);

	list_del(&sess->sessions_entry);
	down_write(&sessions_table_lock);
	hash_del(&sess->hlist);
	up_write(&sessions_table_lock);

	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		__kill_smb1_session(sess);
	else if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		__kill_smb2_session(sess);
	cifsd_ida_free(sess->tree_conn_ida);
	cifsd_free(sess);
}

static struct cifsd_session *__session_lookup(unsigned long long id)
{
	struct cifsd_session *sess;

	hash_for_each_possible(sessions_table, sess, hlist, id) {
		if (id == sess->id)
			return sess;
	}
	return NULL;
}

void cifsd_session_register(struct cifsd_tcp_conn *conn,
			    struct cifsd_session *sess)
{
	sess->valid = 1;
	sess->conn = conn;
	list_add(&sess->sessions_entry, &conn->sessions);
}

void cifsd_sessions_deregister(struct cifsd_tcp_conn *conn)
{
	struct cifsd_session *sess;

	while (!list_empty(&conn->sessions)) {
		sess = list_entry(conn->sessions.next,
				  struct cifsd_session,
				  sessions_entry);

		cifsd_session_destroy(sess);
	}
}

bool cifsd_session_id_match(struct cifsd_session *sess, unsigned long long id)
{
	return sess->id == id;
}

struct cifsd_session *cifsd_session_lookup(struct cifsd_tcp_conn *conn,
					   unsigned long long id)
{
	struct cifsd_session *sess = NULL;

	list_for_each_entry(sess, &conn->sessions, sessions_entry) {
		if (cifsd_session_id_match(sess, id))
			return (sess->valid == 1) ? sess : NULL;
	}
	return NULL;
}

struct cifsd_session *cifsd_session_lookup_slowpath(unsigned long long id)
{
	struct cifsd_session *sess;

	down_read(&sessions_table_lock);
	sess = __session_lookup(id);
	up_read(&sessions_table_lock);

	return sess;
}

static int __init_smb1_session(struct cifsd_session *sess)
{
	int id = cifds_acquire_smb1_uid(session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}

static int __init_smb2_session(struct cifsd_session *sess)
{
	int id = cifds_acquire_smb2_uid(session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return init_fidtable(&sess->fidtable);
}

static struct cifsd_session *__session_create(int protocol)
{
	struct cifsd_session *sess;
	int ret;

	sess = cifsd_alloc(sizeof(struct cifsd_session));
	if (sess == NULL)
		return NULL;

	set_session_flag(sess, protocol);
	INIT_LIST_HEAD(&sess->sessions_entry);
	INIT_LIST_HEAD(&sess->tree_conn_list);
	INIT_LIST_HEAD(&sess->cifsd_chann_list);
	INIT_LIST_HEAD(&sess->rpc_handle_list);
	sess->sequence_number = 1;
	sess->valid = 1;

	switch (protocol) {
	case CIFDS_SESSION_FLAG_SMB1:
		ret = __init_smb1_session(sess);
		break;
	case CIFDS_SESSION_FLAG_SMB2:
		ret = __init_smb2_session(sess);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	sess->tree_conn_ida = cifsd_ida_alloc();
	if (!sess->tree_conn_ida)
		ret = -ENOMEM;

	if (ret) {
		cifsd_session_destroy(sess);
		return NULL;
	}

	down_read(&sessions_table_lock);
	hash_add(sessions_table, &sess->hlist, sess->id);
	up_read(&sessions_table_lock);
	return sess;
}

struct cifsd_session *cifsd_smb1_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB1);
}

struct cifsd_session *cifsd_smb2_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB2);
}

int cifsd_acquire_tree_conn_id(struct cifsd_session *sess)
{
	int id = -EINVAL;

	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		id = cifds_acquire_smb1_tid(sess->tree_conn_ida);
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		id = cifds_acquire_smb2_tid(sess->tree_conn_ida);

	return id;
}

void cifsd_release_tree_conn_id(struct cifsd_session *sess, int id)
{
	cifds_release_id(sess->tree_conn_ida, id);
}

int cifsd_init_session_table(void)
{
	session_ida = cifsd_ida_alloc();
	if (!session_ida)
		return -ENOMEM;
	return 0;
}

void cifsd_free_session_table(void)
{
	cifsd_ida_free(session_ida);
}
