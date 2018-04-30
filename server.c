/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif
#include "oplock.h"
#include "cifsacl.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#include "buffer_pool.h"
#include "transport.h"

bool global_signing;

/*
 * keep MaxBufSize Default: 65536
 * CIFSMaxBufSize can have it in Range: 8192 to 130048(default 16384)
 */
unsigned int SMBMaxBufSize = CIFS_MAX_MSGSIZE;

struct fidtable_desc global_fidtable;

LIST_HEAD(global_lock_list);

/* Default: allocation roundup size = 1048576, to disable set 0 in config */
unsigned int alloc_roundup_size = 1048576;

/**
 * construct_cifsd_tcon() - alloc tcon object and initialize
 *		 from session and share info and increment tcon count
 * @sess:	session to link with tcon object
 * @share:	Related association of tcon object with share
 *
 * Return:	If Succes, Valid initialized tcon object, else errors
 */
struct cifsd_tcon *construct_cifsd_tcon(struct cifsd_share *share,
				struct cifsd_sess *sess)
{
	struct cifsd_tcon *tcon;
	int err;

	tcon = kzalloc(sizeof(struct cifsd_tcon), GFP_KERNEL);
	if (!tcon)
		return ERR_PTR(-ENOMEM);

	if (!share->path)
		goto out;

	err = kern_path(share->path, 0, &tcon->share_path);
	if (err) {
		cifsd_err("kern_path() failed for shares(%s)\n", share->path);
		kfree(tcon);
		return ERR_PTR(-ENOENT);
	}

out:
	tcon->share = share;
	tcon->sess = sess;
	INIT_LIST_HEAD(&tcon->tcon_list);
	list_add(&tcon->tcon_list, &sess->tcon_list);
	sess->tcon_count++;

	return tcon;
}

/**
 * check_conn_state() - check state of server thread connection
 * @smb_work:     smb work containing server thread information
 *
 * Return:	0 on valid connection, otherwise 1 to reconnect
 */
static inline int check_conn_state(struct smb_work *smb_work)
{
	struct smb_hdr *rsp_hdr;

	if (cifsd_tcp_exiting(smb_work) || cifsd_tcp_need_reconnect(smb_work)) {
		rsp_hdr = RESPONSE_BUF(smb_work);
		rsp_hdr->Status.CifsError = NT_STATUS_CONNECTION_DISCONNECTED;
		return 1;
	}
	return 0;
}

/**
 * handle_smb_work() - process pending smb work requests
 * @smb_work:	smb work containing request command buffer
 *
 * called by kworker threads to processing remaining smb work requests
 */
static void handle_smb_work(struct work_struct *work)
{
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct cifsd_tcp_conn *conn = smb_work->conn;
	unsigned int command = 0;
	int rc;
	bool conn_valid = false;
	struct smb_version_cmds *cmds;
	long int start_time = 0, end_time = 0, time_elapsed = 0;

	atomic_inc(&conn->req_running);
	mutex_lock(&conn->srv_mutex);

	if (cifsd_debug_enable)
		start_time = jiffies;

	conn->stats.request_served++;

	if (unlikely(conn->need_neg)) {
		if (is_smb2_neg_cmd(smb_work))
			init_smb2_0_server(conn);
		else if (conn->ops->get_cmd_val(smb_work) !=
						SMB_COM_NEGOTIATE)
			conn->need_neg = false;
	}

	if (conn->ops->allocate_rsp_buf(smb_work)) {
		rc = -ENOMEM;
		goto nosend;
	}

	rc = conn->ops->init_rsp_hdr(smb_work);
	if (rc) {
		/* either uid or tid is not correct */
		conn->ops->set_rsp_status(smb_work, NT_STATUS_INVALID_HANDLE);
		goto send;
	}

	if (conn->ops->check_user_session) {
		rc = conn->ops->check_user_session(smb_work);
		if (rc < 0) {
			command = conn->ops->get_cmd_val(smb_work);
			conn->ops->set_rsp_status(smb_work,
					NT_STATUS_USER_SESSION_DELETED);
			goto send;
		} else if (rc > 0) {
			rc = conn->ops->get_cifsd_tcon(smb_work);
			if (rc < 0) {
				conn->ops->set_rsp_status(smb_work,
					NT_STATUS_NETWORK_NAME_DELETED);
				goto send;
			}
		}
	}

chained:
	rc = check_conn_state(smb_work);
	if (rc)
		goto send;

	conn_valid = true;
	command = conn->ops->get_cmd_val(smb_work);
again:
	if (command >= conn->max_cmds) {
		conn->ops->set_rsp_status(smb_work,
					NT_STATUS_INVALID_PARAMETER);
		goto send;
	}

	cmds = &conn->cmds[command];
	if (cmds->proc == NULL) {
		cifsd_err("*** not implemented yet cmd = %x\n", command);
		conn->ops->set_rsp_status(smb_work,
						NT_STATUS_NOT_IMPLEMENTED);
		goto send;
	}

	mutex_unlock(&conn->srv_mutex);

	if (smb_work->sess && smb_work->sess->sign &&
		conn->ops->is_sign_req &&
		conn->ops->is_sign_req(smb_work, command)) {
		rc = conn->ops->check_sign_req(smb_work);
		if (!rc) {
			conn->ops->set_rsp_status(smb_work,
							NT_STATUS_DATA_ERROR);
			goto send;
		}
	}

	rc = cmds->proc(smb_work);
	mutex_lock(&conn->srv_mutex);
	if (conn->need_neg && (conn->dialect == SMB20_PROT_ID ||
				conn->dialect == SMB21_PROT_ID ||
				conn->dialect == SMB2X_PROT_ID ||
				conn->dialect == SMB30_PROT_ID ||
				conn->dialect == SMB302_PROT_ID ||
				conn->dialect == SMB311_PROT_ID)) {
		cifsd_debug("Need to send the smb2 negotiate response\n");
		init_smb2_neg_rsp(smb_work);
		goto send;
	}
	/* AndX commands - chained request can return positive values */
	if (rc > 0) {
		command = rc;
		goto again;
	} else if (rc < 0)
		cifsd_debug("error(%d) while processing cmd %u\n",
							rc, command);

	if (smb_work->send_no_response) {
		spin_lock(&conn->request_lock);
		if (smb_work->added_in_request_list) {
			list_del_init(&smb_work->request_entry);
			smb_work->added_in_request_list = 0;
		}
		spin_unlock(&conn->request_lock);
		goto nosend;
	}

send:
	if (is_chained_smb2_message(smb_work))
		goto chained;

	/* call set_rsp_credits() function to set number of credits granted in
	 * hdr of smb2 response.
	 */
	if (is_smb2_rsp(smb_work))
		conn->ops->set_rsp_credits(smb_work);

	if (conn->dialect == SMB311_PROT_ID)
		smb3_preauth_hash_rsp(smb_work);

	if (smb_work->sess && smb_work->sess->sign &&
		conn->ops->is_sign_req &&
		conn->ops->is_sign_req(smb_work, command))
		conn->ops->set_sign_rsp(smb_work);

	cifsd_tcp_write(smb_work);

nosend:
	if (cifsd_debug_enable) {
		end_time = jiffies;

		time_elapsed = end_time - start_time;
		conn->stats.avg_req_duration =
				(conn->stats.avg_req_duration *
					conn->stats.request_served +
					time_elapsed)/
					conn->stats.request_served;

		if (time_elapsed > conn->stats.max_timed_request)
			conn->stats.max_timed_request = time_elapsed;
	}

	if (cifsd_tcp_exiting(smb_work))
		force_sig(SIGKILL, conn->handler);

	/* Now can free cifsd work */
	cifsd_free_work_struct(smb_work);

	mutex_unlock(&conn->srv_mutex);
	atomic_dec(&conn->req_running);
	cifsd_debug("req running = %d\n", atomic_read(&conn->req_running));
	if (waitqueue_active(&conn->req_running_q))
		wake_up_all(&conn->req_running_q);

	/*
	 * Decrement Ref count when all processing finished
	 *  - in both success or failure cases
	 */
	atomic_dec(&conn->r_count);
}

/**
 * queue_smb_work() - queue a smb request to worker thread queue
 *		for proccessing smb command and sending response
 * @conn:     TCP server instance of connection
 *
 * read remaining data from socket create and submit work.
 */
static int queue_smb_work(struct cifsd_tcp_conn *conn)
{
	struct smb_work *work;

	dump_smb_msg(conn->request_buf, HEADER_SIZE(conn));

	/* check if the message is ok */
	if (check_smb_message(conn->request_buf)) {
		cifsd_debug("Malformed smb request\n");
		return -EINVAL;
	}

	work = cifsd_alloc_work_struct();
	if (!work) {
		cifsd_err("allocation for work failed\n");
		return -ENOMEM;
	}

	/*
	 * Increment ref count for the Server object, as after this
	 * only fallback point is from handle_smb_work
	 */
	atomic_inc(&conn->r_count);
	work->conn = conn;

	work->request_buf = conn->request_buf;
	conn->request_buf = NULL;
	add_request_to_queue(work);

	/* update activity on connection */
	conn->last_active = jiffies;
	INIT_WORK(&work->work, handle_smb_work);
	schedule_work(&work->work);
	return 0;
}

static void free_channel_list(struct cifsd_sess *sess)
{
	struct channel *chann;
	struct list_head *tmp, *t;

	if (sess->conn->dialect >= SMB30_PROT_ID) {
		list_for_each_safe(tmp, t, &sess->cifsd_chann_list) {
			chann = list_entry(tmp, struct channel, chann_list);
			if (chann) {
				list_del(&chann->chann_list);
				kfree(chann);
			}
		}
	}
}

void smb_delete_session(struct cifsd_sess *sess)
{
	cifsd_debug("delete session ID: %llu, session count: %d\n",
			sess->sess_id, sess->conn->sess_count);

	sess->valid = 0;
	list_del(&sess->cifsd_ses_list);
	list_del(&sess->cifsd_ses_global_list);
	free_channel_list(sess);
	destroy_fidtable(sess);
	sess->conn->sess_count--;
	kfree(sess->Preauth_HashValue);
	kfree(sess);
}

static size_t cifsd_server_get_header_size(void)
{
	size_t sz = sizeof(struct smb_hdr);
#ifdef CONFIG_CIFS_SMB2_SERVER
	sz = sizeof(struct smb2_hdr);
#endif
	return sz;
}

static int cifsd_server_init_conn(struct cifsd_tcp_conn *conn)
{
	init_smb1_server(conn);
	return 0;
}

static int cifsd_server_process_request(struct cifsd_tcp_conn *conn)
{
	return queue_smb_work(conn);
}

static int cifsd_server_terminate_conn(struct cifsd_tcp_conn *conn)
{
	if (conn->sess_count) {
		struct cifsd_sess *sess;
		struct list_head *tmp, *t;
		list_for_each_safe(tmp, t, &conn->cifsd_sess) {
			sess = list_entry(tmp, struct cifsd_sess,
							cifsd_ses_list);
			smb_delete_session(sess);
		}
	}

	destroy_lease_table(conn);
	return 0;
}

static void cifsd_server_tcp_callbacks_init(void)
{
	struct cifsd_tcp_conn_ops ops;

	ops.init_fn = cifsd_server_init_conn;
	ops.process_fn = cifsd_server_process_request;
	ops.terminate_fn = cifsd_server_terminate_conn;
	ops.header_size_fn = cifsd_server_get_header_size;

	cifsd_tcp_init_server_callbacks(&ops);
}

/**
 * init_smb_server() - initialize smb server at module init
 *
 * create smb request/response mempools, initialize export points,
 * initialize fid table and start forker thread to create new smb session
 * threads on new connection requests.
 *
 * Return:	0 on success, otherwise error
 */
static int __init cifsd_server_init(void)
{
	int rc;

	cifsd_server_tcp_callbacks_init();

	rc = cifsd_init_buffer_pools();
	if (rc)
		return rc;

	rc = cifsd_export_init();
	if (rc)
		goto err1;

#ifdef CONFIG_CIFS_SMB2_SERVER
	rc = init_fidtable(&global_fidtable);
	if (rc)
		goto err2;
#endif

	rc = cifsd_net_init();
	if (rc)
		goto err3;

	mfp_hash_init();

#ifdef CONFIG_CIFSD_ACL
	rc = init_cifsd_idmap();
	if (rc)
		goto err3;
#endif

	return 0;
err3:

#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
err2:
#endif
	cifsd_export_exit();
err1:
	cifsd_destroy_buffer_pools();
	return rc;
}

/**
 * exit_smb_server() - shutdown forker thread and free memory at module exit
 */
static void __exit cifsd_server_exit(void)
{
	cifsd_net_exit();

	cifsd_tcp_destroy();
#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
#endif
	cifsd_export_exit();
	destroy_lease_table(NULL);
	cifsd_destroy_buffer_pools();
#ifdef CONFIG_CIFSD_ACL
	exit_cifsd_idmap();
#endif
}

MODULE_AUTHOR("Namjae Jeon <namjae.jeon@protocolfreedom.org>");
MODULE_DESCRIPTION("Linux kernel CIFS/SMB SERVER");
MODULE_LICENSE("GPL");
module_init(cifsd_server_init)
module_exit(cifsd_server_exit)
