// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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
#include <linux/workqueue.h>

#include "server.h"
#include "smb_common.h"
#include "buffer_pool.h"
#include "transport_tcp.h"
#include "transport_ipc.h"
#include "mgmt/user_session.h"

int cifsd_debugging;

/* @FIXME clean up this code */
/*
 * keep MaxBufSize Default: 65536
 * CIFSMaxBufSize can have it in Range: 8192 to 130048(default 16384)
 */
unsigned int SMBMaxBufSize = CIFS_MAX_MSGSIZE;

struct fidtable_desc global_fidtable;

LIST_HEAD(global_lock_list);

/* Default: allocation roundup size = 1048576, to disable set 0 in config */
unsigned int alloc_roundup_size = 1048576;
/* @FIXME end clean up */

struct cifsd_server_config server_conf;

enum SERVER_CTRL_TYPE {
	SERVER_CTRL_TYPE_INIT,
	SERVER_CTRL_TYPE_RESET,
};

struct server_ctrl_struct {
	int			type;
	struct work_struct	ctrl_work;
};

static DEFINE_MUTEX(ctrl_lock);

static int ___server_conf_set(int idx, char *val)
{
	if (idx > sizeof(server_conf.conf))
		return -EINVAL;

	if (!val || val[0] == 0x00)
		return -EINVAL;

	kfree(server_conf.conf[idx]);
	server_conf.conf[idx] = kstrdup(val, GFP_KERNEL);
	if (!server_conf.conf[idx])
		return -ENOMEM;
	return 0;
}

int cifsd_set_netbios_name(char *v)
{
	return ___server_conf_set(SERVER_CONF_NETBIOS_NAME, v);
}

int cifsd_set_server_string(char *v)
{
	return ___server_conf_set(SERVER_CONF_SERVER_STRING, v);
}

int cifsd_set_work_group(char *v)
{
	return ___server_conf_set(SERVER_CONF_WORK_GROUP, v);
}

char *cifsd_netbios_name(void)
{
	return server_conf.conf[SERVER_CONF_NETBIOS_NAME];
}

char *cifsd_server_string(void)
{
	return server_conf.conf[SERVER_CONF_SERVER_STRING];
}

char *cifsd_work_group(void)
{
	return server_conf.conf[SERVER_CONF_WORK_GROUP];
}

/**
 * check_conn_state() - check state of server thread connection
 * @cifsd_work:     smb work containing server thread information
 *
 * Return:	0 on valid connection, otherwise 1 to reconnect
 */
static inline int check_conn_state(struct cifsd_work *work)
{
	struct smb_hdr *rsp_hdr;

	if (cifsd_tcp_exiting(work) || cifsd_tcp_need_reconnect(work)) {
		rsp_hdr = RESPONSE_BUF(work);
		rsp_hdr->Status.CifsError = NT_STATUS_CONNECTION_DISCONNECTED;
		return 1;
	}
	return 0;
}

/* @FIXME what a mess... god help. */

/**
 * handle_cifsd_work() - process pending smb work requests
 * @cifsd_work:	smb work containing request command buffer
 *
 * called by kworker threads to processing remaining smb work requests
 */
static void handle_cifsd_work(struct work_struct *wk)
{
	struct cifsd_work *work = container_of(wk, struct cifsd_work, work);
	struct cifsd_tcp_conn *conn = work->conn;
	unsigned int command = 0;
	int rc;
	bool conn_valid = false;
	struct smb_version_cmds *cmds;
	long int start_time = 0, end_time = 0, time_elapsed = 0;

	cifsd_tcp_conn_lock(conn);

	if (cifsd_debugging)
		start_time = jiffies;

	conn->stats.request_served++;

	if (conn->ops->allocate_rsp_buf(work)) {
		rc = -ENOMEM;
		goto nosend;
	}

	if (conn->ops->is_transform_hdr &&
		conn->ops->is_transform_hdr(REQUEST_BUF(work))) {
		rc = conn->ops->decrypt_req(work);
		if (rc < 0) {
			conn->ops->set_rsp_status(work, NT_STATUS_DATA_ERROR);
			goto send;
		}

		work->encrypted = true;
	}

	rc = conn->ops->init_rsp_hdr(work);
	if (rc) {
		/* either uid or tid is not correct */
		conn->ops->set_rsp_status(work, NT_STATUS_INVALID_HANDLE);
		goto send;
	}

	if (conn->ops->check_user_session) {
		rc = conn->ops->check_user_session(work);
		if (rc < 0) {
			command = conn->ops->get_cmd_val(work);
			conn->ops->set_rsp_status(work,
					NT_STATUS_USER_SESSION_DELETED);
			goto send;
		} else if (rc > 0) {
			rc = conn->ops->get_cifsd_tcon(work);
			if (rc < 0) {
				conn->ops->set_rsp_status(work,
					NT_STATUS_NETWORK_NAME_DELETED);
				goto send;
			}
		}
	}

chained:
	rc = check_conn_state(work);
	if (rc)
		goto send;

	/* check if the message is ok */
	if (check_message(work)) {
		cifsd_err("Malformed smb request\n");
		goto nosend;
	}

	conn_valid = true;
	command = conn->ops->get_cmd_val(work);
again:
	if (command >= conn->max_cmds) {
		conn->ops->set_rsp_status(work,
					NT_STATUS_INVALID_PARAMETER);
		goto send;
	}

	cmds = &conn->cmds[command];
	if (cmds->proc == NULL) {
		cifsd_err("*** not implemented yet cmd = %x\n", command);
		conn->ops->set_rsp_status(work, NT_STATUS_NOT_IMPLEMENTED);
		goto send;
	}

	mutex_unlock(&conn->srv_mutex);

	if (work->sess && conn->ops->is_sign_req &&
		conn->ops->is_sign_req(work, command)) {
		rc = conn->ops->check_sign_req(work);
		if (!rc) {
			conn->ops->set_rsp_status(work, NT_STATUS_DATA_ERROR);
			goto send;
		}
	}

	rc = cmds->proc(work);
	mutex_lock(&conn->srv_mutex);
	if (conn->need_neg && (conn->dialect == CIFSD_SMB20_PROT_ID ||
				conn->dialect == CIFSD_SMB21_PROT_ID ||
				conn->dialect == CIFSD_SMB2X_PROT_ID ||
				conn->dialect == CIFSD_SMB30_PROT_ID ||
				conn->dialect == CIFSD_SMB302_PROT_ID ||
				conn->dialect == CIFSD_SMB311_PROT_ID)) {
		cifsd_debug("Need to send the smb2 negotiate response\n");
		init_smb2_neg_rsp(work);
		goto send;
	}
	/* AndX commands - chained request can return positive values */
	if (rc > 0) {
		command = rc;
		goto again;
	} else if (rc < 0)
		cifsd_debug("error(%d) while processing cmd %u\n",
							rc, command);

	if (work->send_no_response) {
		spin_lock(&conn->request_lock);
		if (work->on_request_list) {
			list_del_init(&work->request_entry);
			work->on_request_list = 0;
		}
		spin_unlock(&conn->request_lock);
		goto nosend;
	}

send:
	if (is_chained_smb2_message(work))
		goto chained;

	/* call set_rsp_credits() function to set number of credits granted in
	 * hdr of smb2 response.
	 */
	if (is_smb2_rsp(work))
		conn->ops->set_rsp_credits(work);

	if (conn->dialect == CIFSD_SMB311_PROT_ID)
		smb3_preauth_hash_rsp(work);

	if (work->sess && work->sess->enc && work->encrypted &&
		conn->ops->encrypt_resp) {
		rc = conn->ops->encrypt_resp(work);
		if (rc < 0) {
			conn->ops->set_rsp_status(work, NT_STATUS_DATA_ERROR);
			goto send;
		}
	} else if (work->sess && (work->sess->sign ||
		(conn->ops->is_sign_req &&
		conn->ops->is_sign_req(work, command))))
		conn->ops->set_sign_rsp(work);

	cifsd_tcp_write(work);

nosend:
	if (cifsd_debugging) {
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

	if (cifsd_tcp_exiting(work))
		force_sig(SIGKILL, conn->handler);

	cifsd_tcp_conn_unlock(conn);
	/* Now can free cifsd work */
	cifsd_free_work_struct(work);

	/*
	 * Decrement Ref count when all processing finished
	 *  - in both success or failure cases
	 */
	atomic_dec(&conn->r_count);
}

/**
 * queue_cifsd_work() - queue a smb request to worker thread queue
 *		for proccessing smb command and sending response
 * @conn:     TCP server instance of connection
 *
 * read remaining data from socket create and submit work.
 */
static int queue_cifsd_work(struct cifsd_tcp_conn *conn)
{
	struct cifsd_work *work;

	work = cifsd_alloc_work_struct();
	if (!work) {
		cifsd_err("allocation for work failed\n");
		return -ENOMEM;
	}

	/*
	 * Increment ref count for the Server object, as after this
	 * only fallback point is from handle_cifsd_work
	 */
	atomic_inc(&conn->r_count);
	work->conn = conn;

	work->request_buf = conn->request_buf;
	conn->request_buf = NULL;

	cifsd_init_smb_server(work);
	cifsd_tcp_enqueue_request(work);

	/* update activity on connection */
	conn->last_active = jiffies;
	INIT_WORK(&work->work, handle_cifsd_work);
	schedule_work(&work->work);
	return 0;
}

static int cifsd_server_process_request(struct cifsd_tcp_conn *conn)
{
	return queue_cifsd_work(conn);
}

static int cifsd_server_terminate_conn(struct cifsd_tcp_conn *conn)
{
	cifsd_sessions_deregister(conn);
	destroy_lease_table(conn);
	return 0;
}

static void cifsd_server_tcp_callbacks_init(void)
{
	struct cifsd_tcp_conn_ops ops;

	ops.process_fn = cifsd_server_process_request;
	ops.terminate_fn = cifsd_server_terminate_conn;

	cifsd_tcp_init_server_callbacks(&ops);
}

static void server_conf_free(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(server_conf.conf); i++) {
		kfree(server_conf.conf[i]);
		server_conf.conf[i] = NULL;
	}
}

static int server_conf_init(void)
{
	server_conf.state = SERVER_STATE_STARTING_UP;
	server_conf.enforced_signing = 0;
	server_conf.min_protocol = cifsd_min_protocol();
	server_conf.max_protocol = cifsd_max_protocol();
	return 0;
}

static void server_ctrl_handle_init(struct server_ctrl_struct *ctrl)
{
	int ret;

	ret = cifsd_tcp_init();
	if (ret) {
		pr_err("Failed to init TCP subsystem: %d\n", ret);
		server_queue_ctrl_reset_work();
		return;
	}

	server_conf.state = SERVER_STATE_RUNNING;
}

static void server_ctrl_handle_reset(struct server_ctrl_struct *ctrl)
{
	cifsd_tcp_destroy();
	server_conf.state = SERVER_STATE_STARTING_UP;
}

static void server_ctrl_handle_work(struct work_struct *work)
{
	struct server_ctrl_struct *ctrl;

	ctrl = container_of(work, struct server_ctrl_struct, ctrl_work);

	mutex_lock(&ctrl_lock);
	switch (ctrl->type) {
	case SERVER_CTRL_TYPE_INIT:
		server_ctrl_handle_init(ctrl);
		break;
	case SERVER_CTRL_TYPE_RESET:
		server_ctrl_handle_reset(ctrl);
		break;
	default:
		pr_err("Unknown server work type: %d\n", ctrl->type);
	}
	mutex_unlock(&ctrl_lock);
	kfree(ctrl);
	module_put(THIS_MODULE);
}

static int __queue_ctrl_work(int type)
{
	struct server_ctrl_struct *ctrl;

	ctrl = kmalloc(sizeof(struct server_ctrl_struct), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	__module_get(THIS_MODULE);
	ctrl->type = type;
	INIT_WORK(&ctrl->ctrl_work, server_ctrl_handle_work);
	queue_work(system_long_wq, &ctrl->ctrl_work);
	return 0;
}

int server_queue_ctrl_init_work(void)
{
	return __queue_ctrl_work(SERVER_CTRL_TYPE_INIT);
}

int server_queue_ctrl_reset_work(void)
{
	return __queue_ctrl_work(SERVER_CTRL_TYPE_RESET);
}

int cifsd_server_daemon_heartbeat(void)
{
	if (cifsd_ipc_heartbeat()) {
		server_conf_free();
		server_conf_init();
		server_queue_ctrl_reset_work();
		return -EINVAL;
	}
	return 0;
}

static int cifsd_server_shutdown(void)
{
	server_conf.state = SERVER_STATE_SHUTTING_DOWN;

	cifsd_ipc_release();
	cifsd_tcp_destroy();
	cifsd_free_session_table();

	destroy_global_fidtable();
	destroy_lease_table(NULL);
	cifsd_destroy_buffer_pools();
	exit_cifsd_idmap();
	server_conf_free();
	return 0;
}

static int __init cifsd_server_init(void)
{
	int ret;

	cifsd_server_tcp_callbacks_init();

	ret = server_conf_init();
	if (ret)
		return ret;

	ret = cifsd_init_buffer_pools();
	if (ret)
		return ret;

	ret = cifsd_init_session_table();
	if (ret)
		goto error;

	ret = cifsd_ipc_init();
	if (ret)
		goto error;

	ret = init_fidtable(&global_fidtable);
	if (ret)
		goto error;

	cifsd_inode_hash_init();

	ret = init_cifsd_idmap();
	if (ret)
		goto error;
	return 0;

error:
	cifsd_server_shutdown();
	return ret;
}

/**
 * exit_smb_server() - shutdown forker thread and free memory at module exit
 */
static void __exit cifsd_server_exit(void)
{
	cifsd_server_shutdown();
}

module_param(cifsd_debugging, int, 0644);
MODULE_PARM_DESC(cifsd_debugging, "Enable/disable CIFSD debugging output");

MODULE_AUTHOR("Namjae Jeon <namjae.jeon@protocolfreedom.org>");
MODULE_DESCRIPTION("Linux kernel CIFS/SMB SERVER");
MODULE_LICENSE("GPL");
module_init(cifsd_server_init)
module_exit(cifsd_server_exit)
