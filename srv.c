/*
 *   fs/cifsd/srv.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include <linux/idr.h>
#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif
#include "oplock.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

bool global_signing;
unsigned long server_start_time;

struct kmem_cache *cifsd_work_cache;
struct kmem_cache *cifsd_filp_cache;

struct kmem_cache *cifsd_req_cachep;
mempool_t *cifsd_req_poolp;
struct kmem_cache *cifsd_sm_req_cachep;
mempool_t *cifsd_sm_req_poolp;
struct kmem_cache *cifsd_sm_rsp_cachep;
mempool_t *cifsd_sm_rsp_poolp;
struct kmem_cache *cifsd_rsp_cachep;
mempool_t *cifsd_rsp_poolp;

unsigned int smb_min_rcv = CIFS_MIN_RCV_POOL;
unsigned int cifs_min_send = CIFS_MIN_RCV_POOL;
unsigned int smb_min_small = 30;

/*
 * keep MaxBufSize Default: 65536
 * CIFSMaxBufSize can have it in Range: 8192 to 130048(default 16384)
 */
unsigned int SMBMaxBufSize = CIFS_MAX_MSGSIZE;

static DEFINE_IDA(cifsd_ida);
static LIST_HEAD(tcp_sess_list);
static DEFINE_SPINLOCK(tcp_sess_list_lock);

struct fidtable_desc global_fidtable;

struct hlist_head global_name_table[1024];
LIST_HEAD(global_lock_list);

/* Default: allocation roundup size = 1048576, to disable set 0 in config */
unsigned int alloc_roundup_size = 1048576;

/**
 * cifsd_buf_get() - get large response buffer
 *
 * Return:	pointer to large response buffer on success,
 *		otherwise NULL
 */
struct smb_hdr *cifsd_buf_get(void)
{
	struct smb_hdr *hdr;
	size_t buf_size = sizeof(struct smb_hdr);

#ifdef CONFIG_CIFS_SMB2_SERVER
	/*
	 * SMB2 header is bigger than CIFS one - no problems to clean some
	 * more bytes for CIFS.
	 */
	buf_size = sizeof(struct smb2_hdr);
#endif
	hdr = mempool_alloc(cifsd_req_poolp, GFP_NOFS | __GFP_ZERO);

	/* clear the first few header bytes */
	if (hdr)
		memset(hdr, 0, buf_size + 3);

	return hdr;
}

/**
 * cifsd_buf_get() - get small response buffer
 *
 * Return:	pointer to small response buffer on success,
 *		otherwise NULL
 */
struct smb_hdr *smb_small_buf_get(void)
{
	/* No need to memset smallbuf as we will fill hdr anyway */
	return mempool_alloc(cifsd_sm_req_poolp, GFP_NOFS | __GFP_ZERO);
}

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
 * allocate_buffers() - allocate response buffer for smb requests
 * @conn:     TCP server instance of connection
 *
 * Return:	true on success, otherwise NULL
 */
static bool allocate_buffers(struct connection *conn)
{
	if (!conn->bigbuf) {
		conn->bigbuf = (char *)cifsd_buf_get();
		if (!conn->bigbuf) {
			cifsd_debug("No memory for large SMB response\n");
			msleep(3000);
			/* retry will check if exiting */
			return false;
		}
	} else if (conn->large_buf) {
		/* we are reusing a dirty large buf, clear its start */
		memset(conn->bigbuf, 0, HEADER_SIZE(conn));
	}

	if (!conn->smallbuf) {
		conn->smallbuf = (char *)smb_small_buf_get();
		if (!conn->smallbuf) {
			cifsd_debug("No memory for SMB response\n");
			/* retry will check if exiting */
			return false;
		}
		/* beginning of smb buffer is cleared in our buf_get */
	} else {
		/* if existing small buf clear beginning */
		memset(conn->smallbuf, 0, HEADER_SIZE(conn));
	}

	return true;
}

/**
 * smb_send_rsp() - send smb response over network socket
 * @smb_work:     smb work containing response buffer
 *
 * TODO: change this function for smb2 currently is working for
 * smb1/smb2 both as smb*_buf_length is at beginning of the  packet
 *
 * Return:	0 on success, otherwise error
 */
int smb_send_rsp(struct smb_work *work)
{

	struct connection *conn = work->conn;
	struct smb_hdr *rsp_hdr = (struct smb_hdr *)work->rsp_buf;
	struct socket *sock = conn->sock;
	struct kvec iov;
	struct msghdr smb_msg = {};
	int len, total_len = 0;
	int val = 1;

	spin_lock(&conn->request_lock);
	if (work->added_in_request_list && !work->multiRsp) {
		list_del_init(&work->request_entry);
		work->added_in_request_list = 0;
	}
	spin_unlock(&conn->request_lock);

	if (rsp_hdr == NULL) {
		cifsd_err("NULL response header\n");
		return -ENOMEM;
	}

	if (!work->rdata_buf) {
		iov.iov_len = get_rfc1002_length(rsp_hdr) + 4;
		iov.iov_base = rsp_hdr;

		len = kernel_sendmsg(sock, &smb_msg, &iov, 1, iov.iov_len);
		if (len < 0) {
			cifsd_err("err1 %d while sending data\n", len);
			goto out;
		}
		total_len = len;
	} else {
		/* cork the socket */
		kernel_setsockopt(sock, SOL_TCP, TCP_CORK,
				(char *)&val, sizeof(val));

		/* write read smb header on socket*/
		iov.iov_base = rsp_hdr;
		iov.iov_len = work->rrsp_hdr_size;

		len = kernel_sendmsg(sock, &smb_msg, &iov, 1, iov.iov_len);
		if (len < 0) {
			cifsd_err("err2 %d while sending data\n", len);
			goto uncork;
		}
		total_len = len;

		/* write data read from file on socket*/
		iov.iov_base = work->rdata_buf;
		iov.iov_len = work->rdata_cnt;
		len = kernel_sendmsg(sock, &smb_msg, &iov, 1, iov.iov_len);
		if (len < 0) {
			cifsd_err("err3 %d while sending data\n", len);
			goto uncork;
		}
		total_len += len;

uncork:
		/* uncork it */
		val = 0;
		kernel_setsockopt(sock, SOL_TCP, TCP_CORK,
				(char *)&val, sizeof(val));
	}

	if (total_len != get_rfc1002_length(rsp_hdr) + 4)
		cifsd_err("transfered %d, expected %d bytes\n",
				total_len, get_rfc1002_length(rsp_hdr) + 4);

out:
	cifsd_debug("data sent = %d\n", total_len);

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (conn->tcp_status == CifsGood && IS_SMB2(conn))
		cifsd_update_durable_stat_info(work->sess);
#endif

	return 0;
}

/**
 * queue_dynamic_work_helper() - helper function to queue smb request
 *		work to worker thread
 * @conn:     TCP server instance of connection
 */
void queue_dynamic_work_helper(struct connection *conn)
{
	struct smb_work *work =	kmem_cache_zalloc(cifsd_work_cache, GFP_NOFS);
	if (!work) {
		cifsd_err("allocation for work failed\n");
		return;
	}

	/*
	 * Increment ref count for the Server object, as after this
	 * only fallback point is from handle_smb_work
	 */
	atomic_inc(&conn->r_count);
	work->conn = conn;

	if (conn->wbuf) {
		work->buf = conn->wbuf;
		work->req_wbuf = 1;
		conn->wbuf = NULL;
	} else if (conn->large_buf) {
		work->buf = conn->bigbuf;
		work->large_buf = 1;
		conn->large_buf = false;
		conn->bigbuf = NULL;
	} else {
		work->buf = conn->smallbuf;
		conn->smallbuf = NULL;
	}

	add_request_to_queue(work);

	/* update activity on connection */
	conn->last_active = jiffies;
	INIT_WORK(&work->work, handle_smb_work);
	schedule_work(&work->work);
}

/**
 * queue_dynamic_work() - queue a smb request to worker thread queue
 *		for proccessing smb command and sending response
 * @conn:     TCP server instance of connection
 *
 * read remaining data from socket create and submit work.
 */
void queue_dynamic_work(struct connection *conn, char *buf)
{
	int ret;

	dump_smb_msg(buf, HEADER_SIZE(conn));

	/* check if the message is ok */
	ret = check_smb_message(buf);
	if (ret) {
		cifsd_debug("Malformed smb request\n");
		return;
	}

	queue_dynamic_work_helper(conn);
}

/**
 * check_conn_state() - check state of server thread connection
 * @smb_work:     smb work containing server thread information
 *
 * Return:	0 on valid connection, otherwise 1 to reconnect
 */
static inline int check_conn_state(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb_hdr *rsp_hdr;

	if (conn->tcp_status == CifsExiting ||
			conn->tcp_status == CifsNeedReconnect) {
		rsp_hdr = (struct smb_hdr *)smb_work->rsp_buf;
		rsp_hdr->Status.CifsError = NT_STATUS_CONNECTION_DISCONNECTED;
		return 1;
	}
	return 0;
}

/**
 * free_workitem_buffers() - free all allocated buffers from different pool
 *			 for smb_work and free workitem itself
 * @smb_work: smb work item
 * Return: void
 */
static void free_workitem_buffers(struct smb_work *smb_work)
{
	if (smb_work->req_wbuf)
		vfree(smb_work->buf);
	else {
		if (smb_work->large_buf)
			mempool_free(smb_work->buf, cifsd_req_poolp);
		else
			mempool_free(smb_work->buf, cifsd_sm_req_poolp);
	}

	if (smb_work->rsp_large_buf)
		mempool_free(smb_work->rsp_buf, cifsd_rsp_poolp);
	else
		mempool_free(smb_work->rsp_buf, cifsd_sm_rsp_poolp);

	if (smb_work->rdata_buf)
		kvfree(smb_work->rdata_buf);
	kmem_cache_free(cifsd_work_cache, smb_work);
}

/**
 * handle_smb_work() - process pending smb work requests
 * @smb_work:	smb work containing request command buffer
 *
 * called by kworker threads to processing remaining smb work requests
 */
void handle_smb_work(struct work_struct *work)
{
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct connection *conn = smb_work->conn;
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

	smb_send_rsp(smb_work);

nosend:
	/* free buffers */
	free_workitem_buffers(smb_work);

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

	if (conn->tcp_status == CifsExiting)
		force_sig(SIGKILL, conn->handler);

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
 * init_tcp_conn() - intialize tcp server thread for a new connection
 * @conn:     TCP server instance of connection
 * @sock:	socket associated with new connection
 *
 * Return:	0 on success, otherwise -ENOMEM
 */
int init_tcp_conn(struct connection *conn, struct socket *sock)
{
	int rc = 0;

	init_smb1_server(conn);

	conn->need_neg = true;
	conn->srv_count = 1;
	conn->sess_count = 0;
	conn->tcp_status = CifsNew;
	conn->sock = sock;
	conn->local_nls = load_nls_default();
	atomic_set(&conn->req_running, 0);
	atomic_set(&conn->r_count, 0);
	conn->max_credits = 0;
	conn->credits_granted = 0;
	init_waitqueue_head(&conn->req_running_q);
	INIT_LIST_HEAD(&conn->tcp_sess);
	INIT_LIST_HEAD(&conn->cifsd_sess);
	INIT_LIST_HEAD(&conn->requests);
	INIT_LIST_HEAD(&conn->async_requests);
	spin_lock_init(&conn->request_lock);
	conn->srv_cap = SERVER_CAPS;
	init_waitqueue_head(&conn->oplock_q);
	spin_lock(&tcp_sess_list_lock);
	list_add(&conn->tcp_sess, &tcp_sess_list);
	spin_unlock(&tcp_sess_list_lock);

	return rc;
}

/**
 * conn_cleanup() - shutdown/release the socket and free server resources
 * @conn:	 - server instance for which socket is to be cleaned
 *
 * During the thread termination, the corresponding conn instance
 * resources(sock/memory) are released and finally the conn object is freed.
 */
static void conn_cleanup(struct connection *conn)
{
	ida_simple_remove(&cifsd_ida, conn->th_id);
	kernel_sock_shutdown(conn->sock, SHUT_RDWR);
	sock_release(conn->sock);
	conn->sock = NULL;

	if (conn->bigbuf)
		mempool_free(conn->bigbuf, cifsd_req_poolp);
	if (conn->smallbuf)
		mempool_free(conn->smallbuf, cifsd_sm_req_poolp);
	if (conn->wbuf)
		vfree(conn->wbuf);

	list_del(&conn->list);
	kfree(conn);
}

void free_channel_list(struct cifsd_sess *sess)
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

/**
 * tcp_sess_kthread() - session thread to listen on new smb requests
 * @p:     TCP conn instance of connection
 *
 * One thread each per connection
 *
 * Return:	0 on success
 */
static int tcp_sess_kthread(void *p)
{
	int length;
	unsigned int pdu_length;
	struct connection *conn = (struct connection *)p;
	char *buf;

	mutex_init(&conn->srv_mutex);
	__module_get(THIS_MODULE);
	list_add(&conn->list, &cifsd_connection_list);
	conn->last_active = jiffies;

	while (!kthread_should_stop() &&
			conn->tcp_status != CifsExiting &&
				!conn_unresponsive(conn)) {
		if (try_to_freeze())
			continue;

		if (!allocate_buffers(conn))
			continue;

		buf = conn->smallbuf;
		pdu_length = 4; /* enough to get RFC1001 header */
		length = cifsd_read_from_socket(conn, buf, pdu_length);
		if (length != pdu_length)
			/* 7 seconds passed. It should be EAGAIN */
			continue;

		conn->total_read = length;
		if (!is_smb_request(conn, buf[0]))
			continue;

		pdu_length = get_rfc1002_length(buf);
		cifsd_debug("RFC1002 header %u bytes\n", pdu_length);
		/* make sure we have enough to get to SMB header end */
		if (pdu_length < HEADER_SIZE(conn) - 4) {
			cifsd_debug("SMB request too short (%u bytes)\n",
					pdu_length);
			continue;
		}

		/*
		 * free write buffer, if we failed to add last write request to
		 * kworker due to errors e.g. socket IO error, and next a small
		 * request should be received from socket and submit to kworker
		 */
		if (conn->wbuf) {
			vfree(conn->wbuf);
			conn->wbuf = NULL;
		}

		/* if required switch to large request buffer */
		if (pdu_length > MAX_CIFS_SMALL_BUFFER_SIZE - 4) {
			if (switch_req_buf(conn))
				continue;
		}

		if (conn->wbuf)
			buf = conn->wbuf;
		else if (conn->large_buf)
			buf = conn->bigbuf;

		/* read the request */
		length = cifsd_read_from_socket(conn, buf + 4, pdu_length);
		if (length < 0) {
			cifsd_err("sock_read failed: %d\n", length);
			continue;
		}

		conn->total_read += length;
		if (length == pdu_length)
			queue_dynamic_work(conn, buf);
		else {
			if (length > pdu_length)
				cifsd_debug("extra read(%d) expected(%u)\n",
						length, pdu_length);
			else
				cifsd_debug("short read(%d) expected(%u)\n",
						length, pdu_length);
		}
	}

	wait_event(conn->req_running_q,
				atomic_read(&conn->req_running) == 0);

	/* Wait till all reference dropped to the Server object*/
	while (atomic_read(&conn->r_count) > 0)
		schedule_timeout(HZ);

	unload_nls(conn->local_nls);
	spin_lock(&tcp_sess_list_lock);
	list_del(&conn->tcp_sess);
	spin_unlock(&tcp_sess_list_lock);

	if (conn->sess_count) {
		struct cifsd_sess *sess;
		struct list_head *tmp, *t;

		list_for_each_safe(tmp, t, &conn->cifsd_sess) {
			sess = list_entry(tmp, struct cifsd_sess,
							cifsd_ses_list);
			free_channel_list(sess);
			list_del(&sess->cifsd_ses_list);
			/* SESSION Global list cifsd_ses_global_list is
			   for SMB2 only*/
			if (conn->connection_type != 0)
				list_del(&sess->cifsd_ses_global_list);
			kfree(sess);
		}
	}

	conn_cleanup(conn);
	module_put(THIS_MODULE);

	cifsd_debug("%s: exiting\n", current->comm);

	return 0;
}


/**
 * connect_tcp_sess() - create a new tcp session on mount
 * @sock:	socket associated with new connection
 *
 * whenever a new connection is requested, create a conn thread
 * (session thread) to handle new incoming smb requests from the connection
 *
 * Return:	0 on success, otherwise error
 */
int connect_tcp_sess(struct socket *sock)
{
	struct sockaddr_storage caddr;
	struct sockaddr *csin = (struct sockaddr *)&caddr;
	int rc = 0, cslen;
	struct connection *conn;

	if (kernel_getpeername(sock, csin, &cslen) < 0) {
		cifsd_err("client ip resolution failed\n");
		return -EINVAL;
	}

	conn = kzalloc(sizeof(struct connection), GFP_KERNEL);
	if (conn == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	snprintf(conn->peeraddr, sizeof(conn->peeraddr), "%pI4",
			&(((const struct sockaddr_in *)csin)->sin_addr));
	cifsd_debug("connect request from [%s]\n", conn->peeraddr);

	conn->family = ((const struct sockaddr_in *)csin)->sin_family;

	rc = init_tcp_conn(conn, sock);
	if (rc) {
		cifsd_err("cannot init tcp conn\n");
		kfree(conn);
		goto out;
	}

	conn->th_id = ida_simple_get(&cifsd_ida, 1, 0, GFP_KERNEL);
	if (conn->th_id < 0) {
		cifsd_err("ida_simple_get failed: %d\n", conn->th_id);
		kfree(conn);
		goto out;
	}

	conn->handler = kthread_run(tcp_sess_kthread, conn,
					"kcifsd/%d", conn->th_id);
	if (IS_ERR(conn->handler)) {
		/* TODO : remove from list and free sock */
		cifsd_err("cannot start conn thread\n");
		ida_simple_remove(&cifsd_ida, conn->th_id);
		spin_lock(&tcp_sess_list_lock);
		list_del(&conn->tcp_sess);
		spin_unlock(&tcp_sess_list_lock);
		rc = PTR_ERR(conn->handler);
		kfree(conn);
	}

out:
	return rc;
}

int cifsd_stop_tcp_sess(void)
{
	int ret;
	int err = 0;
	int etype;
	struct connection *conn, *tmp;

	list_for_each_entry_safe(conn, tmp, &cifsd_connection_list, list) {
		conn->tcp_status = CifsExiting;
		ret = kthread_stop(conn->handler);
		if (ret) {
			etype = CIFSD_KEVENT_SMBPORT_CLOSE_FAIL;
			cifsd_err("failed to stop server thread\n");
			err = ret;
		} else
			etype = CIFSD_KEVENT_SMBPORT_CLOSE_PASS;

		cifsd_kthread_stop_status(etype);
	}

	return err;
}

/**
 * smb_initialize_mempool() - initialize mempool for smb request/response
 *
 * Return:	0 on success, otherwise -ENOMEM
 */
static int smb_initialize_mempool(void)
{
	size_t max_hdr_size = MAX_CIFS_HDR_SIZE;
#ifdef CONFIG_CIFS_SMB2_SERVER
	max_hdr_size = MAX_SMB2_HDR_SIZE;
#endif
	cifsd_req_cachep = kmem_cache_create("cifsd_request",
			SMBMaxBufSize + max_hdr_size, 0,
			SLAB_HWCACHE_ALIGN, NULL);

	if (cifsd_req_cachep == NULL)
		goto err_out1;

	cifsd_req_poolp = mempool_create_slab_pool(smb_min_rcv,
			cifsd_req_cachep);

	if (cifsd_req_poolp == NULL)
		goto err_out2;

	/* Initialize small request pool */
	cifsd_sm_req_cachep = kmem_cache_create("cifsd_small_rq",
			MAX_CIFS_SMALL_BUFFER_SIZE, 0, SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifsd_sm_req_cachep == NULL)
		goto err_out3;

	cifsd_sm_req_poolp = mempool_create_slab_pool(smb_min_small,
			cifsd_sm_req_cachep);

	if (cifsd_sm_req_poolp == NULL)
		goto err_out4;

	cifsd_sm_rsp_cachep = kmem_cache_create("cifsd_small_rsp",
			MAX_CIFS_SMALL_BUFFER_SIZE, 0, SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifsd_sm_rsp_cachep == NULL)
		goto err_out5;

	cifsd_sm_rsp_poolp = mempool_create_slab_pool(smb_min_small,
			cifsd_sm_rsp_cachep);

	if (cifsd_sm_rsp_poolp == NULL)
		goto err_out6;

	cifsd_rsp_cachep = kmem_cache_create("cifsd_rsp",
			SMBMaxBufSize + max_hdr_size, 0,
			SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifsd_rsp_cachep == NULL)
		goto err_out7;

	cifsd_rsp_poolp = mempool_create_slab_pool(cifs_min_send,
			cifsd_rsp_cachep);

	if (cifsd_rsp_poolp == NULL)
		goto err_out8;

	cifsd_work_cache = kmem_cache_create("cifsd_work_cache",
					sizeof(struct smb_work), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (cifsd_work_cache == NULL)
		goto err_out9;

	cifsd_filp_cache = kmem_cache_create("cifsd_file_cache",
					sizeof(struct cifsd_file), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (cifsd_filp_cache == NULL)
		goto err_out10;

	return 0;

err_out10:
	kmem_cache_destroy(cifsd_work_cache);
err_out9:
	mempool_destroy(cifsd_rsp_poolp);
err_out8:
	kmem_cache_destroy(cifsd_rsp_cachep);
err_out7:
	mempool_destroy(cifsd_sm_rsp_poolp);
err_out6:
	kmem_cache_destroy(cifsd_sm_rsp_cachep);
err_out5:
	mempool_destroy(cifsd_sm_req_poolp);
err_out4:
	kmem_cache_destroy(cifsd_sm_req_cachep);
err_out3:
	mempool_destroy(cifsd_req_poolp);
err_out2:
	kmem_cache_destroy(cifsd_req_cachep);
err_out1:
	cifsd_err("failed to allocate memory\n");
	return -ENOMEM;
}

/**
 * smb_free_mempools() - free smb request/response mempools
 */
void smb_free_mempools(void)
{
	mempool_destroy(cifsd_req_poolp);
	kmem_cache_destroy(cifsd_req_cachep);
	mempool_destroy(cifsd_sm_req_poolp);
	kmem_cache_destroy(cifsd_sm_req_cachep);

	mempool_destroy(cifsd_rsp_poolp);
	kmem_cache_destroy(cifsd_rsp_cachep);
	mempool_destroy(cifsd_sm_rsp_poolp);
	kmem_cache_destroy(cifsd_sm_rsp_cachep);

	kmem_cache_destroy(cifsd_work_cache);
	kmem_cache_destroy(cifsd_filp_cache);
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
static int __init init_smb_server(void)
{
	int rc;

	server_start_time = jiffies;

	rc = smb_initialize_mempool();
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
	return 0;

err3:

#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
err2:
#endif
	cifsd_export_exit();
err1:
	smb_free_mempools();
	return rc;
}

/**
 * exit_smb_server() - shutdown forker thread and free memory at module exit
 */
static void __exit exit_smb_server(void)
{
	cifsd_net_exit();

	cifsd_stop_forker_thread();
#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
#endif
	cifsd_export_exit();
	dispose_ofile_list();
	smb_free_mempools();
}

MODULE_AUTHOR("Namjae Jeon <namjae.jeon@protocolfreedom.org>");
MODULE_DESCRIPTION("In-Kernel CIFS/SMB SERVER");
MODULE_LICENSE("GPL");
module_init(init_smb_server)
module_exit(exit_smb_server)
