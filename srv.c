/*
 *   fs/cifssrv/srv.c
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

bool global_signing;
unsigned long server_start_time;

struct kmem_cache *cifssrv_req_cachep;
mempool_t *cifssrv_req_poolp;
struct kmem_cache *cifssrv_sm_req_cachep;
mempool_t *cifssrv_sm_req_poolp;
struct kmem_cache *cifssrv_sm_rsp_cachep;
mempool_t *cifssrv_sm_rsp_poolp;
struct kmem_cache *cifssrv_rsp_cachep;
mempool_t *cifssrv_rsp_poolp;

unsigned int smb_min_rcv = CIFS_MIN_RCV_POOL;
unsigned int cifs_min_send = CIFS_MIN_RCV_POOL;
unsigned int smb_min_small = 30;

/*
 * keep MaxBufSize Default: 65536
 * CIFSMaxBufSize can have it in Range: 8192 to 130048(default 16384)
 */
unsigned int SMBMaxBufSize = CIFS_MAX_MSGSIZE;

static DEFINE_IDA(cifssrv_ida);
static LIST_HEAD(tcp_sess_list);
static DEFINE_SPINLOCK(tcp_sess_list_lock);

struct fidtable_desc global_fidtable;

/* Default: allocation roundup size = 1048576, to disable set 0 in config */
unsigned int alloc_roundup_size = 1048576;

/**
 * cifssrv_buf_get() - get large response buffer
 *
 * Return:	pointer to large response buffer on success,
 *		otherwise NULL
 */
struct smb_hdr *cifssrv_buf_get(void)
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
	hdr = mempool_alloc(cifssrv_req_poolp, GFP_NOFS | __GFP_ZERO);

	/* clear the first few header bytes */
	if (hdr)
		memset(hdr, 0, buf_size + 3);

	return hdr;
}

/**
 * cifssrv_buf_get() - get small response buffer
 *
 * Return:	pointer to small response buffer on success,
 *		otherwise NULL
 */
struct smb_hdr *smb_small_buf_get(void)
{
	/* No need to memset smallbuf as we will fill hdr anyway */
	return mempool_alloc(cifssrv_sm_req_poolp, GFP_NOFS | __GFP_ZERO);
}

/**
 * construct_cifssrv_tcon() - alloc tcon object and initialize
 *		 from session and share info and increment tcon count
 * @sess:	session to link with tcon object
 * @share:	Related association of tcon object with share
 *
 * Return:	If Succes, Valid initialized tcon object, else errors
 */
struct cifssrv_tcon *construct_cifssrv_tcon(struct cifssrv_share *share,
				struct cifssrv_sess *sess)
{
	struct cifssrv_tcon *tcon;
	int err;

	tcon = kzalloc(sizeof(struct cifssrv_tcon), GFP_KERNEL);
	if (!tcon)
		return ERR_PTR(-ENOMEM);

	if (!share->path)
		goto out;

	err = kern_path(share->path, 0, &tcon->share_path);
	if (err) {
		cifssrv_err("kern_path() failed for shares(%s)\n", share->path);
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
 * @server:     TCP server instance of connection
 *
 * Return:	true on success, otherwise NULL
 */
static bool allocate_buffers(struct tcp_server_info *server)
{
	if (!server->bigbuf) {
		server->bigbuf = (char *)cifssrv_buf_get();
		if (!server->bigbuf) {
			cifssrv_debug("No memory for large SMB response\n");
			msleep(3000);
			/* retry will check if exiting */
			return false;
		}
	} else if (server->large_buf) {
		/* we are reusing a dirty large buf, clear its start */
		memset(server->bigbuf, 0, HEADER_SIZE(server));
	}

	if (!server->smallbuf) {
		server->smallbuf = (char *)smb_small_buf_get();
		if (!server->smallbuf) {
			cifssrv_debug("No memory for SMB response\n");
			/* retry will check if exiting */
			return false;
		}
		/* beginning of smb buffer is cleared in our buf_get */
	} else {
		/* if existing small buf clear beginning */
		memset(server->smallbuf, 0, HEADER_SIZE(server));
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

	struct tcp_server_info *server = work->server;
	struct smb_hdr *rsp_hdr = (struct smb_hdr *)work->rsp_buf;
	struct socket *sock = server->sock;
	struct kvec iov;
	struct msghdr smb_msg = {};
	int len, total_len = 0;
	int val = 1;

	spin_lock(&server->request_lock);
	if (work->added_in_request_list && !work->multiRsp) {
		list_del_init(&work->request_entry);
		work->added_in_request_list = 0;
	}
	spin_unlock(&server->request_lock);

	if (rsp_hdr == NULL) {
		cifssrv_err("NULL response header\n");
		return -ENOMEM;
	}

	if (!work->rdata_buf) {
		iov.iov_len = get_rfc1002_length(rsp_hdr) + 4;
		iov.iov_base = rsp_hdr;

		len = kernel_sendmsg(sock, &smb_msg, &iov, 1, iov.iov_len);
		if (len < 0) {
			cifssrv_err("err1 %d while sending data\n", len);
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
			cifssrv_err("err2 %d while sending data\n", len);
			goto uncork;
		}
		total_len = len;

		/* write data read from file on socket*/
		iov.iov_base = work->rdata_buf;
		iov.iov_len = work->rdata_cnt;
		len = kernel_sendmsg(sock, &smb_msg, &iov, 1, iov.iov_len);
		if (len < 0) {
			cifssrv_err("err3 %d while sending data\n", len);
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
		cifssrv_err("transfered %d, expected %d bytes\n",
				total_len, get_rfc1002_length(rsp_hdr) + 4);

out:
	cifssrv_debug("data sent = %d\n", total_len);

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (server->tcp_status == CifsGood && IS_SMB2(server))
		cifssrv_update_durable_stat_info(work->sess);
#endif

	return 0;
}

/**
 * queue_dynamic_work_helper() - helper function to queue smb request
 *		work to worker thread
 * @server:     TCP server instance of connection
 */
void queue_dynamic_work_helper(struct tcp_server_info *server)
{
	struct smb_work *work = kzalloc(sizeof(struct smb_work), GFP_KERNEL);
	if (!work) {
		cifssrv_err("allocation for work failed\n");
		return;
	}

	/*
	 * Increment ref count for the Server object, as after this
	 * only fallback point is from handle_smb_work
	 */
	atomic_inc(&server->r_count);
	work->server = server;

	if (server->wbuf) {
		work->buf = server->wbuf;
		work->req_wbuf = 1;
		server->wbuf = NULL;
	} else if (server->large_buf) {
		work->buf = server->bigbuf;
		work->large_buf = 1;
		server->large_buf = false;
		server->bigbuf = NULL;
	} else {
		work->buf = server->smallbuf;
		server->smallbuf = NULL;
	}

	if (add_request_to_queue(work)) {
		spin_lock(&server->request_lock);
		list_add_tail(&work->request_entry, &server->requests);
		work->added_in_request_list = 1;
		spin_unlock(&server->request_lock);
	}

	/* update activity on server */
	server->last_active = jiffies;
	INIT_WORK(&work->work, handle_smb_work);
	schedule_work(&work->work);
}

/**
 * queue_dynamic_work() - queue a smb request to worker thread queue
 *		for proccessing amd command and sending response
 * @server:     TCP server instance of connection
 *
 * read remaining data from socket create and submit work.
 */
void queue_dynamic_work(struct tcp_server_info *server, char *buf)
{
	int ret;

	dump_smb_msg(buf, HEADER_SIZE(server));

	/* check if the message is ok */
	ret = check_smb_message(buf);
	if (ret) {
		cifssrv_debug("Malformed smb request\n");
		return;
	}

	queue_dynamic_work_helper(server);
}

/**
 * check_server_state() - check state of server thread connection
 * @smb_work:     smb work containing server thread information
 *
 * Return:	0 on valid connection, otherwise 1 to reconnect
 */
static inline int check_server_state(struct smb_work *smb_work)
{
	struct tcp_server_info *server = smb_work->server;
	struct smb_hdr *rsp_hdr;

	if (server->tcp_status == CifsExiting ||
			server->tcp_status == CifsNeedReconnect) {
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
			mempool_free(smb_work->buf, cifssrv_req_poolp);
		else
			mempool_free(smb_work->buf, cifssrv_sm_req_poolp);
	}

	if (smb_work->rsp_large_buf)
		mempool_free(smb_work->rsp_buf, cifssrv_rsp_poolp);
	else
		mempool_free(smb_work->rsp_buf, cifssrv_sm_rsp_poolp);

	if (smb_work->rdata_buf)
		vfree(smb_work->rdata_buf);
	kfree(smb_work);
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
	struct tcp_server_info *server = smb_work->server;
	unsigned int command = 0;
	int rc;
	bool server_valid = false;
	struct smb_version_cmds *cmds;
	long int start_time = 0, end_time = 0, time_elapsed = 0;

	atomic_inc(&server->req_running);
	mutex_lock(&server->srv_mutex);

	if (cifssrv_debug_enable)
		start_time = jiffies;

	server->stats.request_served++;

	if (unlikely(server->need_neg)) {
		if (is_smb2_neg_cmd(smb_work))
			init_smb2_0_server(server);
		else if (server->ops->get_cmd_val(smb_work) !=
						SMB_COM_NEGOTIATE)
			server->need_neg = false;
	}

	if (server->ops->allocate_rsp_buf(smb_work)) {
		rc = -ENOMEM;
		goto nosend;
	}

	rc = server->ops->init_rsp_hdr(smb_work);
	if (rc) {
		/* either uid or tid is not correct */
		server->ops->set_rsp_status(smb_work, NT_STATUS_INVALID_HANDLE);
		goto send;
	}

	if (server->ops->check_user_session) {
		rc = server->ops->check_user_session(smb_work);
		if (rc < 0) {
			command = server->ops->get_cmd_val(smb_work);
			server->ops->set_rsp_status(smb_work,
					NT_STATUS_USER_SESSION_DELETED);
			goto send;
		} else if (rc > 0) {
			rc = server->ops->get_cifssrv_tcon(smb_work);
			if (rc < 0) {
				server->ops->set_rsp_status(smb_work,
					NT_STATUS_NETWORK_NAME_DELETED);
				goto send;
			}
		}
	}

chained:
	rc = check_server_state(smb_work);
	if (rc)
		goto send;

	server_valid = true;
	command = server->ops->get_cmd_val(smb_work);
again:
	if (command >= server->max_cmds) {
		server->ops->set_rsp_status(smb_work,
					NT_STATUS_INVALID_PARAMETER);
		goto send;
	}

	cmds = &server->cmds[command];
	if (cmds->proc == NULL) {
		cifssrv_err("*** not implemented yet cmd = %x\n", command);
		server->ops->set_rsp_status(smb_work,
						NT_STATUS_NOT_IMPLEMENTED);
		goto send;
	}

	mutex_unlock(&server->srv_mutex);

	if (smb_work->sess && smb_work->sess->sign &&
		server->ops->is_sign_req &&
		server->ops->is_sign_req(smb_work, command)) {
		rc = server->ops->check_sign_req(smb_work);
		if (!rc) {
			server->ops->set_rsp_status(smb_work,
							NT_STATUS_DATA_ERROR);
			goto send;
		}
	}

	rc = cmds->proc(smb_work);
	mutex_lock(&server->srv_mutex);
	if (server->need_neg && (server->dialect == SMB20_PROT_ID ||
				server->dialect == SMB21_PROT_ID ||
				server->dialect == SMB2X_PROT_ID ||
				server->dialect == SMB30_PROT_ID ||
				server->dialect == SMB302_PROT_ID ||
				server->dialect == SMB311_PROT_ID)) {
		cifssrv_debug("Need to send the smb2 negotiate response\n");
		init_smb2_neg_rsp(smb_work);
		goto send;
	}
	/* AndX commands - chained request can return positive values */
	if (rc > 0) {
		command = rc;
		goto again;
	} else if (rc < 0)
		cifssrv_debug("error(%d) while processing cmd %u\n",
							rc, command);

	if (smb_work->send_no_response) {
		spin_lock(&server->request_lock);
		if (smb_work->added_in_request_list) {
			list_del_init(&smb_work->request_entry);
			smb_work->added_in_request_list = 0;
		}
		spin_unlock(&server->request_lock);
		goto nosend;
	}

send:
	/* call set_rsp_credits() function to set number of credits granted in
	 * hdr of smb2 response.
	 */
	if (is_smb2_rsp(smb_work))
		server->ops->set_rsp_credits(smb_work);

	if (smb_work->sess && smb_work->sess->sign &&
		server->ops->is_sign_req &&
		server->ops->is_sign_req(smb_work, command))
		server->ops->set_sign_rsp(smb_work);

	if (is_chained_smb2_message(smb_work))
		goto chained;

	smb_send_rsp(smb_work);

nosend:
	/* free buffers */
	free_workitem_buffers(smb_work);

	if (cifssrv_debug_enable) {
		end_time = jiffies;

		time_elapsed = end_time - start_time;
		server->stats.avg_req_duration =
				(server->stats.avg_req_duration *
					server->stats.request_served +
					time_elapsed)/
					server->stats.request_served;

		if (time_elapsed > server->stats.max_timed_request)
			server->stats.max_timed_request = time_elapsed;
	}

	if (server->tcp_status == CifsExiting)
		force_sig(SIGKILL, server->handler);

	mutex_unlock(&server->srv_mutex);
	atomic_dec(&server->req_running);
	cifssrv_debug("req running = %d\n", atomic_read(&server->req_running));
	if (waitqueue_active(&server->req_running_q))
		wake_up_all(&server->req_running_q);

	/*
	 * Decrement Ref count when all processing finished
	 *  - in both success or failure cases
	 */
	atomic_dec(&server->r_count);
}

/**
 * init_tcp_server() - intialize tcp server thread for a new connection
 * @server:     TCP server instance of connection
 * @sock:	socket associated with new connection
 *
 * Return:	0 on success, otherwise -ENOMEM
 */
int init_tcp_server(struct tcp_server_info *server, struct socket *sock)
{
	int rc = 0;

	init_smb1_server(server);

	server->need_neg = true;
	server->srv_count = 1;
	server->sess_count = 0;
	server->tcp_status = CifsNew;
	server->sock = sock;
	server->local_nls = load_nls_default();
	atomic_set(&server->req_running, 0);
	atomic_set(&server->r_count, 0);
	server->max_credits = 0;
	server->credits_granted = 0;
	init_waitqueue_head(&server->req_running_q);
	INIT_LIST_HEAD(&server->tcp_sess);
	INIT_LIST_HEAD(&server->cifssrv_sess);
	INIT_LIST_HEAD(&server->requests);
	spin_lock_init(&server->request_lock);
	server->srv_cap = SERVER_CAPS;
	init_waitqueue_head(&server->oplock_q);
	spin_lock(&tcp_sess_list_lock);
	list_add(&server->tcp_sess, &tcp_sess_list);
	spin_unlock(&tcp_sess_list_lock);

	return rc;
}

/**
 * server_cleanup() - shutdown/release the socket and free server resources
 * @server:	 - server instance for which socket is to be cleaned
 *
 * During the thread termination, the corresponding server instance
 * resources(sock/memory) are released and finally the server object is freed.
 */
static void server_cleanup(struct tcp_server_info *server)
{
	ida_simple_remove(&cifssrv_ida, server->th_id);
	kernel_sock_shutdown(server->sock, SHUT_RDWR);
	sock_release(server->sock);
	server->sock = NULL;

	if (server->bigbuf)
		mempool_free(server->bigbuf, cifssrv_req_poolp);
	if (server->smallbuf)
		mempool_free(server->smallbuf, cifssrv_sm_req_poolp);
	if (server->wbuf)
		vfree(server->wbuf);

	list_del(&server->list);
	kfree(server);
}

void free_channel_list(struct cifssrv_sess *sess)
{
	struct channel *chann;
	struct list_head *tmp, *t;

	if (sess->server->dialect >= SMB30_PROT_ID) {
		list_for_each_safe(tmp, t, &sess->cifssrv_chann_list) {
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
 * @p:     TCP server instance of connection
 *
 * One thread each per connection
 *
 * Return:	0 on success
 */
static int tcp_sess_kthread(void *p)
{
	int length;
	unsigned int pdu_length;
	struct tcp_server_info *server = (struct tcp_server_info *)p;
	char *buf;

	mutex_init(&server->srv_mutex);
	__module_get(THIS_MODULE);
	list_add(&server->list, &cifssrv_connection_list);
	server->last_active = jiffies;

	while (!kthread_should_stop() &&
			server->tcp_status != CifsExiting &&
				!server_unresponsive(server)) {
		if (try_to_freeze())
			continue;

		if (!allocate_buffers(server))
			continue;

		buf = server->smallbuf;
		pdu_length = 4; /* enough to get RFC1001 header */
		length = cifssrv_read_from_socket(server, buf, pdu_length);
		if (length != pdu_length)
			/* 7 seconds passed. It should be EAGAIN */
			continue;

		server->total_read = length;
		if (!is_smb_request(server, buf[0]))
			continue;

		pdu_length = get_rfc1002_length(buf);
		cifssrv_debug("RFC1002 header %u bytes\n", pdu_length);
		/* make sure we have enough to get to SMB header end */
		if (pdu_length < HEADER_SIZE(server) - 4) {
			cifssrv_debug("SMB request too short (%u bytes)\n",
					pdu_length);
			continue;
		}

		/*
		 * free write buffer, if we failed to add last write request to
		 * kworker due to errors e.g. socket IO error, and next a small
		 * request should be received from socket and submit to kworker
		 */
		if (server->wbuf) {
			vfree(server->wbuf);
			server->wbuf = NULL;
		}

		/* if required switch to large request buffer */
		if (pdu_length > MAX_CIFS_SMALL_BUFFER_SIZE - 4) {
			if (switch_req_buf(server))
				continue;
		}

		if (server->wbuf)
			buf = server->wbuf;
		else if (server->large_buf)
			buf = server->bigbuf;

		/* read the request */
		length = cifssrv_read_from_socket(server, buf + 4, pdu_length);
		if (length < 0) {
			cifssrv_err("sock_read failed: %d\n", length);
			continue;
		}

		server->total_read += length;
		if (length == pdu_length)
			queue_dynamic_work(server, buf);
		else {
			if (length > pdu_length)
				cifssrv_debug("extra read(%d) expected(%u)\n",
						length, pdu_length);
			else
				cifssrv_debug("short read(%d) expected(%u)\n",
						length, pdu_length);
		}
	}

	wait_event(server->req_running_q,
				atomic_read(&server->req_running) == 0);

	/* Wait till all reference dropped to the Server object*/
	while (atomic_read(&server->r_count) > 0)
		schedule_timeout(HZ);

	unload_nls(server->local_nls);
	spin_lock(&tcp_sess_list_lock);
	list_del(&server->tcp_sess);
	spin_unlock(&tcp_sess_list_lock);

	if (server->sess_count) {
		struct cifssrv_sess *sess;
		struct list_head *tmp, *t;

		list_for_each_safe(tmp, t, &server->cifssrv_sess) {
			sess = list_entry(tmp, struct cifssrv_sess,
							cifssrv_ses_list);
			free_channel_list(sess);
			list_del(&sess->cifssrv_ses_list);
			/* SESSION Global list cifssrv_ses_global_list is
			   for SMB2 only*/
			if (server->connection_type != 0)
				list_del(&sess->cifssrv_ses_global_list);
			kfree(sess);
		}
	}

	server_cleanup(server);
	module_put(THIS_MODULE);

	cifssrv_debug("%s: exiting\n", current->comm);

	return 0;
}


/**
 * connect_tcp_sess() - create a new tcp session on mount
 * @sock:	socket associated with new connection
 *
 * whenever a new connection is requested, create a server thread
 * (session thread) to handle new incoming smb requests from the connection
 *
 * Return:	0 on success, otherwise error
 */
int connect_tcp_sess(struct socket *sock)
{
	struct sockaddr_storage caddr;
	struct sockaddr *csin = (struct sockaddr *)&caddr;
	int rc = 0, cslen;
	struct tcp_server_info *server;

	if (kernel_getpeername(sock, csin, &cslen) < 0) {
		cifssrv_err("client ip resolution failed\n");
		return -EINVAL;
	}

	server = kzalloc(sizeof(struct tcp_server_info), GFP_KERNEL);
	if (server == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	snprintf(server->peeraddr, sizeof(server->peeraddr), "%pI4",
			&(((const struct sockaddr_in *)csin)->sin_addr));
	cifssrv_debug("connect request from [%s]\n", server->peeraddr);

	server->family = ((const struct sockaddr_in *)csin)->sin_family;

	rc = init_tcp_server(server, sock);
	if (rc) {
		cifssrv_err("cannot init tcp server\n");
		kfree(server);
		goto out;
	}

	server->th_id = ida_simple_get(&cifssrv_ida, 1, 0, GFP_KERNEL);
	if (server->th_id < 0) {
		cifssrv_err("ida_simple_get failed: %d\n", server->th_id);
		kfree(server);
		goto out;
	}

	server->handler = kthread_run(tcp_sess_kthread, server,
					"kcifssrvd/%d", server->th_id);
	if (IS_ERR(server->handler)) {
		/* TODO : remove from list and free sock */
		cifssrv_err("cannot start server thread\n");
		ida_simple_remove(&cifssrv_ida, server->th_id);
		spin_lock(&tcp_sess_list_lock);
		list_del(&server->tcp_sess);
		spin_unlock(&tcp_sess_list_lock);
		rc = PTR_ERR(server->handler);
		kfree(server);
	}

out:
	return rc;
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
	cifssrv_req_cachep = kmem_cache_create("cifssrv_request",
			SMBMaxBufSize + max_hdr_size, 0,
			SLAB_HWCACHE_ALIGN, NULL);

	if (cifssrv_req_cachep == NULL)
		goto err_out1;

	cifssrv_req_poolp = mempool_create_slab_pool(smb_min_rcv,
			cifssrv_req_cachep);

	if (cifssrv_req_poolp == NULL)
		goto err_out2;

	/* Initialize small request pool */
	cifssrv_sm_req_cachep = kmem_cache_create("cifssrv_small_rq",
			MAX_CIFS_SMALL_BUFFER_SIZE, 0, SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifssrv_sm_req_cachep == NULL)
		goto err_out3;

	cifssrv_sm_req_poolp = mempool_create_slab_pool(smb_min_small,
			cifssrv_sm_req_cachep);

	if (cifssrv_sm_req_poolp == NULL)
		goto err_out4;

	cifssrv_sm_rsp_cachep = kmem_cache_create("cifssrv_small_rsp",
			MAX_CIFS_SMALL_BUFFER_SIZE, 0, SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifssrv_sm_rsp_cachep == NULL)
		goto err_out5;

	cifssrv_sm_rsp_poolp = mempool_create_slab_pool(smb_min_small,
			cifssrv_sm_rsp_cachep);

	if (cifssrv_sm_rsp_poolp == NULL)
		goto err_out6;

	cifssrv_rsp_cachep = kmem_cache_create("cifssrv_rsp",
			SMBMaxBufSize + max_hdr_size, 0,
			SLAB_HWCACHE_ALIGN,
			NULL);

	if (cifssrv_rsp_cachep == NULL)
		goto err_out7;

	cifssrv_rsp_poolp = mempool_create_slab_pool(cifs_min_send,
			cifssrv_rsp_cachep);

	if (cifssrv_rsp_poolp == NULL)
		goto err_out8;

	return 0;

err_out8:
	kmem_cache_destroy(cifssrv_rsp_cachep);
err_out7:
	mempool_destroy(cifssrv_sm_rsp_poolp);
err_out6:
	kmem_cache_destroy(cifssrv_sm_rsp_cachep);
err_out5:
	mempool_destroy(cifssrv_sm_req_poolp);
err_out4:
	kmem_cache_destroy(cifssrv_sm_req_cachep);
err_out3:
	mempool_destroy(cifssrv_req_poolp);
err_out2:
	kmem_cache_destroy(cifssrv_req_cachep);
err_out1:
	cifssrv_err("failed to allocate memory\n");
	return -ENOMEM;
}

/**
 * smb_free_mempools() - free smb request/response mempools
 */
void smb_free_mempools(void)
{
	mempool_destroy(cifssrv_req_poolp);
	kmem_cache_destroy(cifssrv_req_cachep);
	mempool_destroy(cifssrv_sm_req_poolp);
	kmem_cache_destroy(cifssrv_sm_req_cachep);

	mempool_destroy(cifssrv_rsp_poolp);
	kmem_cache_destroy(cifssrv_rsp_cachep);
	mempool_destroy(cifssrv_sm_rsp_poolp);
	kmem_cache_destroy(cifssrv_sm_rsp_cachep);
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

	rc = cifssrv_export_init();
	if (rc)
		goto err1;

#ifdef CONFIG_CIFS_SMB2_SERVER
	rc = init_fidtable(&global_fidtable);
	if (rc)
		goto err2;
#endif
	rc = cifssrv_create_socket();
	if (rc)
		goto err3;

#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	rc = cifssrv_net_init();
	if (rc)
		goto err4;
#endif
	return 0;

err4:
	cifssrv_stop_forker_thread();
err3:
#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
err2:
#endif
	cifssrv_export_exit();
err1:
	smb_free_mempools();
	return rc;
}

/**
 * exit_smb_server() - shutdown forker thread and free memory at module exit
 */
static void __exit exit_smb_server(void)
{
#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	cifssrv_net_exit();
#endif

	cifssrv_stop_forker_thread();
#ifdef CONFIG_CIFS_SMB2_SERVER
	destroy_global_fidtable();
#endif
	cifssrv_export_exit();
	dispose_ofile_list();
	smb_free_mempools();
}

MODULE_AUTHOR("Namjae Jeon <namjae.jeon@samsung.com>");
MODULE_DESCRIPTION("CIFS SERVER");
MODULE_LICENSE("GPL");
module_init(init_smb_server)
module_exit(exit_smb_server)
