// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/mutex.h>

#include "server.h"
#include "auth.h"
#include "buffer_pool.h"
#include "transport_tcp.h"
#include "mgmt/cifsd_ida.h"
#include "smb_common.h"

static struct task_struct *cifsd_kthread;
static struct socket *cifsd_socket = NULL;
static struct cifsd_tcp_conn_ops default_tcp_conn_ops;

static DEFINE_MUTEX(init_lock);

static LIST_HEAD(tcp_conn_list);
static DEFINE_RWLOCK(tcp_conn_list_lock);

#define CIFSD_TCP_RECV_TIMEOUT	(7 * HZ)
#define CIFSD_TCP_SEND_TIMEOUT	(5 * HZ)

static bool cifsd_tcp_conn_alive(struct cifsd_tcp_conn *conn)
{
	if (!cifsd_server_running())
		return false;

	if (conn->tcp_status == CIFSD_SESS_EXITING)
		return false;

	if (kthread_should_stop())
		return false;

	if (conn->stats.open_files_count > 0)
		return true;

	/*
	 * Stop current session if the time that get last request from client
	 * is bigger than deadtime user configured and openning file count is
	 * zero.
	 */
	if (server_conf.deadtime > 0 &&
		time_after(jiffies, conn->last_active + server_conf.deadtime))
		cifsd_debug("No response from client in %lu minutes\n",
			server_conf.deadtime);
		return false;
	}
	return true;
}

/**
 * cifsd_tcp_conn_free() - shutdown/release the socket and free server
 *                         resources
 * @conn: - server instance for which socket is to be cleaned
 *
 * During the thread termination, the corresponding conn instance
 * resources(sock/memory) are released and finally the conn object is freed.
 */
static void cifsd_tcp_conn_free(struct cifsd_tcp_conn *conn)
{
	write_lock(&tcp_conn_list_lock);
	list_del(&conn->tcp_conns);
	write_unlock(&tcp_conn_list_lock);

	kernel_sock_shutdown(conn->sock, SHUT_RDWR);
	sock_release(conn->sock);
	conn->sock = NULL;

	cifsd_free_conn_secmech(conn);
	cifsd_free_request(conn->request_buf);
	cifsd_ida_free(conn->async_ida);
	kfree(conn->preauth_info);
	kfree(conn);
}

/**
 * cifsd_tcp_conn_alloc() - initialize tcp server thread for a new connection
 * @conn:     TCP server instance of connection
 * @sock:	socket associated with new connection
 *
 * Return:	0 on success, otherwise -ENOMEM
 */
static struct cifsd_tcp_conn *cifsd_tcp_conn_alloc(struct socket *sock)
{
	struct cifsd_tcp_conn *conn;

	conn = kzalloc(sizeof(struct cifsd_tcp_conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	conn->need_neg = true;
	conn->tcp_status = CIFSD_SESS_NEW;
	conn->sock = sock;
	conn->local_nls = load_nls("utf8");
	if (!conn->local_nls)
		conn->local_nls = load_nls_default();
	atomic_set(&conn->req_running, 0);
	atomic_set(&conn->r_count, 0);
	conn->max_credits = 0;
	conn->credits_granted = 0;
	init_waitqueue_head(&conn->req_running_q);
	INIT_LIST_HEAD(&conn->tcp_conns);
	INIT_LIST_HEAD(&conn->sessions);
	INIT_LIST_HEAD(&conn->requests);
	INIT_LIST_HEAD(&conn->async_requests);
	spin_lock_init(&conn->request_lock);
	conn->srv_cap = 0;
	conn->async_ida = cifsd_ida_alloc();

	write_lock(&tcp_conn_list_lock);
	list_add(&conn->tcp_conns, &tcp_conn_list);
	write_unlock(&tcp_conn_list_lock);
	return conn;
}

/**
 * kvec_array_init() - initialize a IO vector segment
 * @new:	IO vector to be intialized
 * @iov:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @bytes:	total iovec length so far for read
 *
 * Return:	Number of IO segments
 */
static unsigned int kvec_array_init(struct kvec *new, struct kvec *iov,
				    unsigned int nr_segs, size_t bytes)
{
	size_t base = 0;

	while (bytes || !iov->iov_len) {
		int copy = min(bytes, iov->iov_len);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			nr_segs--;
			base = 0;
		}
	}

	memcpy(new, iov, sizeof(*iov) * nr_segs);
	new->iov_base += base;
	new->iov_len -= base;
	return nr_segs;
}

/**
 * get_conn_iovec() - get connection iovec for reading from socket
 * @conn:     TCP server instance of connection
 * @nr_segs:	number of segments in iov
 *
 * Return:	return existing or newly allocate iovec
 */
static struct kvec *get_conn_iovec(struct cifsd_tcp_conn *conn,
				     unsigned int nr_segs)
{
	struct kvec *new_iov;

	if (conn->iov && nr_segs <= conn->nr_iov)
		return conn->iov;

	/* not big enough -- allocate a new one and release the old */
	new_iov = kmalloc(sizeof(*new_iov) * nr_segs, GFP_KERNEL);
	if (new_iov) {
		kfree(conn->iov);
		conn->iov = new_iov;
		conn->nr_iov = nr_segs;
	}
	return new_iov;
}

/**
 * cifsd_tcp_conn_handler_loop() - session thread to listen on new smb requests
 * @p:     TCP conn instance of connection
 *
 * One thread each per connection
 *
 * Return:	0 on success
 */
static int cifsd_tcp_conn_handler_loop(void *p)
{
	struct cifsd_tcp_conn *conn = (struct cifsd_tcp_conn *)p;
	unsigned int pdu_size;
	char hdr_buf[4] = {0,};
	int size;

	mutex_init(&conn->srv_mutex);
	__module_get(THIS_MODULE);
	conn->last_active = jiffies;

	while (cifsd_tcp_conn_alive(conn)) {
		if (try_to_freeze())
			continue;

		cifsd_free_request(conn->request_buf);
		conn->request_buf = NULL;

		size = cifsd_tcp_read(conn, hdr_buf, sizeof(hdr_buf));
		if (size != sizeof(hdr_buf))
			break;

		pdu_size = get_rfc1002_length(hdr_buf);
		cifsd_debug("RFC1002 header %u bytes\n", pdu_size);

		/* make sure we have enough to get to SMB header end */
		if (!cifsd_pdu_size_has_room(pdu_size)) {
			cifsd_debug("SMB request too short (%u bytes)\n",
				    pdu_size);
			continue;
		}

		/* 4 for rfc1002 length field */
		size = pdu_size + 4;
		conn->request_buf = cifsd_alloc_request(size);
		if (!conn->request_buf)
			continue;

		memcpy(conn->request_buf, hdr_buf, sizeof(hdr_buf));
		if (!cifsd_smb_request(conn))
			break;

		/*
		 * We already read 4 bytes to find out PDU size, now
		 * read in PDU
		 */
		size = cifsd_tcp_read(conn, conn->request_buf + 4, pdu_size);
		if (size < 0) {
			cifsd_err("sock_read failed: %d\n", size);
			break;
		}

		if (size != pdu_size) {
			cifsd_err("PDU error. Read: %d, Expected: %d\n",
				  size,
				  pdu_size);
			continue;
		}

		if (!conn->conn_ops->process_fn) {
			cifsd_err("No connection request callback\n");
			break;
		}

		if (conn->conn_ops->process_fn(conn)) {
			cifsd_err("Cannot handle request\n");
			break;
		}
	}

	/* Wait till all reference dropped to the Server object*/
	while (atomic_read(&conn->r_count) > 0)
		schedule_timeout(HZ);

	unload_nls(conn->local_nls);
	if (conn->conn_ops->terminate_fn)
		conn->conn_ops->terminate_fn(conn);
	cifsd_tcp_conn_free(conn);
	module_put(THIS_MODULE);
	return 0;
}

static unsigned short cifsd_tcp_get_port(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	}
	return 0;
}

/**
 * cifsd_tcp_new_connection() - create a new tcp session on mount
 * @sock:	socket associated with new connection
 *
 * whenever a new connection is requested, create a conn thread
 * (session thread) to handle new incoming smb requests from the connection
 *
 * Return:	0 on success, otherwise error
 */
static int cifsd_tcp_new_connection(struct socket *client_sk)
{
	struct sockaddr *csin;
	int rc = 0;
	struct cifsd_tcp_conn *conn;

	conn = cifsd_tcp_conn_alloc(client_sk);
	if (!conn)
		return -ENOMEM;

	csin = CIFSD_TCP_PEER_SOCKADDR(conn);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	if (kernel_getpeername(client_sk, csin, &rc) < 0) {
		cifsd_err("client ip resolution failed\n");
		rc = -EINVAL;
		goto out_error;
	}
	rc = 0;
#else
	if (kernel_getpeername(client_sk, csin) < 0) {
		cifsd_err("client ip resolution failed\n");
		rc = -EINVAL;
		goto out_error;
	}
#endif

	conn->conn_ops = &default_tcp_conn_ops;
	conn->handler = kthread_run(cifsd_tcp_conn_handler_loop,
				    conn,
				    "kcifsd:%u",
				    cifsd_tcp_get_port(csin));
	if (IS_ERR(conn->handler)) {
		cifsd_err("cannot start conn thread\n");
		rc = PTR_ERR(conn->handler);
		cifsd_tcp_conn_free(conn);
	}
	return rc;

out_error:
	cifsd_tcp_conn_free(conn);
	return rc;
}

/**
 * cifsd_kthread_fn() - listen to new SMB connections and callback server
 * @p:		arguments to forker thread
 *
 * Return:	Returns a task_struct or ERR_PTR
 */
static int cifsd_kthread_fn(void *p)
{
	struct socket *client_sk = NULL;
	int ret;

	while (!kthread_should_stop()) {
		if (cifsd_server_daemon_heartbeat()) {
			schedule_timeout_interruptible(HZ);
			continue;
		}

		ret = kernel_accept(cifsd_socket, &client_sk, O_NONBLOCK);
		if (ret) {
			if (ret == -EAGAIN)
				/* check for new connections every 100 msecs */
				schedule_timeout_interruptible(HZ / 10);
			continue;
		}

		cifsd_debug("connect success: accepted new connection\n");
		client_sk->sk->sk_rcvtimeo = 7 * HZ;
		client_sk->sk->sk_sndtimeo = 5 * HZ;

		cifsd_tcp_new_connection(client_sk);
	}

	cifsd_debug("releasing socket\n");
	return 0;
}

/**
 * cifsd_create_cifsd_kthread() - start forker thread
 *
 * start forker thread(kcifsd/0) at module init time to listen
 * on port 445 for new SMB connection requests. It creates per connection
 * server threads(kcifsd/x)
 *
 * Return:	0 on success or error number
 */
static int cifsd_tcp_run_kthread(void)
{
	int rc;

	cifsd_kthread = kthread_run(cifsd_kthread_fn, NULL, "kcifsd");
	if (IS_ERR(cifsd_kthread)) {
		rc = PTR_ERR(cifsd_kthread);
		cifsd_kthread = NULL;
		return rc;
	}

	return 0;
}

/**
 * cifsd_tcp_readv() - read data from socket in given iovec
 * @conn:     TCP server instance of connection
 * @iov_orig:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
static int cifsd_tcp_readv(struct cifsd_tcp_conn *conn,
			   struct kvec *iov_orig,
			   unsigned int nr_segs,
			   unsigned int to_read)
{
	int length = 0;
	int total_read;
	unsigned int segs;
	struct msghdr cifsd_msg;
	struct kvec *iov;

	iov = get_conn_iovec(conn, nr_segs);
	if (!iov)
		return -ENOMEM;

	cifsd_msg.msg_control = NULL;
	cifsd_msg.msg_controllen = 0;

	for (total_read = 0; to_read; total_read += length, to_read -= length) {
		try_to_freeze();

		if (!cifsd_tcp_conn_alive(conn)) {
			total_read = -ESHUTDOWN;
			break;
		}
		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);

		length = kernel_recvmsg(conn->sock, &cifsd_msg,
					iov, segs, to_read, 0);

		if (length == -EINTR) {
			total_read = -ESHUTDOWN;
			break;
		} else if (conn->tcp_status == CIFSD_SESS_NEED_RECONNECT) {
			total_read = -EAGAIN;
			break;
		} else if (length == -ERESTARTSYS || length == -EAGAIN) {
			usleep_range(1000, 2000);
			length = 0;
			continue;
		} else if (length <= 0) {
			total_read = -EAGAIN;
			break;
		}
	}
	return total_read;
}

/**
 * cifsd_tcp_read() - read data from socket in given buffer
 * @conn:     TCP server instance of connection
 * @buf:	buffer to store read data from socket
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
int cifsd_tcp_read(struct cifsd_tcp_conn *conn,
		   char *buf,
		   unsigned int to_read)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;

	return cifsd_tcp_readv(conn, &iov, 1, to_read);
}

/**
 * cifsd_tcp_write() - send smb response over network socket
 * @cifsd_work:     smb work containing response buffer
 *
 * TODO: change this function for smb2 currently is working for
 * smb1/smb2 both as smb*_buf_length is at beginning of the  packet
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_tcp_write(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb_hdr *rsp_hdr = RESPONSE_BUF(work);
	struct msghdr smb_msg = {};
	size_t len = 0;
	int sent;
	struct kvec iov[3];
	int iov_idx = 0;

	cifsd_tcp_try_dequeue_request(work);
	if (!rsp_hdr) {
		cifsd_err("NULL response header\n");
		return -EINVAL;
	}

	if (HAS_TRANSFORM_BUF(work)) {
		iov[iov_idx] = (struct kvec) { work->tr_buf,
				sizeof(struct smb2_transform_hdr) };
		len += iov[iov_idx++].iov_len;
	}

	if (HAS_AUX_PAYLOAD(work)) {
		iov[iov_idx] = (struct kvec) { rsp_hdr, RESP_HDR_SIZE(work) };
		len += iov[iov_idx++].iov_len;
		iov[iov_idx] = (struct kvec) { AUX_PAYLOAD(work),
			AUX_PAYLOAD_SIZE(work) };
		len += iov[iov_idx++].iov_len;
	} else {
		if (HAS_TRANSFORM_BUF(work))
			iov[iov_idx].iov_len = RESP_HDR_SIZE(work);
		else
			iov[iov_idx].iov_len =
				get_rfc1002_length(rsp_hdr) + 4;
		iov[iov_idx].iov_base = rsp_hdr;
		len += iov[iov_idx++].iov_len;
	}

	sent = kernel_sendmsg(conn->sock, &smb_msg, iov, iov_idx, len);
	if (sent < 0) {
		cifsd_err("Failed to send message: %d\n", sent);
		return sent;
	}

	return 0;
}

void cifsd_tcp_conn_lock(struct cifsd_tcp_conn *conn)
{
	mutex_lock(&conn->srv_mutex);
	atomic_inc(&conn->req_running);
}

void cifsd_tcp_conn_unlock(struct cifsd_tcp_conn *conn)
{
	atomic_dec(&conn->req_running);
	mutex_unlock(&conn->srv_mutex);
	if (waitqueue_active(&conn->req_running_q))
		wake_up_all(&conn->req_running_q);
}

void cifsd_tcp_conn_wait_idle(struct cifsd_tcp_conn *conn)
{
	wait_event(conn->req_running_q, atomic_read(&conn->req_running) < 2);
}

int cifsd_tcp_for_each_conn(int (*match)(struct cifsd_tcp_conn *, void *),
	void *arg)
{
	struct cifsd_tcp_conn *t;
	int ret = 0;

	read_lock(&tcp_conn_list_lock);
	list_for_each_entry(t, &tcp_conn_list, tcp_conns)
		if (match(t, arg)) {
			ret = 1;
			break;
		}
	read_unlock(&tcp_conn_list_lock);

	return ret;
}

static void tcp_destroy_socket(void)
{
	int ret;

	if (!cifsd_socket)
		return;

	ret = kernel_sock_shutdown(cifsd_socket, SHUT_RDWR);
	if (ret) {
		cifsd_err("Failed to shutdown socket: %d\n", ret);
	} else {
		sock_release(cifsd_socket);
		cifsd_socket = NULL;
	}
}

/**
 * cifsd_tcp_init - create socket for kcifsd/0
 *
 * Return:	Returns a task_struct or ERR_PTR
 */
int cifsd_tcp_init(void)
{
	int ret;
	struct sockaddr_in sin;
	int opt = 1;
	struct interface *iface;
	struct list_head *tmp;

	mutex_lock(&init_lock);
	if (cifsd_socket) {
		mutex_unlock(&init_lock);
		return 0;
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &cifsd_socket);
	if (ret) {
		cifsd_err("Can't create socket: %d\n", ret);
		goto out_error;
	}

	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = PF_INET;
	sin.sin_port = htons(server_conf.tcp_port);

	ret = kernel_setsockopt(cifsd_socket, SOL_SOCKET, SO_REUSEADDR,
				(char *)&opt, sizeof(opt));
	if (ret < 0) {
		cifsd_err("Failed to set socket options: %d\n", ret);
		goto out_error;
	}

	ret = kernel_setsockopt(cifsd_socket, SOL_TCP, TCP_NODELAY,
				(char *)&opt, sizeof(opt));
	if (ret < 0) {
		cifsd_err("Failed to set TCP_NODELAY: %d\n", ret);
		goto out_error;
	}

	list_for_each(tmp, &server_conf.iface_list) {
		iface = list_entry(tmp,  struct interface, entry);
		ret = kernel_setsockopt(cifsd_socket, SOL_SOCKET,
			SO_BINDTODEVICE, iface->name, strlen(iface->name));
		if (ret != -ENODEV && ret < 0) {
			cifsd_err("Failed to set SO_BINDTODEVICE: %d\n", ret);
			goto out_error;
		}

	}

	ret = kernel_bind(cifsd_socket, (struct sockaddr *)&sin, sizeof(sin));
	if (ret) {
		cifsd_err("Failed to bind socket: %d\n", ret);
		goto out_error;
	}

	cifsd_socket->sk->sk_rcvtimeo = CIFSD_TCP_RECV_TIMEOUT;
	cifsd_socket->sk->sk_sndtimeo = CIFSD_TCP_SEND_TIMEOUT;

	ret = cifsd_socket->ops->listen(cifsd_socket, CIFSD_SOCKET_BACKLOG);
	if (ret) {
		cifsd_err("Port listen() error: %d\n", ret);
		goto out_error;
	}

	ret = cifsd_tcp_run_kthread();
	if (ret) {
		cifsd_err("Can't start cifsd main kthread: %d\n", ret);
		goto out_error;
	}

	mutex_unlock(&init_lock);
	return 0;

out_error:
	tcp_destroy_socket();
	mutex_unlock(&init_lock);
	return ret;
}

static void tcp_stop_sessions(void)
{
	struct cifsd_tcp_conn *conn;

again:
	read_lock(&tcp_conn_list_lock);
	list_for_each_entry(conn, &tcp_conn_list, tcp_conns) {
		conn->tcp_status = CIFSD_SESS_EXITING;
		cifsd_err("Stop session handler %s/%d\n",
				conn->handler->comm,
				task_pid_nr(conn->handler));
	}
	read_unlock(&tcp_conn_list_lock);

	if (!list_empty(&tcp_conn_list)) {
		schedule_timeout_interruptible(CIFSD_TCP_RECV_TIMEOUT / 2);
		goto again;
	}
}

static void tcp_stop_kthread(void)
{
	int ret;

	if (!cifsd_kthread)
		return;

	ret = kthread_stop(cifsd_kthread);
	if (ret)
		cifsd_err("failed to stop forker thread\n");
	else
		cifsd_kthread = NULL;
}

void cifsd_tcp_destroy(void)
{
	mutex_lock(&init_lock);
	tcp_destroy_socket();
	tcp_stop_kthread();
	tcp_stop_sessions();
	mutex_unlock(&init_lock);
}

void cifsd_tcp_enqueue_request(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct list_head *requests_queue = NULL;
	struct smb2_hdr *hdr = REQUEST_BUF(work);

	if (hdr->ProtocolId == SMB2_PROTO_NUMBER) {
		unsigned int command = conn->ops->get_cmd_val(work);

		if (command != SMB2_CANCEL) {
			requests_queue = &conn->requests;
			work->type = SYNC;
		}
	} else {
		if (conn->ops->get_cmd_val(work) != SMB_COM_NT_CANCEL)
			requests_queue = &conn->requests;
	}

	if (requests_queue) {
		spin_lock(&conn->request_lock);
		list_add_tail(&work->request_entry, requests_queue);
		work->on_request_list = 1;
		spin_unlock(&conn->request_lock);
	}
}

int cifsd_tcp_try_dequeue_request(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	int ret = 1;

	if (!work->on_request_list)
		return 0;

	spin_lock(&conn->request_lock);
	if (!work->multiRsp) {
		list_del_init(&work->request_entry);
		work->on_request_list = 0;
		ret = 0;
	}
	spin_unlock(&conn->request_lock);
	return ret;
}

void cifsd_tcp_init_server_callbacks(struct cifsd_tcp_conn_ops *ops)
{
	default_tcp_conn_ops.process_fn = ops->process_fn;
	default_tcp_conn_ops.terminate_fn = ops->terminate_fn;
}
