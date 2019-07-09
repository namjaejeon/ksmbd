// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "smb_common.h"
#include "server.h"
#include "auth.h"
#include "buffer_pool.h"
#include "connection.h"
#include "transport_tcp.h"

struct interface {
	struct task_struct	*cifsd_kthread;
	struct socket		*cifsd_socket;
	struct list_head	entry;
	char			*name;
};

static LIST_HEAD(iface_list);

struct tcp_transport {
	struct cifsd_transport		transport;
	struct socket			*sock;
	struct kvec			*iov;
	unsigned int			nr_iov;
};

static struct cifsd_transport_ops cifsd_tcp_transport_ops;

#define CIFSD_TRANS(t)	(&(t)->transport)
#define TCP_TRANS(t)	((struct tcp_transport *)container_of(t, \
				struct tcp_transport, transport))

static inline void cifsd_tcp_nodelay(struct socket *sock)
{
	int val = 1;

	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
		(char *)&val, sizeof(val));
}

static inline void cifsd_tcp_reuseaddr(struct socket *sock)
{
	int val = 1;

	kernel_setsockopt(sock, SOL_TCP, SO_REUSEADDR,
		(char *)&val, sizeof(val));
}

static struct tcp_transport *alloc_transport(struct socket *client_sk)
{
	struct tcp_transport *t;
	struct cifsd_conn *conn;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;
	t->sock = client_sk;

	conn = cifsd_conn_alloc();
	if (!conn) {
		kfree(t);
		return NULL;
	}

	conn->transport = CIFSD_TRANS(t);
	CIFSD_TRANS(t)->conn = conn;
	CIFSD_TRANS(t)->ops = &cifsd_tcp_transport_ops;
	return t;
}

static void free_transport(struct tcp_transport *t)
{
	kernel_sock_shutdown(t->sock, SHUT_RDWR);
	sock_release(t->sock);
	t->sock = NULL;

	cifsd_conn_free(CIFSD_TRANS(t)->conn);
	kfree(t->iov);
	kfree(t);
}

/**
 * kvec_array_init() - initialize a IO vector segment
 * @new:	IO vector to be initialized
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
 * @t:		TCP transport instance
 * @nr_segs:	number of segments in iov
 *
 * Return:	return existing or newly allocate iovec
 */
static struct kvec *get_conn_iovec(struct tcp_transport *t,
				     unsigned int nr_segs)
{
	struct kvec *new_iov;

	if (t->iov && nr_segs <= t->nr_iov)
		return t->iov;

	/* not big enough -- allocate a new one and release the old */
	new_iov = kmalloc(sizeof(*new_iov) * nr_segs, GFP_KERNEL);
	if (new_iov) {
		kfree(t->iov);
		t->iov = new_iov;
		t->nr_iov = nr_segs;
	}
	return new_iov;
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
	struct tcp_transport *t;

	t = alloc_transport(client_sk);
	if (!t)
		return -ENOMEM;

	csin = CIFSD_TCP_PEER_SOCKADDR(CIFSD_TRANS(t)->conn);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 16, 0)
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
	CIFSD_TRANS(t)->handler = kthread_run(cifsd_conn_handler_loop,
					CIFSD_TRANS(t)->conn,
					"kcifsd:%u", cifsd_tcp_get_port(csin));
	if (IS_ERR(CIFSD_TRANS(t)->handler)) {
		cifsd_err("cannot start conn thread\n");
		rc = PTR_ERR(CIFSD_TRANS(t)->handler);
		free_transport(t);
	}
	return rc;

out_error:
	free_transport(t);
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
	struct socket *cifsd_socket = (struct socket *)p;
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
		client_sk->sk->sk_rcvtimeo = CIFSD_TCP_RECV_TIMEOUT;
		client_sk->sk->sk_sndtimeo = CIFSD_TCP_SEND_TIMEOUT;

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
static int cifsd_tcp_run_kthread(struct interface *iface)
{
	int rc;
	struct task_struct *kthread;

	kthread = kthread_run(cifsd_kthread_fn, (void *)iface->cifsd_socket,
		"kcifsd-%s", iface->name);
	if (IS_ERR(kthread)) {
		rc = PTR_ERR(kthread);
		return rc;
	}
	iface->cifsd_kthread = kthread;

	return 0;
}

/**
 * cifsd_tcp_readv() - read data from socket in given iovec
 * @t:		TCP transport instance
 * @iov_orig:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
static int cifsd_tcp_readv(struct tcp_transport *t,
			   struct kvec *iov_orig,
			   unsigned int nr_segs,
			   unsigned int to_read)
{
	int length = 0;
	int total_read;
	unsigned int segs;
	struct msghdr cifsd_msg;
	struct kvec *iov;
	struct cifsd_conn *conn = CIFSD_TRANS(t)->conn;

	iov = get_conn_iovec(t, nr_segs);
	if (!iov)
		return -ENOMEM;

	cifsd_msg.msg_control = NULL;
	cifsd_msg.msg_controllen = 0;

	for (total_read = 0; to_read; total_read += length, to_read -= length) {
		try_to_freeze();

		if (!cifsd_conn_alive(conn)) {
			total_read = -ESHUTDOWN;
			break;
		}
		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);

		length = kernel_recvmsg(t->sock, &cifsd_msg,
					iov, segs, to_read, 0);

		if (length == -EINTR) {
			total_read = -ESHUTDOWN;
			break;
		} else if (conn->status == CIFSD_SESS_NEED_RECONNECT) {
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
 * @t:		TCP transport instance
 * @buf:	buffer to store read data from socket
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
static int cifsd_tcp_read(struct cifsd_transport *t,
		   char *buf,
		   unsigned int to_read)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;

	return cifsd_tcp_readv(TCP_TRANS(t), &iov, 1, to_read);
}

static int cifsd_tcp_writev(struct cifsd_transport *t, struct kvec *iov,
			int nvecs, int size)

{
	struct msghdr smb_msg = {.msg_flags = MSG_NOSIGNAL};

	return kernel_sendmsg(TCP_TRANS(t)->sock, &smb_msg, iov, nvecs, size);
}

static void cifsd_tcp_disconnect(struct cifsd_transport *t)
{
	free_transport(TCP_TRANS(t));
}

static void tcp_destroy_socket(struct socket *cifsd_socket)
{
	int ret;

	if (!cifsd_socket)
		return;

	ret = kernel_sock_shutdown(cifsd_socket, SHUT_RDWR);
	if (ret) {
		cifsd_err("Failed to shutdown socket: %d\n", ret);
	} else {
		sock_release(cifsd_socket);
	}
}

/**
 * create_socket - create socket for kcifsd/0
 *
 * Return:	Returns a task_struct or ERR_PTR
 */
static int create_socket(struct interface *iface)
{
	int ret;
	struct sockaddr_in sin;
	struct socket *cifsd_socket;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &cifsd_socket);
	if (ret) {
		cifsd_err("Can't create socket: %d\n", ret);
		goto out_error;
	}

	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = PF_INET;
	sin.sin_port = htons(server_conf.tcp_port);

	cifsd_tcp_nodelay(cifsd_socket);
	cifsd_tcp_reuseaddr(cifsd_socket);

	ret = kernel_setsockopt(cifsd_socket,
				SOL_SOCKET,
				SO_BINDTODEVICE,
				iface->name,
				strlen(iface->name));
	if (ret != -ENODEV && ret < 0) {
		cifsd_err("Failed to set SO_BINDTODEVICE: %d\n", ret);
		goto out_error;
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

	iface->cifsd_socket = cifsd_socket;
	ret = cifsd_tcp_run_kthread(iface);
	if (ret) {
		cifsd_err("Can't start cifsd main kthread: %d\n", ret);
		goto out_error;
	}

	return 0;

out_error:
	tcp_destroy_socket(cifsd_socket);
	iface->cifsd_socket = NULL;
	return ret;
}

int cifsd_tcp_init(void)
{
	struct interface *iface;
	struct list_head *tmp;
	int ret;

	if (list_empty(&iface_list))
		return 0;

	list_for_each(tmp, &iface_list) {
		iface = list_entry(tmp, struct interface, entry);
		ret = create_socket(iface);
		if (ret)
			break;
	}

	return ret;
}

static void tcp_stop_kthread(struct task_struct *kthread)
{
	int ret;

	if (!kthread)
		return;

	ret = kthread_stop(kthread);
	if (ret)
		cifsd_err("failed to stop forker thread\n");
}

void cifsd_tcp_destroy(void)
{
	struct interface *iface, *tmp;

	list_for_each_entry_safe(iface, tmp, &iface_list, entry) {
		list_del(&iface->entry);
		tcp_destroy_socket(iface->cifsd_socket);
		tcp_stop_kthread(iface->cifsd_kthread);
		kfree(iface->name);
		cifsd_free(iface);
	}
}

static bool iface_exists(const char *ifname)
{
	struct net_device *netdev;
	bool ret = false;

	rcu_read_lock();
	netdev = dev_get_by_name_rcu(&init_net, ifname);
	if (netdev) {
		if (!(netdev->flags & IFF_UP))
			cifsd_err("Device %s is down\n", ifname);
		else
			ret = true;
	}
	rcu_read_unlock();
	return ret;
}

static int alloc_iface(char *ifname)
{
	struct interface *iface;

	iface = cifsd_alloc(sizeof(struct interface));
	if (!iface)
		return -ENOMEM;

	iface->name = ifname;
	if (!iface->name) {
		cifsd_free(iface);
		return -ENOMEM;
	}
	list_add(&iface->entry, &iface_list);
	return 0;
}

int cifsd_tcp_set_interfaces(char *ifc_list, int ifc_list_sz)
{
	int sz = 0;

	if (!ifc_list_sz) {
		struct net_device *netdev;

		rtnl_lock();
		for_each_netdev(&init_net, netdev) {
			if (alloc_iface(kstrdup(netdev->name, GFP_KERNEL)))
				return -ENOMEM;
		}
		rtnl_unlock();
		return 0;
	}

	while (ifc_list_sz > 0) {
		if (iface_exists(ifc_list)) {
			if (alloc_iface(kstrdup(ifc_list, GFP_KERNEL)))
				return -ENOMEM;
		} else {
			cifsd_err("Unknown interface: %s\n", ifc_list);
		}

		sz = strlen(ifc_list);
		if (!sz)
			break;

		ifc_list += sz + 1;
		ifc_list_sz -= (sz + 1);
	}

	return 0;
}

static struct cifsd_transport_ops cifsd_tcp_transport_ops = {
	.read		= cifsd_tcp_read,
	.writev		= cifsd_tcp_writev,
	.disconnect	= cifsd_tcp_disconnect,
};
