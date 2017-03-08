/*
 *   fs/cifssrv/connect.c
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

#include "export.h"
#include "glob.h"
#include "smb1pdu.h"

struct task_struct *cifssrv_forkerd;

static int deny_new_conn;
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
 * get_server_iovec() - get server iovec for reading from socket
 * @server:     TCP server instance of connection
 * @nr_segs:	number of segments in iov
 *
 * Return:	return existing or newly allocate iovec
 */
static struct kvec *get_server_iovec(struct tcp_server_info *server,
				     unsigned int nr_segs)
{
	struct kvec *new_iov;

	if (server->iov && nr_segs <= server->nr_iov)
		return server->iov;

	/* not big enough -- allocate a new one and release the old */
	new_iov = kmalloc(sizeof(*new_iov) * nr_segs, GFP_NOFS);
	if (new_iov) {
		kfree(server->iov);
		server->iov = new_iov;
		server->nr_iov = nr_segs;
	}
	return new_iov;
}

/**
 * server_unresponsive() - check server is unresponsive or not
 * @server:     TCP server instance of connection
 *
 * Return:	true if server unresponsive, otherwise  false
 */
bool server_unresponsive(struct tcp_server_info *server)
{
	if (server->stats.open_files_count > 0)
		return false;

#ifdef CONFIG_CIFS_SMB2_SERVER

	if (time_after(jiffies, server->last_active + 2 * SMB_ECHO_INTERVAL)) {
		cifssrv_debug("No response from client in 120 secs\n");
		return true;
	}
	return false;
#else
	return false;
#endif
}

/**
 * cifssrv_readv_from_socket() - read data from socket in given iovec
 * @server:     TCP server instance of connection
 * @iov_orig:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
int cifssrv_readv_from_socket(struct tcp_server_info *server,
			      struct kvec *iov_orig, unsigned int nr_segs,
			      unsigned int to_read)
{
	int length = 0;
	int total_read;
	unsigned int segs;
	struct msghdr cifssrv_msg;
	struct kvec *iov;

	iov = get_server_iovec(server, nr_segs);
	if (!iov)
		return -ENOMEM;

	cifssrv_msg.msg_control = NULL;
	cifssrv_msg.msg_controllen = 0;

	for (total_read = 0; to_read; total_read += length, to_read -= length) {
		try_to_freeze();

		if (server_unresponsive(server)) {
			total_read = -EAGAIN;
			break;
		}

		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);

		length = kernel_recvmsg(server->sock, &cifssrv_msg,
				iov, segs, to_read, 0);

		if (server->tcp_status == CifsExiting) {
			total_read = -ESHUTDOWN;
			break;
		} else if (server->tcp_status == CifsNeedReconnect) {
			total_read = -EAGAIN;
			break;
		} else if (length == -ERESTARTSYS ||
				length == -EAGAIN ||
				length == -EINTR) {
			usleep_range(1000, 2000);
			length = 0;
			continue;
		} else if (length <= 0) {
			usleep_range(1000, 2000);
			total_read = -EAGAIN;
			break;
		}
	}
	return total_read;
}

/**
 * cifssrv_readv_from_socket() - read data from socket in given buffer
 * @server:     TCP server instance of connection
 * @buf:	buffer to store read data from socket
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
int cifssrv_read_from_socket(struct tcp_server_info *server, char *buf,
			     unsigned int to_read)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;

	return cifssrv_readv_from_socket(server, &iov, 1, to_read);
}

/**
 * cifssrv_create_socket - create socket for kcifssrvd/0
 *
 * Return:	Returns a task_struct or ERR_PTR
 */
int cifssrv_create_socket(void)
{
	int ret;
	struct socket *socket = NULL;
	struct sockaddr_in sin;
	int opt = 1;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (ret)
		return ret;

	cifssrv_debug("socket created\n");
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = PF_INET;
	sin.sin_port = htons(SMB_PORT);

	ret = kernel_setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
			(char *)&opt, sizeof(opt));
	if (ret < 0) {
		cifssrv_err("failed to set socket options(%d)\n", ret);
		goto release;
	}

	ret = kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY,
			(char *)&opt, sizeof(opt));
	if (ret < 0) {
		cifssrv_err("set TCP_NODELAY socket option error %d\n", ret);
		goto release;
	}

	ret = kernel_bind(socket, (struct sockaddr *)&sin, sizeof(sin));
	if (ret) {
		cifssrv_err("failed to bind socket err = %d\n", ret);
		goto release;
	}

	socket->sk->sk_rcvtimeo = 7 * HZ;
	socket->sk->sk_sndtimeo = 5 * HZ;

	ret = socket->ops->listen(socket, 64);
	if (ret) {
		cifssrv_err("port listen failure(%d)\n", ret);
		goto release;
	}

	ret = cifssrv_start_forker_thread(socket);
	if (ret) {
		cifssrv_err("failed to run forker thread(%d)\n", ret);
		goto release;
	}

	return 0;

release:
	cifssrv_debug("releasing socket\n");
	ret = kernel_sock_shutdown(socket, SHUT_RDWR);
	if (ret)
		cifssrv_err("failed to shutdown socket cleanly\n");

	sock_release(socket);

	return ret;
}

/**
 * cifssrv_do_fork() - forker thread to listen new SMB connection
 * @p:		arguments to forker thread
 *
 * Return:	Returns a task_struct or ERR_PTR
 */
static int cifssrv_do_fork(void *p)
{
	struct socket *socket = p;
	int ret;
	struct socket *newsock = NULL;

	while (!kthread_should_stop()) {
		if (deny_new_conn)
			continue;

		ret = kernel_accept(socket, &newsock, O_NONBLOCK);
		if (ret) {
			if (ret == -EAGAIN)
				/* check for new connections every 100 msecs */
				schedule_timeout_interruptible(HZ/10);
		} else {
			cifssrv_debug("connect success: accepted new connection\n");
			newsock->sk->sk_rcvtimeo = 7 * HZ;
			newsock->sk->sk_sndtimeo = 5 * HZ;
			/* request for new connection */
			connect_tcp_sess(newsock);
		}
	}
	cifssrv_debug("releasing socket\n");
	ret = kernel_sock_shutdown(socket, SHUT_RDWR);
	if (ret)
		cifssrv_err("failed to shutdown socket cleanly\n");

	sock_release(socket);

	return 0;
}

/**
 * cifssrv_start_forker_thread() - start forker thread
 *
 * start forker thread(kcifssrvd/0) at module init time to listen
 * on port 445 for new SMB connection requests. It creates per connection
 * server threads(kcifssrvd/x)
 *
 * Return:	0 on success or error number
 */
int cifssrv_start_forker_thread(struct socket *socket)
{
	int rc;

	deny_new_conn = 0;
	cifssrv_forkerd = kthread_run(cifssrv_do_fork, socket, "kcifssrvd/0");
	if (IS_ERR(cifssrv_forkerd)) {
		rc = PTR_ERR(cifssrv_forkerd);
		cifssrv_forkerd = NULL;
		return rc;
	}

	return 0;
}

/**
 * cifssrv_stop_forker_thread() - stop forker thread
 *
 * stop forker thread(cifssrv_forkerd) at module exit time
 */
void cifssrv_stop_forker_thread(void)
{
	int ret;

	if (cifssrv_forkerd) {
		ret = kthread_stop(cifssrv_forkerd);
		if (ret)
			cifssrv_err("failed to stop forker thread\n");
	}
	cifssrv_forkerd = NULL;
}

void cifssrv_close_socket(void)
{
	int ret;

	cifssrv_debug("closing SMB PORT and releasing socket\n");
	deny_new_conn = 1;
	ret = cifssrv_stop_tcp_sess();
	if (!ret) {
		cifssrv_stop_forker_thread();
		cifssrv_debug("SMB PORT closed\n");
	}
}
