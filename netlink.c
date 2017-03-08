/*
 *   fs/cifssrv/netlink.c
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

#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/types.h>

#include "glob.h"
#include "export.h"
#include "netlink.h"

#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE

#define NETLINK_CIFSSRV			31
#define NETLINK_RRQ_RECV_TIMEOUT	10000
#define cifssrv_ptr(_handle)		((void *)(unsigned long)_handle)
#define cifssrv_sess_handle(_ptr)	((__u64)(unsigned long)_ptr)

struct sock *cifssrv_nlsk;
static DEFINE_MUTEX(nlsk_mutex);
static int pid;

static int cifssrv_nlsk_poll(struct cifssrv_sess *sess)
{
	int rc;

	rc = wait_event_interruptible_timeout(sess->pipe_q,
			sess->ev_state == NETLINK_REQ_RECV,
			msecs_to_jiffies(NETLINK_RRQ_RECV_TIMEOUT));

	if (unlikely(rc <= 0)) {
		rc = (rc == 0) ? -ETIMEDOUT : rc;
		cifssrv_err("failed to get NETLINK response, err %d\n", rc);
		return rc;
	}

	return 0;
}

int cifssrv_sendmsg(struct cifssrv_sess *sess, unsigned int etype,
		int pipe_type, unsigned int data_size,
		unsigned char *data, unsigned int out_buflen)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct cifssrv_uevent *ev;
	int len = nlmsg_total_size(sizeof(*ev) + data_size);
	int rc;
	struct cifssrv_usr *user;
	struct cifssrv_pipe *pipe_desc = sess->pipe_desc[pipe_type];

	if (unlikely(!pipe_desc))
		return -EINVAL;

	if (unlikely(data_size > NETLINK_CIFSSRV_MAX_PAYLOAD)) {
		cifssrv_err("too big(%u) message\n", data_size);
		return -EOVERFLOW;
	}

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifssrv_err("ignored event (%u): len %d\n", etype, len);
		return -ENOMEM;
	}

	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->server_handle = cifssrv_sess_handle(sess);
	ev->pipe_type = pipe_type;

	switch (etype) {
	case CIFSSRV_KEVENT_CREATE_PIPE:
		ev->k.c_pipe.id = pipe_desc->id;
		strncpy(ev->k.c_pipe.codepage, sess->server->local_nls->charset,
				CIFSSRV_CODEPAGE_LEN - 1);
		break;
	case CIFSSRV_KEVENT_DESTROY_PIPE:
		ev->k.d_pipe.id = pipe_desc->id;
		break;
	case CIFSSRV_KEVENT_READ_PIPE:
		ev->k.r_pipe.id = pipe_desc->id;
		ev->k.r_pipe.out_buflen = out_buflen;
		break;
	case CIFSSRV_KEVENT_WRITE_PIPE:
		ev->k.w_pipe.id = pipe_desc->id;
		break;
	case CIFSSRV_KEVENT_IOCTL_PIPE:
		ev->k.i_pipe.id = pipe_desc->id;
		ev->k.i_pipe.out_buflen = out_buflen;
		break;
	case CIFSSRV_KEVENT_LANMAN_PIPE:
		ev->k.l_pipe.out_buflen = out_buflen;
		strncpy(ev->k.l_pipe.codepage, sess->server->local_nls->charset,
				CIFSSRV_CODEPAGE_LEN - 1);
		user = get_smb_session_user(sess);
		if (user)
			strncpy(ev->k.l_pipe.username, user->name,
					CIFSSRV_USERNAME_LEN - 1);
		break;
	default:
		cifssrv_err("invalid event %u\n", etype);
		kfree_skb(skb);
		return -EINVAL;
	}

	if (data_size) {
		ev->buflen = data_size;
		memcpy(ev->buffer, data, data_size);
	}

	cifssrv_debug("sending event(%u) to sess %p\n", etype, sess);
	mutex_lock(&nlsk_mutex);
	sess->ev_state = NETLINK_REQ_SENT;
	rc = nlmsg_unicast(cifssrv_nlsk, skb, pid);
	mutex_unlock(&nlsk_mutex);
	if (unlikely(rc == -ESRCH))
		cifssrv_err("Cannot notify userspace of event %u "
				". Check cifssrvd daemon\n",
				etype);

	if (unlikely(rc)) {
		cifssrv_err("failed to send message, err %d\n", rc);
		return rc;
	}

	/* wait if need response from userspace */
	if (!(etype == CIFSSRV_KEVENT_CREATE_PIPE ||
			etype == CIFSSRV_KEVENT_DESTROY_PIPE))
		rc = cifssrv_nlsk_poll(sess);

	sess->ev_state = NETLINK_REQ_COMPLETED;
	return rc;
}

int cifssrv_kthread_stop_status(int etype)
{
	struct cifssrv_uevent *ev;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int rc;
	int len = nlmsg_total_size(sizeof(*ev)+sizeof(rc));

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifssrv_err("Failed to allocate\n");
		return -ENOMEM;
	}
	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	ev->buflen = sizeof(rc);
	rc = nlmsg_unicast(cifssrv_nlsk, skb, pid);
	return 0;
}

static int cifssrv_init_connection(struct nlmsghdr *nlh)
{
	cifssrv_debug("init connection\n");
	pid = nlh->nlmsg_pid; /*pid of sending process */
	return 0;
}

static int cifssrv_exit_connection(struct nlmsghdr *nlh)
{
	cifssrv_debug("exit connection\n");
	return 0;
}

static int cifssrv_common_pipe_rsp(struct nlmsghdr *nlh)
{
	struct cifssrv_sess *sess;
	struct cifssrv_uevent *ev;
	struct cifssrv_pipe *pipe_desc;

	ev = nlmsg_data(nlh);
	if (unlikely(ev->pipe_type >= MAX_PIPE)) {
		cifssrv_err("invalid pipe type %u\n", ev->pipe_type);
		return -EINVAL;
	}

	sess = validate_sess_handle(cifssrv_ptr(ev->server_handle));
	if (unlikely(!sess)) {
		cifssrv_err("invalid session handle\n");
		return -EINVAL;
	}

	pipe_desc = sess->pipe_desc[ev->pipe_type];
	if (unlikely(!pipe_desc)) {
		cifssrv_err("invalid pipe descriptor\n");
		return -EINVAL;
	}

	if (unlikely(ev->error)) {
		cifssrv_debug("pipe io failed, err %d\n", ev->error);
		goto out;
	}

	if (unlikely(ev->buflen > NETLINK_CIFSSRV_MAX_PAYLOAD)) {
		cifssrv_err("too big response buffer %u\n", ev->buflen);
		goto out;
	}

	memcpy((char *)&pipe_desc->ev, (char *)ev, sizeof(*ev));
	if (ev->buflen)
		memcpy(pipe_desc->rsp_buf, ev->buffer, ev->buflen);

out:
	sess->ev_state = NETLINK_REQ_RECV;
	wake_up_interruptible(&sess->pipe_q);
	return 0;
}

static int cifssrv_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;

	cifssrv_debug("received (%u) event from (pid %u)\n",
			nlh->nlmsg_type, nlh->nlmsg_pid);

	switch (nlh->nlmsg_type) {
	case CIFSSRV_UEVENT_INIT_CONNECTION:
		err = cifssrv_init_connection(nlh);
		break;
	case CIFSSRV_UEVENT_START_SMBPORT:
		err = cifssrv_create_socket();
		if (err)
			cifssrv_err("unable to open SMB PORT\n");
		break;
	case CIFSSRV_UEVENT_STOP_SMBPORT:
		cifssrv_close_socket();
		break;
	case CIFSSRV_UEVENT_EXIT_CONNECTION:
		err = cifssrv_exit_connection(nlh);
		break;
	case CIFSSRV_UEVENT_READ_PIPE_RSP:
	case CIFSSRV_UEVENT_WRITE_PIPE_RSP:
	case CIFSSRV_UEVENT_IOCTL_PIPE_RSP:
	case CIFSSRV_UEVENT_LANMAN_PIPE_RSP:
		err = cifssrv_common_pipe_rsp(nlh);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static void cifssrv_netlink_rcv(struct sk_buff *skb)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return;

	mutex_lock(&nlsk_mutex);
	while (skb->len >= NLMSG_HDRLEN) {
		int err;
		unsigned int rlen;
		struct nlmsghdr	*nlh;
		struct cifssrv_uevent *ev;

		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) ||
				skb->len < nlh->nlmsg_len) {
			break;
		}

		ev = nlmsg_data(nlh);
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		err = cifssrv_if_recv_msg(skb, nlh);
		skb_pull(skb, rlen);
	}
	mutex_unlock(&nlsk_mutex);
}

int cifssrv_net_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input  = cifssrv_netlink_rcv,
	};

	cifssrv_nlsk = netlink_kernel_create(&init_net, NETLINK_CIFSSRV, &cfg);
	if (unlikely(!cifssrv_nlsk)) {
		cifssrv_err("failed to create cifssrv netlink socket\n");
		return -ENOMEM;
	}

	return 0;
}

void cifssrv_net_exit(void)
{
	netlink_kernel_release(cifssrv_nlsk);
}
#endif /* CONFIG_CIFSSRV_NETLINK_INTERFACE */
