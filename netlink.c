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
#include "netlink.h"

#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
#define NETLINK_CIFSSRV		31

#define cifssrv_ptr(_handle) ((void *)(unsigned long)_handle)
#define cifssrv_server_handle(_ptr) ((__u64)(unsigned long)_ptr)

#define NETLINK_RRQ_RECV_TIMEOUT	10000

struct sock *cifssrv_nlsk;
static DEFINE_MUTEX(nlsk_mutex);
static int pid;

static int cifssrv_nlsk_poll(struct tcp_server_info *server)
{
	int rc;

	if (server->ev_state != NETLINK_REQ_SENT)
		return -EINVAL;

	rc = wait_event_interruptible_timeout(server->pipe_q,
			server->ev_state == NETLINK_REQ_RECV,
			msecs_to_jiffies(NETLINK_RRQ_RECV_TIMEOUT));

	if (rc < 0) {
		cifssrv_err("failed to get NETLINK response\n");
		return -ETIMEDOUT;
	}

	return 0;
}

int cifssrv_sendmsg(struct tcp_server_info *server, unsigned int etype,
		unsigned int data_size, unsigned char *data,
		unsigned int out_buflen)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct cifssrv_uevent *ev;
	int len = nlmsg_total_size(sizeof(*ev) + data_size);
	int rc;

	if (unlikely(!server || !server->pipe_desc))
		return -EINVAL;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb) {
		cifssrv_err("ignored event (%u): len %d\n", etype, len);
		return -ENOMEM;
	}

	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->server_handle = (__u64)(unsigned long)server;

	switch (etype) {
	case CIFSSRV_KEVENT_CREATE_PIPE:
		ev->k.c_pipe.id = server->pipe_desc->id;
		ev->k.c_pipe.type = server->pipe_desc->pipe_type;
		break;
	case CIFSSRV_KEVENT_DESTROY_PIPE:
		ev->k.d_pipe.id = server->pipe_desc->id;
		ev->k.d_pipe.type = server->pipe_desc->pipe_type;
		break;
	case CIFSSRV_KEVENT_READ_PIPE:
		ev->k.r_pipe.id = server->pipe_desc->id;
		ev->k.r_pipe.type = server->pipe_desc->pipe_type;
		ev->k.r_pipe.out_buflen = out_buflen;
		break;
	case CIFSSRV_KEVENT_WRITE_PIPE:
		ev->k.w_pipe.id = server->pipe_desc->id;
		ev->k.w_pipe.type = server->pipe_desc->pipe_type;
		break;
	case CIFSSRV_KEVENT_IOCTL_PIPE:
		ev->k.i_pipe.id = server->pipe_desc->id;
		ev->k.i_pipe.type = server->pipe_desc->pipe_type;
		ev->k.i_pipe.out_buflen = out_buflen;
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

	server->ev_state = NETLINK_REQ_SENT;
	rc = nlmsg_unicast(cifssrv_nlsk, skb, pid);
	if (rc == -ESRCH)
		cifssrv_err("Cannot notify userspace of event %u "
				". Check cifssrvd daemon\n",
				etype);

	cifssrv_debug("send event(%u) to server %p, rc %d\n",
			etype, server, rc);
	if (rc)
		return rc;

	/* wait if need response from userspace */
	if (!(etype == CIFSSRV_KEVENT_CREATE_PIPE ||
			etype == CIFSSRV_KEVENT_DESTROY_PIPE))
		rc = cifssrv_nlsk_poll(server);

	server->ev_state = NETLINK_REQ_COMPLETED;
	return rc;
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
	struct tcp_server_info *server;
	struct cifssrv_uevent *ev;

	ev = nlmsg_data(nlh);
	server = validate_server_handle(cifssrv_ptr(ev->server_handle));
	if (!server || !server->pipe_desc || !server->pipe_desc->rsp_buf) {
		cifssrv_err("invalid server handle\n");
		return -EINVAL;
	}

	if (ev->error) {
		cifssrv_err("pipe io failed, err %d\n", ev->error);
		return ev->error;
	}

	if (unlikely(ev->buflen > NETLINK_CIFSSRV_MAX_PAYLOAD)) {
		cifssrv_err("too big response buffer %u\n", ev->buflen);
		return -EINVAL;
	}

	memcpy((char *)&server->pipe_desc->ev, (char *)ev, sizeof(*ev));
	if (ev->buflen)
		memcpy(server->pipe_desc->rsp_buf, ev->buffer, ev->buflen);

	server->ev_state = NETLINK_REQ_RECV;
	wake_up_interruptible(&server->pipe_q);
	return 0;
}

static int cifssrv_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;

	cifssrv_debug("got (%u) event from (pid %u)\n",
			nlh->nlmsg_type, nlh->nlmsg_pid);

	switch (nlh->nlmsg_type) {
	case CIFSSRV_UEVENT_INIT_CONNECTION:
		err = cifssrv_init_connection(nlh);
		break;
	case CIFSSRV_UEVENT_EXIT_CONNECTION:
		err = cifssrv_exit_connection(nlh);
		break;
	case CIFSSRV_UEVENT_READ_PIPE_RSP:
	case CIFSSRV_UEVENT_WRITE_PIPE_RSP:
	case CIFSSRV_UEVENT_IOCTL_PIPE_RSP:
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
	if (!cifssrv_nlsk) {
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
