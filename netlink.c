/*
 *   fs/cifsd/netlink.c
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
#include "transport.h"

#define NETLINK_CIFSD			31
#define NETLINK_RRQ_RECV_TIMEOUT	10000
#define cifsd_ptr(_handle)		((void *)(unsigned long)_handle)
#define cifsd_sess_handle(_ptr)	((__u64)(unsigned long)_ptr)

struct sock *cifsd_nlsk;
static DEFINE_MUTEX(nlsk_mutex);
static int pid;

static int cifsd_early_pid;
static int cifsstat_pid;
static int cifsadmin_pid;

static int cifsd_nlsk_poll(struct cifsd_sess *sess)
{
	int rc;

	rc = wait_event_interruptible_timeout(sess->pipe_q,
			sess->ev_state == NETLINK_REQ_RECV,
			msecs_to_jiffies(NETLINK_RRQ_RECV_TIMEOUT));

	if (unlikely(rc <= 0)) {
		rc = (rc == 0) ? -ETIMEDOUT : rc;
		cifsd_err("failed to get NETLINK response, err %d\n", rc);
		return rc;
	}

	return 0;
}

static int cifsd_nlsk_poll_notify(struct cifsd_sess *sess)
{
	int rc;

	rc = wait_event_interruptible(sess->notify_q,
		sess->ev_state == NETLINK_REQ_RECV);

	return rc;
}

int cifsd_sendmsg(struct cifsd_sess *sess, unsigned int etype,
		int pipe_type, unsigned int data_size,
		unsigned char *data, unsigned int out_buflen)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct cifsd_uevent *ev;
	int len = nlmsg_total_size(sizeof(*ev) + data_size);
	int rc;
	struct cifsd_user *user;
	struct cifsd_pipe *pipe_desc = sess->pipe_desc[pipe_type];

	if (unlikely(!pipe_desc))
		return -EINVAL;

	if (unlikely(data_size > NETLINK_CIFSD_MAX_PAYLOAD)) {
		cifsd_err("too big(%u) message\n", data_size);
		return -EOVERFLOW;
	}

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifsd_err("ignored event (%u): len %d\n", etype, len);
		return -ENOMEM;
	}

	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->conn_handle = cifsd_sess_handle(sess);
	ev->pipe_type = pipe_type;

	switch (etype) {
	case CIFSD_KEVENT_CREATE_PIPE:
		ev->k.c_pipe.id = pipe_desc->id;
		strncpy(ev->k.c_pipe.codepage, sess->conn->local_nls->charset,
				CIFSD_CODEPAGE_LEN - 1);
		break;
	case CIFSD_KEVENT_DESTROY_PIPE:
		ev->k.d_pipe.id = pipe_desc->id;
		break;
	case CIFSD_KEVENT_READ_PIPE:
		ev->k.r_pipe.id = pipe_desc->id;
		ev->k.r_pipe.out_buflen = out_buflen;
		break;
	case CIFSD_KEVENT_WRITE_PIPE:
		ev->k.w_pipe.id = pipe_desc->id;
		break;
	case CIFSD_KEVENT_IOCTL_PIPE:
		ev->k.i_pipe.id = pipe_desc->id;
		ev->k.i_pipe.out_buflen = out_buflen;
		break;
	case CIFSD_KEVENT_LANMAN_PIPE:
		ev->k.l_pipe.out_buflen = out_buflen;
		strncpy(ev->k.l_pipe.codepage, sess->conn->local_nls->charset,
				CIFSD_CODEPAGE_LEN - 1);
		user = get_smb_session_user(sess);
		if (user)
			strncpy(ev->k.l_pipe.username, user_name(user),
					CIFSD_USERNAME_LEN - 1);
		break;
	default:
		cifsd_err("invalid event %u\n", etype);
		kfree_skb(skb);
		return -EINVAL;
	}

	if (data_size) {
		ev->buflen = data_size;
		memcpy(ev->buffer, data, data_size);
	}

	cifsd_debug("sending event(%u) to sess %p\n", etype, sess);
	mutex_lock(&nlsk_mutex);
	sess->ev_state = NETLINK_REQ_SENT;
	rc = nlmsg_unicast(cifsd_nlsk, skb, pid);
	mutex_unlock(&nlsk_mutex);
	if (unlikely(rc == -ESRCH))
		cifsd_err("Cannot notify userspace of event %u "
				". Check cifsd daemon\n", etype);

	if (unlikely(rc)) {
		cifsd_err("failed to send message, err %d\n", rc);
		return rc;
	}

	/* wait if need response from userspace */
	if (!(etype == CIFSD_KEVENT_CREATE_PIPE ||
			etype == CIFSD_KEVENT_DESTROY_PIPE))
		rc = cifsd_nlsk_poll(sess);

	sess->ev_state = NETLINK_REQ_COMPLETED;
	return rc;
}

int cifsd_usendmsg(struct cifsd_uevent *rsp_ev, int upid,
	unsigned int data_size, char *data)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct cifsd_uevent *ev;
	int etype = rsp_ev->type;
	int ev_sz;
	int rc;
	int len = nlmsg_total_size(sizeof(*ev) + data_size);

	if (unlikely(data_size > NETLINK_CIFSD_MAX_PAYLOAD)) {
		cifsd_err("too big(%u) message\n", data_size);
		return -EOVERFLOW;
	}

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifsd_err("ignored event (%u): len %d\n", etype, len);
		return -ENOMEM;
	}

	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	ev_sz = sizeof(struct cifsd_uevent);
	memset(ev, 0, ev_sz);
	memcpy(ev, rsp_ev, ev_sz);

	if (data_size) {
		ev->buflen = data_size;
		memcpy(ev->buffer, data, data_size + 1);
	}

	rc = nlmsg_unicast(cifsd_nlsk, skb, upid);
	if (unlikely(rc == -ESRCH))
		cifsd_err("Cannot notify userspace of event %u "
				". Check cifsd daemon\n",
				etype);
	if (unlikely(rc)) {
		cifsd_err("failed to send message, err %d\n", rc);
		return rc;
	}
	return rc;
}


int cifsd_sendmsg_notify(struct cifsd_sess *sess,
	unsigned int data_size,
	struct smb2_inotify_req_info *inotify_req_info,
	char *path)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct cifsd_uevent *ev;
	int len = nlmsg_total_size(sizeof(*ev) + data_size);
	int offset_of_path = offsetof(struct smb2_inotify_req_info, dir_path);
	int rc = 0;
	unsigned int etype = CIFSD_KEVENT_INOTIFY_REQUEST;

	if (unlikely(data_size > NETLINK_CIFSD_MAX_PAYLOAD)) {
		cifsd_err("too big(%u) message\n", data_size);
		return -EOVERFLOW;
	}

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifsd_err("ignored event (%u): len %d\n", etype, len);
		return -ENOMEM;
	}

	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, etype, (len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->conn_handle = cifsd_sess_handle(sess);

	strncpy(ev->codepage, sess->conn->local_nls->charset,
				CIFSD_CODEPAGE_LEN - 1);

	if (data_size) {
		ev->buflen = data_size;
		memcpy(ev->buffer, inotify_req_info, offset_of_path);
		memcpy(ev->buffer + offset_of_path,
			path, inotify_req_info->path_len+1);
	}

	cifsd_debug("sending event(%u) to sess %p\n", etype, sess);
	mutex_lock(&nlsk_mutex);
	sess->ev_state = NETLINK_REQ_SENT;
	rc = nlmsg_unicast(cifsd_nlsk, skb, pid);
	mutex_unlock(&nlsk_mutex);
	if (unlikely(rc == -ESRCH))
		cifsd_err("Cannot notify userspace of event %u. Check cifsd daemon\n",
				etype);

	if (unlikely(rc)) {
		cifsd_err("failed to send message, err %d\n", rc);
		return rc;
	}

	rc = cifsd_nlsk_poll_notify(sess);
	sess->ev_state = NETLINK_REQ_COMPLETED;
	return rc;
}

static int cifsd_terminate_user_process(int new_cifsd_pid)
{
	struct cifsd_uevent *ev;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int rc;
	int len = nlmsg_total_size(sizeof(*ev)+sizeof(rc));

	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb)) {
		cifsd_err("Failed to allocate\n");
		return -ENOMEM;
	}
	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	nlh = __nlmsg_put(skb, 0, 0, CFISD_KEVENT_USER_DAEMON_EXIST,
		(len - sizeof(*nlh)), 0);
	ev = nlmsg_data(nlh);
	ev->buflen = sizeof(rc);
	rc = nlmsg_unicast(cifsd_nlsk, skb, new_cifsd_pid);
	return 0;
}

/** cifsd_early_init() - handler for cifsd early init
 *		initialize pid
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_early_init(struct nlmsghdr *nlh)
{
	cifsd_debug("init cifsd early connection\n");
	cifsd_early_pid = nlh->nlmsg_pid;

	return 0;
}

/** cifsd_config_user() - handler to export user to user list
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_config_user(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	struct cifsd_uevent rsp_ev;
	int ret = 0;

	if (!ev->buflen) {
		ret = -EINVAL;
		goto out;
	}
	ret = cifsd_user_store(ev->buffer, ev->buflen);

out:
	rsp_ev.type = CIFSD_UEVENT_CONFIG_USER_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsd_early_pid, 0, NULL);
	if (ret)
		cifsd_err("failed to send event, err %d\n", ret);
	return ret;
}

/** cifsd_config_share() - handler to update config setting
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_config_share(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	struct cifsd_uevent rsp_ev;
	int ret;

	if (!ev->buflen) {
		ret = -EINVAL;
		goto out;
	}
	ret = cifsd_config_store(ev->buffer, ev->buflen);

out:
	rsp_ev.type = CIFSD_UEVENT_CONFIG_SHARE_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsd_early_pid, 0, NULL);
	if (ret)
		cifsd_err("failed to send event, err %d\n", ret);
	return ret;
}

static int cifsd_init_connection(struct nlmsghdr *nlh)
{
	int err = 0;
	struct task_struct *cifsd_task;

	cifsd_debug("init connection\n");

	rcu_read_lock();
	cifsd_task = pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (cifsd_task) {
		if (!strncmp(cifsd_task->comm, "cifsd", 5)) {
			cifsd_terminate_user_process(nlh->nlmsg_pid);
			err = -EPERM;
		}
	} else {
		cifsd_tcp_stop_kthread();
		pid = nlh->nlmsg_pid; /*pid of sending process */
	}

	return err;
}

static int cifsd_exit_connection(struct nlmsghdr *nlh)
{
	cifsd_debug("exit connection\n");
	return 0;
}

/** cifsadmin_init_connection() - handler for cifsdadmin init
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsadmin_init_connection(struct nlmsghdr *nlh)
{
	cifsd_debug("init connection\n");
	cifsadmin_pid = nlh->nlmsg_pid;
	return 0;
}

/**
 * cifsadmin_query_user() - handler for cifsd user query
 *            and respond the requested user is present in
 *            cifsd user list or not
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsadmin_query_user(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	char *username = ev->k.u_query.username;
	struct cifsd_uevent rsp_ev;
	int ret;

	ret = cifsadmin_user_query(username);
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSADMIN_UEVENT_QUERY_USER_RSP;
	rsp_ev.error = ret;
	strncpy(rsp_ev.k.u_query.username, username, strlen(username));
	ret = cifsd_usendmsg(&rsp_ev, cifsadmin_pid, 0, NULL);
	if (ret)
		cifsd_err("query user respond failed, err %d\n", ret);

	return ret;
}

/**
 * cifsadmin_remove_user() - handler for cifsd user remove
 *            and respond the requested user is removed
 *            from cifsd user list or not
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsadmin_remove_user(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	char *username = ev->k.u_del.username;
	struct cifsd_uevent rsp_ev;
	int ret;

	ret = cifsadmin_user_del(username);
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSADMIN_UEVENT_REMOVE_USER_RSP;
	rsp_ev.error = ev->error;
	strncpy(rsp_ev.k.u_del.username, username, strlen(username));
	ret = cifsd_usendmsg(&rsp_ev, cifsadmin_pid, 0, NULL);
	if (ret)
		cifsd_err("remove user respond failed, err %d\n", ret);

	return ret;
}

/**
 * cifsd_kernel_debug() - handler for cifsd debug enable/disable setting
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_kernel_debug(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	struct cifsd_uevent rsp_ev;
	int ret;

	ret = cifsd_debug_store(ev->buffer);
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSADMIN_UEVENT_KERNEL_DEBUG_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsadmin_pid, 0, NULL);
	if (ret)
		cifsd_err("cifsd kernel debug setting failed, err %d\n", ret);

	return ret;
}

/**
 * cifsd_kernel_caseless_search() - handler for cifsd
 *		caseless search setting
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_kernel_caseless_search(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev = nlmsg_data(nlh);
	struct cifsd_uevent rsp_ev;
	int ret;

	ret = cifsd_caseless_search_store(ev->buffer);
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSADMIN_UEVENT_CASELESS_SEARCH_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsadmin_pid, 0, NULL);
	if (ret)
		cifsd_err("cifsd caseless search setting failed, err %d\n",
				ret);
	return ret;
}

/**
 * cifsstat_init_connection() - handler for cifsstat init
 * @nlh:       netlink message header
 *
 * Return:	0: on success
 */
static int cifsstat_init_connection(struct nlmsghdr *nlh)
{
	cifsd_debug("init connection\n");
	cifsstat_pid = nlh->nlmsg_pid;
	return 0;
}

/**
 * cifsd_stat_read() - handler for cifsd stat read
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_stat_read(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev;
	struct cifsd_uevent rsp_ev;
	int flag;
	char *buf;
	char *client_ip;
	int ret = 0;

	ev = nlmsg_data(nlh);
	flag = ev->k.r_stat.flag;
	client_ip = ev->k.r_stat.statip;
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	ret = cifsstat_show(buf, client_ip, flag);
	if (!ret)
		cifsd_err("get stat failed\n");

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSSTAT_UEVENT_READ_STAT_RSP;
	rsp_ev.error = ret;
	rsp_ev.k.r_stat.flag = flag;
	ret = cifsd_usendmsg(&rsp_ev, cifsstat_pid, strlen(buf), buf);
	if (ret)
		cifsd_err(" stat respond failed, err %d\n", ret);

	kfree(buf);
	return ret;
}

/**
 * cifsd_userlist() - handler to list exported cifsd users
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_userlist(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev;
	struct cifsd_uevent rsp_ev;
	char *buf;
	int ret;

	ev = nlmsg_data(nlh);
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	ret = cifsd_user_show(buf);
	if (!ret)
		cifsd_err("get user list failed\n");

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSSTAT_UEVENT_LIST_USER_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsstat_pid, strlen(buf), buf);
	if (ret)
		cifsd_err(" user list respond failed, err %d\n", ret);

	kfree(buf);
	return ret;
}

/**
 * cifsd_sharelist() - handler to list exported cifsd shares
 * @nlh:       netlink message header
 *
 * Return:      0: on success
 */
static int cifsd_sharelist(struct nlmsghdr *nlh)
{
	struct cifsd_uevent *ev;
	struct cifsd_uevent rsp_ev;
	char *buf;
	int ret;

	ev = nlmsg_data(nlh);
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	ret = cifsd_share_show(buf);
	if (!ret)
		cifsd_err("get share list failed\n");

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSSTAT_UEVENT_LIST_SHARE_RSP;
	rsp_ev.error = ret;
	ret = cifsd_usendmsg(&rsp_ev, cifsstat_pid, strlen(buf), buf);
	if (ret)
		cifsd_err(" share list respond failed, err %d\n", ret);

	kfree(buf);
	return ret;
}

static int cifsd_common_pipe_rsp(struct nlmsghdr *nlh)
{
	struct cifsd_sess *sess;
	struct cifsd_uevent *ev;
	struct cifsd_pipe *pipe_desc;

	ev = nlmsg_data(nlh);
	if (unlikely(ev->pipe_type >= MAX_PIPE)) {
		cifsd_err("invalid pipe type %u\n", ev->pipe_type);
		return -EINVAL;
	}

	sess = validate_sess_handle(cifsd_ptr(ev->conn_handle));
	if (unlikely(!sess)) {
		cifsd_err("invalid session handle\n");
		return -EINVAL;
	}

	pipe_desc = sess->pipe_desc[ev->pipe_type];
	if (unlikely(!pipe_desc)) {
		cifsd_err("invalid pipe descriptor\n");
		return -EINVAL;
	}

	if (unlikely(ev->error)) {
		cifsd_debug("pipe io failed, err %d\n", ev->error);
		goto out;
	}

	if (unlikely(ev->buflen > NETLINK_CIFSD_MAX_PAYLOAD)) {
		cifsd_err("too big response buffer %u\n", ev->buflen);
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

static int cifsd_notify_rsp(struct nlmsghdr *nlh)
{
	struct cifsd_sess *sess;
	struct cifsd_uevent *ev;
	struct smb2_inotify_res_info *noti_info_res_buf;
	int inotify_res_size = sizeof(struct smb2_inotify_res_info);
	int file_noti_size = sizeof(struct FileNotifyInformation);

	ev = nlmsg_data(nlh);
	sess = validate_sess_handle(cifsd_ptr(ev->conn_handle));
	if (unlikely(!sess)) {
		cifsd_err("invalid session handle\n");
		return -EINVAL;
	}
	noti_info_res_buf = (struct smb2_inotify_res_info *)ev->buffer;

	cifsd_debug("noti_info_res_buf->file_notify_info[0].Action : %d\n",
		noti_info_res_buf->file_notify_info[0].Action);

	sess->inotify_res = kmalloc(inotify_res_size
		+ file_noti_size + NAME_MAX,
		GFP_KERNEL);
	memcpy(sess->inotify_res, noti_info_res_buf,
		inotify_res_size + file_noti_size + NAME_MAX);

	if (!sess->inotify_res)
		return -ENOMEM;

	sess->ev_state = NETLINK_REQ_RECV;
	wake_up_interruptible(&sess->notify_q);

	return 0;
}

static int cifsd_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;

	cifsd_debug("received (%u) event from (pid %u)\n",
			nlh->nlmsg_type, nlh->nlmsg_pid);

	switch (nlh->nlmsg_type) {
	case CIFSD_KEVENT_EARLY_INIT:
		err = cifsd_early_init(nlh);
		break;
	case CIFSD_KEVENT_CONFIG_USER:
		err = cifsd_config_user(nlh);
		break;
	case CIFSD_KEVENT_CONFIG_SHARE:
		err = cifsd_config_share(nlh);
		break;
	case CIFSD_UEVENT_INIT_CONNECTION:
		err = cifsd_init_connection(nlh);
		if (!err) {
			/* No old cifsd task exists */
			err = cifsd_tcp_init(nlh->nlmsg_pid);
			if (err)
				cifsd_err("unable to open SMB PORT\n");
		}
		break;
	case CIFSD_UEVENT_EXIT_CONNECTION:
		cifsd_tcp_destroy();
		err = cifsd_exit_connection(nlh);
		break;
	case CIFSD_UEVENT_READ_PIPE_RSP:
	case CIFSD_UEVENT_WRITE_PIPE_RSP:
	case CIFSD_UEVENT_IOCTL_PIPE_RSP:
	case CIFSD_UEVENT_LANMAN_PIPE_RSP:
		err = cifsd_common_pipe_rsp(nlh);
		break;
	case CIFSD_UEVENT_INOTIFY_RESPONSE:
		err = cifsd_notify_rsp(nlh);
		break;
	case CIFSADMIN_UEVENT_INIT_CONNECTION:
		err = cifsadmin_init_connection(nlh);
		break;
	case CIFSADMIN_KEVENT_QUERY_USER:
		err = cifsadmin_query_user(nlh);
		break;
	case CIFSADMIN_KEVENT_REMOVE_USER:
		err = cifsadmin_remove_user(nlh);
		break;
	case CIFSADMIN_KEVENT_KERNEL_DEBUG:
		err = cifsd_kernel_debug(nlh);
		break;
	case CIFSADMIN_KEVENT_CASELESS_SEARCH:
		err = cifsd_kernel_caseless_search(nlh);
		break;
	case CIFSSTAT_UEVENT_INIT_CONNECTION:
		err = cifsstat_init_connection(nlh);
		break;
	case CIFSSTAT_UEVENT_READ_STAT:
		err = cifsd_stat_read(nlh);
		break;
	case CIFSSTAT_UEVENT_LIST_USER:
		err = cifsd_userlist(nlh);
		break;
	case CIFSSTAT_UEVENT_LIST_SHARE:
		err = cifsd_sharelist(nlh);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static void cifsd_netlink_rcv(struct sk_buff *skb)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return;

	mutex_lock(&nlsk_mutex);
	while (skb->len >= NLMSG_HDRLEN) {
		int err;
		unsigned int rlen;
		struct nlmsghdr	*nlh;
		struct cifsd_uevent *ev;

		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) ||
				skb->len < nlh->nlmsg_len) {
			break;
		}

		ev = nlmsg_data(nlh);
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		err = cifsd_if_recv_msg(skb, nlh);
		skb_pull(skb, rlen);
	}
	mutex_unlock(&nlsk_mutex);
}

int cifsd_net_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input  = cifsd_netlink_rcv,
	};

	cifsd_nlsk = netlink_kernel_create(&init_net, NETLINK_CIFSD, &cfg);
	if (unlikely(!cifsd_nlsk)) {
		cifsd_err("failed to create cifsd netlink socket\n");
		return -ENOMEM;
	}

	return 0;
}

void cifsd_net_exit(void)
{
	netlink_kernel_release(cifsd_nlsk);
}

