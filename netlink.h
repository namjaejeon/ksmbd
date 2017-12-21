/*
 *   fs/cifsd/netlink.h
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

#ifndef __CIFSD_NETLINK_H
#define __CIFSD_NETLINK_H

#define NETLINK_CIFSD_MAX_PAYLOAD	4096

#define NETLINK_REQ_INIT        0x00
#define NETLINK_REQ_SENT        0x01
#define NETLINK_REQ_RECV        0x02
#define NETLINK_REQ_COMPLETED   0x04

#define CIFSD_CODEPAGE_LEN	32
#define CIFSD_USERNAME_LEN	33

#ifdef IPV6_SUPPORTED
#define MAX_IPLEN 128
#else
#define MAX_IPLEN 16
#endif

enum cifsd_uevent_e {
	CIFSD_UEVENT_UNKNOWN            = 0,

	/* down events: userspace to kernel space */
	CIFSD_UEVENT_INIT_CONNECTION    = 10,
	CIFSD_UEVENT_READ_PIPE_RSP,
	CIFSD_UEVENT_WRITE_PIPE_RSP,
	CIFSD_UEVENT_IOCTL_PIPE_RSP,
	CIFSD_UEVENT_LANMAN_PIPE_RSP,
	CIFSD_UEVENT_EXIT_CONNECTION,
	CIFSD_UEVENT_INOTIFY_RESPONSE,
	CIFSD_UEVENT_CONFIG_USER_RSP,
	CIFSD_UEVENT_CONFIG_SHARE_RSP,

	CIFSADMIN_UEVENT_INIT_CONNECTION,
	CIFSADMIN_UEVENT_QUERY_USER_RSP,
	CIFSADMIN_UEVENT_REMOVE_USER_RSP,
	CIFSADMIN_UEVENT_KERNEL_DEBUG_RSP,
	CIFSADMIN_UEVENT_CASELESS_SEARCH_RSP,

	CIFSSTAT_UEVENT_INIT_CONNECTION,
	CIFSSTAT_UEVENT_READ_STAT,
	CIFSSTAT_UEVENT_LIST_USER,
	CIFSSTAT_UEVENT_LIST_SHARE,
	CIFSSTAT_UEVENT_READ_STAT_RSP,
	CIFSSTAT_UEVENT_LIST_USER_RSP,
	CIFSSTAT_UEVENT_LIST_SHARE_RSP,

	/* up events: kernel space to userspace */
	CIFSD_KEVENT_CREATE_PIPE     = 100,
	CIFSD_KEVENT_READ_PIPE,
	CIFSD_KEVENT_WRITE_PIPE,
	CIFSD_KEVENT_IOCTL_PIPE,
	CIFSD_KEVENT_LANMAN_PIPE,
	CIFSD_KEVENT_DESTROY_PIPE,
	CFISD_KEVENT_USER_DAEMON_EXIST,
	CIFSD_KEVENT_INOTIFY_REQUEST,
	CIFSD_KEVENT_EARLY_INIT,
	CIFSD_KEVENT_CONFIG_USER,
	CIFSD_KEVENT_CONFIG_SHARE,

	CIFSADMIN_KEVENT_QUERY_USER,
	CIFSADMIN_KEVENT_REMOVE_USER,
	CIFSADMIN_KEVENT_KERNEL_DEBUG,
	CIFSADMIN_KEVENT_CASELESS_SEARCH
};

struct cifsd_uevent {
	unsigned int	type; /* k/u events type */
	int		error; /* carries interface or resource errors */
	__u64		conn_handle;
	unsigned int	buflen;
	unsigned int	pipe_type;
	char codepage[CIFSD_CODEPAGE_LEN];

	union {
		/* messages u -> k */
		unsigned int	nt_status;
		struct msg_init_conn {
			unsigned int	unused;
		} i_conn;
		struct msg_exit_conn {
			unsigned int	unused;
		} e_conn;
		struct msg_read_pipe_response {
			unsigned int	read_count;
		} r_pipe_rsp;
		struct msg_write_pipe_response {
			unsigned int	write_count;
		} w_pipe_rsp;
		struct msg_ioctl_pipe_response {
			unsigned int	data_count;
		} i_pipe_rsp;
		struct msg_lanman_pipe_response {
			unsigned int	data_count;
			unsigned int	param_count;
		} l_pipe_rsp;
		struct msg_user_query_response {
			unsigned int    unused;
		} u_query_rsp;
		struct msg_user_del_response {
			unsigned int    unused;
		} u_del_rsp;
		struct msg_read_stat_response {
			unsigned int	unused;
		} r_stat_rsp;
	} u;

	union {
		/* messages k -> u */
		struct msg_create_pipe {
			__u64		id;
			char	codepage[CIFSD_CODEPAGE_LEN];
		} c_pipe;
		struct msg_destroy_pipe {
			__u64		id;
		} d_pipe;
		struct msg_read_pipe {
			__u64		id;
			unsigned int	out_buflen;
		} r_pipe;
		struct msg_write_pipe {
			__u64		id;
		} w_pipe;
		struct msg_ioctl_pipe {
			__u64		id;
			unsigned int	out_buflen;
		} i_pipe;
		struct msg_lanman_pipe {
			unsigned int	out_buflen;
			char	codepage[CIFSD_CODEPAGE_LEN];
			char	username[CIFSD_USERNAME_LEN];
		} l_pipe;
		struct msg_user_query {
			char    username[CIFSD_USERNAME_LEN];
		} u_query;
		struct msg_user_del {
			char    username[CIFSD_USERNAME_LEN];
		} u_del;
		struct msg_read_stat {
			__u64           flag;
			char    statip[MAX_IPLEN];
		} r_stat;
	} k;
	char buffer[0];
};

#endif /* __CIFSD_NETLINK_H */
