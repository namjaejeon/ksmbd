// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef _LINUX_CIFSD_SERVER_H
#define _LINUX_CIFSD_SERVER_H

#include <linux/types.h>

#define CIFSD_GENL_NAME      "CIFSD_GENL"
#define CIFSD_GENL_VERSION    0x01

#ifndef __align
#define __align		__attribute__((__aligned__(4)))
#endif

#define CIFSD_REQ_MAX_ACCOUNT_NAME_SZ	48
#define CIFSD_REQ_MAX_HASH_SZ		18
#define CIFSD_REQ_MAX_SHARE_NAME	64

struct cifsd_heartbeat {
	__u32	handle;
} __align;

struct cifsd_startup_request {
	__s32	signing;
	__s8	min_prot[16];
	__s8	max_prot[16];
	__s8	netbios_name[16];
	__s8	work_group[64];
	__s8	server_string[64];
	__u16	tcp_port;
	__u16	ipc_timeout;
} __align;

struct cifsd_shutdown_request {
	__s32	reserved;
} __align;

struct cifsd_login_request {
	__u32	handle;
	__s8	account[CIFSD_REQ_MAX_ACCOUNT_NAME_SZ];
} __align;

struct cifsd_login_response {
	__u32	handle;
	__u32	gid;
	__u32	uid;
	__s8	account[CIFSD_REQ_MAX_ACCOUNT_NAME_SZ];
	__u16	status;
	__u16	hash_sz;
	__s8	hash[CIFSD_REQ_MAX_HASH_SZ];
} __align;

struct cifsd_share_config_request {
	__u32	handle;
	__s8	share_name[CIFSD_REQ_MAX_SHARE_NAME];
} __align;

struct cifsd_share_config_response {
	__u32	handle;
	__u32	flags;
	__u32	veto_list_sz;
	__s8	____payload[0];
} __align;

#define CIFSD_SHARE_CONFIG_VETO_LIST(s)	((s)->____payload)
#define CIFSD_SHARE_CONFIG_PATH(s)				\
	({							\
		char *p = (s)->____payload;			\
		if ((s)->veto_list_sz)				\
			p += (s)->veto_list_sz + 1;		\
		p;						\
	 })

struct cifsd_tree_connect_request {
	__u32	handle;
	__u16	account_flags;
	__u16	flags;
	__u64	session_id;
	__u64	connect_id;
	__s8	account[CIFSD_REQ_MAX_ACCOUNT_NAME_SZ];
	__s8	share[CIFSD_REQ_MAX_SHARE_NAME];
	__s8	peer_addr[64];
} __align;

struct cifsd_tree_connect_response {
	__u32	handle;
	__u16	status;
	__u16	connection_flags;
} __align;

struct cifsd_tree_disconnect_request {
	__u64	session_id;
	__u64	connect_id;
} __align;

struct cifsd_logout_request {
	__s8	account[CIFSD_REQ_MAX_ACCOUNT_NAME_SZ];
} __align;

struct cifsd_rpc_command {
	__u32	handle;
	__u32	flags;
	__u32	payload_sz;
	__u8	payload[0];
};

/*
 * This also used as NETLINK attribute type value.
 *
 * NOTE:
 * Response message type value should be equal to
 * request message type value + 1.
 */
enum cifsd_event {
	CIFSD_EVENT_UNSPEC			= 0,
	CIFSD_EVENT_HEARTBEAT_REQUEST,

	CIFSD_EVENT_STARTING_UP,
	CIFSD_EVENT_SHUTTING_DOWN,

	CIFSD_EVENT_LOGIN_REQUEST,
	CIFSD_EVENT_LOGIN_RESPONSE		= 5,

	CIFSD_EVENT_SHARE_CONFIG_REQUEST,
	CIFSD_EVENT_SHARE_CONFIG_RESPONSE,

	CIFSD_EVENT_TREE_CONNECT_REQUEST,
	CIFSD_EVENT_TREE_CONNECT_RESPONSE,

	CIFSD_EVENT_TREE_DISCONNECT_REQUEST	= 10,

	CIFSD_EVENT_LOGOUT_REQUEST,

	CIFSD_EVENT_RPC_REQUEST,
	CIFSD_EVENT_RPC_RESPONSE,

	CIFSD_EVENT_MAX
};

enum CIFSD_TREE_CONN_STATUS {
	CIFSD_TREE_CONN_STATUS_OK		= 0,
	CIFSD_TREE_CONN_STATUS_NOMEM,
	CIFSD_TREE_CONN_STATUS_NO_SHARE,
	CIFSD_TREE_CONN_STATUS_NO_USER,
	CIFSD_TREE_CONN_STATUS_INVALID_USER,
	CIFSD_TREE_CONN_STATUS_HOST_DENIED	= 5,
	CIFSD_TREE_CONN_STATUS_CONN_EXIST,
	CIFSD_TREE_CONN_STATUS_TOO_MANY_CONNS,
	CIFSD_TREE_CONN_STATUS_TOO_MANY_SESSIONS,
	CIFSD_TREE_CONN_STATUS_ERROR,
};

/*
 * User config flags.
 */
#define CIFSD_USER_FLAG_INVALID		(0)
#define CIFSD_USER_FLAG_OK		(1 << 0)
#define CIFSD_USER_FLAG_BAD_PASSWORD	(1 << 1)
#define CIFSD_USER_FLAG_BAD_UID		(1 << 2)
#define CIFSD_USER_FLAG_BAD_USER	(1 << 3)
#define CIFSD_USER_FLAG_ANONYMOUS	(1 << 4)
#define CIFSD_USER_FLAG_GUEST_ACCOUNT	(1 << 5)

/*
 * Share config flags.
 */
#define CIFSD_SHARE_FLAG_INVALID		(0)
#define CIFSD_SHARE_FLAG_AVAILABLE		(1 << 0)
#define CIFSD_SHARE_FLAG_BROWSEABLE		(1 << 1)
#define CIFSD_SHARE_FLAG_WRITEABLE		(1 << 2)
#define CIFSD_SHARE_FLAG_READONLY		(1 << 3)
#define CIFSD_SHARE_FLAG_GUEST_OK		(1 << 4)
#define CIFSD_SHARE_FLAG_GUEST_ONLY		(1 << 5)
#define CIFSD_SHARE_FLAG_STORE_DOS_ATTRS	(1 << 6)
#define CIFSD_SHARE_FLAG_OPLOCKS		(1 << 7)
#define CIFSD_SHARE_FLAG_PIPE			(1 << 8)

/*
 * Tree connect request flags.
 */
#define CIFSD_TREE_CONN_FLAG_REQUEST_SMB1	(0)
#define CIFSD_TREE_CONN_FLAG_REQUEST_IPV6	(1 << 0)
#define CIFSD_TREE_CONN_FLAG_REQUEST_SMB2	(1 << 1)

/*
 * Tree connect flags.
 */
#define CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT	(1 << 0)
#define CIFSD_TREE_CONN_FLAG_READ_ONLY		(1 << 1)
#define CIFSD_TREE_CONN_FLAG_WRITABLE		(1 << 2)
#define CIFSD_TREE_CONN_FLAG_ADMIN_ACCOUNT	(1 << 3)

/*
 * RPC over IPC defines
 */
#define CIFSD_RPC_METHOD_RETURN		(1 << 0)
#define CIFSD_RPC_RAP_METHOD		(1 << 1 | CIFSD_RPC_METHOD_RETURN)
#define CIFSD_RPC_SRVSVC_METHOD_INVOKE	(1 << 2)
#define CIFSD_RPC_SRVSVC_METHOD_RETURN	(1 << 2 | CIFSD_RPC_METHOD_RETURN)
#define CIFSD_RPC_WKSSVC_METHOD_INVOKE	(1 << 3)
#define CIFSD_RPC_WKSSVC_METHOD_RETURN	(1 << 3 | CIFSD_RPC_METHOD_RETURN)
#define CIFSD_RPC_IOCTL_METHOD		(1 << 4 | CIFSD_RPC_METHOD_RETURN)
#define CIFSD_RPC_OPEN_METHOD		(1 << 5)
#define CIFSD_RPC_WRITE_METHOD		(1 << 6)
#define CIFSD_RPC_READ_METHOD		(1 << 7 | CIFSD_RPC_METHOD_RETURN)
#define CIFSD_RPC_CLOSE_METHOD		(1 << 8)

#define CIFSD_RPC_OK			0
#define CIFSD_RPC_EBAD_FUNC		0x00000001
#define CIFSD_RPC_EBAD_FID		0x00000006
#define CIFSD_RPC_ENOMEM		0x00000008
#define CIFSD_RPC_EBAD_DATA		0x0000000D
#define CIFSD_RPC_ENOTIMPLEMENTED	0x00000040
#define CIFSD_RPC_EMORE_DATA		0x000000EA
#define CIFSD_RPC_EINVALID_LEVEL	0x0000007C

#define CIFSD_CONFIG_OPT_DISABLED	0
#define CIFSD_CONFIG_OPT_ENABLED	1
#define CIFSD_CONFIG_OPT_AUTO		2
#define CIFSD_CONFIG_OPT_MANDATORY	3

#endif /* _LINUX_CIFSD_SERVER_H */
