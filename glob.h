// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_GLOB_H
#define __CIFSD_GLOB_H

#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/byteorder/generic.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/freezer.h>
#include <linux/workqueue.h>
#include <linux/ctype.h>
#include <linux/time.h>
#include <linux/nls.h>
#include <linux/unistd.h>
#include <linux/scatterlist.h>
#include <linux/statfs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <linux/vmalloc.h>
#include <uapi/linux/xattr.h>
#include <linux/hashtable.h>
#include "unicode.h"
#include "vfs_cache.h"
#include <crypto/hash.h>
#include "smberr.h"

/* @FIXME clean up this code */

extern int cifsd_debugging;
extern int cifsd_caseless_search;
extern bool oplocks_enable;
extern bool lease_enable;
extern bool durable_enable;
extern bool multi_channel_enable;

#define NETLINK_CIFSD_MAX_PAYLOAD	4096

/* cifsd's Specific ERRNO */
#define ESHARE 50000

#define LOCKING_ANDX_SHARED_LOCK     0x01
#define LOCKING_ANDX_OPLOCK_RELEASE  0x02
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x04
#define LOCKING_ANDX_CANCEL_LOCK     0x08
#define LOCKING_ANDX_LARGE_FILES     0x10

/*
 *  * Size of the ntlm client response
 *   */
#define CIFS_AUTH_RESP_SIZE (24)
#define CIFS_SMB1_SIGNATURE_SIZE (8)
#define CIFS_SMB1_SESSKEY_SIZE (16)

/*
 *  * Size of the session key (crypto key encrypted with the password
 *   */
#define SMB2_NTLMV2_SESSKEY_SIZE (16)
#define SMB2_SIGNATURE_SIZE (16)
#define SMB2_HMACSHA256_SIZE (32)
#define SMB2_CMACAES_SIZE (16)

/*
 *  * Size of the smb3 signing key
 *   */
#define SMB3_SIGN_KEY_SIZE (16)

#define CIFS_CLIENT_CHALLENGE_SIZE (8)
#define CIFS_SERVER_CHALLENGE_SIZE (8)

/* SMB2 Max Credits */
#define SMB2_MAX_CREDITS 8192

#define SMB2_CLIENT_GUID_SIZE		16
#define SMB2_CREATE_GUID_SIZE		16

/* SMB2 timeouts */
#define SMB_ECHO_INTERVAL		(60*HZ) /* 60 msecs */

/* MAXIMUM KMEM DATA SIZE ORDER */
#define PAGE_ALLOC_KMEM_ORDER	2

#define DATA_STREAM	1
#define DIR_STREAM	2

struct cifsd_stats {
	int open_files_count;
	int request_served;
};

enum asyncEnum {
	ASYNC_PROG = 1,
	ASYNC_CANCEL,
	ASYNC_CLOSE,
	ASYNC_EXITING,
};

#define SYNC 1
#define ASYNC 2

#define WORK_STATE_ENCRYPTED	0x1
#define	WORK_STATE_CANCELLED	0x2
#define WORK_STATE_CLOSED	0x3

struct cifsd_tcp_conn;

/* one of these for every pending CIFS request at the connection */
struct cifsd_work {
	/* Server corresponding to this mid */
	struct cifsd_tcp_conn		*conn;
	struct cifsd_session		*sess;
	struct cifsd_tree_connect	*tcon;

	/* Pointer to received SMB header */
	char				*request_buf;
	/* Response buffer */
	char				*response_buf;
	unsigned int			response_sz;

	/* Read data buffer */
	char				*aux_payload_buf;
	/* Read data count */
	unsigned int			aux_payload_sz;
	/* response smb header size */
	unsigned int			resp_hdr_sz;

	/* Next cmd hdr in compound req buf*/
	int				next_smb2_rcv_hdr_off;
	/* Next cmd hdr in compound rsp buf*/
	int				next_smb2_rsp_hdr_off;

	/* Transform header buffer */
	void				*tr_buf;
	int				type;

	/*
	 * Current Local FID assigned compound response if SMB2 CREATE
	 * command is present in compound request
	 */
	unsigned int			compound_fid;
	unsigned int			compound_pfid;
	unsigned int			compound_sid;

	int				state;

	/* Multiple responses for one request e.g. SMB ECHO */
	bool				multiRsp:1;
	/* Both received */
	bool				multiEnd:1;
	/* No response for cancelled request */
	bool				send_no_response:1;
	/* On the conn->requests list */
	bool				on_request_list:1;
	/* Request is encrypted */
	bool				encrypted:1;

	/* smb command code */
	__le16				command;

	/* List head at conn->requests */
	struct list_head		request_entry;
	struct work_struct		work;

	/* cancel works */
	int				async_id;
	void				**cancel_argv;
	void				(*cancel_fn)(void **argv);
	struct list_head		fp_entry;
	struct list_head		interim_entry;
};

#define RESPONSE_BUF(w)		(void *)((w)->response_buf)
#define RESPONSE_SZ(w)		((w)->response_sz)

#define REQUEST_BUF(w)		(void *)((w)->request_buf)

#define INIT_AUX_PAYLOAD(w)	((w)->aux_payload_buf = NULL)
#define HAS_AUX_PAYLOAD(w)	((w)->aux_payload_sz != 0)
#define AUX_PAYLOAD(w)		(void *)((w)->aux_payload_buf)
#define AUX_PAYLOAD_SIZE(w)	((w)->aux_payload_sz)
#define RESP_HDR_SIZE(w)	((w)->resp_hdr_sz)

#define HAS_TRANSFORM_BUF(w)	((w)->tr_buf != NULL)
#define TRANSFORM_BUF(w)	(void *)((w)->tr_buf)

#define cifsd_debug(fmt, ...)					\
	do {							\
		if (cifsd_debugging)				\
			pr_err("kcifsd: %s:%d: " fmt,		\
			__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define cifsd_info(fmt, ...) pr_info("kcifsd: " fmt, ##__VA_ARGS__)

#define cifsd_err(fmt, ...) pr_err("kcifsd: %s:%d: " fmt,	\
			__func__, __LINE__, ##__VA_ARGS__)

static inline unsigned int get_rfc1002_length(void *buf)
{
	return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

static inline void inc_rfc1001_len(void *buf, int count)
{
	be32_add_cpu((__be32 *)buf, count);
}

#define UNICODE_LEN(x)		((x) * 2)

/* @FIXME clean up this code */
/* @FIXME clean up this code */
/* @FIXME clean up this code */

/* cifsd misc functions */
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);
#endif /* __CIFSD_GLOB_H */
