// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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
#include "fh.h"
#include <crypto/hash.h>
#include "smberr.h"

/* @FIXME clean up this code */

extern int cifsd_debugging;
extern int cifsd_caseless_search;
extern bool oplocks_enable;
extern bool lease_enable;
extern bool durable_enable;
extern bool multi_channel_enable;
extern unsigned int alloc_roundup_size;
extern struct fidtable_desc global_fidtable;
extern char *netbios_name;

extern struct list_head global_lock_list;

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

struct smb_version_values {
	char            *version_string;
	__u16           protocol_id;
	__u32           req_capabilities;
	__u32           large_lock_type;
	__u32           exclusive_lock_type;
	__u32           shared_lock_type;
	__u32           unlock_lock_type;
	size_t          header_size;
	size_t          max_header_size;
	size_t          read_rsp_size;
	__le16          lock_cmd;
	unsigned int    cap_unix;
	unsigned int    cap_nt_find;
	unsigned int    cap_large_files;
	__u16           signing_enabled;
	__u16           signing_required;
	size_t          create_lease_size;
	size_t          create_durable_size;
	size_t          create_durable_v2_size;
	size_t          create_mxac_size;
	size_t          create_disk_id_size;
};

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
	/* List head at conn->requests */
	struct list_head		request_entry;

	/* Pointer to received SMB header */
	char				*request_buf;
	/* Response buffer */
	char				*response_buf;
	unsigned int			response_sz;

	struct cifsd_session		*sess;
	struct cifsd_tree_connect	*tcon;
	__u64				cur_local_sess_id;

	/* Read data buffer */
	char				*aux_payload_buf;
	/* Read data count */
	unsigned int			aux_payload_sz;
	/* response smb header size */
	unsigned int			resp_hdr_sz;

	/* Transform header buffer */
	void				*tr_buf;

	struct work_struct		work;

	int				type;
	/* Workers waiting on reply from this connection */
	struct list_head		qhead;

	int next_smb2_rcv_hdr_off;	/* Next cmd hdr in compound req buf*/
	int next_smb2_rsp_hdr_off;	/* Next cmd hdr in compound rsp buf*/
	/*
	 * Current Local FID assigned compound response if SMB2 CREATE
	 * command is present in compound request
	 */
	__u64				cur_local_fid;
	__u64				cur_local_pfid;

	/* Multiple responses for one request e.g. SMB ECHO */
	bool multiRsp:1;
	/* Both received */
	bool				multiEnd:1;
	/* No response for cancelled request */
	bool				send_no_response:1;
	/* On the conn->requests list */
	bool				on_request_list:1;

	/* smb command code */
	__le16				command;

	int				state;

	/* cancel works */
	uint64_t			async_id;
	void				**cancel_argv;
	void				(*cancel_fn)(void **argv);
	struct list_head		fp_entry;
	struct list_head		interim_entry;

	/* request is encrypted or not */
	bool				encrypted;
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

struct smb_version_ops {
	int (*get_cmd_val)(struct cifsd_work *swork);
	int (*init_rsp_hdr)(struct cifsd_work *swork);
	void (*set_rsp_status)(struct cifsd_work *swork, unsigned int err);
	int (*allocate_rsp_buf)(struct cifsd_work *work);
	void (*set_rsp_credits)(struct cifsd_work *swork);
	int (*check_user_session)(struct cifsd_work *work);
	int (*get_cifsd_tcon)(struct cifsd_work *work);
	int (*is_sign_req)(struct cifsd_work *work, unsigned int command);
	int (*check_sign_req)(struct cifsd_work *work);
	void (*set_sign_rsp)(struct cifsd_work *work);
	int (*generate_signingkey)(struct cifsd_session *sess, bool binding,
		char *hash_value);
	int (*generate_encryptionkey)(struct cifsd_session *sess);
	int (*is_transform_hdr)(void *buf);
	int (*decrypt_req)(struct cifsd_work *work);
	int (*encrypt_resp)(struct cifsd_work *work);
};

struct smb_version_cmds {
	int (*proc)(struct cifsd_work *swork);
};

struct cifsd_dir_info {
	char *name;
	char *bufptr;
	int out_buf_len;
	int num_entry;
	int data_count;
	int last_entry_offset;
};

struct cifsd_pid_info {
	struct socket *socket;
	__u32 cifsd_pid;
};

#define cifsd_debug(fmt, ...)					\
	do {							\
		if (cifsd_debugging)				\
			pr_err("kcifsd: %s:%d: " fmt,		\
			__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define cifsd_info(fmt, ...) pr_info("kcifsd: " fmt, ##__VA_ARGS__)

#define cifsd_err(fmt, ...) pr_err("kcifsd: %s:%d: " fmt,	\
			__func__, __LINE__, ##__VA_ARGS__)

static inline unsigned int
get_rfc1002_length(void *buf)
{
	return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

static inline void
inc_rfc1001_len(void *buf, int count)
{
	be32_add_cpu((__be32 *)buf, count);
}

/* misc functions */
#define NTFS_TIME_OFFSET ((u64)(369*365 + 89) * 24 * 3600 * 10000000)
#define UNICODE_LEN(x)	((x) * 2)

/* Convert the Unix UTC into NT UTC. */
static inline u64
cifs_UnixTimeToNT(struct timespec t)
{
	/* Convert to 100ns intervals and then add the NTFS time offset. */
	return (u64) t.tv_sec * 10000000 + t.tv_nsec/100 + NTFS_TIME_OFFSET;
}

static inline struct timespec
cifs_NTtimeToUnix(__le64 ntutc)
{
	struct timespec ts;
	/* Subtract the NTFS time offset, then convert to 1s intervals. */
	u64 t;

	t = le64_to_cpu(ntutc) - NTFS_TIME_OFFSET;
	ts.tv_nsec = do_div(t, 10000000) * 100;
	ts.tv_sec = t;
	return ts;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static inline struct timespec64 to_kern_timespec(struct timespec ts)
{
	return timespec_to_timespec64(ts);
}

static inline struct timespec from_kern_timespec(struct timespec64 ts)
{
	return timespec64_to_timespec(ts);
}
#else
#define to_kern_timespec(ts) (ts)
#define from_kern_timespec(ts) (ts)
#endif

/* @FIXME clean up this code */
/* @FIXME clean up this code */
/* @FIXME clean up this code */

/* cifsd misc functions */
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);
extern int smb_check_delete_pending(struct file *filp,
	struct cifsd_file *curr_fp);
#endif /* __CIFSD_GLOB_H */
