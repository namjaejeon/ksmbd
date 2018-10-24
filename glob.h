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
 *  * max peer IPv4/IPv6 addr size (including '\0')
 *   */
#ifdef IPV6_SUPPORTED
#define MAX_ADDRBUFLEN 128
#else
#define MAX_ADDRBUFLEN 16
#endif

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
#define CIFS_HMAC_MD5_HASH_SIZE (16)
#define CIFS_NTHASH_SIZE (16)

#define HEADER_SIZE(conn) ((conn)->vals->header_size)
#define HEADER_SIZE_NO_BUF_LEN(conn) ((conn)->vals->header_size - 4)
#define MAX_HEADER_SIZE(conn) ((conn)->vals->max_header_size)

/* CreateOptions */
/* flag is set, it must not be a file , valid for directory only */
#define FILE_DIRECTORY_FILE_LE	cpu_to_le32(0x00000001)
#define FILE_WRITE_THROUGH_LE	cpu_to_le32(0x00000002)
#define FILE_SEQUENTIAL_ONLY_LE	cpu_to_le32(0x00000004)
/* Should not buffer on server*/
#define FILE_NO_INTERMEDIATE_BUFFERING_LE	cpu_to_le32(0x00000008)
#define FILE_SYNCHRONOUS_IO_ALERT_LE	cpu_to_le32(0x00000010)      /* MBZ */
#define FILE_SYNCHRONOUS_IO_NONALERT_LE	cpu_to_le32(0x00000020)      /* MBZ */
/* Flaf must not be set for directory */
#define FILE_NON_DIRECTORY_FILE_LE	cpu_to_le32(0x00000040)
/* should be zero */
#define CREATE_TREE_CONNECTION		cpu_to_le32(0x00000080)
#define FILE_COMPLETE_IF_OPLOCKED_LE	cpu_to_le32(0x00000100)
#define FILE_NO_EA_KNOWLEDGE_LE		cpu_to_le32(0x00000200)
#define FILE_OPEN_REMOTE_INSTANCE	cpu_to_le32(0x00000400)
/* doc says this is obsolete "open for recovery" flag
	should be zero in any case */
#define CREATE_OPEN_FOR_RECOVERY	cpu_to_le32(0x00000400)
#define FILE_RANDOM_ACCESS_LE		cpu_to_le32(0x00000800)
#define FILE_DELETE_ON_CLOSE_LE		cpu_to_le32(0x00001000)
#define FILE_OPEN_BY_FILE_ID_LE		cpu_to_le32(0x00002000)
#define FILE_OPEN_FOR_BACKUP_INTENT_LE	cpu_to_le32(0x00004000)
#define FILE_NO_COMPRESSION_LE		cpu_to_le32(0x00008000)
/* should be zero*/
#define FILE_OPEN_REQUIRING_OPLOCK	cpu_to_le32(0x00010000)
#define FILE_DISALLOW_EXCLUSIVE		cpu_to_le32(0x00020000)
#define FILE_RESERVE_OPFILTER_LE	cpu_to_le32(0x00100000)
#define FILE_OPEN_REPARSE_POINT_LE	cpu_to_le32(0x00200000)
#define FILE_OPEN_NO_RECALL_LE          cpu_to_le32(0x00400000)
/* should be zero */
#define FILE_OPEN_FOR_FREE_SPACE_QUERY_LE   cpu_to_le32(0x00800000)
#define CREATE_OPTIONS_MASK     0x00FFFFFF
#define CREATE_OPTION_READONLY  0x10000000
#define CREATE_OPTION_SPECIAL   0x20000000   /* system. NB not sent over wire */

/* SMB2 Max Credits */
#define SMB2_MAX_CREDITS 8192

#define SMB2_CLIENT_GUID_SIZE		16
#define SMB2_CREATE_GUID_SIZE		16

/* SMB2 timeouts */
#define SMB_ECHO_INTERVAL		(60*HZ) /* 60 msecs */

/* CREATION TIME XATTR PREFIX */
#define CREATION_TIME_PREFIX	"creation.time."
#define CREATION_TIME_PREFIX_LEN	(sizeof(CREATION_TIME_PREFIX) - 1)
#define CREATIOM_TIME_LEN		(sizeof(__u64))
#define XATTR_NAME_CREATION_TIME	(XATTR_USER_PREFIX CREATION_TIME_PREFIX)
#define XATTR_NAME_CREATION_TIME_LEN	(sizeof(XATTR_NAME_CREATION_TIME) - 1)

/* STREAM XATTR PREFIX */
#define STREAM_PREFIX	"stream."
#define STREAM_PREFIX_LEN	(sizeof(STREAM_PREFIX) - 1)
#define XATTR_NAME_STREAM	(XATTR_USER_PREFIX STREAM_PREFIX)
#define XATTR_NAME_STREAM_LEN	(sizeof(XATTR_NAME_STREAM) - 1)

/* FILE ATTRIBUITE XATTR PREFIX */
#define FILE_ATTRIBUTE_PREFIX   "file.attribute."
#define FILE_ATTRIBUTE_PREFIX_LEN   (sizeof(FILE_ATTRIBUTE_PREFIX) - 1)
#define FILE_ATTRIBUTE_LEN      (sizeof(__u32))
#define XATTR_NAME_FILE_ATTRIBUTE   (XATTR_USER_PREFIX FILE_ATTRIBUTE_PREFIX)
#define XATTR_NAME_FILE_ATTRIBUTE_LEN \
	(sizeof(XATTR_USER_PREFIX FILE_ATTRIBUTE_PREFIX) - 1)

/* MAXIMUM KMEM DATA SIZE ORDER */
#define PAGE_ALLOC_KMEM_ORDER	2

#define XATTR_NAME_DEFAULT_DATA_STREAM (XATTR_USER_PREFIX DEF_DATA_STREAM_TYPE)
#define XATTR_NAME_DEFAULT_DIR_STREAM (XATTR_USER_PREFIX DEF_DIR_STREAM_TYPE)

#define DATA_STREAM	1
#define DIR_STREAM	2

/* Security Descriptor XATTR PREFIX */
#define SD_NTSD_PREFIX	"sd.ntsd"
#define SD_NTSD_PREFIX_LEN	(sizeof(SD_NTSD_PREFIX) - 1)
#define XATTR_NAME_SD_NTSD	(XATTR_USER_PREFIX SD_NTSD_PREFIX)
#define XATTR_NAME_SD_NTSD_LEN	(sizeof(XATTR_NAME_SD_NTSD) - 1)

#define SD_OWNER_PREFIX	"sd.OwnerSid"
#define SD_OWNER_PREFIX_LEN	(sizeof(SD_OWNER_PREFIX) - 1)
#define XATTR_NAME_SD_OWNER	(XATTR_USER_PREFIX SD_OWNER_PREFIX)
#define XATTR_NAME_SD_OWNER_LEN	(sizeof(XATTR_NAME_SD_OWNER) - 1)

#define SD_GROUP_PREFIX	"sd.GroupSid"
#define SD_GROUP_PREFIX_LEN	(sizeof(SD_GROUP_PREFIX) - 1)
#define XATTR_NAME_SD_GROUP	(XATTR_USER_PREFIX SD_GROUP_PREFIX)
#define XATTR_NAME_SD_GROUP_LEN	(sizeof(XATTR_NAME_SD_GROUP) - 1)

#define SD_DACL_PREFIX	"sd.dacl"
#define SD_DACL_PREFIX_LEN	(sizeof(SD_DACL_PREFIX) - 1)
#define XATTR_NAME_SD_DACL	(XATTR_USER_PREFIX SD_DACL_PREFIX)
#define XATTR_NAME_SD_DACL_LEN	(sizeof(XATTR_NAME_SD_DACL) - 1)

/* crypto security descriptor definition */
struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

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
	long int avg_req_duration;
	long int max_timed_request;
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

struct FileNotifyInformation {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	__le16 FileName[];
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

bool is_smb_request(struct cifsd_tcp_conn *conn);
int get_nlink(struct kstat *st);

/* cifsd misc functions */
extern int check_message(struct cifsd_work *work);
extern void dump_smb_msg(void *buf, int smb_buf_length);
extern int switch_rsp_buf(struct cifsd_work *work);
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);
extern int get_pos_strnstr(const char *s1, const char *s2, size_t len);
extern int smb_check_delete_pending(struct file *filp,
	struct cifsd_file *curr_fp);
extern int smb_check_shared_mode(struct file *filp,
	struct cifsd_file *curr_fp);
extern int pattern_cmp(const char *string, const char *pattern);
extern bool is_matched(const char *fname, const char *exp);
extern int check_invalid_stream_char(char *stream_name);
extern int check_invalid_char(char *filename);
extern int parse_stream_name(char *filename, char **stream_name, int *s_type);
extern int construct_xattr_stream_name(char *stream_name,
	char **xattr_stream_name);
extern char *convert_to_nt_pathname(char *filename, char *sharepath);

/* functions */
extern void smb_delete_session(struct cifsd_session *sess);

extern int SMB_NTencrypt(unsigned char *, unsigned char *, unsigned char *,
		const struct nls_table *);
extern int smb_E_md4hash(const unsigned char *passwd, unsigned char *p16,
		const struct nls_table *codepage);
extern int E_P24(unsigned char *p21, const unsigned char *c8,
		unsigned char *p24);
extern int smb_mdfour(unsigned char *md4_hash, unsigned char *link_str,
		int link_len);
extern int update_sess_key(unsigned char *md5_hash, char *nonce,
	char *server_challenge, int len);

/* trans2 functions */
struct cifsd_share_config;
char *convert_to_unix_name(struct cifsd_share_config *share, char *name);
void convert_delimiter(char *path, int flags);
/* fill SMB specific fields when smb2 query dir is requested */
char *convname_updatenextoffset(char *namestr, int len, int size,
		const struct nls_table *local_nls, int *name_len,
		int *next_entry_offset, int *buf_len, int *data_count,
		int alignment, bool no_namelen_field);

/* netlink functions */
int cifsd_net_init(void);
void cifsd_net_exit(void);
int cifsd_sendmsg(struct cifsd_session *sess, unsigned int etype,
		int pipe_type, unsigned int data_size,
		unsigned char *data, unsigned int out_buflen);
int cifsd_kthread_stop_status(int etype);

/* asn1 functions */
extern int cifsd_decode_negTokenInit(unsigned char *security_blob, int length,
		struct cifsd_tcp_conn *conn);
extern int cifsd_decode_negTokenTarg(unsigned char *security_blob, int length,
		struct cifsd_tcp_conn *conn);
extern int build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer, u16 *buflen,
		char *ntlm_blob, int ntlm_blob_len);
extern int build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer, u16 *buflen,
		int neg_result);

void smb3_preauth_hash_rsp(struct cifsd_work *work);
#endif /* __CIFSD_GLOB_H */
