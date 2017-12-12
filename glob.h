/*
 *   fs/cifsd/glob.h
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
#include <linux/mempool.h>
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
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
#include <linux/vmalloc.h>
#include <uapi/linux/xattr.h>
#endif
#include <linux/hashtable.h>
#include "unicode.h"
#include "fh.h"
#include <crypto/hash.h>
#include "smberr.h"

extern struct kmem_cache *cifsd_work_cache;
extern struct kmem_cache *cifsd_filp_cache;
extern struct kmem_cache *cifsd_req_cachep;
extern mempool_t *cifsd_req_poolp;
extern struct kmem_cache *cifsd_sm_req_cachep;
extern mempool_t *cifsd_sm_req_poolp;
extern struct kmem_cache *cifsd_sm_rsp_cachep;
extern mempool_t *cifsd_sm_rsp_poolp;
extern struct kmem_cache *cifsd_rsp_cachep;
extern mempool_t *cifsd_rsp_poolp;
extern struct list_head oplock_info_list;

#define CIFS_MIN_RCV_POOL 4
extern unsigned int smb_min_rcv;
extern unsigned int smb_min_small;

extern int cifsd_debug_enable;
extern int cifsd_caseless_search;
extern bool oplocks_enable;
extern bool lease_enable;
extern bool durable_enable;
extern bool multi_channel_enable;
extern unsigned int alloc_roundup_size;
extern unsigned long server_start_time;
extern struct fidtable_desc global_fidtable;
extern char *netbios_name;
extern char NEGOTIATE_GSS_HEADER[74];

extern bool global_signing;

extern struct list_head global_lock_list;

/* cifsd's Specific ERRNO */
#define ESHARE 50000

#define SMB1_VERSION_STRING     "1.0"
#define SMB20_VERSION_STRING    "2.0"
#define SMB21_VERSION_STRING    "2.1"
#define SMB30_VERSION_STRING	"3.0"
#define SMB302_VERSION_STRING	"3.02"
#define SMB311_VERSION_STRING	"3.1.1"

/* Dialects */
#define SMB10_PROT_ID	0x00
#define SMB20_PROT_ID	0x0202
#define SMB21_PROT_ID	0x0210
#define SMB30_PROT_ID	0x0300
#define SMB302_PROT_ID	0x0302
#define SMB311_PROT_ID	0x0311
#define SMB2X_PROT_ID	0x02FF    /* multi-protocol negotiate request */
#define BAD_PROT_ID	0xFFFF

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
 *  * Size of encrypted user password in bytes
 *   */
#define CIFS_ENCPWD_SIZE (16)

/*
 *  * Size of the crypto key returned on the negotiate SMB in bytes
 *   */
#define CIFS_CRYPTO_KEY_SIZE (8)
#define CIFS_KEY_SIZE (40)

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
#define CIFS_CPHTXT_SIZE (16)
#define CIFS_NTHASH_SIZE (16)

/* We don't include wc in HEADER_SIZE */
#define HEADER_SIZE(conn) ((conn)->vals->header_size - 1)
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

enum statusEnum {
	CifsNew = 0,
	CifsGood,
	CifsExiting,
	CifsNeedReconnect,
	CifsNeedNegotiate
};

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
	size_t          create_mxac_size;
	size_t          create_disk_id_size;
};

struct cifsd_stats {
	int open_files_count;
	int request_served;
	long int avg_req_duration;
	long int max_timed_request;
};

/* per smb session structure/fields */
struct ntlmssp_auth {
	bool sesskey_per_smbsess; /* whether session key is per smb session */
	__u32 client_flags; /* sent by client in type 1 ntlmsssp exchange */
	__u32 conn_flags; /* sent by server in type 2 ntlmssp exchange */
	unsigned char ciphertext[CIFS_CPHTXT_SIZE]; /* sent to server */
	char cryptkey[CIFS_CRYPTO_KEY_SIZE]; /* used by ntlmssp */
};

/* crypto hashing related structure/fields, not specific to a sec mech */
struct cifs_secmech {
	struct crypto_shash *hmacmd5; /* hmac-md5 hash function */
	struct crypto_shash *md5; /* md5 hash function */
	struct crypto_shash *hmacsha256; /* hmac-sha256 hash function */
	struct crypto_shash *cmacaes; /* block-cipher based MAC function */
	struct crypto_shash *sha512; /* sha512 hash function */
	struct sdesc *sdeschmacmd5;  /* ctxt to generate ntlmv2 hash, CR1 */
	struct sdesc *sdescmd5; /* ctxt to generate cifs/smb signature */
	struct sdesc *sdeschmacsha256;  /* ctxt to generate smb2 signature */
	struct sdesc *sdesccmacaes;  /* ctxt to generate smb3 signature */
	struct sdesc *sdescsha512;  /* ctxt to generate preauth integrity */
};

struct channel {
	__u8 smb3signingkey[SMB3_SIGN_KEY_SIZE];
	struct connection *conn;
	struct list_head chann_list;
};

struct preauth_session {
	int SessionId;
	int HashId;
	int HashValue;
};

struct connection {
	struct socket *sock;
	unsigned short family;
	int srv_count; /* reference counter */
	int sess_count; /* number of sessions attached with this connection */
	struct smb_version_values   *vals;
	struct smb_version_ops		*ops;
	struct smb_version_cmds		*cmds;
	unsigned int    max_cmds;
	char *hostname;
	struct mutex srv_mutex;
	enum statusEnum tcp_status;
	__u16 cli_sec_mode;
	__u16 srv_sec_mode;
	bool sign;
	__u16 dialect; /* dialect index that server chose */
	bool oplocks:1;
	bool use_spnego:1;
	unsigned int maxReq;
	unsigned int cli_cap;
	unsigned int srv_cap;
	bool	need_neg;
	bool    large_buf;
	struct kvec *iov;
	unsigned int nr_iov;
	char    *smallbuf;
	char    *bigbuf;
	char    *wbuf;
	struct nls_table *local_nls;
	unsigned int total_read;
	/* This session will become part of global tcp session list */
	struct list_head tcp_sess;
	/* smb session 1 per user */
	struct list_head cifsd_sess;
	struct task_struct *handler;
	int th_id;
	__le16 vuid;
	int num_files_open;
	unsigned long last_active;
	struct timespec create_time;
	/* pending trans request table */
	struct trans_state *recent_trans;
	struct list_head trans_list;
	/* How many request are running currently */
	atomic_t req_running;
	/* References which are made for this Server object*/
	atomic_t r_count;
	wait_queue_head_t req_running_q;
	spinlock_t request_lock; /* lock to protect requests list*/
	struct list_head requests;
	struct list_head async_requests;
	int max_credits;
	int credits_granted;
	char peeraddr[MAX_ADDRBUFLEN];
	int connection_type;
	struct cifsd_stats stats;
	struct list_head list;
#ifdef CONFIG_CIFS_SMB2_SERVER
	char ClientGUID[SMB2_CLIENT_GUID_SIZE];
#endif
	struct cifs_secmech secmech;
	char ntlmssp_cryptkey[CIFS_CRYPTO_KEY_SIZE]; /* used by ntlmssp */

	int Preauth_HashId; /* PreAuth integrity Hash ID */
	__u8 Preauth_HashValue[64]; /* PreAuth integrity Hash Value */
	int CipherId;

	struct list_head p_sess_table;	/* PreAuthSession Table */
	bool sec_ntlmssp;		/* supports NTLMSSP */
	bool sec_kerberosu2u;		/* supports U2U Kerberos */
	bool sec_kerberos;		/* supports plain Kerberos */
	bool sec_mskerberos;		/* supports legacy MS Kerberos */
	char *mechToken;
};

struct trans_state {
	struct list_head trans_list;
	__le16		mid;
	__le16		uid;
	char		*rcv_buf;
	char		*rsp_buf;
	int		total_param;
	int		got_param;
	int		total_data;
	int		got_data;
};

enum asyncEnum {
	ASYNC_PROG = 1,
	ASYNC_CANCEL,
	ASYNC_CLOSE,
	ASYNC_EXITING,
};

struct async_info {
	__u64 async_id;	/* Async ID */
	struct	work_struct async_work;
	enum asyncEnum async_status;
	int fd;
	int wd;
};

#define SYNC 1
#define ASYNC 2

/* one of these for every pending CIFS request at the connection */
struct smb_work {
	int type;
	struct list_head qhead;		/* works waiting on reply
							from this connection */
	struct list_head request_entry;	/* list head at conn->requests */
	struct connection *conn; /* server corresponding to this mid */
	unsigned long when_alloc;	/* when mid was created */
	struct	work_struct work;
	/* mid_receive_t *receive; */	/* call receive callback */
	/* mid_callback_t *callback; */	/* call completion callback
							depends on command */
	char	*buf;			/* pointer to received SMB header */
	__le16 command;			/* smb command code */
	char *rdata_buf;		/* read data buffer */
	unsigned int rdata_cnt;		/* read data count */
	unsigned int rrsp_hdr_size;	/* read response smb header size */
	char *rsp_buf;			/* response buffer */
	int next_smb2_rcv_hdr_off;	/* Next cmd hdr in compound req buf*/
	int next_smb2_rsp_hdr_off;	/* Next cmd hdr in compound rsp buf*/
	__u64 cur_local_fid;		/* Current Local FID assigned compound
					   response if SMB2 CREATE command is
					   present in compound request*/
	__u64 cur_local_pfid;
	__u64 cur_local_sess_id;
	bool req_wbuf:1;		/* large write request */
	bool large_buf:1;		/* if valid response, is pointer
							to large buf */
	bool rsp_large_buf:1;
	bool multiRsp:1;		/* multiple responses
					   for one request e.g. SMB ECHO */
	bool multiEnd:1;		/* both received */
	bool send_no_response:1;	/* no response for cancelled request */
	bool added_in_request_list:1;	/* added in conn->requests list */

	struct cifsd_sess *sess;
	struct cifsd_tcon *tcon;

	struct async_info *async;
	struct list_head interim_entry;
};

struct smb_version_ops {
	int (*get_cmd_val)(struct smb_work *swork);
	int (*init_rsp_hdr)(struct smb_work *swork);
	void (*set_rsp_status)(struct smb_work *swork, unsigned int err);
	int (*allocate_rsp_buf)(struct smb_work *smb_work);
	void (*set_rsp_credits)(struct smb_work *swork);
	int (*check_user_session)(struct smb_work *work);
	int (*get_cifsd_tcon)(struct smb_work *smb_work);
	int (*is_sign_req)(struct smb_work *work, unsigned int command);
	int (*check_sign_req)(struct smb_work *work);
	void (*set_sign_rsp)(struct smb_work *work);
	int (*compute_signingkey)(struct cifsd_sess *sess,  __u8 *key,
		unsigned int key_size);
};

struct smb_version_cmds {
	int (*proc)(struct smb_work *swork);
};

struct cifsd_dir_info {
	char *name;
	char *bufptr;
	struct kstat kstat;
	int data_count;
	int out_buf_len;
	int num_entry;
};

/* cifsd kstat wrapper to get valid create time when reading dir entry */
struct smb_kstat {
	struct kstat *kstat;
	__u64 create_time;
	__le32 file_attributes;
};

struct smb2_fs_sector_size {
	unsigned short logical_sector_size;
	unsigned int physical_sector_size;
	unsigned int optimal_io_size;
};

struct cifsd_pid_info {
	struct socket *socket;
	__u32 cifsd_pid;
};

struct smb2_inotify_req_info {
	__le16 watch_tree_flag;
	__le32 CompletionFilter;
	__u32 path_len;
	char dir_path[];
};

struct FileNotifyInformation {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	__le16 FileName[];
};

struct smb2_inotify_res_info {
	__u32 output_buffer_length;
	struct FileNotifyInformation file_notify_info[];
};

#define cifsd_debug(fmt, ...)					\
	do {							\
		if (cifsd_debug_enable)				\
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
#define IS_SMB2(x) ((x)->vals->protocol_id != SMB10_PROT_ID)
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

char *
smb_get_name(const char *src, const int maxlen, struct smb_work *smb_work,
	bool converted);
void smb_put_name(void *name);
bool is_smb_request(struct connection *conn, unsigned char type);
int switch_req_buf(struct connection *conn);
int negotiate_dialect(void *buf);
struct cifsd_sess *lookup_session_on_server(struct connection *conn,
		uint64_t sess_id);

/* cifsd export functions */
extern int cifsd_export_init(void);
extern void cifsd_export_exit(void);

/* cifsd connect functions */
extern void terminate_old_forker_thread(void);
extern int cifsd_create_socket(__u32 cifsd_pid);
extern int cifsd_start_forker_thread(struct cifsd_pid_info *cisfd_pid_info);
extern void cifsd_stop_forker_thread(void);

extern void cifsd_close_socket(void);
extern int cifsd_stop_tcp_sess(void);

/* cifsd misc functions */
extern int check_smb_message(char *buf);
extern void add_request_to_queue(struct smb_work *smb_work);
extern void dump_smb_msg(void *buf, int smb_buf_length);
extern int switch_rsp_buf(struct smb_work *smb_work);
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);
extern struct cifsd_sess *validate_sess_handle(struct cifsd_sess *session);
extern int smb_store_cont_xattr(struct path *path, char *prefix, void *value,
	ssize_t v_len);
extern ssize_t smb_find_cont_xattr(struct path *path, char *prefix, int p_len,
	char **value, int flags);
extern int get_pos_strnstr(const char *s1, const char *s2, size_t len);
extern int smb_check_delete_pending(struct file *filp,
	struct cifsd_file *curr_fp);
extern int smb_check_shared_mode(struct file *filp,
	struct cifsd_file *curr_fp);
extern struct cifsd_file *find_fp_using_inode(struct inode *inode);
extern void remove_async_id(__u64 async_id);
extern char *alloc_data_mem(size_t size);
extern int pattern_cmp(const char *string, const char *pattern);
extern bool is_matched(const char *fname, const char *exp);
extern int check_invalid_stream_char(char *stream_name);
extern int check_invalid_char(char *filename);
extern int parse_stream_name(char *filename, char **stream_name, int *s_type);
extern int construct_xattr_stream_name(char *stream_name,
	char **xattr_stream_name);

/* smb vfs functions */
int smb_vfs_create(const char *name, umode_t mode);
int smb_vfs_mkdir(const char *name, umode_t mode);
int smb_vfs_read(struct cifsd_sess *sess, struct cifsd_file *fp,
	char **buf, size_t count, loff_t *pos);
int smb_vfs_write(struct cifsd_sess *sess, struct cifsd_file *fp,
	char *buf, size_t count, loff_t *pos, bool fsync, ssize_t *written);
int smb_vfs_getattr(struct cifsd_sess *sess, uint64_t fid,
		struct kstat *stat);
int smb_vfs_setattr(struct cifsd_sess *sess, const char *name,
		uint64_t fid, struct iattr *attrs);
int smb_vfs_fsync(struct cifsd_sess *sess, uint64_t fid, uint64_t p_id);
int smb_dentry_open(struct smb_work *work, const struct path *path,
		int flags, __u16 *fid, int *oplock, int option,
		int fexist);
int smb_vfs_remove_file(char *name);
int smb_vfs_link(const char *oldname, const char *newname);
int smb_vfs_symlink(const char *name, const char *symname);
int smb_vfs_readlink(struct path *path, char *buf, int len);
int smb_vfs_rename(struct cifsd_sess *sess, char *oldname,
		char *newname, uint64_t oldfid);
int smb_vfs_truncate(struct cifsd_sess *sess, const char *name,
		uint64_t fid, loff_t size);
ssize_t smb_vfs_listxattr(struct dentry *dentry, char **list, int size);
ssize_t smb_vfs_getxattr(struct dentry *dentry, char *xattr_name,
		char **xattr_buf, int flags);
int smb_vfs_setxattr(const char *filename, struct path *path, const char *name,
		const void *value, size_t size, int flags);
int smb_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless);
int smb_search_dir(char *dirname, char *filename);
void smb_vfs_set_fadvise(struct file *filp, int option);
int smb_vfs_lock(struct file *filp, int cmd, struct file_lock *flock);
int check_lock_range(struct file *filp, loff_t start,
		loff_t end, unsigned char type);
int smb_vfs_readdir(struct file *file, filldir_t filler,
			struct smb_readdir_data *buf);
int smb_vfs_alloc_size(struct connection *conn, struct cifsd_file *fp,
	loff_t len);
int smb_vfs_truncate_xattr(struct dentry *dentry);
int smb_vfs_truncate_stream_xattr(struct dentry *dentry);
int smb_vfs_remove_xattr(struct path *path, char *field_name);
int smb_vfs_unlink(struct dentry *dir, struct dentry *dentry);
unsigned short get_logical_sector_size(struct inode *inode);
void get_smb2_sector_size(struct inode *inode,
	struct smb2_fs_sector_size *fs_ss);

/* smb1ops functions */
extern void init_smb1_server(struct connection *conn);

/* smb2ops functions */
extern void init_smb2_0_server(struct connection *conn);
extern void init_smb2_1_server(struct connection *conn);
extern void init_smb3_0_server(struct connection *conn);
extern void init_smb3_02_server(struct connection *conn);
extern void init_smb3_11_server(struct connection *conn);
extern int is_smb2_neg_cmd(struct smb_work *smb_work);
extern bool is_chained_smb2_message(struct smb_work *smb_work);
extern void init_smb2_neg_rsp(struct smb_work *smb_work);
extern int is_smb2_rsp(struct smb_work *smb_work);

/* functions */
extern void smb_delete_session(struct cifsd_sess *sess);
extern int connect_tcp_sess(struct socket *sock);
extern int cifsd_read_from_socket(struct connection *conn, char *buf,
		unsigned int to_read);

extern void handle_smb_work(struct work_struct *work);
extern int SMB_NTencrypt(unsigned char *, unsigned char *, unsigned char *,
		const struct nls_table *);
extern int smb_E_md4hash(const unsigned char *passwd, unsigned char *p16,
		const struct nls_table *codepage);
extern int E_P24(unsigned char *p21, const unsigned char *c8,
		unsigned char *p24);
extern int smb_mdfour(unsigned char *md4_hash, unsigned char *link_str,
		int link_len);
extern int smb_send_rsp(struct smb_work *smb_work);
bool conn_unresponsive(struct connection *conn);
/* trans2 functions */

int query_fs_info(struct smb_work *smb_work);
void create_trans2_reply(struct smb_work *smb_work, __u16 count);
char *convert_to_unix_name(char *name, int tid);
void convert_delimiter(char *path, int flags);
int find_first(struct smb_work *smb_work);
int find_next(struct smb_work *smb_work);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
int smb_filldir(struct dir_context *ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type);
#else
int smb_filldir(void *__buf, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type);
#endif
int smb_get_shortname(struct connection *conn, char *longname,
		char *shortname);
char *read_next_entry(struct smb_work *smb_work, struct smb_kstat *smb_kstat,
		struct smb_dirent *de, char *dpath);
void *fill_common_info(char **p, struct smb_kstat *smb_kstat);
/* fill SMB specific fields when smb2 query dir is requested */
void fill_create_time(struct smb_work *smb_work,
		struct path *path, struct smb_kstat *smb_kstat);
void fill_file_attributes(struct smb_work *smb_work,
		struct path *path, struct smb_kstat *smb_kstat);
char *convname_updatenextoffset(char *namestr, int len, int size,
		const struct nls_table *local_nls, int *name_len,
		int *next_entry_offset, int *buf_len, int *data_count,
		int alignment);

/* netlink functions */
int cifsd_net_init(void);
void cifsd_net_exit(void);
int cifsd_sendmsg(struct cifsd_sess *sess, unsigned int etype,
		int pipe_type, unsigned int data_size,
		unsigned char *data, unsigned int out_buflen);
int cifsd_sendmsg_notify(struct cifsd_sess *sess,
		unsigned int data_size,
		struct smb2_inotify_req_info *inotify_req_info,
		char *path);
int cifsd_kthread_stop_status(int etype);

/* asn1 functions */
extern int cifsd_decode_negTokenInit(unsigned char *security_blob, int length,
		struct connection *conn);
extern int decode_negTokenTarg(unsigned char *security_blob, int length,
		struct connection *conn);
extern int build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer, u16 *buflen,
		char *ntlm_blob, int ntlm_blob_len);
extern int build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer, u16 *buflen,
		int neg_result);

void smb3_preauth_hash_rsp(struct smb_work *smb_work);
#endif /* __CIFSD_GLOB_H */
