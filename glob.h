/*
 *   fs/cifssrv/glob.h
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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

#ifndef __CIFSSRV_GLOB_H
#define __CIFSSRV_GLOB_H

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
#include "unicode.h"
#include "fh.h"
#include <crypto/hash.h>
#include "smberr.h"

extern struct kmem_cache *cifssrv_req_cachep;
extern mempool_t *cifssrv_req_poolp;
extern struct kmem_cache *cifssrv_sm_req_cachep;
extern mempool_t *cifssrv_sm_req_poolp;
extern struct kmem_cache *cifssrv_sm_rsp_cachep;
extern mempool_t *cifssrv_sm_rsp_poolp;
extern struct kmem_cache *cifssrv_rsp_cachep;
extern mempool_t *cifssrv_rsp_poolp;
extern struct list_head oplock_info_list;

#define CIFS_MIN_RCV_POOL 4
extern unsigned int smb_min_rcv;
extern unsigned int smb_min_small;

extern int cifssrv_debug_enable;
extern int cifssrv_caseless_search;
extern bool oplocks_enable;
extern bool lease_enable;
extern bool durable_enable;
extern unsigned int alloc_roundup_size;
extern unsigned long server_start_time;
extern struct fidtable_desc global_fidtable;
extern char *netbios_name;

#define SMB1_VERSION_STRING     "1.0"
#define SMB20_VERSION_STRING    "2.0"
#define SMB21_VERSION_STRING    "2.1"
#define SMB30_VERSION_STRING	"3.0"

/* Dialects */
#define SMB20_PROT_ID 0x0202
#define SMB21_PROT_ID 0x0210
#define SMB30_PROT_ID 0x0300
#define SMB2X_PROT_ID 0x02FF    /* multi-protocol negotiate request */
#define BAD_PROT_ID   0xFFFF

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

/*
 *  * Size of the ntlm client response
 *   */
#define CIFS_AUTH_RESP_SIZE (24)

/*
 *  * Size of the session key (crypto key encrypted with the password
 *   */
#define CIFS_SESS_KEY_SIZE (16)

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
#define HEADER_SIZE(server) (server->vals->header_size - 1)
#define MAX_HEADER_SIZE(server) (server->vals->max_header_size)


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
#define CREATE_EIGHT_DOT_THREE		cpu_to_le32(0x00000400)
/* doc says this is obsolete "open for recovery" flag
	should be zero in any case */
#define CREATE_OPEN_FOR_RECOVERY	cpu_to_le32(0x00000400)
#define FILE_RANDOM_ACCESS_LE		cpu_to_le32(0x00000800)
#define FILE_DELETE_ON_CLOSE_LE		cpu_to_le32(0x00001000)
#define FILE_OPEN_BY_FILE_ID_LE		cpu_to_le32(0x00002000)
#define FILE_OPEN_FOR_BACKUP_INTENT_LE	cpu_to_le32(0x00004000)
#define FILE_NO_COMPRESSION_LE		cpu_to_le32(0x00008000)
/* should be zero*/
#define FILE_RESERVE_OPFILTER_LE	cpu_to_le32(0x00100000)
#define FILE_OPEN_REPARSE_POINT_LE	cpu_to_le32(0x00200000)
#define FILE_OPEN_NO_RECALL_LE          cpu_to_le32(0x00400000)
/* should be zero */
#define FILE_OPEN_FOR_FREE_SPACE_QUERY_LE   cpu_to_le32(0x00800000)
#define CREATE_OPTIONS_MASK     0x007FFFFF
#define CREATE_OPTION_READONLY  0x10000000
#define CREATE_OPTION_SPECIAL   0x20000000   /* system. NB not sent over wire */

/* SMB2 Max Credits */
#define SMB2_MAX_CREDITS 8192

#define SMB2_CLIENT_GUID_SIZE		16

/* SMB2 timeouts */

#define SMB_ECHO_INTERVAL		(60*HZ) /* 60 msecs */

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

struct smb_work;

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
};

struct smb_version_ops {
	int (*get_cmd_val)(struct smb_work *swork);
	int (*init_rsp_hdr)(struct smb_work *swork);
	void (*set_rsp_status)(struct smb_work *swork, unsigned int err);
	int (*allocate_rsp_buf)(struct smb_work *smb_work);
	void (*set_rsp_credits)(struct smb_work *swork);
	int (*check_user_session)(struct smb_work *work);
};

struct smb_version_cmds {
	int (*proc)(struct smb_work *swork);
};

struct cifssrv_stats {
	int open_files_count;
	int request_served;
	long int avg_req_duration;
	long int max_timed_request;
};

struct tcp_server_info {
	struct socket *sock;
	int srv_count; /* reference counter */
	int sess_count; /* number of sessions attached with this server */
	struct smb_version_values   *vals;
	struct smb_version_ops		*ops;
	struct smb_version_cmds		*cmds;
	unsigned int    max_cmds;
	char *hostname;
	struct mutex srv_mutex;
	enum statusEnum tcp_status;
	__u16 sec_mode;
	bool sign;
	__u16 dialect; /* dialect index that server chose */
	bool oplocks:1;
	unsigned int maxReq;
	unsigned int capabilities;
	bool	need_neg;
	bool    large_buf;
	struct kvec *iov;
	unsigned int nr_iov;
	char    *smallbuf;
	char    *bigbuf;
	char    *wbuf;
	struct nls_table *local_nls;
	unsigned int total_read;
	char cryptkey[CIFS_CRYPTO_KEY_SIZE];
	/* This session will become part of global tcp session list */
	struct list_head tcp_sess;
	/* smb session 1 per user */
	struct list_head cifssrv_sess;
	struct task_struct *handler;
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
	struct fidtable_desc fidtable;
	wait_queue_head_t oplock_q; /* Other server threads */
	struct cifssrv_pipe *pipe_desc;
	spinlock_t request_lock; /* lock to protect requests list*/
	struct list_head requests;
	int max_credits;
	int credits_granted;
	char peeraddr[MAX_ADDRBUFLEN];
	int connection_type;
	struct cifssrv_stats stats;
	struct list_head list;
#ifdef CONFIG_CIFS_SMB2_SERVER
	char ClientGUID[SMB2_CLIENT_GUID_SIZE];
	__u64 sess_id;
#endif
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

/* one of these for every pending CIFS request at the server */
struct smb_work {
	struct list_head qhead;		/* works waiting on reply
							from this server */
	struct list_head request_entry;	/* list head at server->requests */
	struct tcp_server_info *server; /* server corresponding to this mid */
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
	bool added_in_request_list:1;	/* added in server->requests list */
};

#define cifssrv_debug(fmt, ...)					\
	do {							\
		if (cifssrv_debug_enable)			\
			printk(KERN_ERR "%s:%d: " fmt,		\
			__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define cifssrv_info(fmt, ...)					\
	do {							\
		printk(KERN_INFO "%s:%d: " fmt,			\
			__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define cifssrv_err(fmt, ...)					\
	do {							\
		printk(KERN_ERR "%s:%d: " fmt,			\
			__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

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
#define IS_SMB2(x) (x->vals->protocol_id == SMB20_PROT_ID || \
		x->vals->protocol_id == SMB21_PROT_ID)
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
bool is_smb_request(struct tcp_server_info *server, unsigned char type);
int switch_req_buf(struct tcp_server_info *server);
int negotiate_dialect(void *buf);

/* cifssrv export functions */
extern int cifssrv_export_init(void);
extern void cifssrv_export_exit(void);

/* cifssrv connect functions */
extern int cifssrv_start_forker_thread(void);
extern void cifssrv_stop_forker_thread(void);

/* cifssrv misc functions */
extern int check_smb_message(char *buf);
extern bool add_request_to_queue(struct smb_work *smb_work);
extern void dump_smb_msg(void *buf, int smb_buf_length);
extern int switch_rsp_buf(struct smb_work *smb_work);
extern int smb2_get_shortname(struct tcp_server_info *server, char *longname,
				char *shortname);
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);

/* smb vfs functions */
int smb_vfs_create(const char *name, umode_t mode);
int smb_vfs_mkdir(const char *name, umode_t mode);
int smb_vfs_read(struct tcp_server_info *server, uint64_t fid, char **buf,
		size_t count, loff_t *pos);
int smb_vfs_write(struct tcp_server_info *server, uint64_t fid, char *buf,
		size_t count, loff_t *pos,
		bool fsync, ssize_t *written);
int smb_vfs_getattr(struct tcp_server_info *server, __u16 fid,
		struct kstat *stat);
int smb_vfs_setattr(struct tcp_server_info *server, const char *name,
		__u16 fid, struct iattr *attrs);
int smb_vfs_fsync(struct tcp_server_info *server, uint64_t fid);
int smb_dentry_open(struct smb_work *work, const struct path *path,
		int flags, __u16 *fid, int *oplock, int option,
		int fexist);
int smb_vfs_rmdir(const char *name);
int smb_vfs_unlink(const char *name);
int smb_vfs_link(const char *oldname, const char *newname);
int smb_vfs_symlink(const char *name, const char *symname);
int smb_vfs_readlink(struct path *path, char *buf, int len);
int smb_vfs_rename(struct tcp_server_info *server, const char *oldname,
		const char *newname, __u16 oldfid);
int smb_vfs_truncate(struct tcp_server_info *server, const char *name,
		__u16 fid, loff_t size);
int smb_vfs_listxattr(struct dentry *dentry, char **list, int size);
int smb_vfs_getxattr(struct dentry *dentry, char *xattr_name,
		char *xattr_buf, __u32 buf_len);
int smb_vfs_setxattr(const char *filename, struct path *path, const char *name,
		const void *value, size_t size, int flags);
int smb_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless);
int smb_search_dir(char *dirname, char *filename);
void smb_vfs_set_fadvise(struct file *filp, int option);
int smb_vfs_lock(struct file *filp, int cmd, struct file_lock *flock);
int smb_vfs_locks_mandatory_area(struct file *filp, loff_t start,
		loff_t end, unsigned char type);
int smb_vfs_readdir(struct file *file, filldir_t filler, void *buf);

/* smb1ops functions */
extern void init_smb1_server(struct tcp_server_info *server);

/* smb2ops functions */
#ifdef CONFIG_CIFS_SMB2_SERVER
extern void init_smb2_0_server(struct tcp_server_info *server);
extern void init_smb2_1_server(struct tcp_server_info *server);
extern void init_smb3_0_server(struct tcp_server_info *server);
extern int is_smb2_neg_cmd(struct smb_work *smb_work);
extern int is_smb2_rsp(struct smb_work *smb_work);
#else
static inline void init_smb2_0_server(struct tcp_server_info *server) { }
static inline void init_smb2_1_server(struct tcp_server_info *server) { }
static inline void init_smb3_0_server(struct tcp_server_info *server) { }
static inline int is_smb2_neg_cmd(struct smb_work *smb_work) { return 0; }
static inline bool is_chained_smb2_message(struct smb_work *smb_work)
{
	return 0;
}

static inline void init_smb2_neg_rsp(struct smb_work *smb_work)
{
}

#endif

/* functions */
extern int connect_tcp_sess(struct socket *sock);
extern int cifssrv_read_from_socket(struct tcp_server_info *server, char *buf,
		unsigned int to_read);

extern void handle_smb_work(struct work_struct *work);
extern struct cifssrv_tcon *construct_cifssrv_tcon(struct cifssrv_share *share,
		struct cifssrv_sess *sess);
extern struct cifssrv_tcon *get_cifssrv_tcon(struct cifssrv_sess *sess,
			unsigned int tid);
extern int SMB_NTencrypt(unsigned char *, unsigned char *, unsigned char *,
		const struct nls_table *);
extern int smb_E_md4hash(const unsigned char *passwd, unsigned char *p16,
		const struct nls_table *codepage);
extern int E_P24(unsigned char *p21, const unsigned char *c8,
		unsigned char *p24);
extern int smb_send_rsp(struct smb_work *smb_work);
bool server_unresponsive(struct tcp_server_info *server);
/* trans2 functions */

int smb_trans2(struct smb_work *smb_work);
int query_fs_info(struct smb_work *smb_work);
void create_trans2_reply(struct smb_work *smb_work, __u16 count);
int smb_nt_create_andx(struct smb_work *smb_work);
char *convert_to_unix_name(char *name, int tid);
void convert_delimiter(char *path);
int find_first(struct smb_work *smb_work);
int find_next(struct smb_work *smb_work);
int smb_close(struct smb_work *smb_work);
int smb_read_andx(struct smb_work *smb_work);
int smb_write_andx(struct smb_work *smb_work);
int smb_echo(struct smb_work *smb_work);
int smb_flush(struct smb_work *smb_work);
int smb_populate_readdir_entry(struct tcp_server_info *server, int info_level,
		char **p, int reclen, char *namestr, int *space_remaining,
		int *last_entry_offset, struct kstat *kstat, int *data_count,
		int *dir_entry_bytes_count,
		int *num_dir_entries_searched);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
int smb_filldir(struct dir_context *ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type);
#else
int smb_filldir(void *__buf, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type);
#endif

#endif /* __CIFSSRV_GLOB_H */
