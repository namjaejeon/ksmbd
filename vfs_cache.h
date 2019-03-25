// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#ifndef __VFS_CACHE_H__
#define __VFS_CACHE_H__

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <linux/workqueue.h>

#include "vfs.h"

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0X1200a0

#define CIFSD_START_FID		0
#define CIFSD_NO_FID		(UINT_MAX)
#define SMB2_NO_FID		(0xFFFFFFFFFFFFFFFFULL)

#define FP_FILENAME(fp)		fp->filp->f_path.dentry->d_name.name
#define FP_INODE(fp)		fp->filp->f_path.dentry->d_inode
#define PARENT_INODE(fp)	fp->filp->f_path.dentry->d_parent->d_inode

#define ATTR_FP(fp) (fp->attrib_only && \
		(fp->cdoption != FILE_OVERWRITE_IF_LE && \
		fp->cdoption != FILE_OVERWRITE_LE && \
		fp->cdoption != FILE_SUPERSEDE_LE))

#define S_DEL_PENDING			1
#define S_DEL_ON_CLS			2
#define S_DEL_ON_CLS_STREAM		8

/* FP STATE */
#define FP_NEW		0
#define FP_FREEING	1

struct cifsd_tcp_conn;
struct cifsd_session;

struct cifsd_lock {
	struct file_lock *fl;
	struct list_head glist;
	struct list_head llist;
	unsigned int flags;
	unsigned int cmd;
	int zero_len;
	unsigned long long start;
	unsigned long long end;
};

struct stream {
	char *name;
	int type;
	ssize_t size;
};

struct cifsd_inode {
	spinlock_t m_lock;
	atomic_t m_count;
	atomic_t op_count;
	struct inode *m_inode;
	unsigned int m_flags;
	struct hlist_node m_hash;
	struct list_head m_fp_list;
	struct list_head m_op_list;
	struct oplock_info *m_opinfo;
	char *stream_name;
};

struct cifsd_file {
	struct file			*filp;
	char				*filename;
	unsigned int			persistent_id;
	unsigned int			volatile_id;

	spinlock_t			f_lock;

	struct cifsd_inode		*f_ci;
	struct cifsd_inode		*f_parent_ci;
	struct oplock_info		*f_opinfo;
	struct cifsd_tcp_conn		*conn;
	struct cifsd_tree_connect	*tcon;

	int				f_state;
	__le32				daccess;
	__le32				saccess;
	__le32				coption;
	__le32				cdoption;
	__le32				fattr;
	__u64				create_time;

	bool				is_durable;
	bool				is_resilient;
	bool				is_persistent;
	bool				is_nt_open;
	bool				delete_on_close;
	bool				attrib_only;
	bool				is_stream;

	char				client_guid[16];
	char				create_guid[16];
	char				app_instance_id[16];

	struct stream			stream;
	struct list_head		node;
	struct list_head		blocked_works;

	int				durable_timeout;
	/* for SMB1 */
	int				pid;

	/* conflict lock fail count for SMB1 */
	unsigned int			cflock_cnt;
	/* last lock failure start offset for SMB1 */
	unsigned long long		llock_fstart;

	/* if ls is happening on directory, below is valid*/
	struct cifsd_readdir_data	readdir_data;
	int				dot_dotdot[2];
	int				dirent_offset;
};

#define CIFSD_NR_OPEN_DEFAULT BITS_PER_LONG

struct cifsd_file_table {
	struct rw_semaphore	lock;
	struct idr		idr;
};

static inline bool HAS_FILE_ID(unsigned long long req)
{
	unsigned int id = (unsigned int)req;

	return id != CIFSD_NO_FID;
}

int cifsd_init_file_table(struct cifsd_file_table *ft);
void cifsd_destroy_file_table(struct cifsd_file_table *ft);

int cifsd_close_fd(struct cifsd_work *work, unsigned int id);

struct cifsd_file *cifsd_lookup_fd_fast(struct cifsd_work *work,
					unsigned int id);
struct cifsd_file *cifsd_lookup_fd_slow(struct cifsd_work *work,
					unsigned int id,
					unsigned int pid);

struct cifsd_file *cifsd_lookup_durable_fd(unsigned long long id);
struct cifsd_file *cifsd_lookup_fd_app_id(char *app_id);
struct cifsd_file *cifsd_lookup_fd_cguid(char *cguid);
struct cifsd_file *cifsd_lookup_fd_filename(struct cifsd_work *work,
					    char *filename);
struct cifsd_file *cifsd_lookup_fd_inode(struct inode *inode);

unsigned int cifsd_open_durable_fd(struct cifsd_file *fp);

struct cifsd_file *cifsd_open_fd(struct cifsd_work *work,
				 struct file *filp);

void cifsd_close_tree_conn_fds(struct cifsd_work *work);

int cifsd_close_inode_fds(struct cifsd_work *work, struct inode *inode);

int cifsd_reopen_durable_fd(struct cifsd_work *work,
			    struct cifsd_file *fp);

void cifsd_init_global_file_table(void);
void cifsd_free_global_file_table(void);

int cifsd_file_table_flush(struct cifsd_work *work);

/*
 * INODE hash
 */

void __init cifsd_inode_hash_init(void);
int cifsd_inode_init(struct cifsd_inode *ci, struct cifsd_file *fp);
void cifsd_inode_free(struct cifsd_inode *ci);
void cifsd_inode_hash(struct cifsd_inode *ci);
void cifsd_inode_unhash(struct cifsd_inode *ci);
struct cifsd_inode *cifsd_inode_lookup(struct cifsd_file *fp);
struct cifsd_inode *cifsd_inode_lookup_by_vfsinode(struct inode *inode);
struct cifsd_inode *cifsd_inode_get(struct cifsd_file *fp);
void cifsd_inode_put(struct cifsd_inode *ci);

#endif /* __VFS_CACHE_H__ */
