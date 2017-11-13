/*
 *   fs/cifsd/fh.h
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

#ifndef __CIFSD_FH_H
#define __CIFSD_FH_H

#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>

#include "glob.h"
#include "netlink.h"

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0X1200a0

/* Max id limit is 0xFFFF, so create bitmap with only this size*/
#define CIFSD_BITMAP_SIZE        0xFFFF
#define CIFSD_START_FID		 1

#define cifsd_set_bit			__set_bit_le
#define cifsd_test_and_set_bit	__test_and_set_bit_le
#define cifsd_test_bit		test_bit_le
#define cifsd_clear_bit		__clear_bit_le
#define cifsd_test_and_clear_bit	__test_and_clear_bit_le
#define cifsd_find_next_zero_bit	find_next_zero_bit_le
#define cifsd_find_next_bit		find_next_bit_le

#define FP_FILENAME(fp)		fp->filp->f_path.dentry->d_name.name
#define FP_INODE(fp)		fp->filp->f_path.dentry->d_inode
#define PARENT_INODE(fp)	fp->filp->f_path.dentry->d_parent->d_inode

#define ATTR_FP(fp) (fp->attrib_only && \
		(fp->cdoption != FILE_OVERWRITE_IF_LE && \
		fp->cdoption != FILE_OVERWRITE_LE && \
		fp->cdoption != FILE_SUPERSEDE_LE))

#define S_DEL_ON_CLS		1
#define S_DEL_ON_CLS_STREAM	2

/* FP STATE */
#define FP_NEW		0
#define FP_FREEING	1


struct connection;
struct cifsd_sess;

struct smb_readdir_data {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
	struct dir_context ctx;
#endif
	char           *dirent;
	unsigned int   used;
	unsigned int   full;
	unsigned int   dirent_count;
};

struct smb_dirent {
	__le64         ino;
	__le64          offset;
	__le32         namelen;
	__le32         d_type;
	char            name[];
};

struct notification {
	unsigned int mode;
	struct list_head queuelist;
	struct smb_work *work;
};

struct cifsd_lock {
	struct file_lock *fl;
	struct list_head glist;
	struct list_head llist;
	struct list_head flist;
	unsigned int flags;
	unsigned int cmd;
	int zero_len;
	loff_t start;
	loff_t end;
	struct smb_work *work;
};

struct stream {
	char *name;
	int type;
	ssize_t size;
};

struct cifsd_mfile {
	spinlock_t m_lock;
	atomic_t m_count;
	atomic_t op_count;
	struct inode *m_inode;
	unsigned int m_flags;
	struct hlist_node m_hash;
	struct list_head m_fp_list;
	struct oplock_info *m_opinfo;
	bool has_lease;
	bool is_stream;
	char *stream_name;
};

struct cifsd_file {
	struct connection *conn;
	struct cifsd_mfile *f_mfp;
	struct oplock_info *f_opinfo;
	struct file *filp;
	/* Will be used for in case of symlink */
	struct file *lfilp;
	struct timespec open_time;
	bool islink;
	/* if ls is happening on directory, below is valid*/
	struct smb_readdir_data	readdir_data;
	int	dot_dotdot[2];
	int	dirent_offset;
	/* oplock info */
	struct ofile_info *ofile;
	bool is_nt_open;
	bool lease_granted;
	char LeaseKey[16];
	unsigned int volatile_id;
	bool is_durable;
	uint64_t persistent_id;
	uint64_t sess_id;
	uint32_t tid;
	__le32 daccess;
	__le32 saccess;
	__le32 coption;
	__le32 cdoption;
	__le32 fattr;
	__u64 create_time;
	bool attrib_only;
	bool is_stream;
	struct stream stream;
	struct list_head node;
	struct hlist_node notify_node;
	struct list_head queue;
	struct list_head lock_list;
	spinlock_t f_lock;
	wait_queue_head_t wq;
	int f_state;
};

#ifdef CONFIG_CIFS_SMB2_SERVER
struct cifsd_durable_state {
	struct cifsd_sess *sess;
	int volatile_id;
	struct kstat stat;
	int refcount;
};
#endif

enum cifsd_pipe_type {
	SRVSVC,
	WINREG,
	LANMAN,
	MAX_PIPE
};

struct cifsd_pipe_table {
	char pipename[32];
	unsigned int pipetype;
};

#define INVALID_PIPE   0xFFFFFFFF

struct cifsd_pipe {
	unsigned int id;
	char *data;
	int pkt_type;
	int pipe_type;
	int opnum;
	char *buf;
	int datasize;
	int sent;
	struct cifsd_uevent ev;
	char *rsp_buf;
};

#define CIFSD_NR_OPEN_DEFAULT BITS_PER_LONG

/* fidtable structure */
struct fidtable {
	unsigned int max_fids;
	void **fileid;
	unsigned int start_pos;
	unsigned long *cifsd_bitmap;
};

struct fidtable_desc {
	spinlock_t fidtable_lock;
	struct fidtable *ftab;
};

int init_fidtable(struct fidtable_desc *ftab_desc);
void close_opens_from_fibtable(struct cifsd_sess *sess, uint32_t tree_id);
void destroy_fidtable(struct cifsd_sess *sess);
void free_fidtable(struct fidtable *ftab);
struct cifsd_file *
get_id_from_fidtable(struct cifsd_sess *sess, uint64_t id);
int close_id(struct cifsd_sess *sess, uint64_t id, uint64_t p_id);
bool is_dir_empty(struct cifsd_file *fp);
unsigned int get_pipe_type(char *pipename);
int cifsd_get_unused_id(struct fidtable_desc *ftab_desc);
int cifsd_close_id(struct fidtable_desc *ftab_desc, int id);
struct cifsd_file *
insert_id_in_fidtable(struct cifsd_sess *sess, uint64_t sess_id,
		uint32_t tree_id, unsigned int id, struct file *filp);
void delete_id_from_fidtable(struct cifsd_sess *sess,
		unsigned int id);
void __init mfp_hash_init(void);
int mfp_init(struct cifsd_mfile *mfp, struct cifsd_file *fp);
void mfp_free(struct cifsd_mfile *mfp);
void insert_mfp_hash(struct cifsd_mfile *mfp);
void remove_mfp_hash(struct cifsd_mfile *mfp);
struct cifsd_mfile *mfp_lookup(struct cifsd_file *fp);
struct cifsd_mfile *mfp_lookup_inode(struct inode *inode);

#ifdef CONFIG_CIFS_SMB2_SERVER
/* Persistent-ID operations */
int cifsd_insert_in_global_table(struct cifsd_sess *sess,
	struct cifsd_file *fp);
int close_persistent_id(uint64_t id);
void destroy_global_fidtable(void);

/* Durable handle functions */
struct cifsd_file *cifsd_get_durable_fp(uint64_t pid);

int cifsd_reconnect_durable_fp(struct cifsd_sess *sess, struct cifsd_file *fp,
	int tree_id);

#endif

#endif /* __CIFSD_FH_H */
