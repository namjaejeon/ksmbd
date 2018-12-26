// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_FH_H
#define __CIFSD_FH_H

#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>

#include "glob.h"
#include "vfs.h"

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0X1200a0

/* Max id limit is 0xFFFF, so create bitmap with only this size*/
#define CIFSD_BITMAP_SIZE	0xFFFF
#define CIFSD_START_FID		0
#define CIFSD_NO_FID		(-1ULL)

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

#define S_DEL_PENDING			1
#define S_DEL_ON_CLS			2
#define S_DEL_ON_CLS_STREAM		8

/* FP STATE */
#define FP_NEW		0
#define FP_FREEING	1

struct cifsd_tcp_conn;
struct cifsd_session;

struct notification {
	unsigned int mode;
	struct list_head queuelist;
	struct cifsd_work *work;
};

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
	struct cifsd_tcp_conn *conn;
	struct cifsd_session *sess;
	struct cifsd_tree_connect *tcon;
	struct cifsd_inode *f_ci;
	struct cifsd_inode *f_parent_ci;
	struct oplock_info *f_opinfo;
	struct file *filp;
	char *filename;
	/* if ls is happening on directory, below is valid*/
	struct cifsd_readdir_data	readdir_data;
	int	dot_dotdot[2];
	int	dirent_offset;
	/* oplock info */
	unsigned int volatile_id;
	bool is_durable;
	bool is_resilient;
	bool is_persistent;
	bool is_nt_open;
	bool delete_on_close;
	uint64_t persistent_id;
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
	struct list_head blocked_works;
	spinlock_t f_lock;
	int f_state;
	char client_guid[16];
	char create_guid[16];
	char app_instance_id[16];
	int durable_timeout;
	int pid; /* for SMB1 */
	unsigned int cflock_cnt; /* conflict lock fail count for SMB1 */
	unsigned long long llock_fstart; /* last lock failure start offset for SMB1 */
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
void close_opens_from_fibtable(struct cifsd_session *sess,
	struct cifsd_tree_connect *tcon);
void destroy_fidtable(struct cifsd_session *sess);
void free_fidtable(struct fidtable *ftab);
struct cifsd_file *
get_id_from_fidtable(struct cifsd_session *sess, uint64_t id);
int close_id(struct cifsd_session *sess, uint64_t id, uint64_t p_id);
int cifsd_get_unused_id(struct fidtable_desc *ftab_desc);
int cifsd_close_id(struct fidtable_desc *ftab_desc, int id);
struct cifsd_file *
insert_id_in_fidtable(struct cifsd_session *sess, struct cifsd_tree_connect *tcon,
	unsigned int id, struct file *filp);
void delete_id_from_fidtable(struct cifsd_session *sess,
		unsigned int id);
struct cifsd_file *get_fp(struct cifsd_work *work, int64_t req_vid,
	int64_t req_pid);

void __init cifsd_inode_hash_init(void);
int cifsd_inode_init(struct cifsd_inode *ci, struct cifsd_file *fp);
void cifsd_inode_free(struct cifsd_inode *ci);
void cifsd_inode_hash(struct cifsd_inode *ci);
void cifsd_inode_unhash(struct cifsd_inode *ci);
struct cifsd_inode *cifsd_inode_lookup(struct cifsd_file *fp);
struct cifsd_inode *cifsd_inode_lookup_by_vfsinode(struct inode *inode);
struct cifsd_inode *cifsd_inode_get(struct cifsd_file *fp);

/* Persistent-ID operations */
int cifsd_insert_in_global_table(struct cifsd_session *sess,
	struct cifsd_file *fp);
int close_persistent_id(uint64_t id);
void destroy_global_fidtable(void);

/* Durable handle functions */
struct cifsd_file *cifsd_get_global_fp(uint64_t pid);
int cifsd_reconnect_durable_fp(struct cifsd_session *sess, struct cifsd_file *fp,
	struct cifsd_tree_connect *tcon);
struct cifsd_file *lookup_fp_clguid(char *createguid);
struct cifsd_file *lookup_fp_app_id(char *app_id);
struct cifsd_file *find_fp_using_filename(struct cifsd_session *sess,
	char *filename);
struct cifsd_file *find_fp_using_inode(struct inode *inode);
int close_disconnected_handle(struct inode *inode);

#endif /* __CIFSD_FH_H */
