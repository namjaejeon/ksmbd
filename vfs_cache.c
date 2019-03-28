// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 * Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

/* @FIXME */
#include "glob.h"
#include "vfs_cache.h"
#include "buffer_pool.h"

#include "oplock.h"
#include "vfs.h"
#include "transport_tcp.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"

/* @FIXME */
#include "smb_common.h"

static unsigned int inode_hash_mask __read_mostly;
static unsigned int inode_hash_shift __read_mostly;
static struct hlist_head *inode_hashtable __read_mostly;
static DEFINE_RWLOCK(inode_hash_lock);

static struct cifsd_file_table global_ft;

/*
 * INODE hash
 */

static unsigned long inode_hash(struct super_block *sb, unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
		L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> inode_hash_shift);
	return tmp & inode_hash_mask;
}

static struct cifsd_inode *__cifsd_inode_lookup(struct inode *inode)
{
	struct hlist_head *head = inode_hashtable +
		inode_hash(inode->i_sb, inode->i_ino);
	struct cifsd_inode *ci = NULL, *ret_ci = NULL;

	hlist_for_each_entry(ci, head, m_hash) {
		if (ci->m_inode == inode) {
			if (atomic_inc_not_zero(&ci->m_count))
				ret_ci = ci;
			break;
		}
	}

	return ret_ci;
}

static struct cifsd_inode *cifsd_inode_lookup(struct cifsd_file *fp)
{
	return __cifsd_inode_lookup(FP_INODE(fp));
}

struct cifsd_inode *cifsd_inode_lookup_by_vfsinode(struct inode *inode)
{
	struct cifsd_inode *ci;

	read_lock(&inode_hash_lock);
	ci = __cifsd_inode_lookup(inode);
	read_unlock(&inode_hash_lock);
	return ci;
}

static void cifsd_inode_hash(struct cifsd_inode *ci)
{
	struct hlist_head *b = inode_hashtable +
		inode_hash(ci->m_inode->i_sb, ci->m_inode->i_ino);

	hlist_add_head(&ci->m_hash, b);
}

static void cifsd_inode_unhash(struct cifsd_inode *ci)
{
	write_lock(&inode_hash_lock);
	hlist_del_init(&ci->m_hash);
	write_unlock(&inode_hash_lock);
}

static int cifsd_inode_init(struct cifsd_inode *ci, struct cifsd_file *fp)
{
	ci->m_inode = FP_INODE(fp);
	atomic_set(&ci->m_count, 1);
	atomic_set(&ci->op_count, 0);
	ci->m_flags = 0;
	INIT_LIST_HEAD(&ci->m_fp_list);
	INIT_LIST_HEAD(&ci->m_op_list);
	rwlock_init(&ci->m_lock);
	ci->stream_name = NULL;

	if (fp->is_stream) {
		ci->stream_name = kmalloc(fp->stream.size + 1, GFP_KERNEL);
		if (!ci->stream_name)
			return -ENOMEM;
		strncpy(ci->stream_name, fp->stream.name, fp->stream.size);
	}

	return 0;
}

static struct cifsd_inode *cifsd_inode_get(struct cifsd_file *fp)
{
	struct cifsd_inode *ci, *tmpci;
	int rc;

	read_lock(&inode_hash_lock);
	ci = cifsd_inode_lookup(fp);
	read_unlock(&inode_hash_lock);
	if (ci)
		return ci;

	ci = kmalloc(sizeof(struct cifsd_inode), GFP_KERNEL);
	if (!ci)
		return NULL;

	rc = cifsd_inode_init(ci, fp);
	if (rc) {
		cifsd_err("inode initialized failed\n");
		kfree(ci);
		return NULL;
	}

	write_lock(&inode_hash_lock);
	tmpci = cifsd_inode_lookup(fp);
	if (!tmpci) {
		cifsd_inode_hash(ci);
	} else {
		kfree(ci);
		ci = tmpci;
	}
	write_unlock(&inode_hash_lock);
	return ci;
}

static void cifsd_inode_free(struct cifsd_inode *ci)
{
	cifsd_inode_unhash(ci);
	kfree(ci->stream_name);
	kfree(ci);
}

static void cifsd_inode_put(struct cifsd_inode *ci)
{
	if (atomic_dec_and_test(&ci->m_count))
		cifsd_inode_free(ci);
}

void __init cifsd_inode_hash_init(void)
{
	unsigned int loop;
	unsigned long numentries = 16384;
	unsigned long bucketsize = sizeof(struct hlist_head);
	unsigned long size;

	inode_hash_shift = ilog2(numentries);
	inode_hash_mask = (1 << inode_hash_shift) - 1;

	size = bucketsize << inode_hash_shift;

	/* init master fp hash table */
	inode_hashtable = __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL);

	for (loop = 0; loop < (1U << inode_hash_shift); loop++)
		INIT_HLIST_HEAD(&inode_hashtable[loop]);
}

/*
 * CIFSD FP cache
 */

int cifsd_init_file_table(struct cifsd_file_table *ft)
{
	idr_init(&ft->idr);
	init_rwsem(&ft->lock);
	return 0;
}

void cifsd_destroy_file_table(struct cifsd_file_table *ft)
{
	idr_destroy(&ft->idr);
}

/* copy-pasted from old fh */
static void inherit_delete_pending(struct cifsd_file *fp)
{
	struct list_head *cur;
	struct cifsd_file *prev_fp;
	struct cifsd_inode *ci = fp->f_ci;

	fp->delete_on_close = 0;

	write_lock(&ci->m_lock);
	list_for_each_prev(cur, &ci->m_fp_list) {
		prev_fp = list_entry(cur, struct cifsd_file, node);
		if (fp != prev_fp && (fp->tcon == prev_fp->tcon ||
				ci->m_flags & S_DEL_ON_CLS))
			ci->m_flags |= S_DEL_PENDING;
	}
	write_unlock(&ci->m_lock);
}

/* copy-pasted from old fh */
static void invalidate_delete_on_close(struct cifsd_file *fp)
{
	struct list_head *cur;
	struct cifsd_file *prev_fp;
	struct cifsd_inode *ci = fp->f_ci;

	read_lock(&ci->m_lock);
	list_for_each_prev(cur, &ci->m_fp_list) {
		prev_fp = list_entry(cur, struct cifsd_file, node);
		if (fp == prev_fp)
			break;
		if (fp->tcon == prev_fp->tcon)
			prev_fp->delete_on_close = 0;
	}
	read_unlock(&ci->m_lock);
}

/* copy-pasted from old fh */
static void __cifsd_inode_close(struct cifsd_file *fp)
{
	struct dentry *dir, *dentry;
	struct cifsd_inode *ci = fp->f_ci;
	int err;
	struct file *filp;

	filp = fp->filp;
	if (atomic_read(&ci->m_count) >= 2) {
		if (fp->delete_on_close)
			inherit_delete_pending(fp);
		else
			invalidate_delete_on_close(fp);
	}

	if (fp->is_stream && (ci->m_flags & S_DEL_ON_CLS_STREAM)) {
		ci->m_flags &= ~S_DEL_ON_CLS_STREAM;
		err = cifsd_vfs_remove_xattr(filp->f_path.dentry,
					     fp->stream.name);
		if (err)
			cifsd_err("remove xattr failed : %s\n",
				fp->stream.name);
	}

	if (atomic_dec_and_test(&ci->m_count)) {
		write_lock(&ci->m_lock);
		if ((ci->m_flags & (S_DEL_ON_CLS | S_DEL_PENDING)) ||
				fp->delete_on_close) {
			dentry = filp->f_path.dentry;
			dir = dentry->d_parent;
			ci->m_flags &= ~(S_DEL_ON_CLS | S_DEL_PENDING);
			write_unlock(&ci->m_lock);
			cifsd_vfs_unlink(dir, dentry);
			write_lock(&ci->m_lock);
		}
		write_unlock(&ci->m_lock);

		cifsd_inode_free(ci);
	}
}

static void __cifsd_remove_durable_fd(struct cifsd_file *fp)
{
	if (fp->persistent_id == CIFSD_NO_FID)
		return;

	down_write(&global_ft.lock);
	idr_remove(&global_ft.idr, fp->persistent_id);
	up_write(&global_ft.lock);
}

static void __cifsd_remove_fd(struct cifsd_file_table *ft,
			      struct cifsd_file *fp)
{
	WARN_ON(fp->volatile_id == CIFSD_NO_FID);

	write_lock(&fp->f_ci->m_lock);
	list_del_init(&fp->node);
	write_unlock(&fp->f_ci->m_lock);

	idr_remove(&ft->idr, fp->volatile_id);
}

/* copy-pasted from old fh */
static void __cifsd_close_fd(struct cifsd_file_table *ft,
			     struct cifsd_file *fp,
			     unsigned int id)
{
	struct file *filp;
	struct cifsd_work *cancel_work, *ctmp;

	__cifsd_remove_durable_fd(fp);
	__cifsd_remove_fd(ft, fp);

	close_id_del_oplock(fp);
	filp = fp->filp;

	spin_lock(&fp->f_lock);
	list_for_each_entry_safe(cancel_work, ctmp, &fp->blocked_works,
		fp_entry) {
		list_del(&cancel_work->fp_entry);
		cancel_work->state = WORK_STATE_CLOSED;
		cancel_work->cancel_fn(cancel_work->cancel_argv);
	}
	spin_unlock(&fp->f_lock);

	__cifsd_inode_close(fp);
	if (!IS_ERR_OR_NULL(filp))
		filp_close(filp, (struct files_struct *)filp);
	cifsd_free_file_struct(fp);
}

static struct cifsd_file *__cifsd_lookup_fd(struct cifsd_file_table *ft,
					    unsigned int id)
{
	bool unclaimed = true;
	struct cifsd_file *fp;

	down_read(&ft->lock);
	fp = idr_find(&ft->idr, id);
	if (fp && fp->f_ci) {
		read_lock(&fp->f_ci->m_lock);
		unclaimed = list_empty(&fp->node);
		read_unlock(&fp->f_ci->m_lock);
	}
	up_read(&ft->lock);

	if (unclaimed)
		return NULL;
	return fp;
}

int cifsd_close_fd(struct cifsd_work *work, unsigned int id)
{
	struct cifsd_file	*fp;

	if (id == CIFSD_NO_FID)
		return 0;

	fp = __cifsd_lookup_fd(&work->sess->file_table, id);
	if (!fp)
		return -EINVAL;

	__cifsd_close_fd(&work->sess->file_table, fp, id);
	return 0;
}

static bool __sanity_check(struct cifsd_tree_connect *tcon,
			   struct cifsd_file *fp)
{
	if (!fp)
		return false;
	if (fp->tcon != tcon)
		return false;
	return true;
}

struct cifsd_file *cifsd_lookup_fd_fast(struct cifsd_work *work,
					unsigned int id)
{
	struct cifsd_file *fp = __cifsd_lookup_fd(&work->sess->file_table, id);

	if (__sanity_check(work->tcon, fp))
		return fp;
	return NULL;
}

struct cifsd_file *cifsd_lookup_fd_slow(struct cifsd_work *work,
					unsigned int id,
					unsigned int pid)
{
	struct cifsd_file *fp;

	if (id == CIFSD_NO_FID) {
		id = work->compound_fid;
		pid = work->compound_pfid;
	}

	if (id == CIFSD_NO_FID)
		return NULL;

	fp = __cifsd_lookup_fd(&work->sess->file_table, id);
	if (!__sanity_check(work->tcon, fp))
		return NULL;
	if (fp->persistent_id != pid)
		return NULL;
	return fp;
}

struct cifsd_file *cifsd_lookup_durable_fd(unsigned long long id)
{
	return __cifsd_lookup_fd(&global_ft, id);
}

struct cifsd_file *cifsd_lookup_fd_app_id(char *app_id)
{
	struct cifsd_file	*fp = NULL;
	unsigned int		id;

	down_read(&global_ft.lock);
	idr_for_each_entry(&global_ft.idr, fp, id) {
		if (!memcmp(fp->app_instance_id,
			    app_id,
			    SMB2_CREATE_GUID_SIZE))
			break;
	}
	up_read(&global_ft.lock);

	return fp;
}

struct cifsd_file *cifsd_lookup_fd_cguid(char *cguid)
{
	struct cifsd_file	*fp = NULL;
	unsigned int		id;

	down_read(&global_ft.lock);
	idr_for_each_entry(&global_ft.idr, fp, id) {
		if (!memcmp(fp->create_guid,
			    cguid,
			    SMB2_CREATE_GUID_SIZE))
			break;
	}
	up_read(&global_ft.lock);

	return fp;
}

struct cifsd_file *cifsd_lookup_fd_filename(struct cifsd_work *work,
					    char *filename)
{
	struct cifsd_file	*fp = NULL;
	unsigned int		id;

	down_read(&work->sess->file_table.lock);
	idr_for_each_entry(&work->sess->file_table.idr, fp, id) {
		if (!strcmp(fp->filename, filename))
			break;
	}
	down_read(&work->sess->file_table.lock);

	return fp;
}

/* copy-pasted from old fh */
struct cifsd_file *cifsd_lookup_fd_inode(struct inode *inode)
{
	struct cifsd_file	*lfp;
	struct cifsd_inode	*ci;
	struct list_head	*cur;

	ci = cifsd_inode_lookup_by_vfsinode(inode);
	if (!ci)
		return NULL;

	read_lock(&ci->m_lock);
	list_for_each(cur, &ci->m_fp_list) {
		lfp = list_entry(cur, struct cifsd_file, node);
		if (inode == FP_INODE(lfp)) {
			atomic_dec(&ci->m_count);
			read_unlock(&ci->m_lock);
			return lfp;
		}
	}
	atomic_dec(&ci->m_count);
	read_unlock(&ci->m_lock);
	return NULL;
}

#define OPEN_ID_TYPE_VOLATILE_ID	(0)
#define OPEN_ID_TYPE_PERSISTENT_ID	(1)

static void __open_id(struct cifsd_file_table *ft,
		      struct cifsd_file *fp,
		      int type)
{
	unsigned int		id = 0;
	int			ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ret = idr_alloc_u32(&ft->idr, fp, &id, UINT_MAX, GFP_KERNEL);
#else
	ret = idr_alloc(&ft->idr, fp, 0, INT_MAX, GFP_KERNEL);
	if (ret >= 0) {
		id = ret;
		ret = 0;
	}
#endif
	if (ret)
		id = CIFSD_NO_FID;

	if (type == OPEN_ID_TYPE_VOLATILE_ID)
		fp->volatile_id = id;
	if (type == OPEN_ID_TYPE_PERSISTENT_ID)
		fp->persistent_id = id;
}

unsigned int cifsd_open_durable_fd(struct cifsd_file *fp)
{
	down_write(&global_ft.lock);
	__open_id(&global_ft, fp, OPEN_ID_TYPE_PERSISTENT_ID);
	up_write(&global_ft.lock);
	return fp->persistent_id;
}

struct cifsd_file *cifsd_open_fd(struct cifsd_work *work,
				 struct file *filp)
{
	struct cifsd_file	*fp;

	fp = cifsd_alloc_file_struct();
	if (!fp) {
		cifsd_err("Failed to allocate memory\n");
		return NULL;
	}

	INIT_LIST_HEAD(&fp->node);
	spin_lock_init(&fp->f_lock);

	fp->filp		= filp;
	fp->conn		= work->sess->conn;
	fp->tcon		= work->tcon;
	fp->volatile_id		= CIFSD_NO_FID;
	fp->persistent_id	= CIFSD_NO_FID;
	fp->f_ci		= cifsd_inode_get(fp);

	if (!fp->f_ci) {
		cifsd_free_file_struct(fp);
		return NULL;
	}

	__open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);
	if (fp->volatile_id == CIFSD_NO_FID) {
		cifsd_inode_put(fp->f_ci);
		cifsd_free_file_struct(fp);
		return NULL;
	}

	write_lock(&fp->f_ci->m_lock);
	list_add(&fp->node, &fp->f_ci->m_fp_list);
	write_unlock(&fp->f_ci->m_lock);

	return fp;
}

/* copy-pasted from old fh */
static inline bool is_reconnectable(struct cifsd_file *fp)
{
	struct oplock_info *opinfo = fp->f_opinfo;
	int reconn = 0;

	if (!opinfo)
		return 0;

	if (opinfo->op_state != OPLOCK_STATE_NONE)
		return 0;

	if (fp->is_resilient || fp->is_persistent)
		reconn = 1;
	else if (fp->is_durable && opinfo->is_lease &&
			opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING)
		reconn = 1;

	else if (fp->is_durable && opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)
		reconn = 1;

	return reconn;
}

void cifsd_close_tree_conn_fds(struct cifsd_work *work)
{
	struct cifsd_session		*sess = work->sess;
	struct cifsd_tree_connect	*tcon = work->tcon;
	unsigned int			id;
	struct cifsd_file		*fp;

	idr_for_each_entry(&sess->file_table.idr, fp, id) {
		if (fp->tcon != tcon)
			continue;

		if (is_reconnectable(fp)) {
			fp->conn = NULL;
			fp->tcon = NULL;
			fp->volatile_id = CIFSD_NO_FID;
			continue;
		}

		if (work->conn->stats.open_files_count > 0)
			work->conn->stats.open_files_count--;

		__cifsd_close_fd(&sess->file_table, fp, id);
	}
}

void cifsd_init_global_file_table(void)
{
	cifsd_init_file_table(&global_ft);
}

void cifsd_free_global_file_table(void)
{
	struct cifsd_file	*fp = NULL;
	unsigned int		id;

	idr_for_each_entry(&global_ft.idr, fp, id)
		cifsd_free_file_struct(fp);

	cifsd_destroy_file_table(&global_ft);
}

int cifsd_reopen_durable_fd(struct cifsd_work *work,
			    struct cifsd_file *fp)
{
	if (!fp->is_durable || fp->conn || fp->tcon) {
		cifsd_err("Invalid durable fd [%p:%p]\n",
				fp->conn, fp->tcon);
		return -EBADF;
	}

	if (fp->volatile_id != CIFSD_NO_FID) {
		cifsd_err("Still in use durable fd: %u\n", fp->volatile_id);
		return -EBADF;
	}

	fp->conn = work->sess->conn;
	fp->tcon = work->tcon;

	__open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);
	if (fp->volatile_id == CIFSD_NO_FID) {
		fp->conn = NULL;
		fp->tcon = NULL;
		return -EBADF;
	}
	return 0;
}

static void close_fd_list(struct cifsd_work *work, struct list_head *head)
{
	while (!list_empty(head)) {
		struct cifsd_file *fp;

		fp = list_first_entry(head, struct cifsd_file, node);
		list_del_init(&fp->node);

		__cifsd_close_fd(&work->sess->file_table, fp, fp->volatile_id);
	}
}

int cifsd_close_inode_fds(struct cifsd_work *work, struct inode *inode)
{
	struct cifsd_inode *ci;
	bool unlinked = true;
	struct cifsd_file *fp, *fptmp;
	LIST_HEAD(dispose);

	ci = cifsd_inode_lookup_by_vfsinode(inode);
	if (!ci)
		return true;

	write_lock(&ci->m_lock);
	list_for_each_entry_safe(fp, fptmp, &ci->m_fp_list, node) {
		if (!fp->conn) {
			if (ci->m_flags & (S_DEL_ON_CLS | S_DEL_PENDING))
				unlinked = false;
			list_del(&fp->node);
			list_add(&fp->node, &dispose);
		}
	}
	write_unlock(&ci->m_lock);
	atomic_dec(&ci->m_count);

	close_fd_list(work, &dispose);
	return unlinked;
}

int cifsd_file_table_flush(struct cifsd_work *work)
{
	struct cifsd_file	*fp = NULL;
	unsigned int		id;
	int			ret;

	down_read(&work->sess->file_table.lock);
	idr_for_each_entry(&work->sess->file_table.idr, fp, id) {
		ret = cifsd_vfs_fsync(work, fp->volatile_id, CIFSD_NO_FID);
		if (ret)
			break;
	}
	up_read(&work->sess->file_table.lock);
	return ret;
}
