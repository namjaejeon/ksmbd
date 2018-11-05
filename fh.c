// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/bootmem.h>
#include <linux/xattr.h>

#include "glob.h"
#include "oplock.h"
#include "buffer_pool.h"
#include "transport_tcp.h"
#include "vfs.h"
#include "mgmt/user_session.h"
#include "smb_common.h"

/**
 * alloc_fid_mem() - alloc memory for fid management
 * @size:	mem allocation request size
 *
 * Return:      ptr to allocated memory or NULL
 */
static void *alloc_fid_mem(size_t size)
{
	return cifsd_alloc(size);
}

/**
 * free_fid_mem() - free memory allocated for fid management
 * @ptr:	ptr to memory to be freed
 */
static void free_fid_mem(void *ptr)
{
	cifsd_free(ptr);
}

/**
 * free_fidtable() - free memory allocated for fid table
 * @ftab:	fid table ptr to be freed
 */
void free_fidtable(struct fidtable *ftab)
{
	if (!ftab)
		return;

	free_fid_mem(ftab->fileid);
	free_fid_mem(ftab->cifsd_bitmap);
	kfree(ftab);
}

/**
 * alloc_fidtable() - alloc fid table
 * @num:	alloc number of entries in fid table
 *
 * Return:      ptr to allocated fid table or NULL
 */
static struct fidtable *alloc_fidtable(unsigned int num)
{
	struct fidtable *ftab;
	void *tmp;

	ftab = kmalloc(sizeof(struct fidtable), GFP_KERNEL);
	if (!ftab) {
		cifsd_err("kmalloc for fidtable failed!\n");
		goto out;
	}

	ftab->max_fids = num;

	tmp = alloc_fid_mem(num * sizeof(void *));
	if (!tmp) {
		cifsd_err("alloc_fid_mem failed!\n");
		goto out_ftab;
	}

	ftab->fileid = tmp;

	tmp = alloc_fid_mem(num / BITS_PER_BYTE);
	if (!tmp) {
		cifsd_err("alloc_fid_mem failed!\n");
		goto out_fileid;
	}

	ftab->cifsd_bitmap = tmp;

	return ftab;

out_fileid:
	free_fid_mem(ftab->fileid);
out_ftab:
	kfree(ftab);
out:
	return NULL;
}

/**
 * copy_fidtable() - copy a fid table
 * @nftab:	destination fid table ptr
 * @oftab:	src fid table ptr
 */
static void copy_fidtable(struct fidtable *nftab, struct fidtable *oftab)
{
	unsigned int cpy, set;

	BUG_ON(nftab->max_fids < oftab->max_fids);

	cpy = oftab->max_fids * sizeof(void *);
	set = (nftab->max_fids - oftab->max_fids) *
		sizeof(void *);
	memcpy(nftab->fileid, oftab->fileid, cpy);
	memset((char *)(nftab->fileid) + cpy, 0, set);

	cpy = oftab->max_fids / BITS_PER_BYTE;
	set = (nftab->max_fids - oftab->max_fids) / BITS_PER_BYTE;
	memcpy(nftab->cifsd_bitmap, oftab->cifsd_bitmap, cpy);
	memset((char *)(nftab->cifsd_bitmap) + cpy, 0, set);
}

/**
 * grow_fidtable() - grow fid table
 * @num:	requested number of entries in fid table
 *
 * Return:      1 if success, otherwise error number
 */
static int grow_fidtable(struct fidtable_desc *ftab_desc, int num)
{
	struct fidtable *new_ftab, *cur_ftab;
	int old_num = num;

	num /= (1024 / sizeof(struct cifsd_file *));
	num = roundup_pow_of_two(num + 1);
	num *= (1024 / sizeof(struct cifsd_file *));

	if (num >= CIFSD_BITMAP_SIZE + 1)
		return -EMFILE;

	new_ftab = alloc_fidtable(num);
	spin_lock(&ftab_desc->fidtable_lock);
	if (!new_ftab) {
		spin_unlock(&ftab_desc->fidtable_lock);
		return -ENOMEM;
	}

	if (unlikely(new_ftab->max_fids <= old_num)) {
		spin_unlock(&ftab_desc->fidtable_lock);
		free_fidtable(new_ftab);
		return -EMFILE;
	}

	cur_ftab = ftab_desc->ftab;
	if (num >= cur_ftab->max_fids) {
		copy_fidtable(new_ftab, cur_ftab);
		ftab_desc->ftab = new_ftab;
		ftab_desc->ftab->start_pos = cur_ftab->start_pos;
		free_fidtable(cur_ftab);
	} else {
		free_fidtable(new_ftab);
	}

	spin_unlock(&ftab_desc->fidtable_lock);
	return 1;
}

/**
 * cifsd_get_unused_id() - get unused fid entry
 * @ftab_desc:	fid table from where fid should be allocated
 *
 * Return:      id if success, otherwise error number
 */
int cifsd_get_unused_id(struct fidtable_desc *ftab_desc)
{
	void *bitmap;
	int id = -EMFILE;
	int err;
	struct fidtable *fidtable;

repeat:
	spin_lock(&ftab_desc->fidtable_lock);
	fidtable = ftab_desc->ftab;
	bitmap = fidtable->cifsd_bitmap;
	id = cifsd_find_next_zero_bit(bitmap,
			fidtable->max_fids, fidtable->start_pos);
	if (id > fidtable->max_fids - 1) {
		spin_unlock(&ftab_desc->fidtable_lock);
		goto grow;
	}

	cifsd_set_bit(id, bitmap);
	fidtable->start_pos = id + 1;
	spin_unlock(&ftab_desc->fidtable_lock);

	return id;

grow:
	err = grow_fidtable(ftab_desc, id);
	if (err == 1)
		goto repeat;

	return err;
}

/**
 * cifsd_close_id() - mark fid entry as free in fid table bitmap
 * @ftab_desc:	fid table from where fid was allocated
 * @id:		fid entry to be marked as free in fid table bitmap
 *
 * If caller of cifsd_close_id() has already checked for
 * invalid value of ID, return value is not checked in that
 * caller. If caller is not checking invalid ID then caller
 * need to do error handling corresponding the return value
 * of cifsd_close_id()
 *
 * Return:      0 if success, otherwise -EINVAL
 */
int cifsd_close_id(struct fidtable_desc *ftab_desc, int id)
{
	void *bitmap;

	if (id > ftab_desc->ftab->max_fids - 1) {
		cifsd_debug("Invalid id passed to clear in bitmap\n");
		return -EINVAL;
	}

	spin_lock(&ftab_desc->fidtable_lock);
	bitmap = ftab_desc->ftab->cifsd_bitmap;
	cifsd_clear_bit(id, bitmap);
	if (id < ftab_desc->ftab->start_pos)
		ftab_desc->ftab->start_pos = id;
	spin_unlock(&ftab_desc->fidtable_lock);
	return 0;
}

/**
 * init_fidtable() - initialize fid table
 * @ftab_desc:	fid table for which bitmap should be allocated and initialized
 *
 * Return:      0 if success, otherwise -ENOMEM
 */
int init_fidtable(struct fidtable_desc *ftab_desc)
{
	ftab_desc->ftab = alloc_fidtable(CIFSD_NR_OPEN_DEFAULT);
	if (!ftab_desc->ftab) {
		cifsd_err("Failed to allocate fid table\n");
		return -ENOMEM;
	}
	ftab_desc->ftab->max_fids = CIFSD_NR_OPEN_DEFAULT;
	ftab_desc->ftab->start_pos = CIFSD_START_FID;
	spin_lock_init(&ftab_desc->fidtable_lock);
	return 0;
}

/* Volatile ID operations */

/**
 * insert_id_in_fidtable() - insert a fid in fid table
 * @conn:	TCP server instance of connection
 * @id:		fid to be inserted into fid table
 * @filp:	associate this filp with fid
 *
 * allocate a cifsd file node, associate given filp with id
 * add insert this fid in fid table by marking it in fid bitmap
 *
 * Return:      cifsd file pointer if success, otherwise NULL
 */
struct cifsd_file *
insert_id_in_fidtable(struct cifsd_session *sess,
	struct cifsd_tree_connect *tcon, unsigned int id, struct file *filp)
{
	struct cifsd_file *fp = NULL;
	struct fidtable *ftab;

	fp = cifsd_alloc_file_struct();
	if (!fp) {
		cifsd_err("Failed to allocate memory for id (%u)\n", id);
		return NULL;
	}

	fp->filp = filp;
	fp->conn = sess->conn;
	fp->tcon = tcon;
	fp->sess = sess;
	fp->f_state = FP_NEW;
	fp->volatile_id = id;
	INIT_LIST_HEAD(&fp->node);
	spin_lock_init(&fp->f_lock);
	init_waitqueue_head(&fp->wq);

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	BUG_ON(ftab->fileid[id] != NULL);
	ftab->fileid[id] = fp;
	spin_unlock(&sess->fidtable.fidtable_lock);

	return ftab->fileid[id];
}

/**
 * get_id_from_fidtable() - get cifsd file pointer for a fid
 * @conn:	TCP server instance of connection
 * @id:		fid to be looked into fid table
 *
 * lookup a fid in fid table and return associated cifsd file pointer
 *
 * Return:      cifsd file pointer if success, otherwise NULL
 */
struct cifsd_file *
get_id_from_fidtable(struct cifsd_session *sess, uint64_t id)
{
	struct cifsd_file *file;
	struct fidtable *ftab;

	if (!sess)
		return NULL;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	if ((id < CIFSD_START_FID) || (id > ftab->max_fids - 1)) {
		spin_unlock(&sess->fidtable.fidtable_lock);
		cifsd_debug("invalid fileid (%llu)\n", id);
		return NULL;
	}

	file = ftab->fileid[id];
	if (!file) {
		spin_unlock(&sess->fidtable.fidtable_lock);
		return NULL;
	}

	spin_lock(&file->f_lock);
	if (file->f_state == FP_FREEING) {
		spin_unlock(&file->f_lock);
		spin_unlock(&sess->fidtable.fidtable_lock);
		return NULL;
	}

	spin_unlock(&file->f_lock);
	spin_unlock(&sess->fidtable.fidtable_lock);
	return file;
}

struct cifsd_file *get_fp(struct cifsd_work *work, int64_t req_vid,
	int64_t req_pid)
{
	struct cifsd_session *sess = work->sess;
	struct cifsd_tree_connect *tcon = work->tcon;
	struct cifsd_file *fp;
	int64_t vid, pid;

	if (req_vid == -1) {
		cifsd_debug("Compound request assigning stored FID = %llu\n",
				work->cur_local_fid);
		vid = work->cur_local_fid;
		pid = work->cur_local_pfid;
	} else {
		vid = req_vid;
		pid = req_pid;
	}

	fp = get_id_from_fidtable(work->sess, vid);
	if (!fp) {
		cifsd_debug("Invalid id: %llu\n", vid);
		return NULL;
	}

	if (fp->sess != sess || fp->tcon != tcon) {
		cifsd_err("invalid sess or tcon\n");
		return NULL;
	}

	if (IS_SMB2(work->conn) && fp->persistent_id != pid) {
		cifsd_err("persistent id mismatch : %lld, %lld\n",
				fp->persistent_id, pid);
		fp = NULL;
	}

	return fp;
}

struct cifsd_file *find_fp_using_filename(struct cifsd_session *sess,
	char *filename)
{
	struct cifsd_file *file = NULL;
	struct fidtable *ftab;
	int id;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	spin_unlock(&sess->fidtable.fidtable_lock);

	if (!ftab)
		return NULL;

	for (id = 0; id < ftab->max_fids; id++) {
		file = ftab->fileid[id];
		if (file && !strcmp(file->filename, filename))
			break;
		file = NULL;
	}

	return file;
}

struct cifsd_file *find_fp_using_inode(struct inode *inode)
{
	struct cifsd_file *lfp;
	struct cifsd_inode *ci;
	struct list_head *cur;

	ci = cifsd_inode_lookup_by_vfsinode(inode);
	if (!ci)
		goto out;

	spin_lock(&ci->m_lock);
	list_for_each(cur, &ci->m_fp_list) {
		lfp = list_entry(cur, struct cifsd_file, node);
		if (inode == FP_INODE(lfp)) {
			atomic_dec(&ci->m_count);
			spin_unlock(&ci->m_lock);
			return lfp;
		}
	}
	atomic_dec(&ci->m_count);
	spin_unlock(&ci->m_lock);

out:
	return NULL;
}

/**
 * delete_id_from_fidtable() - delete a fid from fid table
 * @conn:	TCP server instance of connection
 * @id:		fid to be deleted from fid table
 *
 * delete a fid from fid table and free associated cifsd file pointer
 */
void delete_id_from_fidtable(struct cifsd_session *sess, unsigned int id)
{
	struct fidtable *ftab;
	struct cifsd_file *fp;

	if (!sess)
		return;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	fp = ftab->fileid[id];
	ftab->fileid[id] = NULL;
	spin_lock(&fp->f_lock);
	kfree(fp->filename);
	if (fp->is_stream)
		kfree(fp->stream.name);
	fp->f_ci = NULL;
	spin_unlock(&fp->f_lock);
	cifsd_free_file_struct(fp);
	spin_unlock(&sess->fidtable.fidtable_lock);
}

static void inherit_delete_pending(struct cifsd_file *fp)
{
	struct list_head *cur;
	struct cifsd_file *prev_fp;
	struct cifsd_inode *ci = fp->f_ci;

	fp->delete_on_close = 0;

	spin_lock(&ci->m_lock);
	list_for_each_prev(cur, &ci->m_fp_list) {
		prev_fp = list_entry(cur, struct cifsd_file, node);
		if (fp != prev_fp && (fp->sess == prev_fp->sess ||
				ci->m_flags & S_DEL_ON_CLS))
			ci->m_flags |= S_DEL_PENDING;
	}
	spin_unlock(&ci->m_lock);
}

static void invalidate_delete_on_close(struct cifsd_file *fp)
{
	struct list_head *cur;
	struct cifsd_file *prev_fp;
	struct cifsd_inode *ci = fp->f_ci;

	spin_lock(&ci->m_lock);
	list_for_each_prev(cur, &ci->m_fp_list) {
		prev_fp = list_entry(cur, struct cifsd_file, node);
		if (fp == prev_fp)
			break;
		if (fp->sess == prev_fp->sess)
			prev_fp->delete_on_close = 0;
	}
	spin_unlock(&ci->m_lock);
}

static int close_fp(struct cifsd_file *fp)
{
	struct cifsd_session *sess = fp->sess;
	struct cifsd_inode *ci;
	struct file *filp;
	struct dentry *dir, *dentry;
	struct cifsd_work *cancel_work, *ctmp;
	int err;

	ci = fp->f_ci;
	if (atomic_read(&ci->m_count) >= 2) {
		if (fp->delete_on_close)
			inherit_delete_pending(fp);
		else
			invalidate_delete_on_close(fp);
	}

	close_id_del_oplock(fp);

	if (fp->islink)
		filp = fp->lfilp;
	else
		filp = fp->filp;

	spin_lock(&fp->f_lock);
	list_for_each_entry_safe(cancel_work, ctmp, &fp->blocked_works,
		fp_entry) {
		list_del(&cancel_work->fp_entry);
		cancel_work->state = WORK_STATE_CLOSED;
		cancel_work->cancel_fn(cancel_work->cancel_argv);
	}
	spin_unlock(&fp->f_lock);

	if (fp->is_stream && (ci->m_flags & S_DEL_ON_CLS_STREAM)) {
		ci->m_flags &= ~S_DEL_ON_CLS_STREAM;
		err = cifsd_vfs_remove_xattr(filp->f_path.dentry,
					     fp->stream.name);
		if (err)
			cifsd_err("remove xattr failed : %s\n",
				fp->stream.name);

	}

	if (atomic_dec_and_test(&ci->m_count)) {
		spin_lock(&ci->m_lock);
		if ((ci->m_flags & (S_DEL_ON_CLS | S_DEL_PENDING)) ||
				fp->delete_on_close) {
			dentry = filp->f_path.dentry;
			dir = dentry->d_parent;
			ci->m_flags &= ~(S_DEL_ON_CLS | S_DEL_PENDING);
			spin_unlock(&ci->m_lock);
			cifsd_vfs_unlink(dir, dentry);
			spin_lock(&ci->m_lock);
		}
		spin_unlock(&ci->m_lock);

		cifsd_inode_free(ci);
	}

	if (fp->persistent_id > 0) {
		err = close_persistent_id(fp->persistent_id);
		if (err)
			return -ENOENT;
	}

	if (sess) {
		cifsd_close_id(&sess->fidtable, fp->volatile_id);
		delete_id_from_fidtable(sess, fp->volatile_id);
	}
	filp_close(filp, (struct files_struct *)filp);
	return 0;
}

/**
 * close_id() - close filp for a fid and delete it from fid table
 * @conn:	TCP server instance of connection
 * @id:		fid to be deleted from fid table
 *
 * lookup fid from fid table, release oplock info and close associated filp.
 * delete fid, free associated cifsd file pointer and clear fid bitmap entry
 * in fid table.
 *
 * Return:      0 on success, otherwise error number
 */
int close_id(struct cifsd_session *sess, uint64_t id, uint64_t p_id)
{
	struct cifsd_file *fp;

	if (p_id != CIFSD_NO_FID) {
		fp = cifsd_get_global_fp(p_id);
		if (!fp || fp->sess != sess) {
			cifsd_err("Invalid id for close: %llu\n", p_id);
			return -EINVAL;
		}
	} else {
		fp = get_id_from_fidtable(sess, id);
		if (!fp) {
			cifsd_err("Invalid id for close: %llu\n", id);
			return -EINVAL;
		}
	}

	spin_lock(&fp->f_lock);
	fp->f_state = FP_FREEING;
	list_del(&fp->node);
	spin_unlock(&fp->f_lock);

	return close_fp(fp);
}

/**
 * close_opens_from_fibtable() - close all opens from a fid table
 * @sess:	session
 *
 * lookup fid from fid table, release oplock info and close associated filp.
 * delete fid, free associated cifsd file pointer and clear fid bitmap entry
 * in fid table.
 */
void close_opens_from_fibtable(struct cifsd_session *sess,
			       struct cifsd_tree_connect *tcon)
{
	struct cifsd_file *file;
	struct fidtable *ftab;
	int id;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	spin_unlock(&sess->fidtable.fidtable_lock);

	for (id = 0; id < ftab->max_fids; id++) {
		file = ftab->fileid[id];
		if (file && file->tcon == tcon) {
			if (!close_id(sess, id, file->persistent_id) &&
				sess->conn->stats.open_files_count > 0)
				sess->conn->stats.open_files_count--;
		}
	}
}

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

/**
 * destroy_fidtable() - destroy a fid table for given cifsd thread
 * @sess:	session
 *
 * lookup fid from fid table, release oplock info and close associated filp.
 * delete fid, free associated cifsd file pointer and clear fid bitmap entry
 * in fid table.
 */
void destroy_fidtable(struct cifsd_session *sess)
{
	struct cifsd_file *file;
	struct fidtable *ftab;
	int id;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	spin_unlock(&sess->fidtable.fidtable_lock);

	if (!ftab)
		return;

	for (id = 0; id < ftab->max_fids; id++) {
		file = ftab->fileid[id];
		if (file) {
			if (is_reconnectable(file)) {
				file->conn = NULL;
				file->sess = NULL;
				file->tcon = NULL;
				continue;
			}

			if (!close_id(sess, id, file->persistent_id) &&
				sess->conn->stats.open_files_count > 0)
				sess->conn->stats.open_files_count--;
		}
	}
	sess->fidtable.ftab = NULL;
	free_fidtable(ftab);
}

/* End of Volatile-ID operations */

/* Persistent-ID operations */

/**
 * cifsd_insert_in_global_table() - insert a fid in global fid table
 *					for persistent id
 * @conn:		TCP server instance of connection
 * @volatile_id:	volatile id
 * @filp:		file pointer
 * @durable_open:	true if durable open is requested
 *
 * Return:      persistent_id on success, otherwise error number
 */
int cifsd_insert_in_global_table(struct cifsd_session *sess,
				 struct cifsd_file *fp)
{
	int persistent_id;
	struct fidtable *ftab;

	persistent_id = cifsd_get_unused_id(&global_fidtable);

	if (persistent_id < 0) {
		cifsd_err("failed to get unused persistent_id for file\n");
		return persistent_id;
	}

	cifsd_debug("persistent_id allocated %d", persistent_id);

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	BUG_ON(ftab->fileid[persistent_id] != NULL);
	ftab->fileid[persistent_id] = fp;
	spin_unlock(&global_fidtable.fidtable_lock);

	return persistent_id;
}

/**
 * cifsd_get_global_fp() - get durable state info for a fid
 * @id:		persistent id
 *
 * Return:      durable state on success, otherwise NULL
 */
struct cifsd_file *cifsd_get_global_fp(uint64_t pid)
{
	struct cifsd_file *durable_fp;
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	if (pid > ftab->max_fids - 1) {
		cifsd_err("invalid persistentID (%lld)\n", pid);
		spin_unlock(&global_fidtable.fidtable_lock);
		return NULL;
	}

	durable_fp = ftab->fileid[pid];
	spin_unlock(&global_fidtable.fidtable_lock);
	return durable_fp;
}

struct cifsd_file *lookup_fp_clguid(char *createguid)
{
	struct cifsd_file *fp = NULL;
	struct fidtable *ftab;
	int i;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	spin_unlock(&global_fidtable.fidtable_lock);

	for (i = 0; i < ftab->max_fids; i++) {
		fp = ftab->fileid[i];
		if (fp && !memcmp(fp->create_guid, createguid,
			SMB2_CREATE_GUID_SIZE))
			break;
		fp = NULL;
	}

	return fp;
}

struct cifsd_file *lookup_fp_app_id(char *app_id)
{
	struct cifsd_file *fp = NULL;
	struct fidtable *ftab;
	int i;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	spin_unlock(&global_fidtable.fidtable_lock);

	for (i = 0; i < ftab->max_fids; i++) {
		fp = ftab->fileid[i];
		if (fp && !memcmp(fp->app_instance_id, app_id,
			SMB2_CREATE_GUID_SIZE))
			break;
		fp = NULL;
	}

	return fp;
}

/**
 * cifsd_update_durable_state() - update durable state for a fid
 * @conn:		TCP server instance of connection
 * @persistent_id:	persistent id
 * @volatile_id:	volatile id
 * @filp:		file pointer
 */
int cifsd_reconnect_durable_fp(struct cifsd_session *sess,
			       struct cifsd_file *fp,
			       struct cifsd_tree_connect *tcon)
{
	struct fidtable *ftab;
	unsigned int volatile_id;
	struct cifsd_file *dfp;

	if (!fp->is_durable || fp->conn || fp->sess) {
		cifsd_err("invalid durable fp, is_durable : %d, conn : %p, sess : %p\n",
			fp->is_durable, fp->conn, fp->sess);
		return -EBADF;
	}

	/* find durable fp is still opened */
	dfp = get_id_from_fidtable(sess, fp->volatile_id);
	if (dfp) {
		cifsd_err("find durable fp is still opened\n");
		return -EBADF;
	}

	/* Obtain Volatile-ID */
	volatile_id = cifsd_get_unused_id(&sess->fidtable);
	if (volatile_id < 0) {
		cifsd_err("failed to get unused volatile_id for file\n");
		return -EBADF;
	}

	fp->conn = sess->conn;
	fp->sess = sess;
	fp->tcon = tcon;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	WARN_ON(ftab->fileid[volatile_id] != NULL);
	ftab->fileid[volatile_id] = fp;
	spin_unlock(&sess->fidtable.fidtable_lock);
	cifsd_debug("durable file updated volatile ID (%u)\n",
		      volatile_id);

	return 0;
}

/**
 * delete_durable_id_from_fidtable() - delete a durable id from fid table
 * @id:	durable id to be deleted from fid table
 *
 * delete a durable id from fid table and free associated cifsd file pointer
 */
void delete_durable_id_from_fidtable(uint64_t id)
{
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	ftab->fileid[id] = NULL;
	spin_unlock(&global_fidtable.fidtable_lock);
}

/**
 * close_persistent_id() - delete a persistent id from global fid table
 * @id:		persistent id
 *
 * Return:      0 on success, otherwise error number
 */
int close_persistent_id(uint64_t id)
{
	int rc = 0;

	if (id > global_fidtable.ftab->max_fids - 1) {
		cifsd_debug("Invalid id passed to clear in bitmap\n");
		return -EINVAL;
	}

	delete_durable_id_from_fidtable(id);
	rc = cifsd_close_id(&global_fidtable, id);
	return rc;
}

/**
 * destroy_global_fidtable() - destroy global fid table at module exit
 */
void destroy_global_fidtable(void)
{
	struct cifsd_file *fp;
	struct fidtable *ftab;
	int i;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	global_fidtable.ftab = NULL;
	spin_unlock(&global_fidtable.fidtable_lock);

	for (i = 0; i < ftab->max_fids; i++) {
		fp = ftab->fileid[i];
		kfree(fp);
		ftab->fileid[i] = NULL;
	}
	free_fidtable(ftab);
}

/* End of persistent-ID functions */

static void dispose_fp_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct cifsd_file *fp;

		fp = list_first_entry(head, struct cifsd_file, node);
		list_del_init(&fp->node);

		close_fp(fp);
		cond_resched();
	}
}

static unsigned int inode_hash_mask __read_mostly;
static unsigned int inode_hash_shift __read_mostly;
static struct hlist_head *inode_hashtable __read_mostly;
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(inode_hash_lock);

int close_disconnected_handle(struct inode *inode)
{
	struct cifsd_inode *ci;
	bool unlinked = true;
	LIST_HEAD(dispose);

	ci = cifsd_inode_lookup_by_vfsinode(inode);
	if (ci) {
		struct cifsd_file *fp, *fptmp;

		spin_lock(&ci->m_lock);
		list_for_each_entry_safe(fp, fptmp, &ci->m_fp_list, node) {
			if (!fp->conn) {
				if (ci->m_flags &
					(S_DEL_ON_CLS | S_DEL_PENDING))
					unlinked = false;
				spin_lock(&fp->f_lock);
				if (fp->f_state != FP_FREEING) {
					list_del(&fp->node);
					list_add(&fp->node, &dispose);
					fp->f_state = FP_FREEING;
				}
				spin_unlock(&fp->f_lock);
			}
		}
		spin_unlock(&ci->m_lock);
		atomic_dec(&ci->m_count);
	}

	dispose_fp_list(&dispose);

	return unlinked;
}

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
			atomic_inc(&ci->m_count);
			ret_ci = ci;
			break;
		}
	}

	return ret_ci;
}

struct cifsd_inode *cifsd_inode_lookup(struct cifsd_file *fp)
{
	return __cifsd_inode_lookup(FP_INODE(fp));
}

struct cifsd_inode *cifsd_inode_lookup_by_vfsinode(struct inode *inode)
{
	struct cifsd_inode *ci;

	spin_lock(&inode_hash_lock);
	ci = __cifsd_inode_lookup(inode);
	spin_unlock(&inode_hash_lock);

	return ci;
}

void cifsd_inode_hash(struct cifsd_inode *ci)
{
	struct hlist_head *b = inode_hashtable +
		inode_hash(ci->m_inode->i_sb, ci->m_inode->i_ino);

	hlist_add_head(&ci->m_hash, b);
}

void cifsd_inode_unhash(struct cifsd_inode *ci)
{
	hlist_del_init(&ci->m_hash);
}

int cifsd_inode_init(struct cifsd_inode *ci, struct cifsd_file *fp)
{
	ci->m_inode = FP_INODE(fp);
	atomic_set(&ci->m_count, 1);
	atomic_set(&ci->op_count, 0);
	ci->m_flags = 0;
	INIT_LIST_HEAD(&ci->m_fp_list);
	INIT_LIST_HEAD(&ci->m_op_list);
	spin_lock_init(&ci->m_lock);
	ci->is_stream = false;

	if (fp->is_stream) {
		ci->stream_name = kmalloc(fp->stream.size + 1, GFP_KERNEL);
		if (!ci->stream_name)
			return -ENOMEM;
		strncpy(ci->stream_name, fp->stream.name, fp->stream.size);
		ci->is_stream = true;
	}

	return 0;
}

struct cifsd_inode *cifsd_inode_get(struct cifsd_file *fp)
{
	struct cifsd_inode *ci, *tmpci;
	int rc;

	spin_lock(&inode_hash_lock);
	ci = cifsd_inode_lookup(fp);
	spin_unlock(&inode_hash_lock);
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

	spin_lock(&inode_hash_lock);
	tmpci = cifsd_inode_lookup(fp);
	if (!tmpci) {
		cifsd_inode_hash(ci);
	} else {
		kfree(ci);
		ci = tmpci;
	}
	spin_unlock(&inode_hash_lock);
	return ci;
}

void cifsd_inode_free(struct cifsd_inode *ci)
{
	cifsd_inode_unhash(ci);
	if (ci->is_stream)
		kfree(ci->stream_name);
	kfree(ci);
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
