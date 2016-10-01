/*
 *   fs/cifssrv/fh.c
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

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#include "oplock.h"

/**
 * alloc_fid_mem() - alloc memory for fid management
 * @size:	mem allocation request size
 *
 * Return:      ptr to allocated memory or NULL
 */
static void *alloc_fid_mem(size_t size)
{
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		return kzalloc(size, GFP_KERNEL|
				__GFP_NOWARN|__GFP_NORETRY);
	}
	return vzalloc(size);
}

/**
 * free_fid_mem() - free memory allocated for fid management
 * @ptr:	ptr to memory to be freed
 */
static void free_fid_mem(void *ptr)
{
	is_vmalloc_addr(ptr) ? vfree(ptr) : kfree(ptr);
}

/**
 * free_fidtable() - free memory allocated for fid table
 * @ftab:	fid table ptr to be freed
 */
void free_fidtable(struct fidtable *ftab)
{
	free_fid_mem(ftab->fileid);
	free_fid_mem(ftab->cifssrv_bitmap);
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
		cifssrv_err("kmalloc for fidtable failed!\n");
		goto out;
	}

	ftab->max_fids = num;

	tmp = alloc_fid_mem(num * sizeof(void *));
	if (!tmp) {
		cifssrv_err("alloc_fid_mem failed!\n");
		goto out_ftab;
	}

	ftab->fileid = tmp;

	tmp = alloc_fid_mem(num / BITS_PER_BYTE);
	if (!tmp) {
		cifssrv_err("alloc_fid_mem failed!\n");
		goto out_fileid;
	}

	ftab->cifssrv_bitmap = tmp;

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
	memcpy(nftab->cifssrv_bitmap, oftab->cifssrv_bitmap, cpy);
	memset((char *)(nftab->cifssrv_bitmap) + cpy, 0, set);
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

	num /= (1024 / sizeof(struct cifssrv_file *));
	num = roundup_pow_of_two(num + 1);
	num *= (1024 / sizeof(struct cifssrv_file *));

	if (num >= CIFSSRV_BITMAP_SIZE + 1)
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
 * cifssrv_get_unused_id() - get unused fid entry
 * @ftab_desc:	fid table from where fid should be allocated
 *
 * Return:      id if success, otherwise error number
 */
int cifssrv_get_unused_id(struct fidtable_desc *ftab_desc)
{
	void *bitmap;
	int id = -EMFILE;
	int err;
	struct fidtable *fidtable;

repeat:
	spin_lock(&ftab_desc->fidtable_lock);
	fidtable = ftab_desc->ftab;
	bitmap = fidtable->cifssrv_bitmap;
	id = cifssrv_find_next_zero_bit(bitmap,
			fidtable->max_fids, fidtable->start_pos);
	if (id > fidtable->max_fids - 1) {
		spin_unlock(&ftab_desc->fidtable_lock);
		goto grow;
	}

	cifssrv_set_bit(id, bitmap);
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
 * cifssrv_close_id() - mark fid entry as free in fid table bitmap
 * @ftab_desc:	fid table from where fid was allocated
 * @id:		fid entry to be marked as free in fid table bitmap
 *
 * If caller of cifssrv_close_id() has already checked for
 * invalid value of ID, return value is not checked in that
 * caller. If caller is not checking invalid ID then caller
 * need to do error handling corresponding the return value
 * of cifssrv_close_id()
 *
 * Return:      0 if success, otherwise -EINVAL
 */
int cifssrv_close_id(struct fidtable_desc *ftab_desc, int id)
{
	void *bitmap;

	if (id >= ftab_desc->ftab->max_fids - 1) {
		cifssrv_debug("Invalid id passed to clear in bitmap\n");
		return -EINVAL;
	}

	spin_lock(&ftab_desc->fidtable_lock);
	bitmap = ftab_desc->ftab->cifssrv_bitmap;
	cifssrv_clear_bit(id, bitmap);
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
	ftab_desc->ftab = alloc_fidtable(CIFSSRV_NR_OPEN_DEFAULT);
	if (!ftab_desc->ftab) {
		cifssrv_err("Failed to allocate fid table\n");
		return -ENOMEM;
	}
	ftab_desc->ftab->max_fids = CIFSSRV_NR_OPEN_DEFAULT;
	ftab_desc->ftab->start_pos = 1;
	spin_lock_init(&ftab_desc->fidtable_lock);
	return 0;
}

/* Volatile ID operations */

/**
 * insert_id_in_fidtable() - insert a fid in fid table
 * @server:	TCP server instance of connection
 * @id:		fid to be inserted into fid table
 * @filp:	associate this filp with fid
 *
 * allocate a cifssrv file node, associate given filp with id
 * add insert this fid in fid table by marking it in fid bitmap
 *
 * Return:      cifssrv file pointer if success, otherwise NULL
 */
struct cifssrv_file *
insert_id_in_fidtable(struct cifssrv_sess *sess, uint64_t sess_id,
		unsigned int id, struct file *filp)
{
	struct cifssrv_file *fp = NULL;
	struct fidtable *ftab;

	fp = kzalloc(sizeof(struct cifssrv_file), GFP_KERNEL);
	if (!fp) {
		cifssrv_err("Failed to allocate memory for id (%u)\n", id);
		return NULL;
	}

	fp->filp = filp;
#ifdef CONFIG_CIFS_SMB2_SERVER
	fp->sess_id = sess_id;
#endif

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	BUG_ON(ftab->fileid[id] != NULL);
	ftab->fileid[id] = fp;
	spin_unlock(&sess->fidtable.fidtable_lock);

	return ftab->fileid[id];
}

/**
 * get_id_from_fidtable() - get cifssrv file pointer for a fid
 * @server:	TCP server instance of connection
 * @id:		fid to be looked into fid table
 *
 * lookup a fid in fid table and return associated cifssrv file pointer
 *
 * Return:      cifssrv file pointer if success, otherwise NULL
 */
struct cifssrv_file *
get_id_from_fidtable(struct cifssrv_sess *sess, uint64_t id)
{
	struct cifssrv_file *file;
	struct fidtable *ftab;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	if ((id < CIFSSRV_START_FID) || (id > ftab->max_fids - 1)) {
		spin_unlock(&sess->fidtable.fidtable_lock);
		cifssrv_debug("invalid fileid (%llu)\n", id);
		return NULL;
	}

	file = ftab->fileid[id];
	spin_unlock(&sess->fidtable.fidtable_lock);
	return file;
}

/**
 * delete_id_from_fidtable() - delete a fid from fid table
 * @server:	TCP server instance of connection
 * @id:		fid to be deleted from fid table
 *
 * delete a fid from fid table and free associated cifssrv file pointer
 */
void delete_id_from_fidtable(struct cifssrv_sess *sess, unsigned int id)
{
	struct cifssrv_file *fp;
	struct fidtable *ftab;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	BUG_ON(!ftab->fileid[id]);
	fp = ftab->fileid[id];
	kfree(fp);
	ftab->fileid[id] = NULL;
	spin_unlock(&sess->fidtable.fidtable_lock);
}

/**
 * close_id() - close filp for a fid and delete it from fid table
 * @server:	TCP server instance of connection
 * @id:		fid to be deleted from fid table
 *
 * lookup fid from fid table, release oplock info and close associated filp.
 * delete fid, free associated cifssrv file pointer and clear fid bitmap entry
 * in fid table.
 *
 * Return:      0 on success, otherwise error number
 */
int close_id(struct cifssrv_sess *sess, uint64_t id)
{
	struct cifssrv_file *fp;
	struct file *filp;
	struct dentry *dir, *dentry;
	int err;

	fp = get_id_from_fidtable(sess, id);
	if (!fp) {
		cifssrv_debug("Invalid id for close: %llu\n", id);
		return -EINVAL;
	}

	close_id_del_oplock(sess->server, fp, id);

	if (fp->islink)
		filp = fp->lfilp;
	else
		filp = fp->filp;

	if (fp->delete_on_close) {
		dentry = filp->f_path.dentry;
		dir = dentry->d_parent;

		dget(dentry);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 10)
		inode_lock(dir->d_inode);
#else
		mutex_lock(&dir->d_inode->i_mutex);
#endif
		if (!dentry->d_inode || !dentry->d_inode->i_nlink) {
			err = -ENOENT;
			goto out;
		}

		if (S_ISDIR(dentry->d_inode->i_mode))
			err = vfs_rmdir(dir->d_inode, dentry);
		else
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
			err = vfs_unlink(dir->d_inode, dentry, NULL);
#else
		err = vfs_unlink(dir->d_inode, dentry);
#endif

out:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 10)
		inode_unlock(dir->d_inode);
#else
		mutex_unlock(&dir->d_inode->i_mutex);
#endif
		dput(dentry);
		if (err)
			cifssrv_debug("failed to delete, err %d\n", err);
	}

	filp_close(filp, (struct files_struct *)filp);
	delete_id_from_fidtable(sess, id);
	cifssrv_close_id(&sess->fidtable, id);
	return 0;
}

/**
 * destroy_fidtable() - destroy a fid table for given cifssrv thread
 * @sess:	TCP server session
 *
 * lookup fid from fid table, release oplock info and close associated filp.
 * delete fid, free associated cifssrv file pointer and clear fid bitmap entry
 * in fid table.
 */
void destroy_fidtable(struct cifssrv_sess *sess)
{
	struct cifssrv_file *file;
	struct fidtable *ftab;
	int id;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;
	spin_unlock(&sess->fidtable.fidtable_lock);

	for (id = 0; id < ftab->max_fids; id++) {
		file = ftab->fileid[id];
		if (file) {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (file->is_durable)
				close_persistent_id(file->persistent_id);
#endif

			close_id(sess, id);
		}
	}
	sess->fidtable.ftab = NULL;
	free_fidtable(ftab);
}

/* End of Volatile-ID operations */

/* Persistent-ID operations */

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * cifssrv_insert_in_global_table() - insert a fid in global fid table
 *					for persistent id
 * @server:		TCP server instance of connection
 * @volatile_id:	volatile id
 * @filp:		file pointer
 * @durable_open:	true if durable open is requested
 *
 * Return:      persistent_id on success, otherwise error number
 */
int cifssrv_insert_in_global_table(struct cifssrv_sess *sess,
				   int volatile_id, struct file *filp,
				   int durable_open)
{
	int rc;
	int persistent_id;
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;

	persistent_id = cifssrv_get_unused_id(&global_fidtable);

	if (persistent_id < 0) {
		cifssrv_err("failed to get unused persistent_id for file\n");
		rc = persistent_id;
		return rc;
	}

	cifssrv_debug("persistent_id allocated %d", persistent_id);

	/* If not durable open just return the ID.
	 * No need to store durable state */
	if (!durable_open)
		return persistent_id;

	durable_state = kzalloc(sizeof(struct cifssrv_durable_state),
			GFP_KERNEL);

	if (durable_state == NULL) {
		cifssrv_err("persistent_id insert failed\n");
		cifssrv_close_id(&global_fidtable, persistent_id);
		rc = -ENOMEM;
		return rc;
	}

	durable_state->sess = sess;
	durable_state->volatile_id = volatile_id;
	generic_fillattr(filp->f_path.dentry->d_inode, &durable_state->stat);
	durable_state->refcount = 1;

	cifssrv_debug("filp stored = 0x%p sess = 0x%p\n", filp, sess);

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	BUG_ON(ftab->fileid[persistent_id] != NULL);
	ftab->fileid[persistent_id] = (void *)durable_state;
	spin_unlock(&global_fidtable.fidtable_lock);

	return persistent_id;
}

/**
 * cifssrv_get_durable_state() - get durable state info for a fid
 * @id:		persistent id
 *
 * Return:      durable state on success, otherwise NULL
 */
struct cifssrv_durable_state *
cifssrv_get_durable_state(uint64_t id)
{
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	if ((id < CIFSSRV_START_FID) || (id > ftab->max_fids - 1)) {
		cifssrv_err("invalid persistentID (%llu)\n", id);
		spin_unlock(&global_fidtable.fidtable_lock);
		return NULL;
	}

	durable_state = (struct cifssrv_durable_state *)ftab->fileid[id];
	spin_unlock(&global_fidtable.fidtable_lock);
	return durable_state;
}

/**
 * cifssrv_update_durable_state() - update durable state for a fid
 * @server:		TCP server instance of connection
 * @persistent_id:	persistent id
 * @volatile_id:	volatile id
 * @filp:		file pointer
 */
void cifssrv_update_durable_state(struct cifssrv_sess *sess,
			     unsigned int persistent_id,
			     unsigned int volatile_id, struct file *filp)
{
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;

	durable_state =
		(struct cifssrv_durable_state *)ftab->fileid[persistent_id];

	durable_state->sess = sess;
	durable_state->volatile_id = volatile_id;
	generic_fillattr(filp->f_path.dentry->d_inode, &durable_state->stat);
	durable_state->refcount++;
	spin_unlock(&global_fidtable.fidtable_lock);
	cifssrv_debug("durable state updated persistentID (%u)\n",
		      persistent_id);
}

/**
 * cifssrv_durable_disconnect() - update file stat with durable state
 * @server:		TCP server instance of connection
 * @persistent_id:	persistent id
 * @filp:		file pointer
 */
void cifssrv_durable_disconnect(struct tcp_server_info *server,
			   unsigned int persistent_id, struct file *filp)
{
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;

	durable_state =
		(struct cifssrv_durable_state *)ftab->fileid[persistent_id];
	BUG_ON(durable_state == NULL);
	generic_fillattr(filp->f_path.dentry->d_inode, &durable_state->stat);
	spin_unlock(&global_fidtable.fidtable_lock);
	cifssrv_debug("durable state disconnect persistentID (%u)\n",
		    persistent_id);
}

/**
 * cifssrv_delete_durable_state() - delete durable state for a id
 * @id:		persistent id
 *
 * Return:      0 or 1 on success, otherwise error number
 */
int cifssrv_delete_durable_state(uint64_t id)
{
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	if (id >= ftab->max_fids - 1) {
		cifssrv_err("Invalid id %llu\n", id);
		spin_unlock(&global_fidtable.fidtable_lock);
		return -EINVAL;
	}
	durable_state = (struct cifssrv_durable_state *)ftab->fileid[id];

	/* If refcount > 1 return 1 to avoid deletion of persistent-id
	   from the global_fidtable bitmap */
	if (durable_state && durable_state->refcount > 1) {
		--durable_state->refcount;
		spin_unlock(&global_fidtable.fidtable_lock);
		return 1;
	}

	/* Check if durable state is associated with file
	   before deleting persistent id of a opened file,
	   because opened file may or may not be associated
	   with a durable handle */
	if (durable_state) {
		cifssrv_debug("durable state delete persistentID (%llu) refcount = %d\n",
			    id, durable_state->refcount);
		kfree(durable_state);
	}

	ftab->fileid[id] = NULL;
	spin_unlock(&global_fidtable.fidtable_lock);
	return 0;
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

	rc = cifssrv_delete_durable_state(id);
	if (rc < 0)
		return rc;
	else if (rc > 0)
		return 0;

	rc = cifssrv_close_id(&global_fidtable, id);
	return rc;
}

/**
 * destroy_global_fidtable() - destroy global fid table at module exit
 */
void destroy_global_fidtable(void)
{
	struct cifssrv_durable_state *durable_state;
	struct fidtable *ftab;
	int i;

	spin_lock(&global_fidtable.fidtable_lock);
	ftab = global_fidtable.ftab;
	global_fidtable.ftab = NULL;
	spin_unlock(&global_fidtable.fidtable_lock);

	for (i = 0; i < ftab->max_fids; i++) {
		durable_state = (struct cifssrv_durable_state *)ftab->fileid[i];
			kfree(durable_state);
			ftab->fileid[i] = NULL;
	}
	free_fidtable(ftab);
}
#endif

/**
 * cifssrv_check_stat_info() - compare durable state and current inode stat
 * @durable_stat:	inode stat stored in durable state
 * @current_stat:	current inode stat
 *
 * Return:		0 if mismatch, 1 if no mismatch
 */
int cifssrv_check_stat_info(struct kstat *durable_stat,
				struct kstat *current_stat)
{
	if (durable_stat->ino != current_stat->ino) {
		cifssrv_err("Inode mismatch\n");
		return 0;
	}

	if (durable_stat->dev != current_stat->dev) {
		cifssrv_err("Device mismatch\n");
		return 0;
	}

	if (durable_stat->mode != current_stat->mode) {
		cifssrv_err("Mode mismatch\n");
		return 0;
	}

	if (durable_stat->nlink != current_stat->nlink) {
		cifssrv_err("Nlink mismatch\n");
		return 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
	if (!uid_eq(durable_stat->uid, current_stat->uid)) {
#else
	if (durable_stat->uid != current_stat->uid) {
#endif
		cifssrv_err("Uid mismatch\n");
		return 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
	if (!gid_eq(durable_stat->gid, current_stat->gid)) {
#else
	if (durable_stat->gid != current_stat->gid) {
#endif
		cifssrv_err("Gid mismatch\n");
		return 0;
	}

	if (durable_stat->rdev != current_stat->rdev) {
		cifssrv_err("Special file devid mismatch\n");
		return 0;
	}

	if (durable_stat->size != current_stat->size) {
		cifssrv_err("Size mismatch\n");
		return 0;
	}

	if (durable_stat->atime.tv_sec != current_stat->atime.tv_sec &&
	    durable_stat->atime.tv_nsec != current_stat->atime.tv_nsec) {
		cifssrv_err("Last access time mismatch\n");
		return 0;
	}

	if (durable_stat->mtime.tv_sec  != current_stat->mtime.tv_sec &&
	    durable_stat->mtime.tv_nsec != current_stat->mtime.tv_nsec) {
		cifssrv_err("Last modification time mismatch\n");
		return 0;
	}

	if (durable_stat->ctime.tv_sec != current_stat->ctime.tv_sec &&
	    durable_stat->ctime.tv_nsec != current_stat->ctime.tv_nsec) {
		cifssrv_err("Last status change time mismatch\n");
		return 0;
	}

	if (durable_stat->blksize != current_stat->blksize) {
		cifssrv_err("Block size mismatch\n");
		return 0;
	}

	if (durable_stat->blocks != current_stat->blocks) {
		cifssrv_err("Block number mismatch\n");
		return 0;
	}

	return 1;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * cifssrv_durable_reconnect() - verify durable state on reconnect
 * @curr_server:	TCP server instance of connection
 * @durable_stat:	durable state of filp
 * @filp:		current inode stat
 *
 * Return:		0 if no mismatch, otherwise error
 */
int cifssrv_durable_reconnect(struct cifssrv_sess *curr_sess,
			  struct cifssrv_durable_state *durable_state,
			  struct file **filp)
{
	struct kstat stat;
	struct path *path;
	int rc = 0;

	rc = cifssrv_durable_verify_and_del_oplock(curr_sess,
						   durable_state->sess,
						   durable_state->volatile_id,
						   filp, curr_sess->sess_id);

	if (rc < 0) {
		*filp = NULL;
		cifssrv_err("Oplock state not consistent\n");
		return rc;
	}

	/* Get the current stat info.
	   Incrementing refcount of filp
	   because when server thread is destroy_fidtable
	   will close the filp when old server thread is destroyed*/
	get_file(*filp);
	path = &((*filp)->f_path);
	generic_fillattr(path->dentry->d_inode, &stat);

	if (!cifssrv_check_stat_info(&durable_state->stat, &stat)) {
		cifssrv_err("Stat info mismatch file state changed\n");
		fput(*filp);
		rc = -EINVAL;
	}

	return rc;
}

/**
 * cifssrv_update_durable_stat_info() - update durable state of all
 *		persistent fid of a server thread
 * @server:	TCP server instance of connection
 */
void cifssrv_update_durable_stat_info(struct cifssrv_sess *sess)
{
	struct cifssrv_file *fp;
	struct fidtable *ftab;
	int id;
	struct cifssrv_durable_state *durable_state;
	struct fidtable *gtab;
	struct file *filp;
	uint64_t p_id;

	if (durable_enable == false || !sess)
		return;

	spin_lock(&sess->fidtable.fidtable_lock);
	ftab = sess->fidtable.ftab;

	for (id = 0; id < ftab->max_fids; id++) {
		fp = ftab->fileid[id];
		if (fp && fp->is_durable) {
			/* Mainly for updating kstat info */
			filp = fp->filp;
			p_id = fp->persistent_id;
			spin_lock(&global_fidtable.fidtable_lock);

			gtab = global_fidtable.ftab;
			durable_state =
			  (struct cifssrv_durable_state *)gtab->fileid[p_id];
			BUG_ON(durable_state == NULL);
			generic_fillattr(filp->f_path.dentry->d_inode,
					 &durable_state->stat);
			spin_unlock(&global_fidtable.fidtable_lock);
		}
	}
	spin_unlock(&sess->fidtable.fidtable_lock);
}
#endif

/* End of persistent-ID functions */

/**
 * smb_dentry_open() - open a dentry and provide fid for it
 * @work:	smb work ptr
 * @path:	path of dentry to be opened
 * @flags:	open flags
 * @ret_id:	fid returned on this
 * @oplock:	return oplock state granted on file
 * @option:	file access pattern options for fadvise
 * @fexist:	file already present or not
 *
 * Return:	0 on success, otherwise error
 */
int smb_dentry_open(struct smb_work *work, const struct path *path,
		    int flags, __u16 *ret_id, int *oplock, int option,
		    int fexist)
{
	struct tcp_server_info *server = work->server;
	struct file *filp;
	int id, err = 0;
	struct cifssrv_file *fp;
	struct smb_hdr *rcv_hdr = (struct smb_hdr *)work->buf;
	uint64_t sess_id;

	/* first init id as invalid id - 0xFFFF ? */
	*ret_id = 0xFFFF;

	id = cifssrv_get_unused_id(&work->sess->fidtable);
	if (id < 0)
		return id;

	if (flags & O_TRUNC) {
		if (oplocks_enable && fexist)
			smb_break_all_oplock(server, NULL,
					path->dentry->d_inode);
		err = vfs_truncate((struct path *)path, 0);
		if (err)
			goto err_out;
	}

	filp = dentry_open(path, flags | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		cifssrv_err("dentry open failed, err %d\n", err);
		goto err_out;
	}

	smb_vfs_set_fadvise(filp, option);

	sess_id = work->sess == NULL ? 0 : work->sess->sess_id;
	fp = insert_id_in_fidtable(work->sess, sess_id, id, filp);
	if (fp == NULL) {
		fput(filp);
		cifssrv_err("id insert failed\n");
		goto err_out;
	}

	if (!oplocks_enable || S_ISDIR(file_inode(filp)->i_mode))
		*oplock = OPLOCK_NONE;

	if (!S_ISDIR(file_inode(filp)->i_mode) &&
			(*oplock & (REQ_BATCHOPLOCK | REQ_OPLOCK))) {
		/* Client cannot request levelII oplock directly */
		err = smb_grant_oplock(server, oplock, id, fp,
				rcv_hdr->Tid, NULL, false);
		/* if we enconter an error, no oplock is granted */
		if (err)
			*oplock = 0;
	}

	*ret_id = id;
	return 0;

err_out:
	cifssrv_close_id(&work->sess->fidtable, id);
	return err;
}

/**
 * is_dir_empty() - check for empty directory
 * @fp:	cifssrv file pointer
 *
 * Return:	true if directory empty, otherwise false
 */
bool is_dir_empty(struct cifssrv_file *fp)
{
	struct smb_readdir_data r_data = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
		.ctx.actor = smb_filldir,
#endif
		.dirent = (void *)__get_free_page(GFP_KERNEL),
		.dirent_count = 0
	};

	if (!r_data.dirent)
		return false;

	smb_vfs_readdir(fp->filp, smb_filldir, &r_data);
	cifssrv_debug("dirent_count = %d\n", r_data.dirent_count);
	if (r_data.dirent_count > 2) {
		free_page((unsigned long)(r_data.dirent));
		return false;
	}

	free_page((unsigned long)(r_data.dirent));
	return true;
}

/**
 * smb_kern_path() - lookup a file and get path info
 * @name:	name of file for lookup
 * @flags:	lookup flags
 * @path:	if lookup succeed, return path info
 * @caseless:	caseless filename lookup
 *
 * Return:	0 on success, otherwise error
 */
int smb_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless)
{
	int err;

	err = kern_path(name, flags, path);
	if (err && caseless) {
		char *filename = strrchr((const char *)name, '/');
		if (filename == NULL)
			return err;
		*(filename++) = '\0';
		if (strlen(name) == 0) {
			/* root reached */
			filename--;
			*filename = '/';
			return err;
		}
		err = smb_search_dir(name, filename);
		if (err)
			return err;
		err = kern_path(name, flags, path);
		return err;
	} else
		return err;
}

/**
 * smb_search_dir() - lookup a file in a directory
 * @dirname:	directory name
 * @filename:	filename to lookup
 *
 * Return:	0 on success, otherwise error
 */
int smb_search_dir(char *dirname, char *filename)
{
	struct path dir_path;
	int ret;
	struct file *dfilp;
	int flags = O_RDONLY|O_LARGEFILE;
	int used_count, reclen;
	int iter;
	struct smb_dirent *buf_p;
	int namelen = strlen(filename);
	int dirnamelen = strlen(dirname);
	bool match_found = false;
	struct smb_readdir_data readdir_data = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
		.ctx.actor = smb_filldir,
#endif
		.dirent = (void *)__get_free_page(GFP_KERNEL)
	};

	if (!readdir_data.dirent) {
		ret = -ENOMEM;
		goto out;
	}

	ret = smb_kern_path(dirname, 0, &dir_path, true);
	if (ret)
		goto out;

	dfilp = dentry_open(&dir_path, flags, current_cred());
	if (IS_ERR(dfilp)) {
		cifssrv_err("cannot open directory %s\n", dirname);
		ret = -EINVAL;
		goto out2;
	}

	while (!ret && !match_found) {
		readdir_data.used = 0;
		readdir_data.full = 0;
		ret = smb_vfs_readdir(dfilp, smb_filldir, &readdir_data);
		used_count = readdir_data.used;
		if (ret || !used_count)
			break;

		buf_p = (struct smb_dirent *)readdir_data.dirent;
		for (iter = 0; iter < used_count; iter += reclen,
		     buf_p = (struct smb_dirent *)((char *)buf_p + reclen)) {
			int length;

			reclen = ALIGN(sizeof(struct smb_dirent) +
				       buf_p->namelen, sizeof(__le64));
			length = buf_p->namelen;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
			if (length != namelen ||
				strncasecmp(filename, buf_p->name, namelen))
#else
			if (length != namelen ||
				strnicmp(filename, buf_p->name, namelen))
#endif
				continue;
			/* got match, make absolute name */
			memcpy(dirname + dirnamelen + 1, buf_p->name, namelen);
			match_found = true;
			break;
		}
	}

	free_page((unsigned long)(readdir_data.dirent));
	fput(dfilp);
out2:
	path_put(&dir_path);
out:
	dirname[dirnamelen] = '/';
	return ret;
}

/**
 * get_pipe_id() - get a free id for a pipe
 * @server:	TCP server instance of connection
 *
 * Return:	id on success, otherwise error
 */
int get_pipe_id(struct cifssrv_sess *sess, unsigned int pipe_type)
{
	int id;
	struct cifssrv_pipe *pipe_desc;
	struct tcp_server_info *server = sess->server;

	id = cifssrv_get_unused_id(&sess->fidtable);
	if (id < 0)
		return -EMFILE;

	server->pipe_desc[pipe_type] = kzalloc(sizeof(struct cifssrv_pipe),
			GFP_KERNEL);
	if (!server->pipe_desc)
		return -ENOMEM;

	pipe_desc = server->pipe_desc[pipe_type];
	pipe_desc->id = id;
	pipe_desc->pkt_type = -1;

#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	pipe_desc->rsp_buf = kmalloc(NETLINK_CIFSSRV_MAX_PAYLOAD,
			GFP_KERNEL);
	if (!pipe_desc->rsp_buf) {
		kfree(pipe_desc);
		server->pipe_desc[pipe_type] = NULL;
		return -ENOMEM;
	}
#endif

	switch (pipe_type) {
	case SRVSVC:
		pipe_desc->pipe_type = SRVSVC;
		break;
	case WINREG:
		pipe_desc->pipe_type = WINREG;
		break;
	default:
		cifssrv_err("pipe type :%d not supported\n", pipe_type);
		return -EINVAL;
	}

	return id;
}

/**
 * close_pipe_id() - free id for pipe on a server thread
 * @server:	TCP server instance of connection
 * @pipe_type:	pipe type
 *
 * Return:	0 on success, otherwise error
 */
int close_pipe_id(struct cifssrv_sess *sess, int pipe_type)
{
	struct cifssrv_pipe *pipe_desc;
	struct tcp_server_info *server = sess->server;
	int rc = 0;

	pipe_desc = server->pipe_desc[pipe_type];
	if (!pipe_desc)
		return -EINVAL;

	rc = cifssrv_close_id(&sess->fidtable, pipe_desc->id);
	if (rc < 0)
		return rc;

#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	kfree(pipe_desc->rsp_buf);
#endif
	kfree(pipe_desc);
	server->pipe_desc[pipe_type] = NULL;

	return rc;
}
