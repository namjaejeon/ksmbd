/*
 *   fs/cifsd/vfs.c
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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/falloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "export.h"
#include "glob.h"
#include "oplock.h"
#include "transport_tcp.h"
#include "buffer_pool.h"
#include "vfs.h"

/**
 * cifsd_vfs_create() - vfs helper for smb create file
 * @name:	file name
 * @mode:	file create mode
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_create(const char *name, umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_err("path create failed for %s, err %d\n", name, err);
		return err;
	}

	mode |= S_IFREG;
	err = vfs_create(path.dentry->d_inode, dentry, mode, true);
	if (err)
		cifsd_err("File(%s): creation failed (err:%d)\n", name, err);

	done_path_create(&path, dentry);

	return err;
}

/**
 * cifsd_vfs_mkdir() - vfs helper for smb create directory
 * @name:	directory name
 * @mode:	directory create mode
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_mkdir(const char *name, umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -EEXIST)
			cifsd_err("path create failed for %s, err %d\n",
					name, err);
		return err;
	}

	mode |= S_IFDIR;
	err = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	if (err)
		cifsd_err("mkdir(%s): creation failed (err:%d)\n", name, err);

	done_path_create(&path, dentry);

	return err;
}

static int cifsd_vfs_stream_read(struct cifsd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	ssize_t v_len;
	char *stream_buf = NULL;
	int err;

	cifsd_debug("read stream data pos : %llu, count : %zd\n",
			*pos, count);

	v_len = smb_find_cont_xattr(&fp->filp->f_path, fp->stream.name,
			fp->stream.size, &stream_buf, 1);
	if (v_len == -ENOENT) {
		cifsd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		return err;
	}

	memcpy(buf, &stream_buf[*pos], count);
	return v_len > count ? count : v_len;
}

/**
 * cifsd_vfs_read() - vfs helper for smb file read
 * @work:	smb work
 * @fid:	file id of open file
 * @count:	read byte count
 * @pos:	file pos
 *
 * Return:	number of read bytes on success, otherwise error
 */
int cifsd_vfs_read(struct cifsd_work *work,
		 struct cifsd_file *fp,
		 size_t count,
		 loff_t *pos)
{
	struct file *filp;
	ssize_t nbytes = 0;
	char *rbuf, *name;
	struct inode *inode;
	char namebuf[NAME_MAX];
	int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

	rbuf = AUX_PAYLOAD(work);
	filp = fp->filp;
	inode = filp->f_path.dentry->d_inode;
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (unlikely(count == 0))
		return 0;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (work->conn->connection_type) {
		if (!(fp->daccess & (FILE_READ_DATA_LE |
		    FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
		    FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to read(%s)\n", FP_FILENAME(fp));
			return -EACCES;
		}
	}
#endif

	if (fp->is_stream)
		return cifsd_vfs_stream_read(fp, rbuf, pos, count);

	ret = check_lock_range(filp, *pos, *pos + count - 1,
			READ);
	if (ret) {
		cifsd_err("%s: unable to read due to lock\n",
				__func__);
		return -EAGAIN;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	nbytes = vfs_read(filp, rbuf, count, pos);
	set_fs(old_fs);
#else
	nbytes = kernel_read(filp, rbuf, count, pos);
#endif
	if (nbytes < 0) {
		name = d_path(&filp->f_path, namebuf, sizeof(namebuf));
		if (IS_ERR(name))
			name = "(error)";
		cifsd_err("smb read failed for (%s), err = %zd\n",
				name, nbytes);
		return nbytes;
	}

	filp->f_pos = *pos;
	return nbytes;
}

static int cifsd_vfs_stream_write(struct cifsd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	char *stream_buf = NULL, *wbuf;
	size_t size, v_len;
	int err = 0;

	cifsd_debug("write stream data pos : %llu, count : %zd\n",
			*pos, count);

	size = *pos + count;
	if (size > XATTR_SIZE_MAX) {
		size = XATTR_SIZE_MAX;
		count = (*pos + count) - XATTR_SIZE_MAX;
	}

	v_len = smb_find_cont_xattr(&fp->filp->f_path, fp->stream.name,
			fp->stream.size, &stream_buf, 1);
	if (v_len == -ENOENT) {
		cifsd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		goto out;
	}

	if (v_len < size) {
		wbuf = cifsd_alloc(size);
		if (!wbuf) {
			err = -ENOMEM;
			goto out;
		}

		if (v_len > 0)
			memcpy(wbuf, stream_buf, v_len);
		stream_buf = wbuf;
	}

	memcpy(&stream_buf[*pos], buf, count);

	err = smb_store_cont_xattr(&fp->filp->f_path, fp->stream.name,
			(void *)stream_buf, size);
	if (err < 0)
		goto out;

	fp->filp->f_pos = *pos;
	err = 0;
out:
	cifsd_free(stream_buf);
	return err;
}

/**
 * cifsd_vfs_write() - vfs helper for smb file write
 * @work:	work
 * @fid:	file id of open file
 * @buf:	buf containing data for writing
 * @count:	read byte count
 * @pos:	file pos
 * @sync:	fsync after write
 * @written:	number of bytes written
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_write(struct cifsd_work *work, struct cifsd_file *fp,
	char *buf, size_t count, loff_t *pos, bool sync, ssize_t *written)
{
	struct cifsd_sess *sess = work->sess;
	struct file *filp;
	loff_t	offset = *pos;
	int err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (sess->conn->connection_type) {
		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
		   FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
		   FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write(%s)\n", FP_FILENAME(fp));
			err = -EACCES;
			goto out;
		}
	}
#endif

	filp = fp->filp;

	if (fp->is_stream) {
		err = cifsd_vfs_stream_write(fp, buf, pos, count);
		if (!err)
			*written = count;
		goto out;
	}

	err = check_lock_range(filp, *pos, *pos + count - 1,
			WRITE);
	if (err) {
		cifsd_err("%s: unable to write due to lock\n",
				__func__);
		err = -EAGAIN;
		goto out;
	}

	if (oplocks_enable) {
		/* Do we need to break any of a levelII oplock? */
		smb_break_all_levII_oplock(sess->conn, fp, 1);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_write(filp, buf, count, pos);
	set_fs(old_fs);
#else
	err = kernel_write(filp, buf, count, pos);
#endif

	if (err < 0) {
		cifsd_debug("smb write failed, err = %d\n", err);
		goto out;
	}

	filp->f_pos = *pos;
	*written = err;
	err = 0;
	if (sync) {
		err = vfs_fsync_range(filp, offset, offset + *written, 0);
		if (err < 0)
			cifsd_err("fsync failed for filename = %s, err = %d\n",
					FP_FILENAME(fp), err);
	}

out:
	return err;
}

/**
 * smb_check_attrs() - sanitize inode attributes
 * @inode:	inode
 * @attrs:	inode attributes
 */
void smb_check_attrs(struct inode *inode, struct iattr *attrs)
{
	/* sanitize the mode change */
	if (attrs->ia_valid & ATTR_MODE) {
		attrs->ia_mode &= S_IALLUGO;
		attrs->ia_mode |= (inode->i_mode & ~S_IALLUGO);
	}

	/* Revoke setuid/setgid on chown */
	if (!S_ISDIR(inode->i_mode) &&
		(((attrs->ia_valid & ATTR_UID) &&
				!uid_eq(attrs->ia_uid, inode->i_uid)) ||
		 ((attrs->ia_valid & ATTR_GID) &&
				!gid_eq(attrs->ia_gid, inode->i_gid)))) {
		attrs->ia_valid |= ATTR_KILL_PRIV;
		if (attrs->ia_valid & ATTR_MODE) {
			/* we're setting mode too, just clear the s*id bits */
			attrs->ia_mode &= ~S_ISUID;
			if (attrs->ia_mode & S_IXGRP)
				attrs->ia_mode &= ~S_ISGID;
		} else {
			/* set ATTR_KILL_* bits and let VFS handle it */
			attrs->ia_valid |= (ATTR_KILL_SUID | ATTR_KILL_SGID);
		}
	}
}

/**
 * cifsd_vfs_setattr() - vfs helper for smb setattr
 * @work:	work
 * @name:	file name
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_setattr(struct cifsd_work *work, const char *name,
		uint64_t fid, struct iattr *attrs)
{
	struct cifsd_sess *sess = work->sess;
	struct file *filp;
	struct dentry *dentry;
	struct inode *inode;
	struct path path;
	bool update_size = false;
	int err = 0;
	struct cifsd_file *fp = NULL;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			cifsd_debug("lookup failed for %s, err = %d\n",
					name, err);
			return -ENOENT;
		}
		dentry = path.dentry;
		inode = dentry->d_inode;
	} else {

		fp = get_id_from_fidtable(sess, fid);
		if (!fp) {
			cifsd_err("failed to get filp for fid %llu\n", fid);
			return -ENOENT;
		}

		filp = fp->filp;
		dentry = filp->f_path.dentry;
		inode = dentry->d_inode;
	}

	/* no need to update mode of symlink */
	if (S_ISLNK(inode->i_mode))
		attrs->ia_valid &= ~ATTR_MODE;

	/* skip setattr, if nothing to update */
	if (!attrs->ia_valid) {
		err = 0;
		goto out;
	}

	smb_check_attrs(inode, attrs);
	if (attrs->ia_valid & ATTR_SIZE) {
		err = get_write_access(inode);
		if (err)
			goto out;

		err = locks_verify_truncate(inode, NULL, attrs->ia_size);
		if (err) {
			put_write_access(inode);
			goto out;
		}
		update_size = true;
	}

	attrs->ia_valid |= ATTR_CTIME;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_lock(inode);
	err = notify_change(dentry, attrs, NULL);
	inode_unlock(inode);
#else
	mutex_lock(&inode->i_mutex);
	err = notify_change(dentry, attrs, NULL);
	mutex_unlock(&inode->i_mutex);
#endif

	if (update_size)
		put_write_access(inode);

	if (!err) {
		sync_inode_metadata(inode, 1);
		cifsd_debug("fid %llu, setattr done\n", fid);
	}

out:
	if (name)
		path_put(&path);
	return err;
}

/**
 * cifsd_vfs_getattr() - vfs helper for smb getattr
 * @work:	work
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_getattr(struct cifsd_work *work, uint64_t fid,
		struct kstat *stat)
{
	struct cifsd_sess *sess = work->sess;
	struct file *filp;
	struct cifsd_file *fp;
	int err;

	fp = get_id_from_fidtable(sess, fid);
	if (!fp) {
		cifsd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}

	filp = fp->filp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	err = vfs_getattr(&filp->f_path, stat, STATX_BASIC_STATS,
		AT_STATX_SYNC_AS_STAT);
#else
	err = vfs_getattr(&filp->f_path, stat);
#endif
	if (err)
		cifsd_err("getattr failed for fid %llu, err %d\n", fid, err);
	return err;
}

/**
 * cifsd_vfs_fsync() - vfs helper for smb fsync
 * @work:	work
 * @fid:	file id of open file
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_fsync(struct cifsd_work *work, uint64_t fid, uint64_t p_id)
{
	struct cifsd_sess *sess = work->sess;
	struct cifsd_file *fp;
	int err;

	fp = get_id_from_fidtable(sess, fid);
	if (!fp) {
		cifsd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}

	if (fp->persistent_id != p_id) {
		cifsd_err("persistent id mismatch : %llu, %llu\n",
				fp->persistent_id, p_id);
		return -ENOENT;
	}

	err = vfs_fsync(fp->filp, 0);
	if (err < 0)
		cifsd_err("smb fsync failed, err = %d\n", err);

	return err;
}

/**
 * cifsd_vfs_remove_file() - vfs helper for smb rmdir or unlink
 * @name:	absolute directory or file name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_remove_file(char *name)
{
	struct path parent;
	struct dentry *dir, *dentry;
	char *last;
	int err = -ENOENT;

	last = strrchr(name, '/');
	if (last && last[1] != '\0') {
		*last = '\0';
		last++;
	}
	else {
		cifsd_debug("can't get last component in path %s\n", name);
		return -ENOENT;
	}

	err = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent);
	if (err) {
		cifsd_debug("can't get %s, err %d\n", name, err);
		return err;
	}

	dir = parent.dentry;
	if (!dir->d_inode)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_lock_nested(dir->d_inode, I_MUTEX_PARENT);
#else
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
#endif
	dentry = lookup_one_len(last, dir, strlen(last));
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_debug("%s: lookup failed, err %d\n", last, err);
		goto out_err;
	}

	if (!dentry->d_inode || !dentry->d_inode->i_nlink) {
		dput(dentry);
		err = -ENOENT;
		goto out_err;
	}

	if (S_ISDIR(dentry->d_inode->i_mode)) {
		err = vfs_rmdir(dir->d_inode, dentry);
		if (err && err != -ENOTEMPTY)
			cifsd_debug("%s: rmdir failed, err %d\n", name, err);
	} else {
		err = vfs_unlink(dir->d_inode, dentry, NULL);
		if (err)
			cifsd_debug("%s: unlink failed, err %d\n", name, err);
	}

	dput(dentry);
out_err:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_unlock(dir->d_inode);
#else
	mutex_unlock(&dir->d_inode->i_mutex);
#endif
out:
	path_put(&parent);
	return err;
}

/**
 * cifsd_vfs_link() - vfs helper for creating smb hardlink
 * @oldname:	source file name
 * @newname:	hardlink name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_link(const char *oldname, const char *newname)
{
	struct path oldpath, newpath;
	struct dentry *dentry;
	int err;

	err = kern_path(oldname, LOOKUP_FOLLOW, &oldpath);
	if (err) {
		cifsd_err("cannot get linux path for %s, err = %d\n",
				oldname, err);
		goto out1;
	}

	dentry = kern_path_create(AT_FDCWD, newname, &newpath,
			LOOKUP_FOLLOW | LOOKUP_REVAL);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_err("path create err for %s, err %d\n", newname, err);
		goto out2;
	}

	err = -EXDEV;
	if (oldpath.mnt != newpath.mnt) {
		cifsd_err("vfs_link failed err %d\n", err);
		goto out3;
	}

	err = vfs_link(oldpath.dentry, newpath.dentry->d_inode, dentry, NULL);
	if (err)
		cifsd_debug("vfs_link failed err %d\n", err);

out3:
	done_path_create(&newpath, dentry);
out2:
	path_put(&oldpath);

out1:
	return err;
}

/**
 * cifsd_vfs_symlink() - vfs helper for creating smb symlink
 * @name:	source file name
 * @symname:	symlink name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_symlink(const char *name, const char *symname)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, symname, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_err("path create failed for %s, err %d\n", name, err);
		return err;
	}

	err = vfs_symlink(dentry->d_parent->d_inode, dentry, name);
	if (err && (err != -EEXIST || err != -ENOSPC))
		cifsd_debug("failed to create symlink, err %d\n", err);

	done_path_create(&path, dentry);

	return err;
}

/**
 * cifsd_vfs_readlink() - vfs helper for reading value of symlink
 * @path:	path of symlink
 * @buf:	destination buffer for symlink value
 * @lenp:	destination buffer length
 *
 * Return:	symlink value length on success, otherwise error
 */
int cifsd_vfs_readlink(struct path *path, char *buf, int lenp)
{
	struct inode *inode;
	mm_segment_t old_fs;
	int err;

	if (!path)
		return -ENOENT;

	inode = path->dentry->d_inode;
	if (!S_ISLNK(inode->i_mode))
		return -EINVAL;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = inode->i_op->readlink(path->dentry, (char __user *)buf, lenp);
	set_fs(old_fs);
	if (err < 0)
		cifsd_err("readlink failed, err = %d\n", err);

	return err;
}

/**
 * cifsd_vfs_rename() - vfs helper for smb rename
 * @sess:		session
 * @abs_oldname:	old filename
 * @abs_newname:	new filename
 * @oldfid:		file id of old file
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_rename(char *abs_oldname, char *abs_newname, struct cifsd_file *fp)
{
	struct path oldpath_p, newpath_p;
	struct dentry *dold, *dnew, *dold_p, *dnew_p, *trap, *child_de;
	char *oldname = NULL, *newname = NULL;
	int err;

	if (abs_oldname) {
		/* normal case: rename with source filename */
		oldname = strrchr(abs_oldname, '/');
		if (oldname && oldname[1] != '\0') {
			*oldname = '\0';
			oldname++;
		}
		else {
			cifsd_err("can't get last component in path %s\n",
					abs_oldname);
			return -ENOENT;
		}

		err = kern_path(abs_oldname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&oldpath_p);
		if (err) {
			cifsd_err("cannot get linux path for %s, err %d\n",
					abs_oldname, err);
			return -ENOENT;
		}
		dold_p = oldpath_p.dentry;

		newname = strrchr(abs_newname, '/');
		if (newname && newname[1] != '\0') {
			*newname = '\0';
			newname++;
		}
		else {
			cifsd_err("can't get last component in path %s\n",
					abs_newname);
			err = -ENOMEM;
			goto out1;
		}

		err = kern_path(abs_newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&newpath_p);
		if (err) {
			cifsd_err("cannot get linux path for %s, err = %d\n",
					abs_newname, err);
			goto out1;
		}
		dnew_p = newpath_p.dentry;
	} else {
		dold_p = fp->filp->f_path.dentry->d_parent;

		newname = strrchr(abs_newname, '/');
		if (newname && newname[1] != '\0') {
			*newname = '\0';
			newname++;
		}
		else {
			cifsd_err("can't get last component in path %s\n",
					abs_newname);
			return -ENOMEM;
		}

		err = kern_path(abs_newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&newpath_p);
		if (err) {
			cifsd_err("cannot get linux path for %s, err = %d\n",
					abs_newname, err);
			return err;
		}
		dnew_p = newpath_p.dentry;
	}

	cifsd_debug("oldname %s, newname %s\n", oldname, newname);
	trap = lock_rename(dold_p, dnew_p);
	if (abs_oldname) {
		dold = lookup_one_len(oldname, dold_p, strlen(oldname));
		err = PTR_ERR(dold);
		if (IS_ERR(dold)) {
			cifsd_err("%s lookup failed with error = %d\n",
					oldname, err);
			goto out2;
		}
	} else {
		dold = fp->filp->f_path.dentry;
		dget(dold);
	}

	spin_lock(&dold->d_lock);
	list_for_each_entry(child_de, &dold->d_subdirs, d_child) {
		struct cifsd_file *child_fp;

		if (!child_de->d_inode)
			continue;

		child_fp = find_fp_using_inode(child_de->d_inode);
		if (child_fp) {
			cifsd_debug("not allow to rename dir with opening sub file\n");
			err = -ENOTEMPTY;
			spin_unlock(&dold->d_lock);
			goto out3;
		}
	}
	spin_unlock(&dold->d_lock);

	err = -ENOENT;
	if (!dold->d_inode)
		goto out3;
	err = -EINVAL;
	if (dold == trap)
		goto out3;

	dnew = lookup_one_len(newname, dnew_p, strlen(newname));
	err = PTR_ERR(dnew);
	if (IS_ERR(dnew)) {
		cifsd_err("%s lookup failed with error = %d\n",
				newname, err);
		goto out3;
	}

	err = -ENOTEMPTY;
	if (dnew == trap)
		goto out4;

	err = vfs_rename(dold_p->d_inode, dold, dnew_p->d_inode, dnew, NULL, 0);
	if (err)
		cifsd_err("vfs_rename failed err %d\n", err);
out4:
	dput(dnew);
out3:
	dput(dold);
out2:
	unlock_rename(dold_p, dnew_p);
	path_put(&newpath_p);
out1:
	if (abs_oldname)
		path_put(&oldpath_p);

	return err;
}

/**
 * cifsd_vfs_truncate() - vfs helper for smb file truncate
 * @work:	work
 * @name:	old filename
 * @fid:	file id of old file
 * @size:	truncate to given size
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_truncate(struct cifsd_work *work, const char *name,
	struct cifsd_file *fp, loff_t size)
{
	struct cifsd_sess *sess = work->sess;
	struct path path;
	int err = 0;
	struct inode *inode;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			cifsd_err("cannot get linux path for %s, err %d\n",
					name, err);
			return err;
		}
		err = vfs_truncate(&path, size);
		if (err)
			cifsd_err("truncate failed for %s err %d\n",
					name, err);
		path_put(&path);
	} else {
		struct file *filp;

		filp = fp->filp;
		if (oplocks_enable) {
			/* Do we need to break any of a levelII oplock? */
			smb_break_all_levII_oplock(sess->conn, fp, 1);
		} else {
			inode = file_inode(filp);
			if (size < inode->i_size) {
				err = check_lock_range(filp, size,
					inode->i_size - 1, WRITE);
			} else {
				err = check_lock_range(filp, inode->i_size,
					size - 1, WRITE);
			}

			if (err) {
				cifsd_err("failed due to lock\n");
				return -EAGAIN;
			}
		}
		err = vfs_truncate(&filp->f_path, size);
		if (err)
			cifsd_err("truncate failed for filename : %s err %d\n",
					fp->filename, err);
	}

	return err;
}

/**
 * cifsd_vfs_listxattr() - vfs helper for smb list extended attributes
 * @dentry:	dentry of file for listing xattrs
 * @list:	destination buffer
 * @size:	destination buffer length
 *
 * Return:	xattr list length on success, otherwise error
 */
ssize_t cifsd_vfs_listxattr(struct dentry *dentry, char **list, int size)
{
	ssize_t err;
	char *vlist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		vlist = vmalloc(size);
		if (!vlist)
			return -ENOMEM;
	}

	*list = vlist;
	err = vfs_listxattr(dentry, vlist, size);
	if (err == -ERANGE) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		err = -E2BIG;
		cifsd_debug("listxattr failed\n");
	}

	return err;
}

/**
 * cifsd_vfs_getxattr() - vfs helper for smb get extended attributes value
 * @dentry:	dentry of file for getting xattrs
 * @xattr_name:	name of xattr name to query
 * @xattr_buf:	destination buffer xattr value
 * @flags: if 0, return stored xattr's length only
 *
 * Return:	read xattr value length on success, otherwise error
 */
ssize_t cifsd_vfs_getxattr(struct dentry *dentry, char *xattr_name,
	char **xattr_buf, int flags)
{
	ssize_t xattr_len;
	char *buf;

	xattr_len = vfs_getxattr(dentry, xattr_name, NULL, 0);
	if (xattr_len <= 0)
		return xattr_len;

	if (!flags)
		return xattr_len;

	buf = cifsd_alloc(xattr_len);
	if (!buf)
		return -ENOMEM;

	xattr_len = vfs_getxattr(dentry, xattr_name, (void *)buf,
		xattr_len);
	if (xattr_len < 0)
		cifsd_debug("getxattr failed, ret %zd\n", xattr_len);
	else
		*xattr_buf = buf;

	return xattr_len;
}

/**
 * cifsd_vfs_setxattr() - vfs helper for smb set extended attributes value
 * @filename:	file name
 * @fpath:	path of file for setxattr
 * @name:	xattr name for setxattr
 * @value:	xattr value to set
 * @size:	size of xattr value
 * @flags:	destination buffer length
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_setxattr(const char *filename, struct path *fpath, const char *name,
		const void *value, size_t size, int flags)
{
	struct path path;
	int err;

	if (filename) {
		err = kern_path(filename, 0, &path);
		if (err) {
			cifsd_debug("cannot get linux path %s, err %d\n",
					filename, err);
			return err;
		}
		err = vfs_setxattr(path.dentry, name, value, size, flags);
		if (err)
			cifsd_debug("setxattr failed, err %d\n", err);
		path_put(&path);
	} else {
		err = vfs_setxattr(fpath->dentry, name, value, size, flags);
		if (err)
			cifsd_debug("setxattr failed, err %d\n", err);
	}

	return err;
}

int cifsd_vfs_truncate_xattr(struct dentry *dentry)
{
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = cifsd_vfs_listxattr(dentry, &xattr_list,
		XATTR_LIST_MAX);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		cifsd_debug("empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
					STREAM_PREFIX_LEN))
			continue;

		err = vfs_removexattr(dentry, name);
		if (err)
			cifsd_err("remove xattr failed : %s\n", name);
	}
out:
	if (xattr_list)
		vfree(xattr_list);

	return err;
}

int cifsd_vfs_truncate_stream_xattr(struct dentry *dentry)
{
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = cifsd_vfs_listxattr(dentry, &xattr_list,
		XATTR_LIST_MAX);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		cifsd_debug("empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));

		if (strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
					STREAM_PREFIX_LEN))
			continue;

		err = vfs_removexattr(dentry, name);
		if (err)
			cifsd_err("remove xattr failed : %s\n", name);
	}
out:
	if (xattr_list)
		vfree(xattr_list);

	return err;
}

/**
 * cifsd_vfs_set_fadvise() - convert smb IO caching options to linux options
 * @filp:	file pointer for IO
 * @options:	smb IO options
 */
void cifsd_vfs_set_fadvise(struct file *filp, int option)
{
	struct address_space *mapping;
	mapping = filp->f_mapping;

	if (!option || !mapping)
		return;

	if (option & FILE_WRITE_THROUGH_LE)
		filp->f_flags |= O_SYNC;
/*
	 * TODO : need to add special handling for Direct I/O.
	 * Direct I/O relies on MM Context of the "current" process
	 * to retrieve the pages corresponding to the user address
	 * do_direct_IO()->dio_get_page()->
				dio_refill_pages()->get_user_pages_fast()
	 * struct mm_struct *mm = current->mm;
	 * All work items in CIFSD are handled through default "kworker"
	 * - which do not have any MM Context.
	 * To handle Direct I/O will need to create another thread
	 * in kernel with MM context and redirect all direct I/O calls to
	 * thread. Since, this is Server and direct I/O not bottleneck.
	 * So, making default READ path to be buffered in all sequences
	 * (clearing direct IO flag).
	else if (option & FILE_NO_INTERMEDIATE_BUFFERING_LE &&
		 filp->f_mapping->a_ops->direct_IO)
		filp->f_flags |= O_DIRECT;
*/
	else if (option & FILE_SEQUENTIAL_ONLY_LE) {
		filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;
		spin_lock(&filp->f_lock);
		filp->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	} else if (option & FILE_RANDOM_ACCESS_LE) {
		spin_lock(&filp->f_lock);
		filp->f_mode |= FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	}
}

/**
 * cifsd_vfs_lock() - vfs helper for smb file locking
 * @filp:	the file to apply the lock to
 * @cmd:	type of locking operation (F_SETLK, F_GETLK, etc.)
 * @flock:	The lock to be applied
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_lock(struct file *filp, int cmd,
			struct file_lock *flock)
{
	cifsd_debug("%s: calling vfs_lock_file\n", __func__);
	return vfs_lock_file(filp, cmd, flock, NULL);
}

/**
 * check_lock_range() - vfs helper for smb byte range file locking
 * @filp:	the file to apply the lock to
 * @start:	lock start byte offset
 * @end:	lock end byte offset
 * @type:	byte range type read/write
 *
 * Return:	0 on success, otherwise error
 */
int check_lock_range(struct file *filp, loff_t start, loff_t end,
		unsigned char type)
{
	struct file_lock *flock;
	struct file_lock_context *ctx = file_inode(filp)->i_flctx;
	int error = 0;

	if (!ctx || list_empty_careful(&ctx->flc_posix))
		return 0;

	list_for_each_entry(flock, &ctx->flc_posix, fl_list) {
		/* check conflict locks */
		if (flock->fl_end >= start && end >= flock->fl_start) {
			if (flock->fl_type == F_RDLCK) {
				if (type == WRITE) {
					cifsd_err("not allow write by shared lock\n");
					error = 1;
					goto out;
				}
			} else if (flock->fl_type == F_WRLCK) {
				/* check owner in lock */
				if (flock->fl_file != filp) {
					error = 1;
					cifsd_err("not allow rw access by exclusive lock from other opens\n");
					goto out;
				}
			}
		}
	}
out:
	return error;
}

int cifsd_vfs_readdir(struct file *file, filldir_t filler,
			struct cifsd_readdir_data *rdata)
{
	return iterate_dir(file, &rdata->ctx);
}

int cifsd_vfs_alloc_size(struct cifsd_work *work,
			 struct cifsd_file *fp,
			 loff_t len)
{
	struct cifsd_tcp_conn *conn = work->sess->conn;

	if (oplocks_enable)
		smb_break_all_levII_oplock(conn, fp, 1);
	return vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, len);
}

int cifsd_vfs_remove_xattr(struct path *path, char *field_name)
{
	return vfs_removexattr(path->dentry, field_name);
}

int cifsd_vfs_unlink(struct dentry *dir, struct dentry *dentry)
{
	int err = 0;

	dget(dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
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
		err = vfs_unlink(dir->d_inode, dentry, NULL);

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_unlock(dir->d_inode);
#else
	mutex_unlock(&dir->d_inode->i_mutex);
#endif
	dput(dentry);
	if (err)
		cifsd_debug("failed to delete, err %d\n", err);

	return err;
}

/*
 * cifsd_vfs_get_logical_sector_size() - get logical sector size from inode
 * @inode: inode
 *
 * Return: logical sector size
 */
unsigned short cifsd_vfs_logical_sector_size(struct inode *inode)
{
	struct request_queue *q;
	unsigned short ret_val = 512;

	if(!inode->i_sb->s_bdev)
		return ret_val;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q && q->limits.logical_block_size)
		ret_val = q->limits.logical_block_size;

	return ret_val;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/*
 * cifsd_vfs_get_smb2_sector_size() - get fs sector sizes
 * @inode: inode
 * @fs_ss: fs sector size struct
 */
void cifsd_vfs_smb2_sector_size(struct inode *inode,
	struct smb2_fs_sector_size *fs_ss)
{
	struct request_queue *q;

	q = inode->i_sb->s_bdev->bd_disk->queue;
	fs_ss->logical_sector_size = 512;
	fs_ss->physical_sector_size = 512;
	fs_ss->optimal_io_size = 512;

	if (q) {
		if (q->limits.logical_block_size)
			fs_ss->logical_sector_size =
				q->limits.logical_block_size;
		if (q->limits.physical_block_size)
			fs_ss->physical_sector_size =
				q->limits.physical_block_size;
		if (q->limits.io_opt)
			fs_ss->optimal_io_size = q->limits.io_opt;
	}
}
#else
void cifsd_vfs_get_smb2_sector_size(struct inode *inode,
	struct smb2_fs_sector_size *fs_ss)
{
}
#endif

/**
 * cifsd_vfs_dentry_open() - open a dentry and provide fid for it
 * @work:	smb work ptr
 * @path:	path of dentry to be opened
 * @flags:	open flags
 * @ret_id:	fid returned on this
 * @option:	file access pattern options for fadvise
 * @fexist:	file already present or not
 *
 * Return:	0 on success, otherwise error
 */
struct cifsd_file *cifsd_vfs_dentry_open(struct cifsd_work *work,
	const struct path *path, int flags, int option, int fexist)
{
	struct cifsd_sess *sess = work->sess;
	struct file *filp;
	int id, err = 0;
	struct cifsd_file *fp = NULL;
	uint64_t sess_id;
	struct cifsd_inode *ci;

	filp = dentry_open(path, flags | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		cifsd_err("dentry open failed, err %d\n", err);
		return ERR_PTR(err);
	}

	cifsd_vfs_set_fadvise(filp, option);

	sess_id = sess == NULL ? 0 : sess->sess_id;
	id = cifsd_get_unused_id(&sess->fidtable);
	if (id < 0)
		goto err_out3;

	cifsd_debug("allocate volatile id : %d\n", id);
	fp = insert_id_in_fidtable(sess, work->tcon, id, filp);
	if (fp == NULL) {
		err = -ENOMEM;
		cifsd_err("id insert failed\n");
		goto err_out2;
	}

	fp->f_ci = ci = cifsd_inode_get(fp);
	if (!ci)
		goto err_out1;

	if (flags & O_TRUNC) {
		if (oplocks_enable && fexist)
			smb_break_all_oplock(work, fp);
		err = vfs_truncate((struct path *)path, 0);
		if (err)
			goto err_out;
	}

	INIT_LIST_HEAD(&fp->lock_list);

	return fp;

err_out:
	list_del(&fp->node);
	if (ci && atomic_dec_and_test(&ci->m_count))
		cifsd_inode_free(ci);
err_out1:
	delete_id_from_fidtable(sess, id);
err_out2:
	cifsd_close_id(&sess->fidtable, id);
err_out3:
	fput(filp);

	if (err) {
		fp = ERR_PTR(err);
		cifsd_err("err : %d\n", err);
	}
	return fp;
}

/**
 * cifsd_vfs_empty_dir() - check for empty directory
 * @fp:	cifsd file pointer
 *
 * Return:	true if directory empty, otherwise false
 */
bool cifsd_vfs_empty_dir(struct cifsd_file *fp)
{
	struct path dir_path;
	struct file *filp;
	struct cifsd_readdir_data r_data = {
		.ctx.actor = smb_filldir,
		.dirent = (void *)__get_free_page(GFP_KERNEL),
		.dirent_count = 0
	};
	int err;

	if (!r_data.dirent)
		return false;

	err = cifsd_vfs_kern_path(fp->filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&dir_path, 0);
	if (err < 0)
		return false;

	filp = dentry_open(&dir_path, O_RDONLY | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		fput(filp);
		cifsd_err("dentry open failed, err %d\n", err);
		return false;
	}

	r_data.used = 0;
	r_data.full = 0;

	err = cifsd_vfs_readdir(filp, smb_filldir, &r_data);
	if (r_data.dirent_count > 2) {
		fput(filp);
		path_put(&dir_path);
		free_page((unsigned long)(r_data.dirent));
		return false;
	}

	free_page((unsigned long)(r_data.dirent));
	fput(filp);
	path_put(&dir_path);
	return true;
}


/**
 * cifsd_vfs_kern_path() - lookup a file and get path info
 * @name:	name of file for lookup
 * @flags:	lookup flags
 * @path:	if lookup succeed, return path info
 * @caseless:	caseless filename lookup
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_kern_path(char *name, unsigned int flags, struct path *path,
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
		err = cifsd_vfs_lookup_in_dir(name, filename);
		if (err)
			return err;
		err = kern_path(name, flags, path);
		return err;
	} else
		return err;
}

/**
 * cifsd_vfs_lookup_in_dir() - lookup a file in a directory
 * @dirname:	directory name
 * @filename:	filename to lookup
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_lookup_in_dir(char *dirname, char *filename)
{
	struct path dir_path;
	int ret;
	struct file *dfilp;
	int flags = O_RDONLY|O_LARGEFILE;
	int used_count, reclen;
	int iter;
	struct cifsd_dirent *buf_p;
	int namelen = strlen(filename);
	int dirnamelen = strlen(dirname);
	bool match_found = false;
	struct cifsd_readdir_data readdir_data = {
		.ctx.actor = smb_filldir,
		.dirent = (void *)__get_free_page(GFP_KERNEL)
	};

	if (!readdir_data.dirent) {
		ret = -ENOMEM;
		goto out;
	}

	ret = cifsd_vfs_kern_path(dirname, 0, &dir_path, true);
	if (ret)
		goto out;

	dfilp = dentry_open(&dir_path, flags, current_cred());
	if (IS_ERR(dfilp)) {
		cifsd_err("cannot open directory %s\n", dirname);
		ret = -EINVAL;
		goto out2;
	}

	while (!ret && !match_found) {
		readdir_data.used = 0;
		readdir_data.full = 0;
		ret = cifsd_vfs_readdir(dfilp, smb_filldir, &readdir_data);
		used_count = readdir_data.used;
		if (ret || !used_count)
			break;

		buf_p = (struct cifsd_dirent *)readdir_data.dirent;
		for (iter = 0; iter < used_count; iter += reclen,
		     buf_p = (struct cifsd_dirent *)((char *)buf_p + reclen)) {
			int length;

			reclen = ALIGN(sizeof(struct cifsd_dirent) +
				       buf_p->namelen, sizeof(__le64));
			length = buf_p->namelen;
			if (length != namelen ||
				strncasecmp(filename, buf_p->name, namelen))
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
 * fill_create_time() - fill create time of directory entry in cifsd_kstat
 * if related config is not yes, create time is same with change time
 *
 * @work: smb work containing share config
 * @path: path info
 * @cifsd_kstat: cifsd kstat wrapper
 */
static void fill_create_time(struct cifsd_work *work,
	struct path *path, struct cifsd_kstat *cifsd_kstat)
{
	char *create_time = NULL;
	int xattr_len;

	/*
	 * if "store dos attributes" conf is not yes,
	 * create time = change time
	 */
	cifsd_kstat->create_time = cifs_UnixTimeToNT(cifsd_kstat->kstat->ctime);

	if (get_attr_store_dos(&work->tcon->share->config.attr)) {
		xattr_len = smb_find_cont_xattr(path,
			XATTR_NAME_CREATION_TIME,
			XATTR_NAME_CREATION_TIME_LEN, &create_time, 1);

		if (xattr_len > 0)
			cifsd_kstat->create_time = *((u64 *)create_time);

		cifsd_free(create_time);
	}
}

/**
 * cifsd_vfs_init_kstat() - convert unix stat information to smb stat format
 * @p:          destination buffer
 * @cifsd_kstat:      cifsd kstat wrapper
 */
void *cifsd_vfs_init_kstat(char **p, struct cifsd_kstat *cifsd_kstat)
{
	FILE_DIRECTORY_INFO *info = (FILE_DIRECTORY_INFO *)(*p);
	info->FileIndex = 0;
	info->CreationTime = cpu_to_le64(cifsd_kstat->create_time);
	info->LastAccessTime = cpu_to_le64(
			cifs_UnixTimeToNT(cifsd_kstat->kstat->atime));
	info->LastWriteTime = cpu_to_le64(
			cifs_UnixTimeToNT(cifsd_kstat->kstat->mtime));
	info->ChangeTime = cpu_to_le64(
			cifs_UnixTimeToNT(cifsd_kstat->kstat->ctime));
	if (cifsd_kstat->file_attributes & ATTR_DIRECTORY) {
		info->EndOfFile = 0;
		info->AllocationSize = 0;
	} else {
		info->EndOfFile = cpu_to_le64(cifsd_kstat->kstat->size);
		info->AllocationSize =
			cpu_to_le64(cifsd_kstat->kstat->blocks << 9);
	}
	info->ExtFileAttributes = cpu_to_le32(cifsd_kstat->file_attributes);

	return info;
}

/*
 * fill_file_attributes() - fill FileAttributes of directory entry in cifsd_kstat.
 * if related config is not yes, just fill 0x10(dir) or 0x80(regular file).
 *
 * @work: smb work containing share config
 * @path: path info
 * @cifsd_kstat: cifsd kstat wrapper
 */

static void fill_file_attributes(struct cifsd_work *work,
	struct path *path, struct cifsd_kstat *cifsd_kstat)
{
	/*
	 * set default value for the case that store dos attributes is not yes
	 * or that acl is disable in server's filesystem and the config is yes.
	 */
	if (S_ISDIR(cifsd_kstat->kstat->mode))
		cifsd_kstat->file_attributes = ATTR_DIRECTORY;
	else
		cifsd_kstat->file_attributes = ATTR_ARCHIVE;

	if (get_attr_store_dos(&work->tcon->share->config.attr)) {
		char *file_attribute = NULL;
		int rc;

		rc = smb_find_cont_xattr(path,
			XATTR_NAME_FILE_ATTRIBUTE,
			XATTR_NAME_FILE_ATTRIBUTE_LEN, &file_attribute, 1);

		if (rc > 0)
			cifsd_kstat->file_attributes =
				*((__le32 *)file_attribute);
		else
			cifsd_debug("fail to fill file attributes.\n");

		cifsd_free(file_attribute);
	}
}

/**
 * read_next_entry() - read next directory entry and return absolute name
 * @work:	smb work containing share config
 * @cifsd_kstat:	cifsd wrapper of next dirent's stat
 * @de:		directory entry
 * @dirpath:	directory path name
 *
 * Return:      on success return absolute path of directory entry,
 *              otherwise NULL
 */
char *cifsd_vfs_readdir_name(struct cifsd_work *work,
			     struct cifsd_kstat *cifsd_kstat,
			     struct cifsd_dirent *de,
			     char *dirpath)
{
	struct path path;
	int rc, file_pathlen, dir_pathlen;
	char *name;

	dir_pathlen = strlen(dirpath);
	/* 1 for '/'*/
	file_pathlen = dir_pathlen +  de->namelen + 1;
	name = kmalloc(file_pathlen + 1, GFP_KERNEL);
	if (!name) {
		cifsd_err("Name memory failed for length %d,"
				" buf_name_len %d\n", dir_pathlen, de->namelen);
		return ERR_PTR(-ENOMEM);
	}

	memcpy(name, dirpath, dir_pathlen);
	memset(name + dir_pathlen, '/', 1);
	memcpy(name + dir_pathlen + 1, de->name, de->namelen);
	name[file_pathlen] = '\0';

	rc = cifsd_vfs_kern_path(name, 0, &path, 1);
	if (rc) {
		cifsd_err("look up failed for (%s) with rc=%d\n", name, rc);
		kfree(name);
		return ERR_PTR(rc);
	}

	generic_fillattr(path.dentry->d_inode, cifsd_kstat->kstat);
	fill_create_time(work, &path, cifsd_kstat);
	fill_file_attributes(work, &path, cifsd_kstat);
	memcpy(name, de->name, de->namelen);
	name[de->namelen] = '\0';
	path_put(&path);
	return name;
}
