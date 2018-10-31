// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_VFS_H__
#define __CIFSD_VFS_H__

#include <linux/file.h>
#include <linux/fs.h>

struct cifsd_work;
struct cifsd_file;

struct cifsd_readdir_data {
	struct dir_context ctx;
	char           *dirent;
	unsigned int   used;
	unsigned int   full;
	unsigned int   dirent_count;
	unsigned int   file_attr;
};

struct cifsd_dirent {
	__le64         ino;
	__le64          offset;
	__le32         namelen;
	__le32         d_type;
	char            name[];
};

/* cifsd kstat wrapper to get valid create time when reading dir entry */
struct cifsd_kstat {
	struct kstat *kstat;
	__u64 create_time;
	__le32 file_attributes;
};

struct cifsd_fs_sector_size {
	unsigned short logical_sector_size;
	unsigned int physical_sector_size;
	unsigned int optimal_io_size;
};

int cifsd_vfs_create(const char *name, umode_t mode);
int cifsd_vfs_mkdir(const char *name, umode_t mode);
int cifsd_vfs_read(struct cifsd_work *work, struct cifsd_file *fp,
		 size_t count, loff_t *pos);
int cifsd_vfs_write(struct cifsd_work *work, struct cifsd_file *fp,
	char *buf, size_t count, loff_t *pos, bool fsync, ssize_t *written);
int cifsd_vfs_getattr(struct cifsd_work *work, uint64_t fid,
		struct kstat *stat);
int cifsd_vfs_setattr(struct cifsd_work *work, const char *name,
		uint64_t fid, struct iattr *attrs);
int cifsd_vfs_fsync(struct cifsd_work *work, uint64_t fid, uint64_t p_id);
int cifsd_vfs_remove_file(char *name);
int cifsd_vfs_link(const char *oldname, const char *newname);
int cifsd_vfs_symlink(const char *name, const char *symname);
int cifsd_vfs_readlink(struct path *path, char *buf, int len);
int cifsd_vfs_rename(char *abs_oldname, char *abs_newname,
		     struct cifsd_file *fp);
int cifsd_vfs_truncate(struct cifsd_work *work, const char *name,
	struct cifsd_file *fp, loff_t size);
struct cifsd_file *cifsd_vfs_dentry_open(struct cifsd_work *work,
					 const struct path *path,
					 int flags,
					 int option,
					 int fexist);

ssize_t cifsd_vfs_listxattr(struct dentry *dentry, char **list, int size);
ssize_t cifsd_vfs_getxattr(struct dentry *dentry,
			   char *xattr_name,
			   char **xattr_buf);

ssize_t cifsd_vfs_casexattr_len(struct dentry *dentry,
				char *attr_name,
				int attr_name_len);

int cifsd_vfs_setxattr(struct dentry *dentry,
		       const char *attr_name,
		       const void *attr_value,
		       size_t attr_size,
		       int flags);

int cifsd_vfs_fsetxattr(const char *filename,
			const char *attr_name,
			const void *attr_value,
			size_t attr_size,
			int flags);

int cifsd_vfs_truncate_xattr(struct dentry *dentry, int wo_streams);
int cifsd_vfs_remove_xattr(struct dentry *dentry, char *attr_name);

int cifsd_vfs_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless);
bool cifsd_vfs_empty_dir(struct cifsd_file *fp);
void cifsd_vfs_set_fadvise(struct file *filp, int option);
int cifsd_vfs_lock(struct file *filp, int cmd, struct file_lock *flock);
int cifsd_vfs_readdir(struct file *file, struct cifsd_readdir_data *buf);
int cifsd_vfs_alloc_size(struct cifsd_work *work,
			 struct cifsd_file *fp,
			 loff_t len);
int cifsd_vfs_unlink(struct dentry *dir, struct dentry *dentry);
unsigned short cifsd_vfs_logical_sector_size(struct inode *inode);
void cifsd_vfs_smb2_sector_size(struct inode *inode,
				struct cifsd_fs_sector_size *fs_ss);
bool cifsd_vfs_empty_dir(struct cifsd_file *fp);
char *cifsd_vfs_readdir_name(struct cifsd_work *work,
			     struct cifsd_kstat *cifsd_kstat,
			     struct cifsd_dirent *de,
			     char *dirpath);
void *cifsd_vfs_init_kstat(char **p, struct cifsd_kstat *cifsd_kstat);

#endif /* __CIFSD_VFS_H__ */
