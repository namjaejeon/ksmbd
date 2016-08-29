/*
 *   fs/cifssrv/fh.h
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

#ifndef __CIFSSRV_FSHANDLE_H
#define __CIFSSRV_FSHANDLE_H

#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>

#include "glob.h"
#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
#include "netlink.h"
#endif

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0X1200a0

/* Max id limit is 0xFFFF, so create bitmap with only this size*/
#define CIFSSRV_BITMAP_SIZE        0xFFFF
#define CIFSSRV_START_FID		 1

#define cifssrv_set_bit			__set_bit_le
#define cifssrv_test_and_set_bit	__test_and_set_bit_le
#define cifssrv_test_bit		test_bit_le
#define cifssrv_clear_bit		__clear_bit_le
#define cifssrv_test_and_clear_bit	__test_and_clear_bit_le
#define cifssrv_find_next_zero_bit	find_next_zero_bit_le
#define cifssrv_find_next_bit		find_next_bit_le

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

struct cifssrv_file {
	struct file *filp;
	/* Will be used for in case of symlink */
	struct file *lfilp;
	bool islink;
	/* if ls is happening on directory, below is valid*/
	struct smb_readdir_data	readdir_data;
	int		dirent_offset;
	/* oplock info */
	struct ofile_info *ofile;
	bool delete_on_close;
	bool is_nt_open;
	bool lease_granted;
	char LeaseKey[16];
	bool is_durable;
	uint64_t persistent_id;
	uint64_t sess_id;
};

#ifdef CONFIG_CIFS_SMB2_SERVER
struct cifssrv_durable_state {
	struct tcp_server_info *server;
	int volatile_id;
	struct kstat stat;
	int refcount;
};
#endif

enum cifssrv_pipe_type {
	SRVSVC	=	1,
	WINREG	=	2,
	LANMAN	=	3,
};

struct cifssrv_pipe_table {
	char pipename[32];
	unsigned int pipetype;
};

#define INVALID_PIPE   0xFFFFFFFF

struct cifssrv_pipe {
	int id;
	char *data;
	int pkt_type;
	int pipe_type;
	int opnum;
	char *buf;
	int datasize;
	int sent;
#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	struct cifssrv_uevent ev;
	char *rsp_buf;
#endif
};

struct cifssrv_lanman_pipe {
	int pipe_type;
#ifdef CONFIG_CIFSSRV_NETLINK_INTERFACE
	struct cifssrv_uevent ev;
	char *rsp_buf;
#endif
};

#define CIFSSRV_NR_OPEN_DEFAULT BITS_PER_LONG

/* fidtable structure */
struct fidtable {
	unsigned int max_fids;
	void **fileid;
	unsigned int start_pos;
	unsigned long *cifssrv_bitmap;
};

struct fidtable_desc {
	spinlock_t fidtable_lock;
	struct fidtable *ftab;
};

int init_fidtable(struct fidtable_desc *ftab_desc);
void destroy_fidtable(struct tcp_server_info *server);
struct cifssrv_file *
get_id_from_fidtable(struct tcp_server_info *server, uint64_t id);
int close_id(struct tcp_server_info *server, uint64_t id);
bool is_dir_empty(struct cifssrv_file *fp);
int get_pipe_id(struct tcp_server_info *server, unsigned int pipe_type);
unsigned int get_pipe_type(char *pipename);
int close_pipe_id(struct tcp_server_info *server, int id);
int cifssrv_get_unused_id(struct fidtable_desc *ftab_desc);
int cifssrv_close_id(struct fidtable_desc *ftab_desc, int id);
struct cifssrv_file *
insert_id_in_fidtable(struct tcp_server_info *server,
		unsigned int id, struct file *filp);
void delete_id_from_fidtable(struct tcp_server_info *server,
		unsigned int id);

#ifdef CONFIG_CIFS_SMB2_SERVER
/* Persistent-ID operations */
int cifssrv_insert_in_global_table(struct tcp_server_info *server,
				   int volatile_id, struct file *filp,
				   int durable_open);
int close_persistent_id(uint64_t id);
void destroy_global_fidtable(void);

/* Durable handle functions */
struct cifssrv_durable_state *
	cifssrv_get_durable_state(uint64_t persistent_id);
void
cifssrv_update_durable_state(struct tcp_server_info *server,
				unsigned int persistent_id,
				unsigned int volatile_id,
				struct file *filp);

int cifssrv_delete_durable_state(uint64_t persistent_id);
int cifssrv_durable_reconnect(struct tcp_server_info *curr_server,
		struct cifssrv_durable_state *durable_state,
		struct file **filp);
void
cifssrv_durable_disconnect(struct tcp_server_info *server,
		unsigned int persistent_id, struct file *filp);

void cifssrv_update_durable_stat_info(struct tcp_server_info *server);
#endif

#endif /* __CIFSSRV_FSHANDLE_H */
