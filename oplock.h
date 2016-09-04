/*
 *   fs/cifssrv/oplock.h
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

#ifndef __CIFSSRV_OPLOCK_H
#define __CIFSSRV_OPLOCK_H

#define OPLOCK_WAIT_TIME	(35*HZ)

/* SMB Oplock levels */
#define OPLOCK_NONE      0
#define OPLOCK_EXCLUSIVE 1
#define OPLOCK_BATCH     2
#define OPLOCK_READ      3  /* level 2 oplock */

/* SMB2 Oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE          0x00
#define SMB2_OPLOCK_LEVEL_II            0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE     0x08
#define SMB2_OPLOCK_LEVEL_BATCH         0x09
#define SMB2_OPLOCK_LEVEL_LEASE         0xFF

/* Oplock states */
#define OPLOCK_NOT_BREAKING             0x00
#define OPLOCK_BREAKING                 0x01

#define OPLOCK_WRITE_TO_READ		0x01
#define OPLOCK_WRITE_TO_NONE		0x02
#define OPLOCK_READ_TO_NONE		0x04

#define SMB2_LEASE_KEY_SIZE		16
extern struct mutex ofile_list_lock;

struct lease_ctx_info {
	__u8			LeaseKey[SMB2_LEASE_KEY_SIZE];
	__le32			CurrentLeaseState;
	__le32			LeaseFlags;
	__le64			LeaseDuration;
};

struct lease_fidinfo {
	__u32                   fid;
	struct list_head        fid_entry;
};

struct oplock_info {
	struct tcp_server_info  *server;
	int                     lock_type;
	int                     state;
	int                     fid;
	__u16                   Tid;
	struct list_head        op_list;

	/* lease info */
	bool			leased;
	__u8			LeaseKey[SMB2_LEASE_KEY_SIZE];
	__le32			CurrentLeaseState;
	__le32			NewLeaseState;
	__le32			LeaseFlags;
	__le64			LeaseDuration;
	atomic_t		LeaseCount;
	struct list_head	fid_list;

	bool			open_trunc:1;	/* truncate on open */
};

struct ofile_info {
	struct inode            *inode;
	struct list_head        i_list;
	struct list_head        op_write_list;
	struct list_head        op_read_list;
	struct list_head        op_none_list;
	atomic_t                op_count;
	wait_queue_head_t	op_end_wq;
};

extern int smb_grant_oplock(struct tcp_server_info *server, int *oplock,
		int id, struct cifssrv_file *fp, __u16 Tid,
		struct lease_ctx_info *lctx, bool attr_only);
extern void smb1_send_oplock_break(struct work_struct *work);
#ifdef CONFIG_CIFS_SMB2_SERVER
extern void smb2_send_oplock_break(struct work_struct *work);
#endif
extern void smb_breakII_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, struct ofile_info *ofile);

struct oplock_info *get_matching_opinfo(struct tcp_server_info *server,
		struct ofile_info *ofile, int fid, int fhclose);
int opinfo_write_to_read(struct ofile_info *ofile,
		struct oplock_info *opinfo, __le32 lease_state);
int opinfo_write_to_none(struct ofile_info *ofile,
		struct oplock_info *opinfo);
int opinfo_read_to_none(struct ofile_info *ofile,
		struct oplock_info *opinfo);
void close_id_del_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, unsigned int id);
void dispose_ofile_list(void);
void smb_break_all_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, struct inode *inode);

#ifdef CONFIG_CIFS_SMB2_SERVER
/* Lease related functions */
void create_lease_buf(u8 *rbuf, u8 *LeaseKey, u8 oplock, u8 handle);
__u8 parse_lease_state(void *open_req, struct lease_ctx_info *lreq);
struct oplock_info *get_matching_opinfo_lease(struct tcp_server_info *server,
		struct ofile_info **ofile, char *LeaseKey,
		struct lease_fidinfo **fidinfo, int id);
int smb_break_write_lease(struct ofile_info *ofile,
		struct oplock_info *opinfo);
int lease_read_to_write(struct ofile_info *ofile, struct oplock_info *opinfo);

/* Durable related functions */
void create_durable_buf(char *buf);
void create_durable_rsp_buf(char *buf);
struct create_context *smb2_find_context_vals(void *open_req, char *str);
int cifssrv_durable_verify_and_del_oplock(struct tcp_server_info *curr_server,
					  struct tcp_server_info *prev_server,
					  int fid, struct file **filp,
					  uint64_t sess_id);
#endif

#endif /* __CIFSSRV_OPLOCK_H */
