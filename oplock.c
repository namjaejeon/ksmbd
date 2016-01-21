/*
 *   fs/cifssrv/oplock.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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
#include "smb2pdu.h"
#include "oplock.h"

bool oplocks_enable = true;
#ifdef CONFIG_CIFS_SMB2_SERVER
bool lease_enable = true;
bool durable_enable = true;
#endif

LIST_HEAD(ofile_list);
DEFINE_MUTEX(ofile_list_lock);

module_param(oplocks_enable, bool, 0644);
MODULE_PARM_DESC(oplocks_enable, "Enable or disable oplocks. Default: y/Y/1");

#ifdef CONFIG_CIFS_SMB2_SERVER
module_param(lease_enable, bool, 0644);
MODULE_PARM_DESC(lease_enable, "Enable or disable lease. Default: y/Y/1");

module_param(durable_enable, bool, 0644);
MODULE_PARM_DESC(durable_enable, "Enable or disable lease. Default: y/Y/1");
#endif

/**
 * dispose_ofile_list() - free all memory allocated for ofile
 *
 * unlikely that ofile_list will have any remaining entry at rmmod,
 * still check and dispose if any entry present at rmmod time.
 */
void dispose_ofile_list(void)
{
	struct ofile_info *ofile, *tmp1;
	struct oplock_info *opinfo, *tmp2;

	mutex_lock(&ofile_list_lock);
	list_for_each_entry_safe(ofile, tmp1, &ofile_list, i_list) {
		if (atomic_read(&ofile->op_count) > 0) {
			list_for_each_entry_safe(opinfo, tmp2,
					&ofile->op_write_list, op_list) {
				list_del(&opinfo->op_list);
				kfree(opinfo);
				atomic_dec(&ofile->op_count);
			}

			list_for_each_entry_safe(opinfo, tmp2,
					&ofile->op_read_list, op_list) {
				list_del(&opinfo->op_list);
				kfree(opinfo);
				atomic_dec(&ofile->op_count);
			}

			list_for_each_entry_safe(opinfo, tmp2,
					&ofile->op_none_list, op_list) {
				list_del(&opinfo->op_list);
				kfree(opinfo);
				atomic_dec(&ofile->op_count);
			}
		}

		if (!atomic_read(&ofile->op_count)) {
			list_del(&ofile->i_list);
			kfree(ofile);
		}
	}
	mutex_unlock(&ofile_list_lock);
}

/**
 * get_new_ofile() - allocate a new ofile object for open file
 * @inode:	inode of opened file
 *
 * Return:      allocated ofile object on success, otherwise NULL
 */
struct ofile_info *get_new_ofile(struct inode *inode)
{
	struct ofile_info *ofile_new;
	ofile_new = kmalloc(sizeof(struct ofile_info), GFP_NOFS);
	if (!ofile_new)
		return NULL;

	ofile_new->inode = inode;
	INIT_LIST_HEAD(&ofile_new->i_list);
	INIT_LIST_HEAD(&ofile_new->op_write_list);
	INIT_LIST_HEAD(&ofile_new->op_read_list);
	INIT_LIST_HEAD(&ofile_new->op_none_list);
	atomic_set(&ofile_new->op_count, 0);
	init_waitqueue_head(&ofile_new->op_end_wq);
	return ofile_new;
}

/**
 * get_new_opinfo() - allocate a new opinfo object for oplock info
 * @server:     TCP server instance of connection
 * @id:		fid of open file
 * @Tid:	tree id of connection
 * @lctx:	lease context information
 *
 * Return:      allocated opinfo object on success, otherwise NULL
 */
static struct oplock_info *get_new_opinfo(struct tcp_server_info *server,
		int id, __u16 Tid, struct lease_ctx_info *lctx)
{
	struct oplock_info *opinfo;
#ifdef CONFIG_CIFS_SMB2_SERVER
	struct lease_fidinfo *fidinfo;
#endif
	opinfo = kzalloc(sizeof(struct oplock_info), GFP_NOFS);
	if (!opinfo)
		return NULL;

	opinfo->server = server;
	opinfo->lock_type = OPLOCK_NONE;
	opinfo->state = OPLOCK_NOT_BREAKING;
	opinfo->fid = id;
	opinfo->Tid = Tid;
	INIT_LIST_HEAD(&opinfo->op_list);

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		memcpy(opinfo->LeaseKey, lctx->LeaseKey, SMB2_LEASE_KEY_SIZE);
		opinfo->CurrentLeaseState = lctx->CurrentLeaseState;
		opinfo->NewLeaseState = 0;
		opinfo->LeaseFlags = lctx->LeaseFlags;
		opinfo->LeaseDuration = lctx->LeaseDuration;
		INIT_LIST_HEAD(&opinfo->fid_list);

		fidinfo = kmalloc(sizeof(struct lease_fidinfo), GFP_NOFS);
		if (!fidinfo) {
			kfree(opinfo);
			return NULL;
		}
		INIT_LIST_HEAD(&fidinfo->fid_entry);
		fidinfo->fid = id;
		list_add(&fidinfo->fid_entry, &opinfo->fid_list);
		atomic_set(&opinfo->LeaseCount, 1);
		opinfo->leased = 1;
	}
#endif
	return opinfo;
}

/**
 * get_new_opinfo() - check if write oplock is granted on file
 * @ofile:	opened file to be checked for oplock status
 *
 * Return:      opinfo if write oplock is granted, otherwise NULL
 */
static struct oplock_info *get_write_oplock(struct ofile_info *ofile)
{
	if (list_empty(&ofile->op_write_list))
		return NULL;

	return list_first_entry(&ofile->op_write_list,
			struct oplock_info, op_list);
}

/**
 * get_matching_opinfo() - find a matching oplock info object
 * @server:     TCP server instance of connection
 * @ofile:	opened file to be checked for oplock status
 * @fid:	fid of open file
 * @fhclose:	is it called from file close context
 *
 * Return:      opinfo if found matching opinfo, otherwise NULL
 */
struct oplock_info *get_matching_opinfo(struct tcp_server_info *server,
		struct ofile_info *ofile, int fid, int fhclose)
{
	struct oplock_info *opinfo;

	if (!ofile)
		return NULL;

	list_for_each_entry(opinfo, &ofile->op_write_list, op_list) {
		if (!opinfo->leased && (server == opinfo->server) &&
				(opinfo->fid == fid))
			return opinfo;
	}

	list_for_each_entry(opinfo, &ofile->op_read_list, op_list) {
		if (!opinfo->leased && (server == opinfo->server) &&
				(opinfo->fid == fid))
			return opinfo;
	}

	/* none list should be traversed only from file close path */
	if (!fhclose)
		return NULL;

	list_for_each_entry(opinfo, &ofile->op_none_list, op_list) {
		if (!opinfo->leased && (server == opinfo->server) &&
				(opinfo->fid == fid))
			return opinfo;
	}

	return NULL;
}

/**
 * opinfo_write_to_read() - convert a write oplock to read oplock
 * @ofile:		opened file to be checked for oplock status
 * @opinfo:		current oplock info
 * @lease_state:	current lease state
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_read(struct ofile_info *ofile,
		struct oplock_info *opinfo, __le32 lease_state)
{
	if (!ofile || !opinfo)
		return -EINVAL;

	if (!IS_SMB2(opinfo->server)) {
		if (!((opinfo->lock_type == OPLOCK_EXCLUSIVE) ||
					(opinfo->lock_type == OPLOCK_BATCH))) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			return -EINVAL;
		}
		opinfo->lock_type = OPLOCK_READ;
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			if (opinfo->leased)
				cifssrv_err("lease state(0x%x)\n",
						opinfo->CurrentLeaseState);
			return -EINVAL;
		}
		opinfo->lock_type = SMB2_OPLOCK_LEVEL_II;

		if (opinfo->leased) {
			opinfo->NewLeaseState = SMB2_LEASE_NONE;
			opinfo->CurrentLeaseState = SMB2_LEASE_READ_CACHING;
			if (lease_state & SMB2_LEASE_HANDLE_CACHING)
				opinfo->CurrentLeaseState |=
					SMB2_LEASE_HANDLE_CACHING;
		}
#endif
	}

	list_move(&opinfo->op_list, &ofile->op_read_list);
	return 0;
}

/**
 * opinfo_write_to_none() - convert a write oplock to none
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_none(struct ofile_info *ofile,
		struct oplock_info *opinfo)
{
	if (!ofile || !opinfo)
		return -EINVAL;

	if (!IS_SMB2(opinfo->server)) {
		if (!((opinfo->lock_type == OPLOCK_EXCLUSIVE) ||
					(opinfo->lock_type == OPLOCK_BATCH))) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			return -EINVAL;
		}
		opinfo->lock_type = OPLOCK_NONE;
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			if (opinfo->leased)
				cifssrv_err("lease state(0x%x)\n",
						opinfo->CurrentLeaseState);
			return -EINVAL;
		}
		opinfo->lock_type = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->leased) {
			opinfo->NewLeaseState = SMB2_LEASE_NONE;
			opinfo->CurrentLeaseState = SMB2_LEASE_NONE;
		}
#endif
	}

	list_move(&opinfo->op_list, &ofile->op_none_list);
	return 0;
}

/**
 * opinfo_read_to_none() - convert a write read to none
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_to_none(struct ofile_info *ofile,
		struct oplock_info *opinfo)
{
	if (!ofile || !opinfo)
		return -EINVAL;

	if (!IS_SMB2(opinfo->server)) {
		if (opinfo->lock_type != OPLOCK_READ) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			return -EINVAL;
		}
		opinfo->lock_type = OPLOCK_NONE;
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (opinfo->lock_type != SMB2_OPLOCK_LEVEL_II) {
			cifssrv_err("bad oplock(0x%x)\n", opinfo->lock_type);
			if (opinfo->leased)
				cifssrv_err("lease state(0x%x)\n",
						opinfo->CurrentLeaseState);
			return -EINVAL;
		}
		opinfo->lock_type = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->leased) {
			opinfo->NewLeaseState = SMB2_LEASE_NONE;
			opinfo->CurrentLeaseState = SMB2_LEASE_NONE;
		}
#endif
	}

	list_move(&opinfo->op_list, &ofile->op_none_list);
	return 0;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * lease_read_to_write() - upgrade lease state from read to write
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current lease info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int lease_read_to_write(struct ofile_info *ofile, struct oplock_info *opinfo)
{
	if (!(opinfo->CurrentLeaseState & SMB2_LEASE_READ_CACHING)) {
		cifssrv_debug("bad lease state(0x%x)\n",
				opinfo->CurrentLeaseState);
		return -EINVAL;
	}

	opinfo->NewLeaseState = SMB2_LEASE_NONE;
	opinfo->CurrentLeaseState |= SMB2_LEASE_WRITE_CACHING;
	if (opinfo->CurrentLeaseState & SMB2_LEASE_HANDLE_CACHING)
		opinfo->lock_type = SMB2_OPLOCK_LEVEL_BATCH;
	else
		opinfo->lock_type = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	list_move(&opinfo->op_list, &ofile->op_write_list);
	return 0;
}

/**
 * close_id_del_lease() - release lease object at file close time
 * @server:     TCP server instance of connection
 * @fp:		cifssrv file pointer
 * @id:		fid of open file
 */
static void close_id_del_lease(struct tcp_server_info *server,
		struct cifssrv_file *fp, unsigned int id)
{
	struct ofile_info *ofile = NULL;
	struct oplock_info *opinfo = NULL;
	struct lease_fidinfo *fidinfo = NULL;

	ofile = fp->ofile;
	opinfo = get_matching_opinfo_lease(server, &ofile, fp->LeaseKey,
			&fidinfo, id);
	if (!opinfo || !fidinfo)
		goto out;

	if (atomic_read(&opinfo->LeaseCount) > 1) {
		list_del(&fidinfo->fid_entry);
		kfree(fidinfo);
		atomic_dec(&opinfo->LeaseCount);
	} else if (atomic_read(&opinfo->LeaseCount) == 1) {
		if ((opinfo->state == OPLOCK_BREAKING) &&
			(opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			 opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH)) {
			opinfo->lock_type = SMB2_OPLOCK_LEVEL_II;
			wake_up_interruptible(&server->oplock_q);

			mutex_unlock(&ofile_list_lock);
			wait_event_timeout(ofile->op_end_wq,
					opinfo->state == OPLOCK_NOT_BREAKING,
					OPLOCK_WAIT_TIME);
			mutex_lock(&ofile_list_lock);
		}

		list_del(&fidinfo->fid_entry);
		kfree(fidinfo);
		atomic_dec(&opinfo->LeaseCount);
		list_del(&opinfo->op_list);
		kfree(opinfo);
		atomic_dec(&ofile->op_count);
	} else {
		cifssrv_err("bad lease cnt %d\n",
				atomic_read(&opinfo->LeaseCount));
	}

out:
	if (!atomic_read(&ofile->op_count)) {
		list_del(&ofile->i_list);
		kfree(ofile);
		fp->ofile = NULL;
	}
}
#endif

/**
 * close_id_del_oplock() - release oplock object at file close time
 * @server:     TCP server instance of connection
 * @fp:		cifssrv file pointer
 * @id:		fid of open file
 */
void close_id_del_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, unsigned int id)
{
	struct ofile_info *ofile;
	struct oplock_info *opinfo;

	if (!oplocks_enable || S_ISDIR(file_inode(fp->filp)->i_mode))
		return;

	mutex_lock(&ofile_list_lock);
	ofile = fp->ofile;
	if (!ofile || atomic_read(&ofile->op_count) <= 0) {
		mutex_unlock(&ofile_list_lock);
		return;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (fp->lease_granted) {
		close_id_del_lease(server, fp, id);
		mutex_unlock(&ofile_list_lock);
		return;
	}
#endif

	opinfo = get_matching_opinfo(server, ofile, id, 1);
	if (!opinfo)
		goto out;
	if ((opinfo->state == OPLOCK_BREAKING) &&
			(opinfo->lock_type == OPLOCK_EXCLUSIVE ||
			 opinfo->lock_type == OPLOCK_BATCH ||
			 opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			 opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH)) {
		if (!IS_SMB2(opinfo->server))
			opinfo->lock_type = OPLOCK_READ;
		else {
#ifdef CONFIG_CIFS_SMB2_SERVER
			opinfo->lock_type = SMB2_OPLOCK_LEVEL_II;
#endif
		}

		wake_up_interruptible(&server->oplock_q);

		mutex_unlock(&ofile_list_lock);
		wait_event_timeout(ofile->op_end_wq,
				opinfo->state == OPLOCK_NOT_BREAKING,
				OPLOCK_WAIT_TIME);
		mutex_lock(&ofile_list_lock);
	}
	list_del(&opinfo->op_list);
	kfree(opinfo);
	atomic_dec(&ofile->op_count);

out:
	if (!atomic_read(&ofile->op_count)) {
		list_del(&ofile->i_list);
		kfree(ofile);
		fp->ofile = NULL;
	}
	mutex_unlock(&ofile_list_lock);
}


#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb_send_lease_break() - send lease break command from server to client
 * @work:     smb work object
 */
static void smb_send_lease_break(struct work_struct *work)
{
	struct smb2_lease_break *rsp = NULL;
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct oplock_info *opinfo = (struct oplock_info *)smb_work->buf;
	struct tcp_server_info *server = opinfo->server;
	struct smb2_hdr *rsp_hdr;

	atomic_inc(&server->req_running);
	mutex_lock(&server->srv_mutex);

	if (server->ops->allocate_rsp_buf(smb_work)) {
		cifssrv_debug("smb2_allocate_rsp_buf failed! ");
		mutex_unlock(&server->srv_mutex);
		kfree(smb_work);
		return;
	}

	rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->smb2_buf_length = cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	rsp_hdr->ProtocolId[0] = 0XFE;
	rsp_hdr->ProtocolId[1] = 'S';
	rsp_hdr->ProtocolId[2] = 'M';
	rsp_hdr->ProtocolId[3] = 'B';
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = cpu_to_le16(0x12);
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->ProcessId = 0;
	rsp_hdr->TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = (struct smb2_lease_break *)smb_work->rsp_buf;
	rsp->StructureSize = cpu_to_le16(44);
	rsp->Reserved = 0;

	if (opinfo->CurrentLeaseState & (SMB2_LEASE_WRITE_CACHING |
				SMB2_LEASE_HANDLE_CACHING))
		rsp->Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;

	memcpy(rsp->LeaseKey, opinfo->LeaseKey, SMB2_LEASE_KEY_SIZE);
	rsp->CurrentLeaseState = opinfo->CurrentLeaseState;
	rsp->NewLeaseState = opinfo->NewLeaseState;
	rsp->BreakReason = 0;
	rsp->AccessMaskHint = 0;
	rsp->ShareMaskHint = 0;

	inc_rfc1001_len(rsp, 44);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifssrv_sm_rsp_poolp);
	kfree(smb_work);
	mutex_unlock(&server->srv_mutex);

	atomic_dec(&server->req_running);
	if (waitqueue_active(&server->req_running_q))
		wake_up_all(&server->req_running_q);

}
#endif

/**
 * smb_breakII_oplock() - send level2 oplock or read lease break command from
 *			server to client
 * @server:     TCP server instance of connection
 * @fp:		cifssrv file pointer
 * @openfile:	open file information
 */
void smb_breakII_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, struct ofile_info *openfile)
{
	struct ofile_info *ofile;
	struct oplock_info *opinfo, *tmp;
	struct smb_work *work;
	bool ack_required = 0;
	bool lease_granted = 0;

	if (!(fp && fp->ofile) && !openfile)
		return;

	if (openfile)
		ofile = openfile;
	else {
		ofile = fp->ofile;
		if (fp->lease_granted)
			lease_granted = 1;
	}

	list_for_each_entry_safe(opinfo, tmp,
			&ofile->op_read_list, op_list) {
		if (!IS_SMB2(opinfo->server)) {
			if (opinfo->lock_type != OPLOCK_READ) {
				cifssrv_err("unexpected oplock(0x%x)\n",
						opinfo->lock_type);
				continue;
			}
		} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (opinfo->leased && (opinfo->CurrentLeaseState &
					(~(SMB2_LEASE_READ_CACHING |
					   SMB2_LEASE_HANDLE_CACHING)))) {
				cifssrv_err("unexpected lease state(0x%x)\n",
						opinfo->CurrentLeaseState);
				continue;
			} else if (opinfo->lock_type !=
					SMB2_OPLOCK_LEVEL_II) {
				cifssrv_err("unexpected oplock(0x%x)\n",
						opinfo->lock_type);
				continue;
			}
#endif
		}

#ifdef CONFIG_CIFS_SMB2_SERVER
		/* upgrade lease state of current client */
		if (lease_granted && opinfo->leased &&
				!memcmp(server->ClientGUID,
					opinfo->server->ClientGUID,
					SMB2_CLIENT_GUID_SIZE) &&
				!memcmp(fp->LeaseKey,
					opinfo->LeaseKey,
					SMB2_LEASE_KEY_SIZE)) {
			if (lease_read_to_write(ofile, opinfo) < 0)
				cifssrv_err("lease upgrade failed\n");

			continue;
		}
#endif

		work = kzalloc(sizeof(struct smb_work), GFP_KERNEL);
		if (!work) {
			cifssrv_err("cannot allocate memory\n");
			continue;
		}
		work->server = opinfo->server;
		work->buf = (char *)opinfo;
		ack_required = 0;
		if (!IS_SMB2(opinfo->server)) {
			ack_required = 1;
			opinfo->state = OPLOCK_BREAKING;
			smb1_send_oplock_break(&work->work);
		} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (opinfo->leased) {
				/* send lease break */
				if (opinfo->CurrentLeaseState &
						SMB2_LEASE_HANDLE_CACHING) {
					ack_required = 1;
					opinfo->state = OPLOCK_BREAKING;
				}

				opinfo->NewLeaseState = SMB2_LEASE_NONE;
				smb_send_lease_break(&work->work);
				if (!ack_required)
					opinfo->CurrentLeaseState =
						SMB2_LEASE_NONE;
			} else {
				/* send oplock break */
				smb2_send_oplock_break(&work->work);
			}
#endif
		}

		if (!ack_required)
			list_move(&opinfo->op_list, &ofile->op_none_list);
	}
}

/**
 * smb1_oplock_break_to_levelII() - send smb1 exclusive/batch to level2 oplock
 *		break command from server to client
 * @ofile:	open file object
 * @opinfo:	oplock info object
 *
 * Return:      0 on success, otherwise error
 */
static int smb1_oplock_break_to_levelII(struct ofile_info *ofile,
		struct oplock_info *opinfo)
{
	struct tcp_server_info *server = opinfo->server;
	int ret = 0;
	struct smb_work *work = kzalloc(sizeof(struct smb_work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->buf = (char *)opinfo;
	work->server = server;

	INIT_WORK(&work->work, smb1_send_oplock_break);
	schedule_work(&work->work);

	/*
	 * TODO: change to wait_event_interruptible_timeout once oplock break
	 * notification timeout is decided. In case of oplock break from
	 * levelII to none, we don't need to wait for client response.
	 */
	wait_event_interruptible_timeout(server->oplock_q,
			opinfo->lock_type == OPLOCK_READ ||
			opinfo->lock_type == OPLOCK_NONE,
			OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (opinfo->lock_type == OPLOCK_EXCLUSIVE ||
			opinfo->lock_type == OPLOCK_BATCH) {
		mutex_lock(&ofile_list_lock);
		ret = opinfo_write_to_read(ofile, opinfo, 0);
		mutex_unlock(&ofile_list_lock);
	}

	return ret;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_oplock_break_to_levelII() - send smb2 exclusive/batch to level2 oplock
 *		break command from server to client
 * @ofile:	open file object
 * @opinfo:	oplock info object
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_oplock_break_to_levelII(struct ofile_info *ofile,
		struct oplock_info *opinfo)
{
	struct tcp_server_info *server = opinfo->server;
	int ret = 0;
	struct smb_work *work = kzalloc(sizeof(struct smb_work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->buf = (char *)opinfo;
	work->server = server;
	INIT_WORK(&work->work, smb2_send_oplock_break);
	schedule_work(&work->work);

	wait_event_interruptible_timeout(server->oplock_q,
			opinfo->lock_type == SMB2_OPLOCK_LEVEL_II ||
			opinfo->lock_type == SMB2_OPLOCK_LEVEL_NONE,
			OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH) {
		mutex_lock(&ofile_list_lock);
		ret = opinfo_write_to_read(ofile, opinfo, 0);
		mutex_unlock(&ofile_list_lock);
	}
	return ret;
}
#endif

/**
 * grant_write_oplock() - grant exclusive/batch oplock or write lease
 * @ofile:	open file object
 * @opinfo_new:	new oplock info object
 * @oplock:	granted oplock type
 * @fp:		cifssrv file pointer
 * @lctx:	lease context information
 *
 * Return:      0
 */
static int grant_write_oplock(struct ofile_info *ofile,
		struct oplock_info *opinfo_new, int *oplock,
		struct cifssrv_file *fp, struct lease_ctx_info *lctx)
{
	WARN_ON(!list_empty(&ofile->op_write_list));

	if (!IS_SMB2(opinfo_new->server)) {
		if (*oplock == REQ_BATCHOPLOCK) {
			*oplock = OPLOCK_BATCH;
			opinfo_new->lock_type = OPLOCK_BATCH;
		} else {
			*oplock = OPLOCK_EXCLUSIVE;
			opinfo_new->lock_type = OPLOCK_EXCLUSIVE;
		}
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (*oplock == SMB2_OPLOCK_LEVEL_BATCH) {
			*oplock = SMB2_OPLOCK_LEVEL_BATCH;
			opinfo_new->lock_type = SMB2_OPLOCK_LEVEL_BATCH;
		} else {
			*oplock = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			opinfo_new->lock_type = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		}
#endif
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lctx->CurrentLeaseState = opinfo_new->CurrentLeaseState;
		memcpy(fp->LeaseKey, lctx->LeaseKey,
				SMB2_LEASE_KEY_SIZE);
		fp->lease_granted = 1;
	}
#endif
	list_add(&opinfo_new->op_list, &ofile->op_write_list);
	atomic_inc(&ofile->op_count);
	fp->ofile = ofile;
	return 0;
}

/**
 * grant_read_oplock() - grant level2 oplock or read lease
 * @ofile:	open file object
 * @opinfo_new:	new oplock info object
 * @oplock:	granted oplock type
 * @fp:		cifssrv file pointer
 * @lctx:	lease context information
 *
 * Return:      0
 */
static int grant_read_oplock(struct ofile_info *ofile,
		struct oplock_info *opinfo_new, int *oplock,
		struct cifssrv_file *fp, struct lease_ctx_info *lctx)
{
	if (!IS_SMB2(opinfo_new->server)) {
		*oplock = OPLOCK_READ;
		opinfo_new->lock_type = OPLOCK_READ;
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		*oplock = SMB2_OPLOCK_LEVEL_II;
		opinfo_new->lock_type = SMB2_OPLOCK_LEVEL_II;
#endif
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		opinfo_new->CurrentLeaseState = SMB2_LEASE_READ_CACHING;
		if (lctx->CurrentLeaseState & SMB2_LEASE_HANDLE_CACHING)
			opinfo_new->CurrentLeaseState |=
				SMB2_LEASE_HANDLE_CACHING;
		lctx->CurrentLeaseState = opinfo_new->CurrentLeaseState;
		memcpy(fp->LeaseKey, lctx->LeaseKey,
				SMB2_LEASE_KEY_SIZE);
		fp->lease_granted = 1;
	}
#endif

	list_add(&opinfo_new->op_list, &ofile->op_read_list);
	atomic_inc(&ofile->op_count);

	/*
	 * adding opinfo in fp will help in identifying opinfo without
	 * the need of traversing global oplock list in case of
	 * file close response and oplock break response
	 */
	fp->ofile = ofile;
	return 0;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * find_opinfo() - find lease object for given client guid and lease key
 * @head:	oplock list(read,write or none) head
 * @guid1:	client guid of matching lease owner
 * @key1:	lease key of matching lease owner
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
static inline struct oplock_info *find_opinfo(struct list_head *head,
		const char *guid1, const char *key1)
{
	struct list_head *tmp;
	struct oplock_info *opinfo;
	const char *guid2, *key2;

	list_for_each(tmp, head) {
		opinfo = list_entry(tmp, struct oplock_info, op_list);
		guid2 = opinfo->server->ClientGUID;
		key2 = opinfo->LeaseKey;
		if (!memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE) &&
				!memcmp(key1, key2, SMB2_LEASE_KEY_SIZE))
			return opinfo;
	}

	return NULL;
}

/**
 * same_client_has_lease() - check whether current lease request is
 *		from lease owner of file
 * @server:     TCP server instance of connection
 * @lctx:	lease context information
 * @ofile:	open file object
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
static struct oplock_info *same_client_has_lease(struct tcp_server_info *server,
		struct lease_ctx_info *lctx, struct ofile_info *ofile)
{
	struct oplock_info *opinfo = NULL;

	if (!lctx)
		return NULL;

	/* check if current client has write oplock */
	opinfo = get_write_oplock(ofile);
	if (opinfo && !opinfo->leased)
		return NULL;

	/* check if current client has write lease */
	opinfo = find_opinfo(&ofile->op_write_list,
			server->ClientGUID, lctx->LeaseKey);
	if (opinfo)
		return opinfo;

	/* check if current client has read lease */
	opinfo = find_opinfo(&ofile->op_read_list,
			server->ClientGUID, lctx->LeaseKey);
	if (opinfo) {
		if (atomic_read(&ofile->op_count) == 1) {
			/* it is the only client which has lease,
			   upgrade lease ? */
			if (lctx->CurrentLeaseState & SMB2_LEASE_WRITE_CACHING)
				lease_read_to_write(ofile, opinfo);
		}
		return opinfo;
	}

	return NULL;
}
#endif

/**
 * smb_grant_oplock() - handle oplock/lease request on file open
 * @server:	TCP server instance of connection
 * @oplock:	granted oplock type
 * @id:		fid of open file
 * @fp:		cifssrv file pointer
 * @Tid:	Tree id of connection
 * @lctx:	lease context information on file open
 * @attr_only:	attribute only file open type
 *
 * Return:      0 on success, otherwise error
 */
int smb_grant_oplock(struct tcp_server_info *server, int *oplock,
		int id, struct cifssrv_file *fp, __u16 Tid,
		struct lease_ctx_info *lctx, bool attr_only)
{
	int err = 0;
	struct inode *inode = file_inode(fp->filp);
	struct ofile_info *ofile = NULL;
	struct oplock_info *opinfo_new, *opinfo_old;
	struct list_head *tmp;
	bool oplocked = false;
#ifdef CONFIG_CIFS_SMB2_SERVER
	struct oplock_info *opinfo_matching = NULL;
	struct lease_fidinfo *fidinfo = NULL;
#endif

	opinfo_new = get_new_opinfo(server, id, Tid, lctx);
	if (!opinfo_new)
		return -ENOMEM;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx)
		fidinfo = list_first_entry(&opinfo_new->fid_list,
				struct lease_fidinfo, fid_entry);
#endif

	/* check if the inode is already oplocked */
	mutex_lock(&ofile_list_lock);
	list_for_each(tmp, &ofile_list) {
		ofile = list_entry(tmp, struct ofile_info, i_list);
		if (ofile->inode == inode) {
			oplocked = true;
			break;
		}
	}

	/* inode does not have any oplock */
	if (!oplocked) {
		ofile = get_new_ofile(inode);
		if (!ofile) {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (lctx && fidinfo) {
				list_del(&fidinfo->fid_entry);
				kfree(fidinfo);
			}
#endif
			kfree(opinfo_new);
			mutex_unlock(&ofile_list_lock);
			return -ENOMEM;
		}
		err = grant_write_oplock(ofile, opinfo_new, oplock,
				fp, lctx);
		/* Add this to the global list */
		list_add(&ofile->i_list, &ofile_list);
		mutex_unlock(&ofile_list_lock);
		return err;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	/* is lease already granted ? */
	opinfo_matching = same_client_has_lease(server, lctx, ofile);
	if (opinfo_matching) {
		if (fidinfo)
			list_move(&fidinfo->fid_entry,
					&opinfo_matching->fid_list);
		atomic_inc(&opinfo_matching->LeaseCount);
		kfree(opinfo_new);
		fp->ofile = ofile;
		memcpy(fp->LeaseKey, lctx->LeaseKey,
				SMB2_LEASE_KEY_SIZE);
		fp->lease_granted = 1;

		lctx->CurrentLeaseState = opinfo_matching->CurrentLeaseState;
		*oplock = opinfo_matching->lock_type;
		mutex_unlock(&ofile_list_lock);
		return err;
	}

	if (attr_only) {
		cifssrv_debug("second attrib only open: don't grant oplock\n");
		*oplock = SMB2_OPLOCK_LEVEL_NONE;
		mutex_unlock(&ofile_list_lock);
		kfree(opinfo_new);
		return 0;
	}
#endif

	/* check if file has exclusive/batch oplock or write lease */
	opinfo_old = get_write_oplock(ofile);
	if (!opinfo_old)
		goto op_break_not_needed;

	/* Need to break exclusive/batch oplock or write lease */
	cifssrv_debug("id old = %d(%d) was oplocked\n",
			opinfo_old->fid, opinfo_old->lock_type);

	if (!IS_SMB2(opinfo_old->server)) {
		cifssrv_debug("oplock break for inode %lu\n",
				inode->i_ino);
		WARN_ON(!((opinfo_old->lock_type == OPLOCK_BATCH) ||
					(opinfo_old->lock_type ==
					 OPLOCK_EXCLUSIVE)));

		/*
		 * Don't wait for oplock break while grabbing mutex.
		 * As server mutex is released here for sending oplock break,
		 * take a dummy ref count on ofile to prevent it getting freed
		 * from parallel close path. Decrement dummy ref count once
		 * oplock break response is received.
		 */
		opinfo_old->state = OPLOCK_BREAKING;
		atomic_inc(&ofile->op_count);
		mutex_unlock(&ofile_list_lock);
		err = smb1_oplock_break_to_levelII(ofile, opinfo_old);
		mutex_lock(&ofile_list_lock);
		atomic_dec(&ofile->op_count);
		if (err) {
			opinfo_old->state = OPLOCK_NOT_BREAKING;
			mutex_unlock(&ofile_list_lock);
			kfree(opinfo_new);
			return err;
		}

		cifssrv_debug("oplock granted = %d\n", opinfo_old->lock_type);
	} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
		cifssrv_debug("oplock break for inode %lu\n",
				inode->i_ino);
		WARN_ON(!((opinfo_old->lock_type ==
						SMB2_OPLOCK_LEVEL_BATCH) ||
					(opinfo_old->lock_type ==
					 SMB2_OPLOCK_LEVEL_EXCLUSIVE)));

		opinfo_old->state = OPLOCK_BREAKING;
		atomic_inc(&ofile->op_count);
		mutex_unlock(&ofile_list_lock);
		if (opinfo_old->leased) {
			/* break lease */
			if (opinfo_old->lock_type == SMB2_OPLOCK_LEVEL_BATCH)
				opinfo_old->NewLeaseState =
					SMB2_LEASE_READ_CACHING |
					SMB2_LEASE_HANDLE_CACHING;
			else
				opinfo_old->NewLeaseState =
					SMB2_LEASE_READ_CACHING;
			opinfo_new->CurrentLeaseState =
				opinfo_old->NewLeaseState;
			err = smb_break_write_lease(ofile, opinfo_old);
		} else {
			/* break oplock */
			err = smb2_oplock_break_to_levelII(ofile, opinfo_old);
		}
		mutex_lock(&ofile_list_lock);
		atomic_dec(&ofile->op_count);
		if (err) {
			opinfo_old->state = OPLOCK_NOT_BREAKING;
			if (lctx && fidinfo) {
				list_del(&fidinfo->fid_entry);
				kfree(fidinfo);
			}
			kfree(opinfo_new);
			mutex_unlock(&ofile_list_lock);
			return err;
		}

		cifssrv_debug("oplock granted = %d\n", opinfo_old->lock_type);
#endif
	}

	if (opinfo_old->state == OPLOCK_BREAKING) {
		opinfo_old->state = OPLOCK_NOT_BREAKING;
		wake_up(&ofile->op_end_wq);
	}

op_break_not_needed:
	/* add new oplock to read list */
	err = grant_read_oplock(ofile, opinfo_new, oplock, fp, lctx);
	mutex_unlock(&ofile_list_lock);
	return err;
}

/**
 * smb_break_write_oplock() - break batch/exclusive oplock to level2
 * @server:	TCP server instance of connection
 * @fp:		cifssrv file pointer
 * @openfile:	open file object
 */
void smb_break_write_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, struct ofile_info *openfile)
{
	struct ofile_info *ofile;
	struct oplock_info *opinfo, *tmp;
	struct inode *inode;
	int err = 0;

	if (!(fp && fp->ofile) && !openfile)
		return;

	if (openfile) {
		ofile = openfile;
		inode = openfile->inode;
	} else {
		ofile = fp->ofile;
		inode = file_inode(fp->filp);
	}

	list_for_each_entry_safe(opinfo, tmp,
			&ofile->op_write_list, op_list) {
		opinfo->open_trunc = 1;
		if (!IS_SMB2(opinfo->server)) {
			cifssrv_debug("oplock break for inode %lu\n",
					inode->i_ino);
			WARN_ON(!((opinfo->lock_type == OPLOCK_BATCH) ||
						(opinfo->lock_type ==
						 OPLOCK_EXCLUSIVE)));

			opinfo->state = OPLOCK_BREAKING;
			atomic_inc(&ofile->op_count);
			mutex_unlock(&ofile_list_lock);
			err = smb1_oplock_break_to_levelII(ofile, opinfo);
			mutex_lock(&ofile_list_lock);
			atomic_dec(&ofile->op_count);
			if (err) {
				opinfo->state = OPLOCK_NOT_BREAKING;
				mutex_unlock(&ofile_list_lock);
				return;
			}

			cifssrv_debug("oplock granted %d\n", opinfo->lock_type);
		} else {
#ifdef CONFIG_CIFS_SMB2_SERVER
			cifssrv_debug("oplock break for inode %lu\n",
					inode->i_ino);
			WARN_ON(!((opinfo->lock_type ==
						SMB2_OPLOCK_LEVEL_BATCH) ||
						(opinfo->lock_type ==
						 SMB2_OPLOCK_LEVEL_EXCLUSIVE)));

			opinfo->state = OPLOCK_BREAKING;
			atomic_inc(&ofile->op_count);
			mutex_unlock(&ofile_list_lock);
			if (opinfo->leased) {
				/* break lease */
				opinfo->NewLeaseState = SMB2_LEASE_NONE;
				err = smb_break_write_lease(ofile, opinfo);
			} else {
				/* break oplock */
				err = smb2_oplock_break_to_levelII(ofile,
						opinfo);
			}
			mutex_lock(&ofile_list_lock);
			atomic_dec(&ofile->op_count);
			if (err) {
				opinfo->state = OPLOCK_NOT_BREAKING;
				mutex_unlock(&ofile_list_lock);
				return;
			}

			cifssrv_debug("oplock granted %d\n", opinfo->lock_type);
#endif
		}

		if (opinfo->state == OPLOCK_BREAKING) {
			opinfo->state = OPLOCK_NOT_BREAKING;
			wake_up(&ofile->op_end_wq);
		}
	}
}

/**
 * smb_break_all_oplock() - break both batch/exclusive and level2 oplock
 * @server:	TCP server instance of connection
 * @fp:		cifssrv file pointer
 * @openfile:	open file object
 */
void smb_break_all_oplock(struct tcp_server_info *server,
		struct cifssrv_file *fp, struct inode *inode)
{
	struct ofile_info *ofile = NULL;
	struct list_head *tmp;
	bool file_open = false;

	mutex_lock(&ofile_list_lock);
	list_for_each(tmp, &ofile_list) {
		ofile = list_entry(tmp, struct ofile_info, i_list);
		if (ofile->inode == inode) {
			file_open = true;
			break;
		}
	}

	if (file_open) {
		smb_break_write_oplock(server, fp, ofile);
		smb_breakII_oplock(server, fp, ofile);
	}
	mutex_unlock(&ofile_list_lock);
}

/**
 * smb1_send_oplock_break() - send smb1 oplock break cmd from server to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * smb_work->buf contains oplock_info.
 */
void smb1_send_oplock_break(struct work_struct *work)
{
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct tcp_server_info *server = smb_work->server;
	struct smb_hdr *rsp_hdr;
	LOCK_REQ *req;
	struct oplock_info *opinfo = (struct oplock_info *)smb_work->buf;

	atomic_inc(&server->req_running);

	mutex_lock(&server->srv_mutex);

	smb_work->rsp_large_buf = false;
	if (server->ops->allocate_rsp_buf(smb_work)) {
		cifssrv_err("smb_allocate_rsp_buf failed! ");
		mutex_unlock(&server->srv_mutex);
		kfree(smb_work);
		return;
	}


	/* Init response header */
	rsp_hdr = (struct smb_hdr *)smb_work->rsp_buf;
	/* wct is 8 for locking andx */
	memset(rsp_hdr, 0, sizeof(struct smb_hdr) + 2 + 8*2);
	rsp_hdr->smb_buf_length = cpu_to_be32(HEADER_SIZE(server) - 1 + 8*2);
	rsp_hdr->Protocol[0] = 0xFF;
	rsp_hdr->Protocol[1] = 'S';
	rsp_hdr->Protocol[2] = 'M';
	rsp_hdr->Protocol[3] = 'B';

	rsp_hdr->Command = SMB_COM_LOCKING_ANDX;
	/* we know unicode, long file name and use nt error codes */
	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_KNOWS_LONG_NAMES |
		SMBFLG2_ERR_STATUS;
	rsp_hdr->Uid = server->vuid;
	rsp_hdr->Pid = 0xFFFF;
	rsp_hdr->Mid = 0xFFFF;
	rsp_hdr->Tid = cpu_to_le16(opinfo->Tid);
	rsp_hdr->WordCount = 8;

	/* Init locking request */
	req = (LOCK_REQ *)smb_work->rsp_buf;

	req->AndXCommand = 0xFF;
	req->AndXReserved = 0;
	req->AndXOffset = 0;
	req->Fid = opinfo->fid;
	req->LockType = LOCKING_ANDX_OPLOCK_RELEASE;
	if (!opinfo->open_trunc && (opinfo->lock_type == OPLOCK_BATCH ||
			opinfo->lock_type == OPLOCK_EXCLUSIVE))
		req->OplockLevel = 1;
	else {
		req->OplockLevel = 0;
	}
	req->Timeout = 0;
	req->NumberOfUnlocks = 0;
	req->ByteCount = 0;
	cifssrv_debug("sending oplock break for fid %d lock level = %d\n",
			req->Fid, req->OplockLevel);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifssrv_sm_rsp_poolp);
	kfree(smb_work);
	mutex_unlock(&server->srv_mutex);

	atomic_dec(&server->req_running);
	if (waitqueue_active(&server->req_running_q))
		wake_up_all(&server->req_running_q);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_send_oplock_break() - send smb1 oplock break cmd from server to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * smb_work->buf contains oplock_info.
 */
void smb2_send_oplock_break(struct work_struct *work)
{
	struct smb2_oplock_break *rsp = NULL;
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct tcp_server_info *server = smb_work->server;
	struct oplock_info *opinfo = (struct oplock_info *)smb_work->buf;
	struct smb2_hdr *rsp_hdr;
	struct cifssrv_file *fp;
	int persistent_id;

	atomic_inc(&server->req_running);

	mutex_lock(&server->srv_mutex);

	fp = get_id_from_fidtable(server, opinfo->fid);
	if (!fp) {
		mutex_unlock(&server->srv_mutex);
		kfree(smb_work);
		return;
	}
	persistent_id = fp->persistent_id;

	if (server->ops->allocate_rsp_buf(smb_work)) {
		cifssrv_err("smb2_allocate_rsp_buf failed! ");
		mutex_unlock(&server->srv_mutex);
		kfree(smb_work);
		return;
	}

	rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->smb2_buf_length = cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	rsp_hdr->ProtocolId[0] = 0XFE;
	rsp_hdr->ProtocolId[1] = 'S';
	rsp_hdr->ProtocolId[2] = 'M';
	rsp_hdr->ProtocolId[3] = 'B';
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = cpu_to_le16(0x12);
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->ProcessId = 0;
	rsp_hdr->TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);


	rsp = (struct smb2_oplock_break *)smb_work->rsp_buf;

	rsp->StructureSize = cpu_to_le16(24);
	if (!opinfo->open_trunc &&
			(opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH ||
			opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		rsp->OplockLevel = 1;
	else
		rsp->OplockLevel = 0;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->PersistentFid = cpu_to_le64(persistent_id);
	rsp->VolatileFid = cpu_to_le64(opinfo->fid);

	inc_rfc1001_len(rsp, 24);

	cifssrv_debug("sending oplock break v_id %llu p_id = %llu lock level = %d\n",
			rsp->VolatileFid, rsp->PersistentFid, rsp->OplockLevel);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifssrv_sm_rsp_poolp);
	kfree(smb_work);
	mutex_unlock(&server->srv_mutex);

	atomic_dec(&server->req_running);
	if (waitqueue_active(&server->req_running_q))
		wake_up_all(&server->req_running_q);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_map_lease_to_oplock() - map lease state to corresponding oplock type
 * @lease_state:     lease type
 *
 * Return:      0 if no mapping, otherwise corresponding oplock type
 */
static __u8 smb2_map_lease_to_oplock(__le32 lease_state)
{
	if (lease_state & SMB2_LEASE_WRITE_CACHING) {
		if (lease_state & SMB2_LEASE_HANDLE_CACHING)
			return SMB2_OPLOCK_LEVEL_BATCH;
		else
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (lease_state & SMB2_LEASE_READ_CACHING)
		return SMB2_OPLOCK_LEVEL_II;
	return 0;
}

/**
 * create_lease_buf() - create lease context for open cmd response
 * @rbuf:	buffer to create lease context response
 * @LeaseKey:	lease key
 * @oplock:	granted oplock/lease type
 * @handle:	handle caching granted on this file
 */
void create_lease_buf(u8 *rbuf, u8 *LeaseKey, u8 oplock, u8 handle)
{
	struct create_lease *buf = (struct create_lease *)rbuf;
	memset(buf, 0, sizeof(struct create_lease));

	buf->lcontext.LeaseKeyLow = *((u64 *)LeaseKey);
	buf->lcontext.LeaseKeyHigh = *((u64 *)(LeaseKey + 8));
	if (oplock == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
		buf->lcontext.LeaseState = SMB2_LEASE_WRITE_CACHING |
					   SMB2_LEASE_READ_CACHING;
	else if (oplock == SMB2_OPLOCK_LEVEL_II) {
		buf->lcontext.LeaseState = SMB2_LEASE_READ_CACHING;
		if (handle)
			buf->lcontext.LeaseState |= SMB2_LEASE_HANDLE_CACHING;
	} else if (oplock == SMB2_OPLOCK_LEVEL_BATCH)
		buf->lcontext.LeaseState = SMB2_LEASE_HANDLE_CACHING |
					   SMB2_LEASE_READ_CACHING |
					   SMB2_LEASE_WRITE_CACHING;

	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_lease, lcontext));
	buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context));
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_lease, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	buf->Name[0] = 'R';
	buf->Name[1] = 'q';
	buf->Name[2] = 'L';
	buf->Name[3] = 's';
}

/**
 * parse_lease_state() - parse lease context containted in file open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @lreq:	buffer to stored parsed lease state information
 *
 * Return:      0
 */
__u8 parse_lease_state(void *open_req, struct lease_ctx_info *lreq)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	bool found = false;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;

	data_offset = (char *)req + 4 + le32_to_cpu(req->CreateContextsOffset);
	cc = (struct create_context *)data_offset;
	do {
		cc = (struct create_context *)((char *)cc + next);
		name = le16_to_cpu(cc->NameOffset) + (char *)cc;
		if (le16_to_cpu(cc->NameLength) != 4 ||
				strncmp(name, SMB2_CREATE_REQUEST_LEASE, 4)) {
			next = le32_to_cpu(cc->Next);
			continue;
		}
		found = true;
		break;
	} while (next != 0);

	if (found) {
		struct create_lease *lc = (struct create_lease *)cc;
		*((u64 *)lreq->LeaseKey) = lc->lcontext.LeaseKeyLow;
		*((u64 *)(lreq->LeaseKey + 8)) = lc->lcontext.LeaseKeyHigh;
		lreq->CurrentLeaseState = lc->lcontext.LeaseState;
		lreq->LeaseFlags = lc->lcontext.LeaseFlags;
		lreq->LeaseDuration = lc->lcontext.LeaseDuration;
		return smb2_map_lease_to_oplock(lc->lcontext.LeaseState);
	}

	return 0;
}

/**
 * smb2_find_context_vals() - find a particular context info in open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @str:	context name to search for
 *
 * Return:      pointer to requested context, NULL if @str context not found
 */
struct create_context *smb2_find_context_vals(void *open_req, char *str)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	bool found = false;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;

	data_offset = (char *)req + 4 + le32_to_cpu(req->CreateContextsOffset);
	cc = (struct create_context *)data_offset;
	do {
		cc = (struct create_context *)((char *)cc + next);
		name = le16_to_cpu(cc->NameOffset) + (char *)cc;
		if (le16_to_cpu(cc->NameLength) != 4 ||
				strncmp(name, str, 4)) {
			next = le32_to_cpu(cc->Next);
			continue;
		}
		found = 1;
		break;
	} while (next != 0);

	if (found)
		return cc;
	else
		return NULL;
}

/**
 * create_durable_buf() - create durable handle context
 * @cc:	buffer to create durable context response
 *
 * TODO: not used, remove it ??
 */
void create_durable_buf(char *cc)
{
	struct create_durable *buf;
	buf = (struct create_durable *)cc;
	memset(buf, 0, sizeof(struct create_durable));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable, Data));
	buf->ccontext.DataLength = cpu_to_le32(16);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
}

/**
 * create_durable_buf() - create durable handle context
 * @cc:	buffer to create durable context response
 */
void create_durable_rsp_buf(char *cc)
{
	struct create_durable_rsp *buf;
	buf = (struct create_durable_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Data));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
}

/*
 * Find lease object(opinfo) for given lease key/fid from lease
 * break/file close path.
 * If needed, return ofile and fidinfo for given lease key/fid.
 */
/**
 * get_matching_opinfo_lease() - find a matching lease info object
 * @server:     TCP server instance of connection
 * @ofile:	opened file to be searched. If NULL polplate this
 *              with ofile of lease owner
 * @LeaseKey:	lease key to be searched for
 * @fidinfo:	check that this fid is associated with lease object
 * @id:		fid containing lease key, local to smb connection
 *
 * Return:      opinfo if found matching opinfo, otherwise NULL
 */
struct oplock_info *get_matching_opinfo_lease(struct tcp_server_info *server,
		struct ofile_info **ofile, char *LeaseKey,
		struct lease_fidinfo **fidinfo, int id)
{
	struct ofile_info *ofile_tmp = NULL;
	struct oplock_info *opinfo = NULL;
	__u8 op_found = 0, fid_found = 0;

	if (*ofile) {
		ofile_tmp = *ofile;
		opinfo = find_opinfo(&ofile_tmp->op_write_list,
				server->ClientGUID, LeaseKey);
		if (opinfo) {
			op_found = 1;
			goto out;
		}

		opinfo = find_opinfo(&ofile_tmp->op_read_list,
				server->ClientGUID, LeaseKey);
		if (opinfo) {
			op_found = 1;
			goto out;
		}

		/* none list needs to be serached only from file close path */
		if (!fidinfo)
			goto out;

		opinfo = find_opinfo(&ofile_tmp->op_none_list,
				server->ClientGUID, LeaseKey);
		if (opinfo) {
			op_found = 1;
			goto out;
		}
	} else {
		list_for_each_entry(ofile_tmp, &ofile_list, i_list) {
			opinfo = find_opinfo(&ofile_tmp->op_write_list,
					server->ClientGUID, LeaseKey);
			if (opinfo) {
				*ofile = ofile_tmp;
				op_found = 1;
				goto out;
			}

			opinfo = find_opinfo(&ofile_tmp->op_read_list,
					server->ClientGUID, LeaseKey);
			if (opinfo) {
				*ofile = ofile_tmp;
				op_found = 1;
				goto out;
			}

			if (!fidinfo)
				goto out;

			opinfo = find_opinfo(&ofile_tmp->op_none_list,
					server->ClientGUID, LeaseKey);
			if (opinfo) {
				*ofile = ofile_tmp;
				op_found = 1;
				goto out;
			}
		}
	}

out:
	if (op_found) {
		if (fidinfo) {
			/* this is close path, make sure opinfo has given fid */
			struct lease_fidinfo *fidinfo_tmp;
			list_for_each_entry(fidinfo_tmp, &opinfo->fid_list,
					fid_entry) {
				if (fidinfo_tmp->fid == id) {
					*fidinfo = fidinfo_tmp;
					fid_found = 1;
					break;
				}
			}

			if (!fid_found)
				return NULL;

		}
		return opinfo;
	}

	return NULL;
}

/**
 * smb_break_write_lease() - break write lease when a new client request
 *			write lease
 * @ofile:	open file object
 * @opinfo:	conains lease state information
 *
 * Return:	0 on success, otherwise error
 */
int smb_break_write_lease(struct ofile_info *ofile,
		struct oplock_info *opinfo)
{
	struct tcp_server_info *server = opinfo->server;
	int ret = 0;
	struct smb_work *work = kzalloc(sizeof(struct smb_work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->buf = (char *)opinfo;
	work->server = server;
	INIT_WORK(&work->work, smb_send_lease_break);
	schedule_work(&work->work);

	wait_event_interruptible_timeout(server->oplock_q,
			(opinfo->lock_type == SMB2_OPLOCK_LEVEL_II ||
			 opinfo->lock_type == SMB2_OPLOCK_LEVEL_NONE),
			OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (opinfo->lock_type == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			opinfo->lock_type == SMB2_OPLOCK_LEVEL_BATCH) {
		mutex_lock(&ofile_list_lock);
		ret = opinfo_write_to_read(ofile, opinfo,
				opinfo->CurrentLeaseState);
		mutex_unlock(&ofile_list_lock);
	}
	return ret;
}

/**
 * cifssrv_durable_verify_and_del_oplock() - Check if the file is already
 *					opened on current server
 * @curr_server:	current TCP server instance of connection
 * @prev_server:	previous TCP server instance of connection
 * @fid:		file id of open file
 * @filp:		file pointer of open file
 *
 * Return:	0 on success, otherwise error
 */
int cifssrv_durable_verify_and_del_oplock(struct tcp_server_info *curr_server,
					  struct tcp_server_info *prev_server,
					  int fid, struct file **filp)
{
	struct cifssrv_file *fp, *fp_curr;
	struct ofile_info *ofile;
	struct oplock_info *opinfo;
	int lock_type;
	int op_state;
	int rc = 0;

	mutex_lock(&ofile_list_lock);

	fp_curr = get_id_from_fidtable(curr_server, fid);
	if (fp_curr && fp_curr->sess_id == curr_server->sess_id) {
		mutex_unlock(&ofile_list_lock);
		cifssrv_err("File already opened on current server\n");
		rc = -EINVAL;
		goto out;
	}

	fp = get_id_from_fidtable(prev_server, fid);
	if (!fp) {
		mutex_unlock(&ofile_list_lock);
		cifssrv_err("File struct not found\n");
		rc = -EINVAL;
		goto out;
	}

	ofile = fp->ofile;
	if (ofile == NULL) {
		mutex_unlock(&ofile_list_lock);
		cifssrv_err("unexpected null ofile_info\n");
		rc = -EINVAL;
		goto out;
	}

	opinfo = get_matching_opinfo(prev_server, ofile, fid, 0);
	if (opinfo == NULL) {
		mutex_unlock(&ofile_list_lock);
		cifssrv_err("Unexpected null oplock_info\n");
		rc = -EINVAL;
		goto out;
	}

	lock_type = opinfo->lock_type;
	*filp = fp->filp;
	op_state = opinfo->state;

	mutex_unlock(&ofile_list_lock);

	if (op_state == OPLOCK_BREAKING) {
		cifssrv_err("Oplock is breaking state\n");
		rc = -EINVAL;
		goto out;
	}

	if (lock_type != SMB2_OPLOCK_LEVEL_BATCH) {
		cifssrv_err("Oplock is broken from Batch oplock\n");
		rc = -EINVAL;
		goto out;
	}

	/* Remove the oplock associated with previous server thread */
	close_id_del_oplock(prev_server, fp, fid);
	delete_id_from_fidtable(prev_server, fid);
	cifssrv_close_id(&prev_server->fidtable, fid);

out:
	return rc;
}
#endif

#endif
