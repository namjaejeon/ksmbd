/*
 *   fs/cifsd/oplock.c
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
#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif
#include "oplock.h"

bool oplocks_enable = true;
#ifdef CONFIG_CIFS_SMB2_SERVER
bool lease_enable = true;
bool durable_enable = true;
#endif

LIST_HEAD(lease_table_list);
DEFINE_MUTEX(lease_list_lock);

module_param(oplocks_enable, bool, 0644);
MODULE_PARM_DESC(oplocks_enable, "Enable or disable oplocks. Default: y/Y/1");

#ifdef CONFIG_CIFS_SMB2_SERVER
module_param(lease_enable, bool, 0644);
MODULE_PARM_DESC(lease_enable, "Enable or disable lease. Default: y/Y/1");

module_param(durable_enable, bool, 0644);
MODULE_PARM_DESC(durable_enable, "Enable or disable lease. Default: y/Y/1");
#endif

/**
 * get_new_opinfo() - allocate a new opinfo object for oplock info
 * @conn:     TCP server instance of connection
 * @id:		fid of open file
 * @Tid:	tree id of connection
 * @lctx:	lease context information
 *
 * Return:      allocated opinfo object on success, otherwise NULL
 */
static struct oplock_info *alloc_opinfo(struct smb_work *work,
		int id, __u16 Tid)
{
	struct cifsd_sess *sess = work->sess;
	struct oplock_info *opinfo;

	opinfo = kzalloc(sizeof(struct oplock_info), GFP_NOFS);
	if (!opinfo)
		return NULL;

	opinfo->sess = sess;
	opinfo->conn = sess->conn;
	opinfo->level = OPLOCK_NONE;
	opinfo->op_state = OPLOCK_STATE_NONE;
	opinfo->fid = id;
	opinfo->Tid = Tid;
	INIT_LIST_HEAD(&opinfo->interim_list);
	init_waitqueue_head(&opinfo->op_end_wq);

	return opinfo;
}

static int alloc_lease(struct oplock_info *opinfo,
	struct lease_ctx_info *lctx)
{
	struct lease *lease;

	lease = kmalloc(sizeof(struct lease), GFP_KERNEL);
	if (!lease)
		return -ENOMEM;

	memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
	lease->state = lctx->req_state;
	lease->new_state = 0;
	lease->flags = lctx->flags;
	lease->duration = lctx->duration;
	opinfo->o_lease = lease;

	return 0;
}

void free_lease(struct oplock_info *opinfo)
{
	struct lease *lease;

	list_del(&opinfo->lease_entry);
	lease = opinfo->o_lease;
	opinfo->o_lease = NULL;
	kfree(lease);
}

/**
 * opinfo_write_to_read() - convert a write oplock to read oplock
 * @ofile:		opened file to be checked for oplock status
 * @opinfo:		current oplock info
 * @lease_state:	current lease state
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (IS_SMB2(opinfo->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (!((opinfo->level == OPLOCK_EXCLUSIVE) ||
			(opinfo->level == OPLOCK_BATCH))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_READ;
	}

	return 0;
}

/**
 * opinfo_read_handle_to_read() - convert a read/handle oplock to read oplock
 * @ofile:		opened file to be checked for oplock status
 * @opinfo:		current oplock info
 * @lease_state:	current lease state
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_handle_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

#ifdef CONFIG_CIFS_SMB2_SERVER
	lease->state = lease->new_state;
	opinfo->level = SMB2_OPLOCK_LEVEL_II;
#endif
	return 0;
}

/**
 * opinfo_write_to_none() - convert a write oplock to none
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (IS_SMB2(opinfo->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n",
						lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (!((opinfo->level == OPLOCK_EXCLUSIVE) ||
			(opinfo->level == OPLOCK_BATCH))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}

	return 0;
}

/**
 * opinfo_read_to_none() - convert a write read to none
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (IS_SMB2(opinfo->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (opinfo->level != OPLOCK_READ) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}

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
int lease_read_to_write(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state & SMB2_LEASE_READ_CACHING)) {
		cifsd_debug("bad lease state(0x%x)\n",
				lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE;
	lease->state |= SMB2_LEASE_WRITE_CACHING;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
	else
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	return 0;
}

/**
 * lease_none_upgrade() - upgrade lease state from none
 * @ofile:	opened file to be checked for oplock status
 * @opinfo:	current lease info
 * @curr_state:	current lease state
 *
 * Return:	0 on success, otherwise -EINVAL
 */
int lease_none_upgrade(struct oplock_info *opinfo,
	__le32 new_state)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state == SMB2_LEASE_NONE)) {
		cifsd_debug("bad lease state(0x%x)\n",
				lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE;
	lease->state = new_state;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING)
		if (lease->state & SMB2_LEASE_WRITE_CACHING)
			opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo->level = SMB2_OPLOCK_LEVEL_II;
	else if (lease->state & SMB2_LEASE_WRITE_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	else if (lease->state & SMB2_LEASE_READ_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

	return 0;
}
#endif

/**
 * close_id_del_oplock() - release oplock object at file close time
 * @conn:     TCP server instance of connection
 * @fp:		cifsd file pointer
 * @id:		fid of open file
 */
void close_id_del_oplock(struct connection *conn, struct cifsd_file *fp)
{
	struct oplock_info *opinfo;

	if (!oplocks_enable || S_ISDIR(file_inode(fp->filp)->i_mode))
		return;

	opinfo = fp->f_opinfo;
	if (!opinfo)
		return;

	fp->f_opinfo = NULL;
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		opinfo->op_state = OPLOCK_CLOSING;
		wake_up_interruptible(&conn->oplock_q);
		if (opinfo->is_lease) {
			atomic_set(&opinfo->breaking_cnt, 0);
			wake_up_interruptible(&conn->oplock_brk);
		}
	} else {
		mutex_lock(&lease_list_lock);
		if (opinfo->is_lease)
			free_lease(opinfo);
		atomic_dec(&fp->f_mfp->op_count);
		kfree(opinfo);
		mutex_unlock(&lease_list_lock);
	}
}


#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_send_lease_break_notification() - send lease break command from server
 * to client
 * @work:     smb work object
 */
static void smb2_send_lease_break_notification(struct work_struct *work)
{
	struct smb2_lease_break *rsp = NULL;
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct lease_break_info *br_info =
		(struct lease_break_info *)smb_work->buf;
	struct connection *conn = smb_work->conn;
	struct smb2_hdr *rsp_hdr;

	atomic_inc(&conn->req_running);
	mutex_lock(&conn->srv_mutex);

	if (conn->ops->allocate_rsp_buf(smb_work)) {
		cifsd_debug("smb2_allocate_rsp_buf failed! ");
		mutex_unlock(&conn->srv_mutex);
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
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = (struct smb2_lease_break *)smb_work->rsp_buf;
	rsp->StructureSize = cpu_to_le16(44);
	rsp->Reserved = 0;
	rsp->Flags = 0;

	if (br_info->curr_state & (SMB2_LEASE_WRITE_CACHING |
			SMB2_LEASE_HANDLE_CACHING))
		rsp->Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;

	memcpy(rsp->LeaseKey, br_info->lease_key, SMB2_LEASE_KEY_SIZE);
	rsp->CurrentLeaseState = br_info->curr_state;
	rsp->NewLeaseState = br_info->new_state;
	rsp->BreakReason = 0;
	rsp->AccessMaskHint = 0;
	rsp->ShareMaskHint = 0;

	inc_rfc1001_len(rsp, 44);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifsd_sm_rsp_poolp);
	kfree(smb_work);
	mutex_unlock(&conn->srv_mutex);

	atomic_dec(&conn->req_running);
	if (waitqueue_active(&conn->req_running_q))
		wake_up_all(&conn->req_running_q);

}
#endif

/**
 * smb1_oplock_break_notification() - send smb1 exclusive/batch to level2 oplock
 *		break command from server to client
 * @ofile:	open file object
 * @opinfo:	oplock info object
 *
 * Return:      0 on success, otherwise error
 */
static int smb1_oplock_break_notification(struct oplock_info *opinfo,
	int ack_required)
{
	struct connection *conn = opinfo->conn;
	int ret = 0;
	struct smb_work *work = kmem_cache_zalloc(cifsd_work_cache, GFP_NOFS);
	if (!work)
		return -ENOMEM;

	work->buf = (char *)opinfo;
	work->conn = conn;

	if (ack_required) {
		int rc;

		INIT_WORK(&work->work, smb1_send_oplock_break_notification);
		schedule_work(&work->work);

		/*
		 * TODO: change to wait_event_interruptible_timeout once oplock
		 * break notification timeout is decided. In case of oplock
		 * break from levelII to none, we don't need to wait for client
		 * response.
		 */
		rc = wait_event_interruptible_timeout(conn->oplock_q,
				opinfo->op_state == OPLOCK_STATE_NONE ||
				opinfo->op_state == OPLOCK_CLOSING,
				OPLOCK_WAIT_TIME);

		/* is this a timeout ? */
		if (!rc) {
			opinfo->level = OPLOCK_NONE;
			opinfo->op_state = OPLOCK_STATE_NONE;
		}
	} else {
		smb1_send_oplock_break_notification(&work->work);
		if (opinfo->level == OPLOCK_READ)
			opinfo->level = OPLOCK_NONE;
	}
	return ret;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_oplock_break_notification() - send smb2 exclusive/batch to level2 oplock
 *		break command from server to client
 * @ofile:	open file object
 * @opinfo:	oplock info object
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_oplock_break_notification(struct oplock_info *opinfo,
	int ack_required)
{
	struct connection *conn = opinfo->conn;
	struct oplock_break_info *br_info;
	int ret = 0;
	struct smb_work *work = kmem_cache_zalloc(cifsd_work_cache, GFP_NOFS);
	if (!work)
		return -ENOMEM;

	br_info = kmalloc(sizeof(struct oplock_break_info), GFP_KERNEL);
	if (!br_info)
		return -ENOMEM;

	br_info->level = opinfo->level;
	br_info->fid = opinfo->fid;
	br_info->open_trunc = opinfo->open_trunc;

	work->buf = (char *)br_info;
	work->conn = conn;
	work->sess = opinfo->sess;

	if (ack_required) {
		int rc;

		INIT_WORK(&work->work, smb2_send_oplock_break_notification);
		schedule_work(&work->work);

		rc = wait_event_interruptible_timeout(conn->oplock_q,
			opinfo->op_state == OPLOCK_STATE_NONE ||
			opinfo->op_state == OPLOCK_CLOSING,
			OPLOCK_WAIT_TIME);

		/* is this a timeout ? */
		if (!rc) {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
			opinfo->op_state = OPLOCK_STATE_NONE;
		}
	} else {
		smb2_send_oplock_break_notification(&work->work);
		if (opinfo->level == SMB2_OPLOCK_LEVEL_II)
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	}
	return ret;
}
#endif

/**
 * grant_write_oplock() - grant exclusive/batch oplock or write lease
 * @ofile:	open file object
 * @opinfo_new:	new oplock info object
 * @fp:		cifsd file pointer
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (IS_SMB2(opinfo_new->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)
			opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
#endif
	} else {
		if (req_oplock == REQ_BATCHOPLOCK)
			opinfo_new->level = OPLOCK_BATCH;
		else
			opinfo_new->level = OPLOCK_EXCLUSIVE;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = lctx->req_state;
		lctx->rsp_state = lease->state;
		memcpy(lease->lease_key, lctx->lease_key,
				SMB2_LEASE_KEY_SIZE);
	}
#endif
}

/**
 * grant_read_oplock() - grant level2 oplock or read lease
 * @ofile:	open file object
 * @opinfo_new:	new oplock info object
 * @fp:		cifsd file pointer
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_read_oplock(struct oplock_info *opinfo_new,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (IS_SMB2(opinfo_new->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		opinfo_new->level = SMB2_OPLOCK_LEVEL_II;
#endif
	} else
		opinfo_new->level = OPLOCK_READ;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = SMB2_LEASE_READ_CACHING;
		if (lctx->req_state & SMB2_LEASE_HANDLE_CACHING)
			lease->state |= SMB2_LEASE_HANDLE_CACHING;
		lctx->rsp_state = lease->state;
		memcpy(lease->lease_key, lctx->lease_key,
				SMB2_LEASE_KEY_SIZE);
	}
#endif
}

/**
 * grant_none_oplock() - grant none oplock or none lease
 * @ofile:	open file object
 * @opinfo_new:	new oplock info object
 * @fp:		cifsd file pointer
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_none_oplock(struct oplock_info *opinfo_new,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (IS_SMB2(opinfo_new->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;
#endif
	} else
		opinfo_new->level = OPLOCK_NONE;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = 0;
		lctx->rsp_state = 0;
		memcpy(lease->lease_key, lctx->lease_key,
			SMB2_LEASE_KEY_SIZE);
	}
#endif
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
static inline int compare_guid_key(struct oplock_info *opinfo,
		const char *guid1, const char *key1)
{
	const char *guid2, *key2;

	guid2 = opinfo->conn->ClientGUID;
	key2 = opinfo->o_lease->lease_key;
	if (!memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE) &&
			!memcmp(key1, key2, SMB2_LEASE_KEY_SIZE))
		return 1;

	return 0;
}

/**
 * same_client_has_lease() - check whether current lease request is
 *		from lease owner of file
 * @conn:     TCP server instance of connection
 * @lctx:	lease context information
 * @ofile:	open file object
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
struct oplock_info *same_client_has_lease(struct cifsd_mfile *mfp,
	char *client_guid, struct lease_ctx_info *lctx)
{
	int ret;
	struct lease *lease;
	struct cifsd_file *prev_fp;
	struct oplock_info *opinfo;
	struct oplock_info *m_opinfo = NULL;

	if (!lctx)
		return NULL;

	/*
	 * Compare lease key and client_guid to know request from same owner
	 * of same client
	 */
	list_for_each_entry(prev_fp, &mfp->m_fp_list, node) {
		opinfo = prev_fp->f_opinfo;
		if (!opinfo || !opinfo->is_lease)
			continue;
		lease = opinfo->o_lease;

		ret = compare_guid_key(opinfo, client_guid, lctx->lease_key);
		if (ret) {
			m_opinfo = opinfo;

			/* upgrading lease */
			if (atomic_read(&mfp->op_count) == 2) {
				if (lease->state ==
					(lctx->req_state & lease->state)) {
					lease->state |= lctx->req_state;
					if (lctx->req_state &
						SMB2_LEASE_WRITE_CACHING)
						lease_read_to_write(opinfo);
				}
			} else if (atomic_read(&mfp->op_count) > 2) {
				if (lctx->req_state == 0x3)
					lease->state = lctx->req_state;
			}

			if (lctx->req_state && lease->state == SMB2_LEASE_NONE)
				lease_none_upgrade(opinfo, lctx->req_state);
		}
	}

	return m_opinfo;
}
#endif

void wait_for_lease_break_ack(struct oplock_info *opinfo)
{
	struct connection *conn = opinfo->conn;
	int rc = 0;

	rc = wait_event_interruptible_timeout(conn->oplock_q,
		opinfo->op_state == OPLOCK_STATE_NONE ||
		opinfo->op_state == OPLOCK_CLOSING,
		OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (!rc) {
		if (opinfo->is_lease)
			opinfo->o_lease->state = SMB2_LEASE_NONE;
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		opinfo->op_state = OPLOCK_STATE_NONE;
	}
}

/**
 * smb2_break_lease_notification() - break lease when a new client request
 *			write lease
 * @ofile:	open file object
 * @opinfo:	conains lease state information
 *
 * Return:	0 on success, otherwise error
 */
int smb2_break_lease_notification(struct oplock_info *opinfo, int ack_required)
{
	struct connection *conn = opinfo->conn;
	struct list_head *tmp, *t;
	struct smb_work *work;
	struct lease_break_info *br_info;
	struct lease *lease = opinfo->o_lease;

	work = kmem_cache_zalloc(cifsd_work_cache, GFP_NOFS);
	if (!work)
		return -ENOMEM;

	br_info = kmalloc(sizeof(struct lease_break_info), GFP_KERNEL);
	if (!br_info)
		return -ENOMEM;

	br_info->curr_state = lease->state;
	br_info->new_state = lease->new_state;
	memcpy(br_info->lease_key, lease->lease_key, SMB2_LEASE_KEY_SIZE);

	work->buf = (char *)br_info;
	work->conn = conn;
	work->sess = opinfo->sess;

	if (ack_required) {
		list_for_each_safe(tmp, t, &opinfo->interim_list) {
			struct smb_work *in_work;

			in_work = list_entry(tmp, struct smb_work,
				interim_entry);
			smb2_send_interim_resp(in_work);
			list_del(&in_work->interim_entry);
		}
		INIT_WORK(&work->work, smb2_send_lease_break_notification);
		schedule_work(&work->work);
		wait_for_lease_break_ack(opinfo);

		if (!atomic_read(&opinfo->breaking_cnt))
			wake_up_interruptible(&conn->oplock_brk);

		if (atomic_read(&opinfo->breaking_cnt)) {
			int ret = 0;

			ret = wait_event_interruptible_timeout(conn->oplock_brk,
				atomic_read(&opinfo->breaking_cnt) == 0,
				OPLOCK_WAIT_TIME);
			if (!ret)
				atomic_set(&opinfo->breaking_cnt, 0);
		}
	} else {
		smb2_send_lease_break_notification(&work->work);
		if (opinfo->o_lease->state == SMB2_LEASE_READ_CACHING) {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
			opinfo->o_lease->state = SMB2_LEASE_NONE;
		}
	}
	return 0;
}

static int smb_send_oplock_break_notification(struct oplock_info *brk_opinfo)
{
	int err = 0;
	int is_smb2 = IS_SMB2(brk_opinfo->conn);
	int ack_required = 0;

	/* Need to break exclusive/batch oplock, write lease or overwrite_if */
	cifsd_debug("request to send oplock(level : 0x%x) break notification\n",
		brk_opinfo->level);

	/*
	* Don't wait for oplock break while grabbing mutex.
	* As conn mutex is released here for sending oplock break,
	* take a dummy ref count on ofile to prevent it getting freed
	* from parallel close path. Decrement dummy ref count once
	* oplock break response is received.
	*/

	if (brk_opinfo->is_lease) {
		struct lease *lease = brk_opinfo->o_lease;

		if (!(lease->state == SMB2_LEASE_READ_CACHING))
			atomic_inc(&brk_opinfo->breaking_cnt);

		if (brk_opinfo->op_state == OPLOCK_ACK_WAIT) {
			/* wait till getting break ack */
			wait_for_lease_break_ack(brk_opinfo);

			/* Not immediately break to none. */
			brk_opinfo->open_trunc = 0;
		}

		if (brk_opinfo->open_trunc) {
			/*
			 * Create overwrite break trigger the lease break to
			 * none.
			 */
			lease->new_state = SMB2_LEASE_NONE;
		} else {
			if (lease->state & SMB2_LEASE_WRITE_CACHING) {
				if (lease->state & SMB2_LEASE_HANDLE_CACHING)
					lease->new_state =
						SMB2_LEASE_READ_CACHING |
						SMB2_LEASE_HANDLE_CACHING;
				else
					lease->new_state =
						SMB2_LEASE_READ_CACHING;
			} else {
				if (lease->state & SMB2_LEASE_HANDLE_CACHING)
					lease->new_state =
						SMB2_LEASE_READ_CACHING;
				else
					lease->new_state = SMB2_LEASE_NONE;
			}
		}

		if (lease->state & (SMB2_LEASE_WRITE_CACHING |
				SMB2_LEASE_HANDLE_CACHING))
			brk_opinfo->op_state = OPLOCK_ACK_WAIT;
	} else if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
		brk_opinfo->op_state = OPLOCK_ACK_WAIT;

	if (is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (brk_opinfo->is_lease) {
			struct lease *lease = brk_opinfo->o_lease;

			if ((brk_opinfo->open_trunc == 1 &&
				!(lease->state & SMB2_LEASE_WRITE_CACHING)) ||
				lease->state == SMB2_LEASE_READ_CACHING)
				ack_required = 0;
			else
				ack_required = 1;

			err = smb2_break_lease_notification(brk_opinfo,
				ack_required);
		} else {
			/* break oplock */
			if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
				brk_opinfo->level ==
				SMB2_OPLOCK_LEVEL_EXCLUSIVE)
				ack_required = 1;
			err = smb2_oplock_break_notification(brk_opinfo,
				ack_required);
		}
#endif
	} else {
		if ((brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
			ack_required = 1;
		err = smb1_oplock_break_notification(brk_opinfo,
			ack_required);
	}

	cifsd_debug("oplock granted = %d\n", brk_opinfo->level);
	if (brk_opinfo->op_state == OPLOCK_CLOSING) {
		mutex_lock(&lease_list_lock);
		if (brk_opinfo->is_lease)
			free_lease(brk_opinfo);
		kfree(brk_opinfo);
		err = -ENOENT;
		mutex_unlock(&lease_list_lock);
	}

	return err;
}

void destroy_lease_table(struct connection *conn)
{
	struct lease_table *lb, *lbtmp;

	if (list_empty(&lease_table_list))
		return;

	list_for_each_entry_safe(lb, lbtmp, &lease_table_list, l_entry) {
		if (conn && memcmp(lb->client_guid, conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE))
			continue;

		if (!list_empty(&lb->lease_list)) {
			cifsd_err("lease table list is not empty\n");
			WARN_ON(1);
		}

		list_del(&lb->l_entry);
		kfree(lb);
	}
}

int find_same_lease_key(struct cifsd_sess *sess, struct cifsd_mfile *mfp,
		struct lease_ctx_info *lctx)
{
	struct oplock_info *opinfo;
	int err = 0;
	struct lease_table *lb;

	if (!lctx)
		return err;

	mutex_lock(&lease_list_lock);
	if (list_empty(&lease_table_list))
		goto out;

	list_for_each_entry(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, sess->conn->ClientGUID,
					SMB2_CLIENT_GUID_SIZE)) {
			list_for_each_entry(opinfo, &lb->lease_list,
					lease_entry) {
				if (opinfo->o_fp->f_mfp == mfp)
					continue;
				err = compare_guid_key(opinfo,
					sess->conn->ClientGUID,
					lctx->lease_key);
				if (err) {
					err = -EINVAL;
					cifsd_debug("found same lease key is already used in other files\n");
					goto out;
				}
			}
		}
	}

out:
	mutex_unlock(&lease_list_lock);
	return err;
}

static void copy_lease(struct oplock_info *op1, struct oplock_info *op2)
{
	struct lease *lease1 = op1->o_lease;
	struct lease *lease2 = op2->o_lease;

	op2->level = op1->level;
	lease2->state = lease1->state;
	memcpy(lease2->lease_key, lease1->lease_key,
		SMB2_LEASE_KEY_SIZE);
	lease2->duration = lease1->duration;
	lease2->flags = lease1->flags;
}

void add_lease_global_list(struct oplock_info *opinfo)
{
	struct lease_table *lb;
	int added = 0;

	mutex_lock(&lease_list_lock);
	list_for_each_entry(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, opinfo->conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE)) {
			list_add(&opinfo->lease_entry, &lb->lease_list);
			added = 1;
			break;
		}
	}

	if (!added) {
		lb = kmalloc(sizeof(struct lease_table), GFP_KERNEL);
		memcpy(lb->client_guid, opinfo->conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE);
		INIT_LIST_HEAD(&lb->lease_list);
		list_add(&opinfo->lease_entry, &lb->lease_list);
		list_add(&lb->l_entry, &lease_table_list);
	}
	mutex_unlock(&lease_list_lock);
}

/**
 * smb_grant_oplock() - handle oplock/lease request on file open
 * @fp:		cifsd file pointer
 * @oplock:	granted oplock type
 * @id:		fid of open file
 * @Tid:	Tree id of connection
 * @lctx:	lease context information on file open
 * @attr_only:	attribute only file open type
 *
 * Return:      0 on success, otherwise error
 */
int smb_grant_oplock(struct smb_work *work, int req_op_level, int id,
	struct cifsd_file *fp, __u16 tid, struct lease_ctx_info *lctx)
{
	struct cifsd_sess *sess = work->sess;
	int err = 0;
	struct oplock_info *opinfo = NULL, *prev_opinfo = NULL;
	struct cifsd_mfile *mfp = fp->f_mfp;
	struct cifsd_file *prev_fp;
	int share_ret = 0;

	/* not support directory lease */
	if (lctx && S_ISDIR(file_inode(fp->filp)->i_mode)) {
		lctx->dlease = 1;
		return 0;
	}

	opinfo = alloc_opinfo(work, id, tid);
	if (!opinfo)
		return -ENOMEM;

	fp->f_opinfo = opinfo;
	opinfo->o_fp = fp;
	atomic_inc(&mfp->op_count);
	if (lctx) {
		err = alloc_lease(opinfo, lctx);
		if (err)
			goto out;
		opinfo->is_lease = 1;
		add_lease_global_list(opinfo);
	}

	/* inode does not have any oplock */
	if (list_empty(&mfp->m_fp_list)) {
new_oplock:
		switch (req_op_level) {
		case SMB2_OPLOCK_LEVEL_BATCH:
		case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
			grant_write_oplock(opinfo,
				req_op_level, lctx);
			break;
		case SMB2_OPLOCK_LEVEL_II:
			grant_read_oplock(opinfo, lctx);
			break;
		default:
			grant_none_oplock(opinfo, lctx);
			break;
		}
		return 0;
	}

	/* grant none-oplock if second open is trunc */
	if (ATTR_FP(fp)) {
		req_op_level = 0;
		goto grant_none;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		struct oplock_info *m_opinfo;

		/* is lease already granted ? */
		m_opinfo = same_client_has_lease(mfp, sess->conn->ClientGUID,
			lctx);
		if (m_opinfo) {
			copy_lease(m_opinfo, opinfo);
			if (atomic_read(&m_opinfo->breaking_cnt))
				lctx->flags = SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
			lctx->rsp_state = opinfo->o_lease->state;
			return 0;
		}
	}
#endif

	prev_fp = list_first_entry(&mfp->m_fp_list, struct cifsd_file, node);
	prev_opinfo = prev_fp->f_opinfo;

	share_ret = smb_check_shared_mode(fp->filp, fp);
	if (share_ret < 0 &&
		(prev_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE &&
		!S_ISDIR(FP_INODE(fp)->i_mode))) {
		err = share_ret;
		goto out;
	}

	if ((prev_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH) &&
		(prev_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		goto op_break_not_needed;

	list_add(&work->interim_entry, &prev_opinfo->interim_list);
	err = smb_send_oplock_break_notification(prev_opinfo);
	if (err == -ENOENT)
		goto new_oplock;
	/* Check all oplock was freed by close */
	else if (err < 0)
		goto out;

op_break_not_needed:
	if (share_ret < 0) {
		err = share_ret;
		goto out;
	}

	/* Check delete pending among previous fp before oplock break */
	if (mfp->m_flags & S_DEL_ON_CLS) {
		err = -EBUSY;
		goto out;
	}

	/* grant fixed oplock on stacked locking between lease and oplock */
	if (prev_opinfo->is_lease && !lctx) {
		if (prev_opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING) {
			req_op_level = SMB2_OPLOCK_LEVEL_NONE;
			goto grant_none;
		}
	}
	if (!prev_opinfo->is_lease && lctx)
		lctx->req_state = SMB2_LEASE_READ_CACHING;

grant_none:
	if (req_op_level == SMB2_OPLOCK_LEVEL_NONE)
		grant_none_oplock(opinfo, lctx);
	else {
		/* add new oplock to read state */
		grant_read_oplock(opinfo, lctx);
	}
out:
	if (err < 0) {
		mutex_lock(&lease_list_lock);
		if (opinfo->is_lease)
			free_lease(opinfo);
		kfree(opinfo);
		fp->f_opinfo = NULL;
		atomic_dec(&mfp->op_count);
		mutex_unlock(&lease_list_lock);
	}

	return err;
}

/**
 * smb_break_write_oplock() - break batch/exclusive oplock to level2
 * @conn:	TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file object
 */
int smb_break_all_write_oplock(struct smb_work *work,
	struct cifsd_file *fp, int is_trunc)
{
	struct cifsd_file *brk_fp;
	struct cifsd_mfile *mfp;
	struct oplock_info *brk_opinfo;

	mfp = fp->f_mfp;
	if (list_empty(&mfp->m_fp_list))
		return 0;
	brk_fp = list_first_entry(&mfp->m_fp_list, struct cifsd_file, node);
	brk_opinfo = brk_fp->f_opinfo;
	if (!brk_opinfo || (brk_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&
			brk_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
		return 0;
	}

	brk_opinfo->open_trunc = is_trunc;
	list_add(&work->interim_entry, &brk_opinfo->interim_list);
	smb_send_oplock_break_notification(brk_opinfo);

	return 1;
}

/**
 * smb_break_all_levII_oplock() - send level2 oplock or read lease break command
 *	from server to client
 * @conn:     TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file information
 */
void smb_break_all_levII_oplock(struct connection *conn,
	struct cifsd_file *fp, int is_trunc)
{
	struct oplock_info *op, *brk_op;
	struct cifsd_mfile *mfp;
	struct cifsd_file *brk_fp, *fptmp;

	mfp = fp->f_mfp;
	op = fp->f_opinfo;
	if (!op)
		return;

	list_for_each_entry_safe(brk_fp, fptmp, &mfp->m_fp_list, node) {
		brk_op = brk_fp->f_opinfo;
		if (IS_SMB2(brk_op->conn)) {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (brk_op->is_lease && (brk_op->o_lease->state &
					(~(SMB2_LEASE_READ_CACHING |
					   SMB2_LEASE_HANDLE_CACHING)))) {
				cifsd_debug("unexpected lease state(0x%x)\n",
						brk_op->o_lease->state);
				continue;
			} else if (brk_op->level !=
					SMB2_OPLOCK_LEVEL_II) {
				cifsd_debug("unexpected oplock(0x%x)\n",
						brk_op->level);
				continue;
			}

			/* Skip oplock being break to none */
			if (brk_op->is_lease && (brk_op->o_lease->new_state ==
					SMB2_LEASE_NONE) &&
				atomic_read(&brk_op->breaking_cnt))
				continue;
#endif
		} else {
			if (brk_op->level != OPLOCK_READ) {
				cifsd_debug("unexpected oplock(0x%x)\n",
					brk_op->level);
				continue;
			}
		}

#ifdef CONFIG_CIFS_SMB2_SERVER
		if (op && op->is_lease &&
			brk_op->is_lease &&
			!memcmp(conn->ClientGUID, brk_op->conn->ClientGUID,
				SMB2_CLIENT_GUID_SIZE) &&
			!memcmp(op->o_lease->lease_key,
				brk_op->o_lease->lease_key,
				SMB2_LEASE_KEY_SIZE))
			continue;
#endif
		brk_op->open_trunc = is_trunc;
		smb_send_oplock_break_notification(brk_op);
	}
}

/**
 * smb_break_all_oplock() - break both batch/exclusive and level2 oplock
 * @conn:	TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file object
 */
void smb_break_all_oplock(struct smb_work *work, struct cifsd_file *fp)
{
	int ret;

	ret = smb_break_all_write_oplock(work, fp, 1);
	if (!ret)
		smb_break_all_levII_oplock(work->conn, fp, 1);
}

/**
 * smb1_send_oplock_break_notification() - send smb1 oplock break cmd from conn
 * to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * smb_work->buf contains oplock_info.
 */
void smb1_send_oplock_break_notification(struct work_struct *work)
{
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct connection *conn = smb_work->conn;
	struct smb_hdr *rsp_hdr;
	LOCK_REQ *req;
	struct oplock_info *opinfo = (struct oplock_info *)smb_work->buf;

	atomic_inc(&conn->req_running);

	mutex_lock(&conn->srv_mutex);

	smb_work->rsp_large_buf = false;
	if (conn->ops->allocate_rsp_buf(smb_work)) {
		cifsd_err("smb_allocate_rsp_buf failed! ");
		mutex_unlock(&conn->srv_mutex);
		kfree(smb_work);
		return;
	}

	/* Init response header */
	rsp_hdr = (struct smb_hdr *)smb_work->rsp_buf;
	/* wct is 8 for locking andx */
	memset(rsp_hdr, 0, sizeof(struct smb_hdr) + 2 + 8*2);
	rsp_hdr->smb_buf_length = cpu_to_be32(HEADER_SIZE(conn) - 1 + 8*2);
	rsp_hdr->Protocol[0] = 0xFF;
	rsp_hdr->Protocol[1] = 'S';
	rsp_hdr->Protocol[2] = 'M';
	rsp_hdr->Protocol[3] = 'B';

	rsp_hdr->Command = SMB_COM_LOCKING_ANDX;
	/* we know unicode, long file name and use nt error codes */
	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_KNOWS_LONG_NAMES |
		SMBFLG2_ERR_STATUS;
	rsp_hdr->Uid = conn->vuid;
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
	if (!opinfo->open_trunc && (opinfo->level == OPLOCK_BATCH ||
			opinfo->level == OPLOCK_EXCLUSIVE))
		req->OplockLevel = 1;
	else {
		req->OplockLevel = 0;
	}
	req->Timeout = 0;
	req->NumberOfUnlocks = 0;
	req->ByteCount = 0;
	cifsd_debug("sending oplock break for fid %d lock level = %d\n",
			req->Fid, req->OplockLevel);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifsd_sm_rsp_poolp);
	kmem_cache_free(cifsd_work_cache, smb_work);
	mutex_unlock(&conn->srv_mutex);

	atomic_dec(&conn->req_running);
	if (waitqueue_active(&conn->req_running_q))
		wake_up_all(&conn->req_running_q);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_send_oplock_break_notification() - send smb1 oplock break cmd from conn
 * to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * smb_work->buf contains oplock_info.
 */
void smb2_send_oplock_break_notification(struct work_struct *work)
{
	struct smb2_oplock_break *rsp = NULL;
	struct smb_work *smb_work = container_of(work, struct smb_work, work);
	struct connection *conn = smb_work->conn;
	struct oplock_break_info *br_info =
		(struct oplock_break_info *)smb_work->buf;
	struct smb2_hdr *rsp_hdr;
	struct cifsd_file *fp;
	int persistent_id;

	atomic_inc(&conn->req_running);

	mutex_lock(&conn->srv_mutex);
	fp = get_id_from_fidtable(smb_work->sess, br_info->fid);
	if (!fp) {
		mutex_unlock(&conn->srv_mutex);
		kfree(smb_work);
		return;
	}
	persistent_id = fp->persistent_id;
	if (conn->ops->allocate_rsp_buf(smb_work)) {
		cifsd_err("smb2_allocate_rsp_buf failed! ");
		mutex_unlock(&conn->srv_mutex);
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
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);


	rsp = (struct smb2_oplock_break *)smb_work->rsp_buf;

	rsp->StructureSize = cpu_to_le16(24);
	if (!br_info->open_trunc &&
			(br_info->level == SMB2_OPLOCK_LEVEL_BATCH ||
			br_info->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		rsp->OplockLevel = 1;
	else
		rsp->OplockLevel = 0;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->PersistentFid = cpu_to_le64(persistent_id);
	rsp->VolatileFid = cpu_to_le64(br_info->fid);

	inc_rfc1001_len(rsp, 24);

	cifsd_debug("sending oplock break v_id %llu p_id = %llu lock level = %d\n",
			rsp->VolatileFid, rsp->PersistentFid, rsp->OplockLevel);
	smb_send_rsp(smb_work);
	mempool_free(smb_work->rsp_buf, cifsd_sm_rsp_poolp);
	kfree(smb_work);
	mutex_unlock(&conn->srv_mutex);

	atomic_dec(&conn->req_running);
	if (waitqueue_active(&conn->req_running_q))
		wake_up_all(&conn->req_running_q);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_map_lease_to_oplock() - map lease state to corresponding oplock type
 * @lease_state:     lease type
 *
 * Return:      0 if no mapping, otherwise corresponding oplock type
 */
__u8 smb2_map_lease_to_oplock(__le32 lease_state)
{
	if (lease_state == (SMB2_LEASE_HANDLE_CACHING |
		SMB2_LEASE_READ_CACHING | SMB2_LEASE_WRITE_CACHING))
		return SMB2_OPLOCK_LEVEL_BATCH;
	else if (lease_state != SMB2_LEASE_WRITE_CACHING &&
		lease_state & SMB2_LEASE_WRITE_CACHING) {
		if (!(lease_state & SMB2_LEASE_HANDLE_CACHING))
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (lease_state & SMB2_LEASE_READ_CACHING)
		return SMB2_OPLOCK_LEVEL_II;
	return 0;
}

/**
 * create_lease_buf() - create lease context for open cmd response
 * @rbuf:	buffer to create lease context response
 * @lreq:	buffer to stored parsed lease state information
 */
void create_lease_buf(u8 *rbuf, struct lease_ctx_info *lreq)
{
	struct create_lease *buf = (struct create_lease *)rbuf;
	char *LeaseKey = (char *)&lreq->lease_key;

	memset(buf, 0, sizeof(struct create_lease));
	buf->lcontext.LeaseKeyLow = *((u64 *)LeaseKey);
	buf->lcontext.LeaseKeyHigh = *((u64 *)(LeaseKey + 8));
	buf->lcontext.LeaseFlags = lreq->flags;
	buf->lcontext.LeaseState = lreq->rsp_state;
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
 * Return:  oplock state, -ENOENT if create lease context not found
 */
struct lease_ctx_info *parse_lease_state(void *open_req)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	bool found = false;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;
	struct lease_ctx_info *lreq = kzalloc(sizeof(struct lease_ctx_info),
		GFP_KERNEL);
	if (!lreq)
		return NULL;

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
		*((u64 *)lreq->lease_key) = lc->lcontext.LeaseKeyLow;
		*((u64 *)(lreq->lease_key + 8)) = lc->lcontext.LeaseKeyHigh;
		lreq->req_state = lc->lcontext.LeaseState;
		lreq->flags = lc->lcontext.LeaseFlags;
		lreq->duration = lc->lcontext.LeaseDuration;
		return lreq;
	}

	return NULL;
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
		if (le16_to_cpu(cc->NameLength) < 4)
			return ERR_PTR(-EINVAL);

		if (strncmp(name, str, 4)) {
			next = le32_to_cpu(cc->Next);
			continue;
		}
		found = 1;
		break;
	} while (next != 0);

	if (found)
		return cc;
	else
		return ERR_PTR(-ENOENT);
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
	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
}

/**
 * create_mxac_buf() - create query maximal access context
 * @cc:	buffer to create maximal access context response
 */
void create_mxac_rsp_buf(char *cc, int maximal_access)
{
	struct create_mxac_rsp *buf;

	buf = (struct create_mxac_rsp *)cc;
	memset(buf, 0, sizeof(struct create_mxac_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, QueryStatus));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE is "MxAc" */
	buf->Name[0] = 'M';
	buf->Name[1] = 'x';
	buf->Name[2] = 'A';
	buf->Name[3] = 'c';

	buf->QueryStatus = NT_STATUS_OK;
	buf->MaximalAccess = cpu_to_le32(maximal_access);
}

/**
 * create_mxac_buf() - create query maximal access context
 * @cc:	buffer to create query disk on id context response
 */
void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id)
{
	struct create_disk_id_rsp *buf;

	buf = (struct create_disk_id_rsp *)cc;
	memset(buf, 0, sizeof(struct create_disk_id_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_disk_id_rsp, DiskFileId));
	buf->ccontext.DataLength = cpu_to_le32(32);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_ON_DISK_ID_RESPONSE is "QFid" */
	buf->Name[0] = 'Q';
	buf->Name[1] = 'F';
	buf->Name[2] = 'i';
	buf->Name[3] = 'd';

	buf->DiskFileId = cpu_to_le64(file_id);
	buf->VolumeId = cpu_to_le64(vol_id);
}

/*
 * Find lease object(opinfo) for given lease key/fid from lease
 * break/file close path.
 * If needed, return ofile.
 */
/**
 * get_matching_opinfo_lease() - find a matching lease info object
 * @conn:     TCP server instance of connection
 * @ofile:	opened file to be searched. If NULL polplate this
 *              with ofile of lease owner
 * @LeaseKey:	lease key to be searched for
 * @id:		fid containing lease key, local to smb connection
 *
 * Return:      opinfo if found matching opinfo, otherwise NULL
 */
struct oplock_info *lookup_lease_in_table(struct connection *conn,
	char *lease_key)
{
	struct oplock_info *opinfo = NULL, *ret_op = NULL;
	struct lease_table *lt;
	int ret;

	list_for_each_entry(lt, &lease_table_list, l_entry) {
		if (memcmp(lt->client_guid, conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE))
			continue;
		list_for_each_entry(opinfo, &lt->lease_list, lease_entry) {
			if (!opinfo->op_state ||
				opinfo->op_state == OPLOCK_CLOSING)
				continue;
			if (!(opinfo->o_lease->state &
				(SMB2_LEASE_HANDLE_CACHING |
				SMB2_LEASE_WRITE_CACHING)))
				continue;
			ret = compare_guid_key(opinfo, conn->ClientGUID,
				lease_key);
			if (ret) {
				cifsd_debug("found opinfo\n");
				ret_op = opinfo;
				goto out;
			}
		}
	}

out:
	return ret_op;
}

#endif

#endif
