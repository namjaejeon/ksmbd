/*
 *   fs/cifsd/smb2pdu.c
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
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "cifsacl.h"

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/inotify.h>

bool multi_channel_enable;

struct fs_type_info fs_type[] = {
	{ "ADFS",	0xadf5},
	{ "AFFS",	0xadff},
	{ "AFS",	0x5346414F},
	{ "AUTOFS",	0x0187},
	{ "CODA",	0x73757245},

	{ "CRAMFS",	0x28cd3d45},
	{ "CRAMFSW",	0x453dcd28},
	{ "DEBUGFS",	0x64626720},
	{ "SECURITYFS",	0x73636673},
	{ "SELINUX",	0xf97cff8c},

	{ "SMACK",	0x43415d53},
	{ "RAMFS",	0x858458f6},
	{ "TMPFS",	0x01021994},
	{ "HUGETLBFS",	0x958458f6},
	{ "SQUASHFS",	0x73717368},

	{ "ECRYPTFS",	0xf15f},
	{ "EFS",	0x414A53},
	{ "EXT2",	0xEF53},
	{ "EXT3",	0xEF53},
	{ "XENFS",	0xabba1974},

	{ "EXT4",	0xEF53},
	{ "BTRFS",	0x9123683E},
	{ "NILFS",	0x3434},
	{ "F2FS",	0xF2F52010},
	{ "HPFS",	0xf995e849},

	{ "ISOFS",	0x9660},
	{ "JFFS2",	0x72b6},
	{ "PSTOREFS",	0x6165676C},
	{ "EFIVARFS",	0xde5e81e4},
	{ "HOSTFS",	0x00c0ffee},

	{ "MINIX",	0x137F},        /* minix v1 fs, 14 char names */
	{ "MINIX_2",	0x138F},        /* minix v1 fs, 30 char names */
	{ "MINIX2",	0x2468},        /* minix v2 fs, 14 char names */
	{ "MINIX2_2",	0x2478},        /* minix v2 fs, 30 char names */
	{ "MINIX3",	0x4d5a},        /* minix v3 fs, 60 char names */

	{ "MSDOS",	0x4d44},        /* MD */
	{ "NCP",	0x564c},
	{ "NFS",	0x6969},
	{ "OPENPROM",	0x9fa1},
	{ "QNX4",	0x002f},        /* qnx4 fs detection */

	{ "QNX6",	0x68191122},    /* qnx6 fs detection */
	{ "REISERFS",	0x52654973},    /* used by gcc */
	{ "SMB",	0x517B},
	{ "CGROUP",	0x27e0eb},
	};

/**
 * check_session_id() - check for valid session id in smb header
 * @conn:	TCP server instance of connection
 * @id:		session id from smb header
 *
 * Return:      1 if valid session id, otherwise 0
 */
static inline int check_session_id(struct connection *conn, uint64_t id)
{
	struct cifsd_sess *sess;

	WARN(conn->sess_count > 1, "sess_count %d", conn->sess_count);

	if (id == 0 || id == -1)
		return 0;

	sess = lookup_session_on_server(conn, id);
	if (sess) {
		if (sess->valid)
			return 1;
		else
			cifsd_err("Invalid user session\n");
	}

	return 0;
}

static inline struct channel *lookup_chann_list(struct cifsd_sess *sess)
{
	struct channel *chann;
	struct list_head *t;

	list_for_each(t, &sess->cifsd_chann_list) {
		chann = list_entry(t, struct channel, chann_list);
		if (chann && chann->conn == sess->conn)
			return chann;
	}

	return NULL;
}

/**
 * smb2_get_cifsd_tcon() - get tree connection information for a tree id
 * @sess:	session containing tree list
 * @tid:	match tree connection with tree id
 *
 * Return:      matching tree connection on success, otherwise error
 */
int smb2_get_cifsd_tcon(struct smb_work *smb_work)
{
	struct cifsd_tcon *tcon;
	struct list_head *tmp;
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)smb_work->buf;
	int rc = -1;

	smb_work->tcon = NULL;
	if ((smb_work->conn->ops->get_cmd_val(smb_work) ==
		SMB2_TREE_CONNECT_HE) ||
		(smb_work->conn->ops->get_cmd_val(smb_work) ==
		SMB2_CANCEL_HE) ||
		(smb_work->conn->ops->get_cmd_val(smb_work) ==
		SMB2_LOGOFF_HE)) {
		cifsd_debug("skip to check tree connect request\n");
		return 0;
	}

	if (!smb_work->sess->tcon_count) {
		cifsd_debug("NO tree connected\n");
		return -1;
	}

	list_for_each(tmp, &smb_work->sess->tcon_list) {
		tcon = list_entry(tmp, struct cifsd_tcon, tcon_list);
		if (tcon->share->tid ==
			le32_to_cpu(req_hdr->Id.SyncId.TreeId)) {
			rc = 1;
			smb_work->tcon = tcon;
			break;
		}
	}

	if (rc < 0)
		cifsd_err("Invalid tid %d\n",
			req_hdr->Id.SyncId.TreeId);

	return rc;
}

/**
 * smb2_set_err_rsp() - set error response code on smb response
 * @smb_work:	smb work containing response buffer
 */
void smb2_set_err_rsp(struct smb_work *smb_work)
{
	char *rsp = smb_work->rsp_buf;
	struct smb2_err_rsp *err_rsp;

	if (smb_work->next_smb2_rcv_hdr_off)
		err_rsp = (struct smb2_err_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	else
		err_rsp = (struct smb2_err_rsp *)rsp;

	if (err_rsp->hdr.Status != cpu_to_le32(NT_STATUS_STOPPED_ON_SYMLINK)) {
		err_rsp->StructureSize =
			cpu_to_le16(SMB2_ERROR_STRUCTURE_SIZE2);
		err_rsp->ByteCount = 0;
		err_rsp->ErrorData[0] = 0;
		inc_rfc1001_len(rsp, SMB2_ERROR_STRUCTURE_SIZE2);
	}
}

/**
 * is_smb2_neg_cmd() - is it smb2 negotiation command
 * @smb_work:	smb work containing smb header
 *
 * Return:      1 if smb2 negotiation command, otherwise 0
 */
int is_smb2_neg_cmd(struct smb_work *smb_work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->buf;

	/* is it SMB2 header ? */
	if (*(__le32 *)hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return 0;

	/* make sure it is request not response message */
	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
		return 0;

	if (hdr->Command != SMB2_NEGOTIATE)
		return 0;

	return 1;
}

/**
 * is_smb2_rsp() - is it smb2 response
 * @smb_work:	smb work containing smb response buffer
 *
 * Return:      1 if smb2 response, otherwise 0
 */
int is_smb2_rsp(struct smb_work *smb_work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->rsp_buf;

	/* is it SMB2 header ? */
	if (*(__le32 *)hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return 0;

	/* make sure it is response not request message */
	if (!(hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
		return 0;

	return 1;
}

/**
 * get_smb2_cmd_val() - get smb command code from smb header
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      smb2 request command value
 */
int get_smb2_cmd_val(struct smb_work *smb_work)
{
	struct smb2_hdr *rcv_hdr = (struct smb2_hdr *)smb_work->buf;
	if (smb_work->next_smb2_rcv_hdr_off)
		rcv_hdr = (struct smb2_hdr *)((char *)rcv_hdr
					+ smb_work->next_smb2_rcv_hdr_off);
	return le16_to_cpu(rcv_hdr->Command);
}

/**
 * set_smb2_rsp_status() - set error response code on smb2 header
 * @smb_work:	smb work containing response buffer
 */
void set_smb2_rsp_status(struct smb_work *smb_work, unsigned int err)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *) smb_work->rsp_buf;
	if (smb_work->next_smb2_rcv_hdr_off)
		rsp_hdr = (struct smb2_hdr *)((char *)rsp_hdr
					+ smb_work->next_smb2_rsp_hdr_off);
	rsp_hdr->Status = cpu_to_le32(err);
	smb2_set_err_rsp(smb_work);
}

/**
 * init_smb2_neg_rsp() - initialize smb2 response for negotiate command
 * @smb_work:	smb work containing smb request buffer
 *
 * smb2 negotiate response is sent in reply of smb1 negotiate command for
 * dialect auto-negotiation.
 */
void init_smb2_neg_rsp(struct smb_work *smb_work)
{
	struct smb2_hdr *rsp_hdr;
	struct smb2_negotiate_rsp *rsp;
	struct connection *conn = smb_work->conn;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct timespec ts;
#endif
	init_smb2_0_server(conn);
	rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;

	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);

	rsp_hdr->smb2_buf_length =
		cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	rsp_hdr->ProtocolId[0] = 0xFE;
	rsp_hdr->ProtocolId[1] = 'S';
	rsp_hdr->ProtocolId[2] = 'M';
	rsp_hdr->ProtocolId[3] = 'B';

	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(1);
	rsp_hdr->Command = 0;
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = 0;
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = (struct smb2_negotiate_rsp *)smb_work->rsp_buf;

	WARN_ON(conn->tcp_status == CifsGood);

	rsp->StructureSize = cpu_to_le16(65);
	rsp->SecurityMode = 0;
	cifsd_debug("conn->dialect 0x%x\n", conn->dialect);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/* Not setting conn guid rsp->ServerGUID, as it
	 * not used by client for identifying connection */
	rsp->Capabilities = 0;
	/* Default Max Message Size till SMB2.0, 64K*/
	rsp->MaxTransactSize = SMBMaxBufSize;
	rsp->MaxReadSize = SMBMaxBufSize;
	rsp->MaxWriteSize = SMBMaxBufSize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	ktime_get_real_ts(&ts);
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(ts));
#else
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(CURRENT_TIME));
#endif
	rsp->ServerStartTime = 0;
	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = 0;
	inc_rfc1001_len(rsp, 65);
	conn->tcp_status = CifsNeedNegotiate;
	rsp->hdr.CreditRequest = cpu_to_le16(2);
}

/**
 * init_chained_smb2_rsp() - initialize smb2 chained response
 * @smb_work:	smb work containing smb response buffer
 */
void init_chained_smb2_rsp(struct smb_work *smb_work)
{
	struct smb2_hdr *req;
	struct smb2_hdr *rsp;
	struct smb2_hdr *rsp_hdr;
	struct smb2_hdr *rcv_hdr;
	int next_hdr_offset = 0;
	int len, new_len;


	req = (struct smb2_hdr *)(smb_work->buf +
				  smb_work->next_smb2_rcv_hdr_off);
	rsp = (struct smb2_hdr *)(smb_work->rsp_buf +
				  smb_work->next_smb2_rsp_hdr_off);

	/* Len of this response = updated RFC len - offset of previous cmd
	   in the compound rsp */

	/* Storing the current local FID which may be needed by subsequent
	   command in the compound request */
	if (le16_to_cpu(req->Command) == SMB2_CREATE &&
			le32_to_cpu(rsp->Status) == NT_STATUS_OK) {
		smb_work->cur_local_fid =
			le64_to_cpu(((struct smb2_create_rsp *)rsp)->
				VolatileFileId);
		smb_work->cur_local_pfid =
			le64_to_cpu(((struct smb2_create_rsp *)rsp)->
				PersistentFileId);
		smb_work->cur_local_sess_id = rsp->SessionId;
	}

	len = get_rfc1002_length(smb_work->rsp_buf) -
				 smb_work->next_smb2_rsp_hdr_off;

	next_hdr_offset = le32_to_cpu(req->NextCommand);

	/* Align the length to 8Byte  */
	new_len = ((len + 7) & ~7);
	inc_rfc1001_len(smb_work->rsp_buf, ((sizeof(struct smb2_hdr) - 4)
			+ new_len - len));
	rsp->NextCommand = cpu_to_le32(new_len);

	smb_work->next_smb2_rcv_hdr_off += next_hdr_offset;
	smb_work->next_smb2_rsp_hdr_off += new_len;
	cifsd_debug("Compound req new_len = %d rcv off = %d rsp off = %d\n",
		      new_len, smb_work->next_smb2_rcv_hdr_off,
		      smb_work->next_smb2_rsp_hdr_off);

	rsp_hdr = (struct smb2_hdr *)(((char *)smb_work->rsp_buf +
					smb_work->next_smb2_rsp_hdr_off));
	rcv_hdr = (struct smb2_hdr *)(((char *)smb_work->buf +
					smb_work->next_smb2_rcv_hdr_off));

	if (!(le32_to_cpu(rcv_hdr->Flags) & SMB2_FLAGS_RELATED_OPERATIONS)) {
		cifsd_debug("related flag should be set\n");
		smb_work->cur_local_fid = -1;
		smb_work->cur_local_pfid = -1;
	}
	memset((char *)rsp_hdr + 4, 0, sizeof(struct smb2_hdr) + 2);
	memcpy(rsp_hdr->ProtocolId, rcv_hdr->ProtocolId, 4);
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = rcv_hdr->CreditRequest;
	rsp_hdr->Command = rcv_hdr->Command;

	/*
	 * Message is response. We don't grant oplock yet.
	 */
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR |
				SMB2_FLAGS_RELATED_OPERATIONS);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = rcv_hdr->MessageId;
	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;
	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;
	rsp_hdr->SessionId = rcv_hdr->SessionId;
	memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16);
}

/**
 * is_chained_smb2_message() - check for chained command
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      true if chained request, otherwise false
 */
bool is_chained_smb2_message(struct smb_work *smb_work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->buf;
	unsigned int len;

	if (*(__le32 *)(hdr->ProtocolId) != SMB2_PROTO_NUMBER)
		return false;

	hdr = (struct smb2_hdr *)(smb_work->buf +
			smb_work->next_smb2_rcv_hdr_off);
	if (le32_to_cpu(hdr->NextCommand) > 0) {
		cifsd_debug("got SMB2 chained command\n");
		init_chained_smb2_rsp(smb_work);
		return true;
	} else if (smb_work->next_smb2_rcv_hdr_off) {
		/*
		 * This is last request in chained command,
		 * align response to 8 byte
		 */
		len = ((get_rfc1002_length(smb_work->rsp_buf) + 7) & ~7);
		len = len - get_rfc1002_length(smb_work->rsp_buf);
		if (len) {
			cifsd_debug("padding len %u\n", len);
			inc_rfc1001_len(smb_work->rsp_buf, len);
			if (smb_work->rdata_buf)
				smb_work->rrsp_hdr_size += len;
		}
	}
	return false;
}

/**
 * init_smb2_rsp_hdr() - initialize smb2 response
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int init_smb2_rsp_hdr(struct smb_work *smb_work)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;
	struct smb2_hdr *rcv_hdr = (struct smb2_hdr *)smb_work->buf;
	struct connection *conn = smb_work->conn;
	int next_hdr_offset = 0;

	next_hdr_offset = le32_to_cpu(rcv_hdr->NextCommand);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);

	rsp_hdr->smb2_buf_length = cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	memcpy(rsp_hdr->ProtocolId, rcv_hdr->ProtocolId, 4);
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = rcv_hdr->CreditRequest;
	rsp_hdr->Command = rcv_hdr->Command;

	/*
	 * Message is response. We don't grant oplock yet.
	 */
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	if (next_hdr_offset)
		rsp_hdr->NextCommand = cpu_to_le32(next_hdr_offset);
	else
		rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = rcv_hdr->MessageId;
	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;
	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;
	rsp_hdr->SessionId = rcv_hdr->SessionId;
	memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16);

	if (conn->credits_granted) {
		if (le16_to_cpu(rcv_hdr->CreditCharge))
			conn->credits_granted -=
				le16_to_cpu(rcv_hdr->CreditCharge);
		else
			conn->credits_granted -= 1;
	}

	return 0;
}

/**
 * smb2_allocate_rsp_buf() - allocate smb2 response buffer
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise -ENOMEM
 */
int smb2_allocate_rsp_buf(struct smb_work *smb_work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->buf;
	struct smb2_query_info_req *req;
	bool need_large_buf = false;

	/* allocate large response buf for chained commands */
	if (le32_to_cpu(hdr->NextCommand) > 0)
		need_large_buf = true;
	else {
		switch (le16_to_cpu(hdr->Command)) {
		case SMB2_READ:
			/* fall through */
		case SMB2_IOCTL_HE:
			/* fall through */
		case SMB2_QUERY_DIRECTORY_HE:
			need_large_buf = true;
			break;
		case SMB2_QUERY_INFO_HE:
			req = (struct smb2_query_info_req *)smb_work->buf;
			if (req->InfoType == SMB2_O_INFO_FILE &&
					(req->FileInfoClass ==
					FILE_FULL_EA_INFORMATION ||
					req->FileInfoClass ==
					FILE_ALL_INFORMATION)) {
				need_large_buf = true;
			}
			break;
		default:
			break;
		}
	}

	if (need_large_buf) {
		smb_work->rsp_large_buf = true;
		smb_work->rsp_buf = mempool_alloc(cifsd_rsp_poolp, GFP_NOFS);
	} else {
		smb_work->rsp_large_buf = false;
		smb_work->rsp_buf = mempool_alloc(cifsd_sm_rsp_poolp,
								GFP_NOFS);
	}

	if (!smb_work->rsp_buf) {
		cifsd_err("failed to alloc response buffer, large_buf %d\n",
				smb_work->rsp_large_buf);
		return -ENOMEM;
	}

	return 0;
}

/**
 * smb2_set_rsp_credits() - set number of credits in response buffer
 * @smb_work:	smb work containing smb response buffer
 */
void smb2_set_rsp_credits(struct smb_work *smb_work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->rsp_buf;
	struct connection *conn = smb_work->conn;
	unsigned int status = le32_to_cpu(hdr->Status);
	unsigned int flags = le32_to_cpu(hdr->Flags);
	unsigned short credits_requested = le16_to_cpu(hdr->CreditRequest);
	unsigned short cmd = le16_to_cpu(hdr->Command);
	unsigned short credit_charge = 1, credits_granted = 0;
	unsigned short aux_max, aux_credits, min_credits;

	BUG_ON(conn->credits_granted >= conn->max_credits);

	/* get default minimum credits by shifting maximum credits by 4 */
	min_credits = conn->max_credits >> 4;

	if (flags & SMB2_FLAGS_ASYNC_COMMAND) {
		credits_granted = 0;
	} else if (credits_requested > 0) {
		aux_max = 0;
		aux_credits = credits_requested - 1;
		switch (cmd) {
		case SMB2_NEGOTIATE:
			break;
		case SMB2_SESSION_SETUP:
			aux_max = (status) ? 0 : 32;
			break;
		default:
			aux_max = 32;
			break;
		}
		aux_credits = (aux_credits < aux_max) ? aux_credits : aux_max;
		credits_granted = aux_credits + credit_charge;

		/* if credits granted per client is getting bigger than default
		 * minimum credits then we should wrap it up within the limits.
		 */
		if ((conn->credits_granted + credits_granted) > min_credits)
			credits_granted = min_credits -	conn->credits_granted;

	} else if (conn->credits_granted == 0) {
		credits_granted = 1;
	}

	conn->credits_granted += credits_granted;
	cifsd_debug("credits: requested[%d] granted[%d] total_granted[%d]\n",
			credits_requested, credits_granted,
			conn->credits_granted);
	/* set number of credits granted in SMB2 hdr */
	hdr->CreditRequest = cpu_to_le16(credits_granted);

}

/**
 * smb2_check_user_session() - check for valid session for a user
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_check_user_session(struct smb_work *smb_work)
{
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)smb_work->buf;
	struct connection *conn = smb_work->conn;
	struct cifsd_sess *sess;
	int rc;
	unsigned int cmd = conn->ops->get_cmd_val(smb_work);

	smb_work->sess = NULL;

	/*
	 * ECHO, KEEP_ALIVE, SMB2_NEGOTIATE, SMB2_SESSION_SETUP command does not
	 * require a session id, so no need to validate user session's for these
	 * commands.
	 */
	if (cmd == SMB2_ECHO || cmd == SMB2_NEGOTIATE ||
			cmd == SMB2_SESSION_SETUP)
		return 0;

	if (conn->tcp_status != CifsGood) {
		if (conn->sess_count) {
			struct cifsd_sess *sess;
			struct list_head *tmp, *t;

			list_for_each_safe(tmp, t, &conn->cifsd_sess) {
				sess = list_entry(tmp, struct cifsd_sess,
						cifsd_ses_list);
				if (sess->state == SMB2_SESSION_EXPIRED) {
					cifsd_debug("invalid session\n");
					smb_work->sess = sess;
					break;
				}
			}
		}
		return -EINVAL;
	}

	rc = -EINVAL;
	/* Check for validity of user session */
	sess = lookup_session_on_server(conn, le64_to_cpu(req_hdr->SessionId));
	if (sess) {
		if (sess->valid) {
			smb_work->sess = sess;
			rc = 1;
		} else {
			cifsd_err("Invalid user session\n");
		}
	}

	return rc;
}


/**
 * smb2_invalidate_prev_session() - invalidate existing session of an user
 * @sess_id:	session id to be invalidated
 */
void smb2_invalidate_prev_session(uint64_t sess_id)
{
	struct cifsd_sess *sess;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifsd_session_list) {
		sess = list_entry(tmp, struct cifsd_sess,
				cifsd_ses_global_list);
		if (sess->sess_id == sess_id) {
			smb_delete_session(sess);
			break;
		}
	}
}

/**
 * smb2_get_session_global_list() - get existing session from global session
 * list
 * @sess_id:	session id to be invalidated
 */
struct cifsd_sess *smb2_get_session_global_list(uint64_t sess_id)
{
	struct cifsd_sess *sess;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifsd_session_list) {
		sess = list_entry(tmp, struct cifsd_sess,
				cifsd_ses_global_list);
		if (sess->sess_id == sess_id && sess->valid)
			return sess;
	}

	return NULL;
}

/**
 * smb2_get_name() - get filename string from on the wire smb format
 * @src:	source buffer
 * @maxlen:	maxlen of source string
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      matching converted filename on success, otherwise error ptr
 */
char *
smb2_get_name(const char *src, const int maxlen, struct smb_work *smb_work)
{
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)smb_work->buf;
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;
	char *name, *unixname;

	if (smb_work->next_smb2_rcv_hdr_off)
		req_hdr = (struct smb2_hdr *)((char *)req_hdr
				+ smb_work->next_smb2_rcv_hdr_off);

	name = smb_strndup_from_utf16(src, maxlen, 1,
			smb_work->conn->local_nls);
	if (IS_ERR(name)) {
		cifsd_err("failed to get name %ld\n", PTR_ERR(name));
		if (PTR_ERR(name) == -ENOMEM)
			rsp_hdr->Status = NT_STATUS_NO_MEMORY;
		else
			rsp_hdr->Status = NT_STATUS_OBJECT_NAME_INVALID;
		return name;
	}

	/* change it to absolute unix name */
	convert_delimiter(name, 0);

	unixname = convert_to_unix_name(name, req_hdr->Id.SyncId.TreeId);
	kfree(name);
	if (!unixname) {
		cifsd_err("can not convert absolute name\n");
		rsp_hdr->Status = NT_STATUS_NO_MEMORY;
		return ERR_PTR(-ENOMEM);
	}

	cifsd_debug("absoulte name = %s\n", unixname);
	return unixname;
}

/**
 * smb2_get_name_from_filp() - get filename string from filp
 * @filp:	file pointer containing filename
 *
 * Reconstruct complete pathname from filp, required in cases e.g. durable
 * reconnect where incoming filename in SMB2 CREATE request need to be ignored
 *
 * Return:      filename on success, otherwise NULL
 */
char *
smb2_get_name_from_filp(struct file *filp)
{
	char *pathname, *name, *full_pathname;
	int namelen;

	pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname)
		return ERR_PTR(-ENOMEM);

	name = d_path(&filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(name)) {
		kfree(pathname);
		return name;
	}

	namelen = strlen(name);
	full_pathname = kmalloc(namelen + 1, GFP_KERNEL);
	if (!full_pathname) {
		kfree(pathname);
		return ERR_PTR(-ENOMEM);
	}

	memcpy(full_pathname, name, namelen);
	full_pathname[namelen] = '\0';

	kfree(pathname);
	return full_pathname;
}

/* Async ida to generate async id */
DEFINE_IDA(async_ida);

inline void remove_async_id(__u64 async_id)
{
	ida_simple_remove(&async_ida, (int)async_id);
}

/**
 * smb2_send_interim_resp() - Send interim Response to inform
 *				asynchronous request
 * @smb_work:	smb work containing smb request buffer
 *
 */
void smb2_send_interim_resp(struct smb_work *smb_work)
{
	struct smb2_hdr *rsp_hdr;
	struct connection *conn = smb_work->conn;
	struct async_info *async;

	rsp_hdr = (struct smb2_hdr *)smb_work->rsp_buf;

	async = kmalloc(sizeof(struct async_info), GFP_KERNEL);
	async->async_status = ASYNC_PROG;
	smb_work->async = async;
	rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;

	smb_work->async->async_id = (__u64) ida_simple_get(&async_ida, 1, 0,
		GFP_KERNEL);
	smb_work->type = ASYNC;
	rsp_hdr->Id.AsyncId = cpu_to_le64(smb_work->async->async_id);

	cifsd_debug("Send interim Response to inform asynchronous request id : %lld\n",
			async->async_id);

	spin_lock(&conn->request_lock);
	list_del_init(&smb_work->request_entry);
	list_add_tail(&smb_work->request_entry,
		&conn->async_requests);
	smb_work->added_in_request_list = 1;
	spin_unlock(&conn->request_lock);

	smb2_set_err_rsp(smb_work);
	rsp_hdr->Status = NT_STATUS_PENDING;
	smb_work->multiRsp = 1;
	smb_send_rsp(smb_work);
	smb_work->multiRsp = 0;

	init_smb2_rsp_hdr(smb_work);
}

/**
 * smb2_get_dos_mode() - get file mode in dos format from unix mode
 * @stat:	kstat containing file mode
 *
 * Return:      converted dos mode
 */
__le32 smb2_get_dos_mode(struct kstat *stat, __le32 attribute)
{
	__le32 attr = 0;

	attr = (attribute & 0x00005137) | ATTR_ARCHIVE;

	if (S_ISDIR(stat->mode))
		attr = ATTR_DIRECTORY;
	else
		attr &= ~(ATTR_DIRECTORY);

	return attr;
}

/* offset is sizeof smb2_negotiate_rsp - 4 but rounded up to 8 bytes */
#define OFFSET_OF_NEG_CONTEXT 0xd0  /* sizeof(struct smb2_negotiate_rsp) - 4 */

#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(1)
#define SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(2)

static void
build_preauth_ctxt(struct smb2_preauth_neg_context *pneg_ctxt, int hash_id)
{
	pneg_ctxt->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(38);
	pneg_ctxt->HashAlgorithmCount = cpu_to_le16(1);
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->SaltLength = cpu_to_le16(SMB311_SALT_SIZE);
	get_random_bytes(pneg_ctxt->Salt, SMB311_SALT_SIZE);
	pneg_ctxt->HashAlgorithms = cpu_to_le16(hash_id);
}

static void
build_encrypt_ctxt(struct smb2_encryption_neg_context *pneg_ctxt, int cipher_id)
{
	pneg_ctxt->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(4);
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->CipherCount = cpu_to_le16(1);
	pneg_ctxt->Ciphers[0] = cpu_to_le16(cipher_id);
}

static void
assemble_neg_contexts(struct connection *conn,
	struct smb2_negotiate_rsp *rsp)
{
	/* +4 is to account for the RFC1001 len field */
	char *pneg_ctxt = (char *)rsp +
			le32_to_cpu(rsp->NegotiateContextOffset) + 4;

	cifsd_debug("assemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt,
		conn->Preauth_HashId);
	rsp->NegotiateContextCount = cpu_to_le16(1);
	inc_rfc1001_len(rsp, 4 + sizeof(struct smb2_preauth_neg_context));

	if (conn->CipherId) {
		/* Add 2 to size to round to 8 byte boundary */
		cifsd_debug("assemble SMB2_ENCRYPTION_CAPABILITIES context\n");
		pneg_ctxt += 2 + sizeof(struct smb2_preauth_neg_context);
		build_encrypt_ctxt(
			(struct smb2_encryption_neg_context *)pneg_ctxt,
			conn->CipherId);
		rsp->NegotiateContextCount = cpu_to_le16(2);
		inc_rfc1001_len(rsp, 4 +
				sizeof(struct smb2_encryption_neg_context) - 2);
	}
}

static int
decode_preauth_ctxt(struct connection *conn,
	struct smb2_preauth_neg_context *pneg_ctxt)
{
	int err = NT_STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;

	if (pneg_ctxt->HashAlgorithms ==
			SMB2_PREAUTH_INTEGRITY_SHA512) {
		conn->Preauth_HashId = SMB2_PREAUTH_INTEGRITY_SHA512;
		err = NT_STATUS_OK;
	}

	return err;
}

static void
decode_encrypt_ctxt(struct connection *conn,
	struct smb2_encryption_neg_context *pneg_ctxt)
{
	int i;
	int cph_cnt = pneg_ctxt->CipherCount;

	conn->CipherId = 0;
	for (i = 0; i < cph_cnt; i++) {
		if (pneg_ctxt->Ciphers[i] == SMB2_ENCRYPTION_AES128_GCM) {
			cifsd_debug("Cipher ID = SMB2_ENCRYPTION_AES128_GCM\n");
			conn->CipherId = SMB2_ENCRYPTION_AES128_GCM;
			break;
		} else if (pneg_ctxt->Ciphers[i] ==
			SMB2_ENCRYPTION_AES128_CCM) {
			cifsd_debug("Cipher ID = SMB2_ENCRYPTION_AES128_CCM\n");
			conn->CipherId = SMB2_ENCRYPTION_AES128_CCM;
			break;
		}
	}
}

static int
deassemble_neg_contexts(struct connection *conn,
	struct smb2_negotiate_req *req)
{
	int i = 0, status = 0;
	/* +4 is to account for the RFC1001 len field */
	char *pneg_ctxt = (char *)req +
			le32_to_cpu(req->NegotiateContextOffset) + 4;
	__le16 *ContextType = (__le16 *)pneg_ctxt;
	int neg_ctxt_cnt = le16_to_cpu(req->NegotiateContextCount);

	cifsd_debug("negotiate context count = %d\n", neg_ctxt_cnt);
	status = NT_STATUS_INVALID_PARAMETER;
	while (i++ < neg_ctxt_cnt) {
		if (*ContextType == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
			cifsd_debug("deassemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
			if (conn->Preauth_HashId)
				break;

			status = decode_preauth_ctxt(conn,
				(struct smb2_preauth_neg_context *)pneg_ctxt);
			pneg_ctxt +=
				sizeof(struct smb2_preauth_neg_context) + 2;
			ContextType = (__le16 *)pneg_ctxt;
		} else if (*ContextType == SMB2_ENCRYPTION_CAPABILITIES) {
			cifsd_debug("deassemble SMB2_ENCRYPTION_CAPABILITIES context\n");
			if (conn->CipherId)
				break;

			decode_encrypt_ctxt(conn,
					(struct smb2_encryption_neg_context *)
					pneg_ctxt);
			pneg_ctxt +=
				sizeof(struct smb2_encryption_neg_context) + 2;
		}

		if (status != NT_STATUS_OK)
			break;
	}
	return status;
}

/**
 * smb2_negotiate() - handler for smb2 negotiate command
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int smb2_negotiate(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_negotiate_req *req;
	struct smb2_negotiate_rsp *rsp;
	unsigned int limit;
	int err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct timespec ts;
#endif

	req = (struct smb2_negotiate_req *)smb_work->buf;
	rsp = (struct smb2_negotiate_rsp *)smb_work->rsp_buf;

	if (conn->tcp_status == CifsGood) {
		cifsd_err("conn->tcp_status is already in CifsGood State\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	cifsd_debug("%s: Recieved negotiate request\n", __func__);
	if (req->StructureSize != 36 || req->DialectCount == 0) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	conn->dialect = negotiate_dialect(smb_work->buf);
	cifsd_debug("conn->dialect 0x%x\n", conn->dialect);

	switch (conn->dialect) {
	case SMB311_PROT_ID:
		init_smb3_11_server(conn);
		rsp->NegotiateContextOffset = cpu_to_le32(208);
		err = deassemble_neg_contexts(conn, req);
		if (err != NT_STATUS_OK) {
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			return -EINVAL;
		}

		calc_preauth_integrity_hash(conn, smb_work->buf,
			conn->Preauth_HashValue);
		assemble_neg_contexts(conn, rsp);
		break;
	case SMB302_PROT_ID:
		init_smb3_02_server(conn);
		break;
	case SMB30_PROT_ID:
		init_smb3_0_server(conn);
		break;
	case SMB21_PROT_ID:
		init_smb2_1_server(conn);
		break;
	case SMB20_PROT_ID:
		init_smb2_0_server(conn);
		break;
	case BAD_PROT_ID:
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		return 0;
	default:
		cifsd_err("Server dialect :%x not supported\n",
							conn->dialect);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		return 0;
	}
	rsp->Capabilities = conn->srv_cap;

	/* For stats */
	conn->connection_type = conn->dialect;
	/* Default message size limit 64K till SMB2.0, no LargeMTU*/
	limit = SMBMaxBufSize;

	conn->cli_cap = req->Capabilities;
	if (conn->dialect > SMB20_PROT_ID) {
		memcpy(conn->ClientGUID, req->ClientGUID,
				SMB2_CLIENT_GUID_SIZE);
		/* With LargeMTU above SMB2.0, default message limit is 1MB */
		limit = CIFS_DEFAULT_IOSIZE;
		conn->cli_sec_mode = req->SecurityMode;
	}

	rsp->StructureSize = cpu_to_le16(65);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/* Not setting conn guid rsp->ServerGUID, as it
	 * not used by client for identifying server*/
	memset(rsp->ServerGUID, 0, SMB2_CLIENT_GUID_SIZE);
	rsp->MaxTransactSize = SMBMaxBufSize;
	rsp->MaxReadSize = min(limit, (unsigned int)CIFS_DEFAULT_IOSIZE);
	rsp->MaxWriteSize = min(limit, (unsigned int)CIFS_DEFAULT_IOSIZE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	ktime_get_real_ts(&ts);
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(ts));
#else
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(CURRENT_TIME));
#endif
	rsp->ServerStartTime = 0;
	rsp->NegotiateContextOffset = cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
	cifsd_debug("negotiate context count %d\n",
				le16_to_cpu(rsp->NegotiateContextCount));

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = 74;
	memcpy(((char *)(&rsp->hdr) +
		sizeof(rsp->hdr.smb2_buf_length)) +
		rsp->SecurityBufferOffset, NEGOTIATE_GSS_HEADER, 74);
	inc_rfc1001_len(rsp, 64 + 74);
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	conn->use_spnego = true;

	if ((server_signing == AUTO || server_signing == DISABLE) &&
		req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
		conn->sign = true;
	else if (server_signing == MANDATORY) {
		global_signing = true;
		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
		conn->sign = true;
	}

	conn->srv_sec_mode = rsp->SecurityMode;
	conn->tcp_status = CifsNeedNegotiate;
	conn->need_neg = false;
	return 0;

}

/**
 * smb2_sess_setup() - handler for smb2 session setup command
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_sess_setup(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_sess_setup_req *req;
	struct smb2_sess_setup_rsp *rsp;
	struct cifsd_sess *sess;
	NEGOTIATE_MESSAGE *negblob;
	struct channel *chann = NULL;
	int rc = 0;
	unsigned char *spnego_blob;
	u16 spnego_blob_len;
	char *neg_blob;
	int neg_blob_len;

	req = (struct smb2_sess_setup_req *)smb_work->buf;
	rsp = (struct smb2_sess_setup_rsp *)smb_work->rsp_buf;

	cifsd_debug("Received request for session setup\n");
	if (req->StructureSize != 25) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	rsp->StructureSize = cpu_to_le16(9);
	rsp->SessionFlags = 0;
	rsp->SecurityBufferOffset = cpu_to_le16(72);
	rsp->SecurityBufferLength = 0;
	inc_rfc1001_len(rsp, 9);


	if (!req->hdr.SessionId) {
		/* Check for previous session */
		if (le64_to_cpu(req->PreviousSessionId))
			smb2_invalidate_prev_session(
				le64_to_cpu(req->PreviousSessionId));

		sess = kzalloc(sizeof(struct cifsd_sess), GFP_KERNEL);
		if (sess == NULL) {
			rc = -ENOMEM;
			goto out_err;
		}

		get_random_bytes(&sess->sess_id, sizeof(__u64));
		cifsd_debug("generate session ID : %llu\n", sess->sess_id);
		rsp->hdr.SessionId = cpu_to_le64(sess->sess_id);
		sess->conn = conn;
		INIT_LIST_HEAD(&sess->cifsd_ses_list);
		INIT_LIST_HEAD(&sess->cifsd_chann_list);
		list_add(&sess->cifsd_ses_list, &conn->cifsd_sess);
		list_add(&sess->cifsd_ses_global_list, &cifsd_session_list);
		hash_init(sess->notify_table);

		INIT_LIST_HEAD(&sess->tcon_list);
		sess->tcon_count = 0;
		sess->valid = 1;
		conn->sess_count++;
		rc = init_fidtable(&sess->fidtable);
		if (rc < 0)
			goto out_err;

		init_waitqueue_head(&sess->pipe_q);
		init_waitqueue_head(&sess->notify_q);
		sess->ev_state = NETLINK_REQ_INIT;
	} else {
		struct smb2_hdr *req_hdr = (struct smb2_hdr *)smb_work->buf;

		if (multi_channel_enable &&
			req_hdr->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
			sess = smb2_get_session_global_list(
					le64_to_cpu(req->hdr.SessionId));
			if (!sess) {
				cifsd_err(
					"not found session from global list");
				rc = -ENOENT;
				rsp->hdr.Status =
					NT_STATUS_USER_SESSION_DELETED;
				goto out_err;
			}

			if (!(req_hdr->Flags & SMB2_FLAGS_SIGNED)) {
				rc = -EINVAL;
				rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
				goto out_err;
			}

			if (sess->state & SMB2_SESSION_IN_PROGRESS) {
				rc = -EINVAL;
				rsp->hdr.Status =
					NT_STATUS_REQUEST_NOT_ACCEPTED;
				goto out_err;
			}

			if (sess->state & SMB2_SESSION_EXPIRED) {
				rc = -EINVAL;
				rsp->hdr.Status =
					NT_STATUS_NETWORK_SESSION_EXPIRED;
				goto out_err;
			}

			if (sess->is_anonymous || sess->is_guest) {
				rc = -EINVAL;
				rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
				goto out_err;
			}

			sess = lookup_session_on_server(conn,
					le64_to_cpu(req->hdr.SessionId));
			if (sess) {
				rc = -EINVAL;
				rsp->hdr.Status =
					NT_STATUS_REQUEST_NOT_ACCEPTED;
				goto out_err;
			}
		} else {
			sess = lookup_session_on_server(conn,
					le64_to_cpu(req->hdr.SessionId));
			if (!sess) {
				rc = -ENOENT;
				rsp->hdr.Status =
					NT_STATUS_USER_SESSION_DELETED;
				goto out_err;
			}
		}
	}
	smb_work->sess = sess;

	if (sess->state & SMB2_SESSION_EXPIRED)
		sess->state = SMB2_SESSION_IN_PROGRESS;

	negblob = (NEGOTIATE_MESSAGE *)(req->hdr.ProtocolId +
			le16_to_cpu(req->SecurityBufferOffset));

	if (conn->use_spnego) {
		rc = cifsd_decode_negTokenInit((char *)negblob,
				le16_to_cpu(req->SecurityBufferLength), conn);
		if (!rc) {
			cifsd_debug("negTokenInit parse err %d\n", rc);
			/* If failed, it might be negTokenTarg */
			rc = decode_negTokenTarg((char *)negblob,
					le16_to_cpu(req->SecurityBufferLength),
					conn);
			if (!rc) {
				cifsd_debug("negTokenTarg parse err %d\n",
					rc);
				conn->use_spnego = false;
			}
			rc = 0;
		}

		if (conn->mechToken)
			negblob = (NEGOTIATE_MESSAGE *)conn->mechToken;
	}

	if (conn->dialect == SMB311_PROT_ID &&
			negblob->MessageType == NtLmNegotiate)
		memcpy(sess->Preauth_HashValue, conn->Preauth_HashValue, 64);

	if (conn->dialect == SMB311_PROT_ID)
		calc_preauth_integrity_hash(conn, smb_work->buf,
			sess->Preauth_HashValue);

	if (negblob->MessageType == NtLmNegotiate) {
		CHALLENGE_MESSAGE *chgblob;

		cifsd_debug("negotiate phase\n");
		rc = decode_ntlmssp_negotiate_blob(negblob,
			le16_to_cpu(req->SecurityBufferLength), sess);
		if (rc)
			goto out_err;

		chgblob = (CHALLENGE_MESSAGE *)(rsp->hdr.ProtocolId +
				rsp->SecurityBufferOffset);
		memset(chgblob, 0, sizeof(CHALLENGE_MESSAGE));

		if (conn->use_spnego) {
			neg_blob = kmalloc(sizeof(struct _NEGOTIATE_MESSAGE) +
					(strlen(netbios_name) * 2  + 4) * 6,
					GFP_KERNEL);
			if (!neg_blob) {
				rc = -ENOMEM;
				goto out_err;
			}
			chgblob = (CHALLENGE_MESSAGE *)neg_blob;
			neg_blob_len = build_ntlmssp_challenge_blob(
					chgblob, sess);
			if (neg_blob_len < 0) {
				kfree(neg_blob);
				rc = -ENOMEM;
				goto out_err;
			}

			if (build_spnego_ntlmssp_neg_blob(&spnego_blob,
						&spnego_blob_len,
						neg_blob, neg_blob_len)) {
				kfree(neg_blob);
				rc = -ENOMEM;
				goto out_err;
			}

			memcpy((char *)rsp->hdr.ProtocolId +
					rsp->SecurityBufferOffset, spnego_blob,
					spnego_blob_len);
			rsp->SecurityBufferLength =
				cpu_to_le16(spnego_blob_len);
			kfree(spnego_blob);
			kfree(neg_blob);
		} else {
			neg_blob_len = build_ntlmssp_challenge_blob(chgblob,
					sess);
			if (neg_blob_len < 0) {
				rc = -ENOMEM;
				goto out_err;
			}

			rsp->SecurityBufferLength = neg_blob_len;
		}

		rsp->hdr.Status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		/* Note: here total size -1 is done as
		   an adjustment for 0 size blob */
		inc_rfc1001_len(rsp, rsp->SecurityBufferLength - 1);
	} else if (negblob->MessageType == NtLmAuthenticate) {
		AUTHENTICATE_MESSAGE *authblob;
		char *username;

		if (conn->dialect >= SMB30_PROT_ID) {
			chann = lookup_chann_list(sess);
			if (!chann) {
				chann = kmalloc(sizeof(struct channel),
					GFP_KERNEL);
				if (!chann) {
					rc = -ENOMEM;
					goto out_err;
				}

				chann->conn = conn;
				INIT_LIST_HEAD(&chann->chann_list);
				list_add(&chann->chann_list,
					&sess->cifsd_chann_list);
			}
		}

		cifsd_debug("authenticate phase\n");
		if (conn->use_spnego && conn->mechToken)
			authblob = (AUTHENTICATE_MESSAGE *)conn->mechToken;
		else
			authblob = (AUTHENTICATE_MESSAGE *)
				(req->hdr.ProtocolId +
				 req->SecurityBufferOffset);

		username = smb_strndup_from_utf16((const char *)authblob +
				authblob->UserName.BufferOffset,
				authblob->UserName.Length, true,
				conn->local_nls);

		if (IS_ERR(username)) {
			cifsd_err("cannot allocate memory\n");
			rc = PTR_ERR(username);
			rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
			goto out_err;
		}

		cifsd_debug("session setup request for user %s\n", username);
		sess->usr = cifsd_is_user_present(username);
		if (!sess->usr) {
			cifsd_debug("user (%s) is not present in database or guest account is not set\n",
				username);
			kfree(username);
			rc = -EINVAL;
			rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
			goto out_err;
		}
		kfree(username);

		if (sess->usr->guest) {
			if (conn->sign) {
				cifsd_debug("Guest login not allowed when signing enabled\n");
				rc = -EACCES;
				rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
				goto out_err;
			}

			rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST;
			sess->is_guest = true;
			if (maptoguest) {
				rsp->SessionFlags = SMB2_SESSION_FLAG_IS_NULL;
				sess->is_anonymous = true;
				sess->is_guest	= false;
			}
		} else {
			rc = decode_ntlmssp_authenticate_blob(authblob,
				le16_to_cpu(req->SecurityBufferLength), sess);
			if (rc) {
				cifsd_debug("authentication failed\n");
				rc = -EINVAL;
				rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
				goto out_err;
			}

			if (!sess->sign && ((req->SecurityMode &
				SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
				(conn->sign || global_signing) ||
				(conn->dialect == SMB311_PROT_ID))) {
				if (conn->dialect >= SMB30_PROT_ID &&
					conn->ops->compute_signingkey) {
					rc = conn->ops->compute_signingkey(
						sess, chann->smb3signingkey,
						SMB3_SIGN_KEY_SIZE);
					if (rc) {
						cifsd_debug("SMB3 session key generation failed\n");
						rsp->hdr.Status =
							NT_STATUS_LOGON_FAILURE;
						goto out_err;
					}
				}
				sess->sign = true;
			}
		}

		if (conn->use_spnego) {
			if (build_spnego_ntlmssp_auth_blob(&spnego_blob,
					&spnego_blob_len, 0)) {
				rc = -ENOMEM;
				goto out_err;
			}

			memcpy((char *)rsp->hdr.ProtocolId +
				rsp->SecurityBufferOffset,
				spnego_blob, spnego_blob_len);
			rsp->SecurityBufferLength =
				cpu_to_le16(spnego_blob_len);
			kfree(spnego_blob);
			inc_rfc1001_len(rsp, rsp->SecurityBufferLength);
		}

		conn->tcp_status = CifsGood;
		sess->state = SMB2_SESSION_VALID;
		smb_work->sess = sess;
	} else {
		cifsd_err("%s Invalid phase\n", __func__);
		rc = -EINVAL;
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
	}

out_err:
	if (conn->use_spnego && conn->mechToken)
		kfree(conn->mechToken);

	if (rc < 0 && sess) {
		smb_delete_session(sess);
		smb_work->sess = NULL;
	}

	return rc;
}

/**
 * smb2_tree_connect() - handler for smb2 tree connect command
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_tree_connect(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_tree_connect_req *req;
	struct smb2_tree_connect_rsp *rsp;
	struct cifsd_sess *sess = smb_work->sess;
	struct cifsd_share *share;
	struct cifsd_tcon *tcon;
	char *treename = NULL, *name = NULL;
	int rc = 0;
	bool can_write;

	req = (struct smb2_tree_connect_req *)smb_work->buf;
	rsp = (struct smb2_tree_connect_rsp *)smb_work->rsp_buf;

	if (req->StructureSize != 9) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	treename = smb_strndup_from_utf16(req->Buffer, req->PathLength,
					  true, conn->local_nls);
	if (IS_ERR(treename)) {
		cifsd_err("treename is NULL\n");
		rc = PTR_ERR(treename);
		goto out_err1;
	}

	name = extract_sharename(treename);
	if (IS_ERR(name)) {
		kfree(treename);
		rc = PTR_ERR(name);
		goto out_err1;
	}

	cifsd_debug("tree connect request for tree %s treename %s\n",
		      name, treename);

	share = get_cifsd_share(conn, sess, name, &can_write);
	if (IS_ERR(share)) {
		rc = PTR_ERR(share);
		goto out_err;
	}

	tcon = construct_cifsd_tcon(share, sess);
	if (IS_ERR(tcon)) {
		rc = PTR_ERR(tcon);
		goto out_err;
	}

	tcon->writeable = can_write;
	rsp->hdr.Id.SyncId.TreeId = tcon->share->tid;

	if (!strncmp("IPC$", name, 4)) {
		tcon->share->is_pipe = true;
		cifsd_debug("IPC share path request\n");
		share->type = SMB2_SHARE_TYPE_PIPE;
		rsp->ShareType = SMB2_SHARE_TYPE_PIPE;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_EXECUTE_LE | FILE_READ_ATTRIBUTES_LE |
			FILE_DELETE_LE | FILE_READ_CONTROL_LE |
			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			FILE_SYNCHRONIZE_LE;
	} else {
		share->type = SMB2_SHARE_TYPE_DISK;
		rsp->ShareType = SMB2_SHARE_TYPE_DISK;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			FILE_WRITE_EA_LE | FILE_EXECUTE_LE | FILE_DELETE_CHILD |
			FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
			FILE_DELETE_LE | FILE_READ_CONTROL_LE |
			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			FILE_SYNCHRONIZE_LE;
	}

	tcon->maximal_access = le32_to_cpu(rsp->MaximalAccess);

out_err:
	kfree(treename);
	kfree(name);
out_err1:
	rsp->StructureSize = cpu_to_le16(16);
	rsp->Capabilities = 0;
	rsp->Reserved = 0;
	/* default manual caching */
	rsp->ShareFlags = SMB2_SHAREFLAG_MANUAL_CACHING;
	inc_rfc1001_len(rsp, 16);
	switch (rc) {
	case -ENOENT:
		rsp->hdr.Status = NT_STATUS_BAD_NETWORK_PATH;
		break;
	case -ENOMEM:
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		break;
	case -EACCES:
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		break;
	case -EINVAL:
		if (IS_ERR(treename) || IS_ERR(name))
			rsp->hdr.Status = NT_STATUS_BAD_NETWORK_NAME;
		else
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		rsp->hdr.Status = NT_STATUS_OK;
	}
	return rc;
}

/**
 * smb2_create_open_flags() - convert smb open flags to unix open flags
 * @file_present:	is file already present
 * @access:		file access flags
 * @disposition:	file disposition flags
 * @smb_work:	smb work containing smb request buffer
 *
 * Return:      file open flags
 */
int smb2_create_open_flags(bool file_present, __le32 access,
		__le32 disposition)
{
	int oflags = 0;

	if (((access & FILE_READ_DATA_LE || access & FILE_GENERIC_READ_LE) &&
			(access & FILE_WRITE_DATA_LE ||
			 access & FILE_GENERIC_WRITE_LE)) ||
			access & FILE_MAXIMAL_ACCESS_LE ||
			access & FILE_GENERIC_ALL_LE)
		oflags |= O_RDWR;
	else if (access & FILE_READ_DATA_LE  || access & FILE_GENERIC_READ_LE)
		oflags |= O_RDONLY;
	else if (access & FILE_WRITE_DATA_LE || access & FILE_GENERIC_WRITE_LE)
		oflags |= O_WRONLY;
	else
		oflags |= O_RDONLY;

	if (file_present) {
		switch (disposition & 0x00000007) {
		case FILE_OPEN_LE:
		case FILE_CREATE_LE:
			break;
		case FILE_SUPERSEDE_LE:
		case FILE_OVERWRITE_LE:
		case FILE_OVERWRITE_IF_LE:
			oflags |= O_TRUNC;
			break;
		default:
			break;
		}
	} else {
		switch (disposition & 0x00000007) {
		case FILE_SUPERSEDE_LE:
		case FILE_CREATE_LE:
		case FILE_OPEN_IF_LE:
		case FILE_OVERWRITE_IF_LE:
			oflags |= O_CREAT;
			break;
		case FILE_OPEN_LE:
		case FILE_OVERWRITE_LE:
			oflags &= ~O_CREAT;
			break;
		default:
			break;
		}
	}
	return oflags;
}

/**
 * smb2_tree_disconnect() - handler for smb tree connect request
 * @smb_work:	smb work containing request buffer
 *
 * Return:      0
 */
int smb2_tree_disconnect(struct smb_work *smb_work)
{
	struct smb2_tree_disconnect_req *req;
	struct smb2_tree_disconnect_rsp *rsp;
	struct cifsd_sess *sess = smb_work->sess;
	struct cifsd_tcon *tcon = smb_work->tcon;

	req = (struct smb2_tree_disconnect_req *)smb_work->buf;
	rsp = (struct smb2_tree_disconnect_rsp *)smb_work->rsp_buf;

	if (req->StructureSize != 4) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}
	rsp->StructureSize = cpu_to_le16(4);
	inc_rfc1001_len(rsp, 4);

	cifsd_debug("%s : request\n", __func__);

	if (!tcon) {
		cifsd_debug("Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);
		rsp->hdr.Status = NT_STATUS_NETWORK_NAME_DELETED;
		smb2_set_err_rsp(smb_work);
		return 0;
	}

	/* delete tcon from sess tcon list and decrease sess tcon count */
	if (tcon->share->sharename)
		path_put(&tcon->share_path);
	list_del(&tcon->tcon_list);
	sess->tcon_count--;
	close_opens_from_fibtable(sess, tcon);
	kfree(tcon);

	return 0;
}

/**
 * smb2_session_logoff() - handler for session log off request
 * @smb_work:	smb work containing request buffer
 *
 * Return:      0
 */
int smb2_session_logoff(struct smb_work *smb_work)
{

	struct connection *conn = smb_work->conn;
	struct smb2_logoff_req *req;
	struct smb2_logoff_rsp *rsp;
	struct cifsd_sess *sess = smb_work->sess;
	struct cifsd_tcon *tcon;
	struct list_head *tmp, *t;

	req = (struct smb2_logoff_req *)smb_work->buf;
	rsp = (struct smb2_logoff_rsp *)smb_work->rsp_buf;

	if (req->StructureSize != 4) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	rsp->StructureSize = cpu_to_le16(4);
	inc_rfc1001_len(rsp, 4);

	cifsd_debug("%s : request\n", __func__);

	/* Got a valid session, set connection state */
	WARN_ON(sess->conn != conn || conn->sess_count != 1);

	/* setting CifsExiting here may race with start_tcp_sess */
	conn->tcp_status = CifsNeedReconnect;

	destroy_fidtable(sess);

	/*
	 * We cannot discard session in case some request are already running.
	 * Need to wait for them to finish and update req_running.
	 */
	wait_event(conn->req_running_q,
			atomic_read(&conn->req_running) == 1);

	/* Free the tree connection to session */
	list_for_each_safe(tmp, t, &sess->tcon_list) {
		tcon = list_entry(tmp, struct cifsd_tcon, tcon_list);
		if (tcon == NULL) {
			cifsd_debug("Invalid tid %d\n",
				req->hdr.Id.SyncId.TreeId);
			rsp->hdr.Status = NT_STATUS_NETWORK_NAME_DELETED;
			smb2_set_err_rsp(smb_work);
			return 0;
		}
		list_del(&tcon->tcon_list);
		sess->tcon_count--;
		kfree(tcon);
	}

	WARN_ON(sess->tcon_count != 0);

	sess->valid = 0;
	sess->state = SMB2_SESSION_EXPIRED;

	/* let start_tcp_sess free connection info now */
	conn->tcp_status = CifsNeedNegotiate;
	return 0;
}

/**
 * create_smb2_pipe() - create IPC pipe
 * @smb_work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
static int create_smb2_pipe(struct smb_work *smb_work)
{
	struct smb2_create_rsp *rsp;
	struct smb2_create_req *req;
	int id;
	int err;
	unsigned int pipe_type;
	char *name;

	rsp = (struct smb2_create_rsp *)smb_work->rsp_buf;
	req = (struct smb2_create_req *)smb_work->buf;
	name = smb_strndup_from_utf16(req->Buffer, req->NameLength, 1,
				smb_work->conn->local_nls);
	if (IS_ERR(name)) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		return PTR_ERR(name);
	}

	pipe_type = get_pipe_type(name);
	if (pipe_type == INVALID_PIPE) {
		cifsd_debug("pipe %s not supported\n", name);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		return -EOPNOTSUPP;
	}

	/* Assigning temporary fid for pipe */
	id = get_pipe_id(smb_work->sess, pipe_type);
	if (id < 0) {
		if (id == -EMFILE)
			rsp->hdr.Status = NT_STATUS_TOO_MANY_OPENED_FILES;
		else
			rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		return id;
	}

	err = cifsd_sendmsg(smb_work->sess,
			CIFSD_KEVENT_CREATE_PIPE, pipe_type, 0, NULL, 0);
	if (err)
		cifsd_err("failed to send event, err %d\n", err);

	rsp->StructureSize = cpu_to_le16(89);
	rsp->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
	rsp->Reserved = 0;
	rsp->CreateAction = FILE_OPENED;

	rsp->CreationTime = cpu_to_le64(0);
	rsp->LastAccessTime = cpu_to_le64(0);
	rsp->ChangeTime = cpu_to_le64(0);
	rsp->AllocationSize = cpu_to_le64(0);
	rsp->EndofFile = cpu_to_le64(0);
	rsp->FileAttributes = ATTR_NORMAL;
	rsp->Reserved2 = 0;
	rsp->VolatileFileId = cpu_to_le64(id);
	rsp->PersistentFileId = 0;
	rsp->CreateContextsOffset = 0;
	rsp->CreateContextsLength = 0;

	inc_rfc1001_len(rsp, 88); /* StructureSize - 1*/
	kfree(name);
	return 0;
}

int close_disconnected_handle(struct inode *inode)
{
	struct cifsd_mfile *mfp;
	bool unlinked = true;

	mfp = mfp_lookup_inode(inode);
	if (mfp) {
		struct cifsd_file *fp, *fptmp;

		atomic_dec(&mfp->m_count);
		list_for_each_entry_safe(fp, fptmp, &mfp->m_fp_list, node) {
			if (!fp->conn) {
				if (mfp->m_flags & S_DEL_ON_CLS)
					unlinked = false;
				close_id(fp->sess, fp->volatile_id,
					fp->persistent_id);
			}
		}
	}

	return unlinked;
}

/**
 * smb2_open() - handler for smb file open request
 * @smb_work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_open(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct cifsd_sess *sess = smb_work->sess;
	struct cifsd_tcon *tcon = smb_work->tcon;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp, *rsp_org;
	struct path path, lpath;
	struct cifsd_share *share;
	struct cifsd_mfile *mfp = NULL;
	struct cifsd_file *fp = NULL;
	struct file *filp = NULL, *lfilp = NULL;
	struct kstat stat;
	struct create_context *context;
	struct create_durable_reconn_req *recon_state;
	struct create_durable_reconn_v2_req *recon_state_v2 = NULL;
	struct lease_ctx_info *lc = NULL;
	struct create_context *lease_ccontext = NULL, *durable_ccontext = NULL,
		*mxac_ccontext = NULL, *disk_id_ccontext = NULL;
	struct create_ea_buf_req *ea_buf = NULL;
	umode_t mode = 0;
	__le32 *next_ptr = NULL;
	uint64_t persistent_id = 0;
	int req_op_level = 0, rsp_op_level = 0, open_flags = 0, file_info = 0;
	int volatile_id = 0;
	int rc = 0, len = 0;
	int durable_open = false, recon_ver = 0;
	int maximal_access = 0, contxt_cnt = 0, query_disk_id = 0;
	int xattr_stream_size = 0, s_type = 0, store_stream = 0;
	int next_off = 0, tree_id = 0;
	char *name = NULL, *lname = NULL, *pathname = NULL;
	char *stream_name = NULL, *xattr_stream_name = NULL;
	bool file_present = false, created = false, islink = false;
	struct create_durable_req_v2 *durable_v2_blob = NULL;
	struct create_app_inst_id *app_inst_id = NULL;

	req = (struct smb2_create_req *)smb_work->buf;
	rsp = (struct smb2_create_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_create_req *)((char *)req +
					smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_create_rsp *)((char *)rsp +
					smb_work->next_smb2_rsp_hdr_off);
	}

	if (le32_to_cpu(req->hdr.NextCommand) &&
			!smb_work->next_smb2_rcv_hdr_off &&
			(le32_to_cpu(req->hdr.Flags) &
			 SMB2_FLAGS_RELATED_OPERATIONS)) {
		cifsd_debug("invalid flag in chained command\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(smb_work);
		return -EINVAL;
	}

	if (req->StructureSize != 57) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (tcon->share->is_pipe == true) {
		cifsd_debug("IPC pipe create request\n");
		return create_smb2_pipe(smb_work);
	}

	if (req->NameLength) {
		if ((req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&
			*(char *)req->Buffer == '\\') {
			cifsd_err("not allow directory name included leadning slash\n");
			rc = -EINVAL;
			goto err_out1;
		}

		name = smb2_get_name(req->Buffer, req->NameLength, smb_work);
		if (IS_ERR(name)) {
			rc = PTR_ERR(name);
			goto err_out1;
		}
	} else {
		share = find_matching_share(rsp->hdr.Id.SyncId.TreeId);
		if (!share) {
			rsp->hdr.Status = NT_STATUS_NO_MEMORY;
			rc = -ENOMEM;
			goto err_out1;
		}

		len = strlen(share->path);
		cifsd_debug("[%s] %d\n", __func__, len);
		name = kmalloc(len + 1, GFP_KERNEL);
		if (!name) {
			rsp->hdr.Status = NT_STATUS_NO_MEMORY;
			rc = -ENOMEM;
			goto err_out1;
		}

		memcpy(name, share->path, len);
		*(name + len) = '\0';
	}

	cifsd_debug("converted name = %s\n", name);
	if (strchr(name, ':')) {
		rc = parse_stream_name(name, &stream_name, &s_type);
		if (rc < 0)
			goto err_out1;
	}

	rc = check_invalid_char(name);
	if (rc < 0)
		goto err_out1;

	req_op_level = req->RequestedOplockLevel;
	if (req->CreateContextsOffset) {
		context = smb2_find_context_vals(
			req, SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			recon_state_v2 =
				(struct create_durable_reconn_v2_req *)context;
			recon_ver = 2;
			persistent_id = le64_to_cpu(
				recon_state_v2->Fid.PersistentFileId);
			fp = cifsd_get_global_fp(persistent_id);

			if (!fp) {
				cifsd_err(
					"Failed to get Durable handle state\n");
				rc = -EBADF;
				fp = NULL;
				goto err_out1;
			}

			cifsd_debug("reconnect v2 Persistent-id from reconnect = %llu\n",
				persistent_id);
		}

		context = smb2_find_context_vals(
			req, SMB2_CREATE_DURABLE_HANDLE_RECONNECT);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			if (recon_ver) {
				rc = -EINVAL;
				fp = NULL;
				goto err_out1;
			}

			recon_state =
				(struct create_durable_reconn_req *)context;
			recon_ver = 1;
			persistent_id = le64_to_cpu(
				recon_state->Data.Fid.PersistentFileId);
			fp = cifsd_get_global_fp(persistent_id);
			if (!fp) {
				cifsd_err(
					"Failed to get Durable handle state\n");
				rc = -EBADF;
				goto err_out1;
			}

			cifsd_debug("reconnect Persistent-id from reconnect = %llu\n",
				persistent_id);
		}

		if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE || recon_ver)
			lc = parse_lease_state(req);

		context = smb2_find_context_vals(req,
			SMB2_CREATE_APP_INSTANCE_ID);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
			rc = 0;
		} else {
			app_inst_id = (struct create_app_inst_id *)context;
			fp = lookup_fp_app_id(app_inst_id->AppInstanceId);
			if (fp) {
				cifsd_err("fp : %p, find same app id\n", fp);
				close_id(fp->sess, fp->volatile_id,
					fp->persistent_id);
			}
		}

		context = smb2_find_context_vals(req,
			SMB2_CREATE_DURABLE_HANDLE_REQUEST);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
			rc = 0;
		} else {
			if (recon_ver == 2) {
				rc = -EINVAL;
				fp = NULL;
				goto err_out1;
			}

			if (((lc &&
				(lc->req_state & SMB2_LEASE_HANDLE_CACHING)) ||
				(req_op_level == SMB2_OPLOCK_LEVEL_BATCH))) {
				cifsd_debug("Request for durable open\n");
				durable_open = 1;
			}
		}

		context = smb2_find_context_vals(req,
			SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
			rc = 0;
		} else {
			if (recon_ver) {
				rc = -EINVAL;
				fp = NULL;
				goto err_out1;
			}
			durable_v2_blob =
				(struct create_durable_req_v2 *)context;
			cifsd_debug("Request for durable v2 open\n");

			fp = lookup_fp_clguid(durable_v2_blob->CreateGuid);
			if (fp) {
				if (!memcmp(conn->ClientGUID, fp->client_guid,
					SMB2_CLIENT_GUID_SIZE)) {
					if (!(le32_to_cpu(req->hdr.Flags) &
						SMB2_FLAGS_REPLAY_OPERATIONS)) {
						rc = -EIO;
						rsp->hdr.Status =
						NT_STATUS_DUPLICATE_OBJECTID;
						goto err_out1;
					}

					fp->conn = conn;
					goto reconnect;
				}
			}
			if (((lc &&
				(lc->req_state & SMB2_LEASE_HANDLE_CACHING)) ||
				(req_op_level == SMB2_OPLOCK_LEVEL_BATCH))) {
				durable_open = 2;
			}
		}

		if (recon_ver)
			goto reconnect;
	}

	if (req->ImpersonationLevel > IL_DELEGATE) {
		cifsd_err("Invalid impersonationlevel : 0x%x\n",
			le32_to_cpu(req->ImpersonationLevel));
		rc = -EIO;
		rsp->hdr.Status = NT_STATUS_BAD_IMPERSONATION_LEVEL;
		goto err_out1;
	}

	if (req->CreateOptions && !(req->CreateOptions & CREATE_OPTIONS_MASK)) {
		cifsd_err("Invalid create options : 0x%x\n",
			le32_to_cpu(req->CreateOptions));
		rc = -EINVAL;
		goto err_out1;
	} else {

		if (req->CreateOptions & FILE_SEQUENTIAL_ONLY_LE &&
			req->CreateOptions & FILE_RANDOM_ACCESS_LE)
			req->CreateOptions = ~(FILE_SEQUENTIAL_ONLY_LE);

		if (req->CreateOptions & (FILE_OPEN_BY_FILE_ID_LE |
			CREATE_TREE_CONNECTION | FILE_RESERVE_OPFILTER_LE)) {
			rc = -EOPNOTSUPP;
			goto err_out1;
		}

		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
			if (req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE) {
				rc = -EINVAL;
				goto err_out1;
			} else if (req->CreateOptions & FILE_NO_COMPRESSION_LE)
				req->CreateOptions = ~(FILE_NO_COMPRESSION_LE);
		}
	}

	if (req->CreateDisposition > FILE_OVERWRITE_IF_LE) {
		cifsd_err("Invalid create disposition : 0x%x\n",
			req->CreateDisposition);
		rc = -EINVAL;
		goto err_out1;
	}

	if (req->DesiredAccess && !(req->DesiredAccess & DISIRED_ACCESS_MASK)) {
		cifsd_err("Invalid disired access : 0x%x\n",
			le32_to_cpu(req->DesiredAccess));
		rc = -EACCES;
		goto err_out1;
	}

	if (req->FileAttributes &&
		!(req->FileAttributes & FILE_ATTRIBUTE_MASK)) {
		cifsd_err("Invalid file attribute : 0x%x\n",
			le32_to_cpu(req->FileAttributes));
		rc = -EINVAL;
		goto err_out1;
	}

	tree_id = le32_to_cpu(req->hdr.Id.SyncId.TreeId);
	if (req->CreateContextsOffset) {
		/* Parse non-durable handle create contexts */
		context = smb2_find_context_vals(req, SMB2_CREATE_EA_BUFFER);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			ea_buf = (struct create_ea_buf_req *)context;
			if (req->CreateOptions & FILE_NO_EA_KNOWLEDGE_LE) {
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
				rc = -EACCES;
				goto err_out1;
			}
		}

		context = smb2_find_context_vals(req,
				SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			struct create_mxac_req *mxac_req =
				(struct create_mxac_req *)context;
			cifsd_debug("get query maximal access context (timestamp : %llu)\n",
				le64_to_cpu(mxac_req->Timestamp));
			maximal_access = tcon->maximal_access;
		}

		context = smb2_find_context_vals(req,
				SMB2_CREATE_TIMEWARP_REQUEST);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			cifsd_debug("get timewarp context\n");
			rc = -EBADF;
			goto err_out1;
		}

	}

	if (le32_to_cpu(req->CreateOptions) & FILE_DELETE_ON_CLOSE_LE) {
		/*
		 * On delete request, instead of following up, need to
		 * look the current entity
		 */
		rc = smb_kern_path(name, 0, &path, 1);
	} else {
		/*
		* Use LOOKUP_FOLLOW to follow the path of
		* symlink in path buildup
		*/
		rc = smb_kern_path(name, LOOKUP_FOLLOW, &path, 1);
		if (rc) { /* Case for broken link ?*/
			rc = smb_kern_path(name, 0, &path, 1);
		}
	}

	if (rc) {
		cifsd_debug("can not get linux path for %s, rc = %d\n",
				name, rc);
		rc = 0;
	} else {
		file_present = true;
		generic_fillattr(path.dentry->d_inode, &stat);
	}
	if (stream_name) {
		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
			if (s_type == DATA_STREAM) {
				rc = -EIO;
				rsp->hdr.Status = NT_STATUS_NOT_A_DIRECTORY;
			}
		} else {
			if (S_ISDIR(stat.mode) && s_type == DATA_STREAM) {
				rc = -EIO;
				rsp->hdr.Status = NT_STATUS_FILE_IS_A_DIRECTORY;
			}
		}

		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE &&
			req->FileAttributes & FILE_ATTRIBUTE_NORMAL_LE) {
			rsp->hdr.Status = NT_STATUS_NOT_A_DIRECTORY;
			rc = -EIO;
		}

		if (rc < 0) {
			goto err_out;
		}
	}

	if (file_present && req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE
		&& S_ISDIR(stat.mode) &&
		!(req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {
		cifsd_err("Can't open dir %s, request is to open file : %x\n",
			      name, req->CreateOptions);
		rsp->hdr.Status = NT_STATUS_FILE_IS_A_DIRECTORY;
		rc = -EIO;
		goto err_out;
	}

	if (file_present && (req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&
		!(req->CreateDisposition == FILE_CREATE_LE) &&
		!S_ISDIR(stat.mode)) {
		rsp->hdr.Status = NT_STATUS_NOT_A_DIRECTORY;
		rc = -EIO;
		goto err_out;
	}

	if (!stream_name && file_present &&
		(req->CreateDisposition == FILE_CREATE_LE)) {
		rc = -EBADF;
		goto err_out;
	}

	if (file_present)
		file_present = close_disconnected_handle(path.dentry->d_inode);

	if (tcon->writeable)
		open_flags = smb2_create_open_flags(file_present,
			req->DesiredAccess, req->CreateDisposition);
	else
		open_flags = O_RDONLY;

	/*create file if not present */
	if (!file_present) {
		if (open_flags & O_CREAT) {
			cifsd_debug("file does not exist, so creating\n");
			if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
				cifsd_debug("creating directory\n");
				mode = 00777 & ~current_umask();
				rc = smb_vfs_mkdir(name, mode);
				if (rc) {
					rsp->hdr.Status = cpu_to_le32(
							NT_STATUS_DATA_ERROR);
					rsp->hdr.Status =
						NT_STATUS_UNEXPECTED_IO_ERROR;
					kfree(name);
					return rc;
				}
			} else {
				cifsd_debug("creating regular file\n");
				mode = 00666 & ~current_umask();
				rc = smb_vfs_create(name, mode);
				if (rc) {
					rsp->hdr.Status =
						NT_STATUS_UNEXPECTED_IO_ERROR;
					kfree(name);
					return rc;
				}
			}

			rc = smb_kern_path(name, 0, &path, 0);
			if (rc) {
				cifsd_err("cannot get linux path (%s), err = %d\n",
						name, rc);
				rsp->hdr.Status =
					NT_STATUS_UNEXPECTED_IO_ERROR;
				kfree(name);
				return rc;
			}
			created = true;
			if (ea_buf) {
				rc = smb2_set_ea(&ea_buf->ea, &path);
				if (rc)
					goto err_out;
			}
		} else {
			kfree(name);
			if (tcon->writeable) {
				cifsd_debug("returning as file does not exist\n");
				rsp->hdr.Status =
					NT_STATUS_OBJECT_NAME_NOT_FOUND;
			} else {
				cifsd_debug("returning as user does not have permission to write\n");
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
			}
			smb2_set_err_rsp(smb_work);
			return 0;
		}
	}

	filp = dentry_open(&path, open_flags | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		cifsd_err("dentry open for dir failed, rc %d\n", rc);
		goto err_out;
	}

	pathname = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname) {
		rc = -ENOMEM;
		cifsd_err("Failed to allocate memory for linkpath\n");
		goto err_out;
	}

	lname = d_path(&(filp->f_path), pathname, PATH_MAX);
	if (IS_ERR(lname)) {
		rc = PTR_ERR(lname);
		kfree(pathname);
		goto err_out;
	}

	if (strncmp(name, lname, PATH_MAX)) {
		islink = true;
		cifsd_debug("Case for symlink follow, name(%s)->path(%s)\n",
				name, lname);
		rc = smb_kern_path(name, 0, &lpath, 0);
		if (rc) {
			cifsd_err("cannot get linux path (%s), err = %d\n",
				name, rc);
			kfree(pathname);
			goto err_out;
		}
		lfilp = dentry_open(&lpath, open_flags
				| O_LARGEFILE, current_cred());
		if (IS_ERR(lfilp)) {
			rc = PTR_ERR(lfilp);
			cifsd_err("dentry open for (%s) failed, rc %d\n",
				name, rc);
			kfree(pathname);
			path_put(&lpath);
			goto err_out;
		}
		path_put(&lpath);
	}
	kfree(pathname);

	if (file_present) {
		if (!(open_flags & O_TRUNC))
			file_info = FILE_OPENED;
		else
			file_info = FILE_OVERWRITTEN;

		if ((req->CreateDisposition & 0x00000007) == FILE_SUPERSEDE_LE)
			file_info = FILE_SUPERSEDED;
	} else if (open_flags & O_CREAT)
		file_info = FILE_CREATED;

	smb_vfs_set_fadvise(filp, le32_to_cpu(req->CreateOptions));

	/* Obtain Volatile-ID */
	volatile_id = cifsd_get_unused_id(&sess->fidtable);
	if (volatile_id < 0) {
		cifsd_err("failed to get unused volatile_id for file\n");
		rc = volatile_id;
		goto err_out;
	}

	cifsd_debug("volatile_id returned: %d\n", volatile_id);
	fp = insert_id_in_fidtable(sess, tcon, volatile_id, filp);
	if (fp == NULL) {
		cifsd_err("volatile_id insert failed\n");
		cifsd_close_id(&sess->fidtable, volatile_id);
		rc = -ENOMEM;
		goto err_out;
	}

	if (S_ISDIR(stat.mode))
		fp->readdir_data.dirent = NULL;

	fp->filename = name;
	fp->cdoption = req->CreateDisposition;
	fp->daccess = req->DesiredAccess;
	fp->saccess = req->ShareAccess;
	fp->coption = req->CreateOptions;
	INIT_LIST_HEAD(&fp->lock_list);

	/* Get Persistent-ID */
	persistent_id = cifsd_insert_in_global_table(sess, fp);
	if (persistent_id < 0) {
		cifsd_err("persistent id insert failed\n");
		rc = -ENOMEM;
		goto err_out;
	}
	fp->persistent_id = persistent_id;

	mfp = mfp_lookup(fp);
	if (!mfp) {
		mfp = kmalloc(sizeof(struct cifsd_mfile), GFP_KERNEL);
		if (!mfp) {
			rc = -ENOMEM;
			goto err_out;
		}

		rc = mfp_init(mfp, fp);
		if (rc) {
			cifsd_err("mfp initialized failed\n");
			rc = -ENOMEM;
			goto err_out;
		}
	}
	fp->f_mfp = mfp;

	if (req->CreateContextsOffset) {
		struct create_alloc_size_req *az_req;

		az_req = (struct create_alloc_size_req *)
				smb2_find_context_vals(req,
				SMB2_CREATE_ALLOCATION_SIZE);
		if (IS_ERR(az_req)) {
			rc = PTR_ERR(az_req);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			loff_t alloc_size = le64_to_cpu(az_req->AllocationSize);

			cifsd_debug("request smb2 create allocate size : %llu\n",
				alloc_size);
			rc = smb_vfs_alloc_size(conn, fp, alloc_size);
			if (rc < 0)
				cifsd_debug("smb_vfs_alloc_size is failed : %d\n",
					rc);
		}

		context = smb2_find_context_vals(req,
				SMB2_CREATE_QUERY_ON_DISK_ID);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			cifsd_debug("get query on disk id context\n");
			query_disk_id = 1;
		}

#ifdef CONFIG_CIFSD_ACL
		context = smb2_find_context_vals(req, SMB2_CREATE_SD_BUFFER);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			if (rc == -EINVAL) {
				cifsd_err("bad name length\n");
				goto err_out1;
			}
		} else {
			cifsd_err("Create SMB2_CREATE_SD_BUFFER\n");

			if (!(req->DesiredAccess & FILE_WRITE_DAC_LE)) {
				rc = -EACCES;
				goto err_out1;
			}

			if (open_flags & O_CREAT) {
				struct cifs_ntsd *pntsd;
				struct cifsd_fattr fattr;

				pntsd = (struct cifs_ntsd *)
					(((char *) context) +
					 context->DataOffset);

				parse_sec_desc(pntsd,
					le32_to_cpu(context->DataLength),
					&fattr);

				cifsd_fattr_to_inode(path.dentry->d_inode,
					&fattr);
			}
		}
#endif
	}

	if (islink) {
		fp->lfilp = lfilp;
		fp->islink = islink;
	}

	if (stream_name) {
		xattr_stream_size = construct_xattr_stream_name(stream_name,
			&xattr_stream_name);

		fp->is_stream = true;
		fp->stream.name = xattr_stream_name;
		fp->stream.type = s_type;
		fp->stream.size = xattr_stream_size;

		/* Check if there is stream prefix in xattr space */
		rc = smb_find_cont_xattr(&path, xattr_stream_name,
				xattr_stream_size, NULL, 0);
		if (rc < 0) {
			if (fp->cdoption == FILE_OPEN_LE) {
				cifsd_err("failed to find stream name in xattr, rc : %d\n",
						rc);
				rc = -EBADF;
				goto err_out;
			}

			store_stream = 1;
		}
		rc = 0;
	}

	fp->attrib_only = !(req->DesiredAccess & ~(FILE_READ_ATTRIBUTES_LE |
			FILE_WRITE_ATTRIBUTES_LE | FILE_SYNCHRONIZE_LE));
	if (!S_ISDIR(file_inode(filp)->i_mode) && open_flags & O_TRUNC
		&& !fp->attrib_only) {
		if (oplocks_enable)
			smb_break_all_oplock(smb_work, fp);

		rc = vfs_truncate(&path, 0);
		if (rc) {
			cifsd_err("vfs_truncate failed, rc %d\n", rc);
			goto err_out;
		}

		/*
		 * destroy xattr only when CreateDisposition is
		 * FILE_SUPERSEDE
		 */
		if (req->CreateDisposition & FILE_SUPERSEDE_LE) {
			rc = smb_vfs_truncate_xattr(path.dentry);
			if (rc) {
				cifsd_err("smb_vfs_truncate_xattr is failed, rc %d\n",
					rc);
				goto err_out;
			}
		}
	}

	generic_fillattr(path.dentry->d_inode, &stat);

	if (!oplocks_enable || (req_op_level == SMB2_OPLOCK_LEVEL_LEASE &&
		!(conn->srv_cap & SMB2_GLOBAL_CAP_LEASING))) {
		rsp_op_level = SMB2_OPLOCK_LEVEL_NONE;
	} else if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE) {
		req_op_level = smb2_map_lease_to_oplock(lc->req_state);
		cifsd_debug("lease req for(%s) req oplock state 0x%x, lease state 0x%x\n",
				name, req_op_level, lc->req_state);
		rc = find_same_lease_key(sess, mfp, lc);
		if (rc)
			goto err_out;
		rc = smb_grant_oplock(smb_work, req_op_level,
			persistent_id, fp, tree_id, lc);
		if (rc < 0)
			goto err_out;
	} else {
		rc = smb_grant_oplock(smb_work, req_op_level,
			persistent_id, fp, tree_id, NULL);
		if (rc < 0)
			goto err_out;
	}

	if (le32_to_cpu(req->CreateOptions) & FILE_DELETE_ON_CLOSE_LE) {
		if (fp->is_stream)
			mfp->m_flags |= S_DEL_ON_CLS_STREAM;
		else
			mfp->m_flags |= S_DEL_ON_CLS;
	}

	/* Add fp to master fp list. */
	list_add(&fp->node, &mfp->m_fp_list);

	if ((file_info != FILE_OPENED) && !S_ISDIR(file_inode(filp)->i_mode)) {
		/* Create default data stream in xattr */
		smb_store_cont_xattr(&path, XATTR_NAME_STREAM, NULL, 0);
	}

	if (store_stream) {
		rc = smb_store_cont_xattr(&path, xattr_stream_name, NULL, 0);
		if (rc < 0) {
			cifsd_err("failed to store stream name in xattr, rc :%d\n",
					rc);
		}
		file_info = FILE_CREATED;
		rc = 0;
	}

	if (created) {
		i_uid_write(FP_INODE(fp), sess->usr->uid.val);
		i_gid_write(FP_INODE(fp), sess->usr->gid.val);
	}

	if (!created) {
		fp->create_time = cifs_UnixTimeToNT(stat.ctime);
		if (get_attr_store_dos(&tcon->share->config.attr)) {
			char *create_time = NULL;

			rc = smb_find_cont_xattr(&path,
				XATTR_NAME_CREATION_TIME,
				XATTR_NAME_CREATION_TIME_LEN, &create_time, 1);

			if (rc > 0)
				fp->create_time = *((__u64 *)create_time);

			kvfree(create_time);
			rc = 0;
		}
	} else {
		fp->create_time = cifs_UnixTimeToNT(stat.ctime);
		if (get_attr_store_dos(&tcon->share->config.attr)) {
			rc = smb_store_cont_xattr(&path,
				XATTR_NAME_CREATION_TIME,
				(void *)&fp->create_time, CREATIOM_TIME_LEN);
			if (rc)
				cifsd_debug("failed to store creation time in EA\n");
			rc = 0;
		}
	}

	fp->fattr = cpu_to_le32(smb2_get_dos_mode(&stat,
		le32_to_cpu(req->FileAttributes)));

	if (!created) {
		/* get FileAttributes from XATTR_NAME_FILE_ATTRIBUTE */
		if (get_attr_store_dos(&tcon->share->config.attr)) {
			char *file_attribute = NULL;

			rc = smb_find_cont_xattr(&path,
				 XATTR_NAME_FILE_ATTRIBUTE,
				 XATTR_NAME_FILE_ATTRIBUTE_LEN,
				 &file_attribute, 1);

			if (rc > 0)
				fp->fattr = *((__le32 *)file_attribute);

			kvfree(file_attribute);
			rc = 0;
		}
	} else {
		/* set XATTR_NAME_FILE_ATTRIBUTE with req->FileAttributes */
		if (get_attr_store_dos(&tcon->share->config.attr)) {
			rc = smb_store_cont_xattr(&path,
				XATTR_NAME_FILE_ATTRIBUTE,
				(void *)&fp->fattr, FILE_ATTRIBUTE_LEN);

			if (rc)
				cifsd_debug("failed to store file attribute in EA\n");

			rc = 0;
		}
	}

	memcpy(fp->client_guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);

	if (durable_open) {
		int timeout;

		if (durable_v2_blob && le32_to_cpu(durable_v2_blob->Flags))
			fp->is_persistent = 1;
		else
			fp->is_durable = 1;

		if (durable_open == 2) {
			memcpy(fp->create_guid, durable_v2_blob->CreateGuid,
				SMB2_CREATE_GUID_SIZE);
			timeout = le32_to_cpu(durable_v2_blob->Timeout);
			if (timeout)
				fp->durable_timeout = timeout;
			else
				fp->durable_timeout = 1600;
			if (app_inst_id) {
				memcpy(fp->app_instance_id,
					app_inst_id->AppInstanceId, 16);
			}

		}
	}

reconnect:
	if (recon_ver) {
		if (recon_ver == 2 && memcmp(fp->create_guid,
			recon_state_v2->CreateGuid, SMB2_CREATE_GUID_SIZE)) {
			rc = -EBADF;
			fp = NULL;
			goto err_out1;
		}

		rc = smb2_check_durable_oplock(fp, lc, name, recon_ver);
		if (rc) {
			fp = NULL;
			goto err_out;
		}
		rc = cifsd_reconnect_durable_fp(sess, fp, tcon);
		if (rc) {
			fp = NULL;
			goto err_out;
		}
		generic_fillattr(FP_INODE(fp), &stat);
		file_info = FILE_OPENED;
	}

	rsp->StructureSize = cpu_to_le16(89);
	rsp->OplockLevel = fp->f_opinfo != NULL ? fp->f_opinfo->level : 0;
	rsp->Reserved = 0;
	rsp->CreateAction = file_info;
	rsp->CreationTime = cpu_to_le64(fp->create_time);
	rsp->LastAccessTime = cpu_to_le64(cifs_UnixTimeToNT(stat.atime));
	rsp->LastWriteTime = cpu_to_le64(cifs_UnixTimeToNT(stat.mtime));
	rsp->ChangeTime = cpu_to_le64(cifs_UnixTimeToNT(stat.ctime));
	rsp->AllocationSize = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64((stat.size + 511) >> 9);
	rsp->EndofFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	rsp->FileAttributes = fp->fattr;

	rsp->Reserved2 = 0;

	rsp->PersistentFileId = cpu_to_le64(fp->persistent_id);
	rsp->VolatileFileId = cpu_to_le64(fp->volatile_id);
	rsp->CreateContextsOffset = 0;
	rsp->CreateContextsLength = 0;
	inc_rfc1001_len(rsp_org, 88); /* StructureSize - 1*/

	/* If lease is request send lease context response */
	if (fp->f_opinfo && fp->f_opinfo->is_lease) {
		cifsd_debug("lease granted on(%s) lease state 0x%x\n",
				name, fp->f_opinfo->o_lease->state);
		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_LEASE;

		lease_ccontext = (struct create_context *)rsp->Buffer;
		contxt_cnt++;
		create_lease_buf(rsp->Buffer, fp->f_opinfo->o_lease);
		rsp->CreateContextsLength =
			cpu_to_le32(conn->vals->create_lease_size);
		inc_rfc1001_len(rsp_org, conn->vals->create_lease_size);
		next_ptr = &lease_ccontext->Next;
		next_off = conn->vals->create_lease_size;
	}

	if (durable_open) {
		durable_ccontext = (struct create_context *)(rsp->Buffer +
			rsp->CreateContextsLength);
		contxt_cnt++;
		if (durable_open == 1) {
			create_durable_rsp_buf(rsp->Buffer +
				rsp->CreateContextsLength);
			rsp->CreateContextsLength +=
				cpu_to_le32(conn->vals->create_durable_size);
			inc_rfc1001_len(rsp_org,
				conn->vals->create_durable_size);
			fp->is_durable = 1;
		} else {
			create_durable_v2_rsp_buf(rsp->Buffer +
				rsp->CreateContextsLength, fp);
			rsp->CreateContextsLength +=
				cpu_to_le32(conn->vals->create_durable_v2_size);
			inc_rfc1001_len(rsp_org,
				conn->vals->create_durable_v2_size);
		}

		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &durable_ccontext->Next;
		next_off = conn->vals->create_durable_size;
	}

	if (maximal_access) {
		mxac_ccontext = (struct create_context *)(rsp->Buffer +
			rsp->CreateContextsLength);
		contxt_cnt++;
		create_mxac_rsp_buf(rsp->Buffer + rsp->CreateContextsLength,
			maximal_access);
		rsp->CreateContextsLength +=
			cpu_to_le32(conn->vals->create_mxac_size);
		inc_rfc1001_len(rsp_org, conn->vals->create_mxac_size);
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &mxac_ccontext->Next;
		next_off = conn->vals->create_mxac_size;
	}

	if (query_disk_id) {
		disk_id_ccontext = (struct create_context *)(rsp->Buffer +
			rsp->CreateContextsLength);
		contxt_cnt++;
		create_disk_id_rsp_buf(rsp->Buffer + rsp->CreateContextsLength,
			stat.ino, tcon->share->tid);
		rsp->CreateContextsLength +=
			cpu_to_le32(conn->vals->create_disk_id_size);
		inc_rfc1001_len(rsp_org, conn->vals->create_disk_id_size);
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
	}

	if (contxt_cnt > 0) {
		rsp->CreateContextsOffset =
			cpu_to_le32(offsetof(struct smb2_create_rsp, Buffer)
			- 4);
	}

err_out:
	if (file_present || created)
		path_put(&path);
err_out1:
	if (rc) {
		if (rc == -EINVAL)
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		else if (rc == -EOPNOTSUPP)
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		else if (rc == -EACCES)
			rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		else if (rc == -ENOENT)
			rsp->hdr.Status = NT_STATUS_OBJECT_NAME_INVALID;
		else if (rc == -ESHARE)
			rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
		else if (rc == -EBUSY)
			rsp->hdr.Status = NT_STATUS_DELETE_PENDING;
		else if (rc == -EBADF)
			rsp->hdr.Status = NT_STATUS_OBJECT_NAME_NOT_FOUND;

		if (!rsp->hdr.Status)
			rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;

		if (mfp && atomic_dec_and_test(&mfp->m_count))
			mfp_free(mfp);
		if (fp != NULL) {
			filp_close(filp, (struct files_struct *)filp);
			delete_id_from_fidtable(sess, volatile_id);
			cifsd_close_id(&sess->fidtable, volatile_id);
		}
		smb2_set_err_rsp(smb_work);
	} else
		conn->stats.open_files_count++;

	return 0;
}

/**
 * smb2_populate_readdir_entry() - encode directory entry in smb2 response buffer
 * @conn:	TCP server instance of connection
 * @info_level:	smb information level
 * @d_info:	structure included variables for query dir
 * @smb_kstat:	cifsd wrapper of dirent stat information
 *
 * if directory has many entries, find first can't read it fully.
 * find next might be called multiple times to read remaining dir entries
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_populate_readdir_entry(struct connection *conn,
	int info_level, struct cifsd_dir_info *d_info,
	struct smb_kstat *smb_kstat)
{
	int name_len;
	int next_entry_offset;
	char *utfname = NULL;

	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
	{
		FILE_FULL_DIRECTORY_INFO *ffdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_FULL_DIRECTORY_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;

		ffdinfo = (FILE_FULL_DIRECTORY_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		ffdinfo->FileNameLength = cpu_to_le32(name_len);
		ffdinfo->EaSize = 0;

		memcpy(ffdinfo->FileName, utfname, name_len);
		ffdinfo->FileName[name_len] = 0;
		ffdinfo->FileName[name_len + 1] = 0;
		ffdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_BOTH_DIRECTORY_INFORMATION:
	{
		FILE_BOTH_DIRECTORY_INFO *fbdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_BOTH_DIRECTORY_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;
		fbdinfo = (FILE_BOTH_DIRECTORY_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		fbdinfo->FileNameLength = cpu_to_le32(name_len);
		fbdinfo->EaSize = 0;
		fbdinfo->ShortNameLength = smb_get_shortname(conn, d_info->name,
			&(fbdinfo->ShortName[0]));
		fbdinfo->Reserved = 0;

		memcpy(fbdinfo->FileName, utfname, name_len);
		fbdinfo->FileName[name_len] = 0;
		fbdinfo->FileName[name_len + 1] = 0;
		fbdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_DIRECTORY_INFORMATION:
	{
		FILE_DIRECTORY_INFO *fdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_DIRECTORY_INFO), conn->local_nls, &name_len,
			&next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;

		fdinfo = (FILE_DIRECTORY_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		fdinfo->FileNameLength = cpu_to_le32(name_len);

		memcpy(fdinfo->FileName, utfname, name_len);
		fdinfo->FileName[name_len] = 0;
		fdinfo->FileName[name_len + 1] = 0;
		fdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_NAMES_INFORMATION:
	{
		FILE_NAMES_INFO *fninfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_NAMES_INFO), conn->local_nls, &name_len,
			&next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;

		fninfo = (FILE_NAMES_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		fninfo->FileNameLength = cpu_to_le32(name_len);

		memcpy(fninfo->FileName, utfname, name_len);
		fninfo->FileName[name_len] = 0;
		fninfo->FileName[name_len + 1] = 0;
		fninfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILEID_FULL_DIRECTORY_INFORMATION:
	{
		SEARCH_ID_FULL_DIR_INFO *dinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(SEARCH_ID_FULL_DIR_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;

		dinfo = (SEARCH_ID_FULL_DIR_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		dinfo->FileNameLength = cpu_to_le32(name_len);
		dinfo->EaSize = 0;
		dinfo->Reserved = 0;
		dinfo->UniqueId = cpu_to_le64(smb_kstat->kstat->ino);

		memcpy(dinfo->FileName, utfname, name_len);
		dinfo->FileName[name_len] = 0;
		dinfo->FileName[name_len + 1] = 0;
		dinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	{
		FILE_ID_BOTH_DIRECTORY_INFO *fibdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_ID_BOTH_DIRECTORY_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7);
		if (!utfname)
			break;

		fibdinfo = (FILE_ID_BOTH_DIRECTORY_INFO *)
				fill_common_info(&d_info->bufptr, smb_kstat);
		fibdinfo->FileNameLength = cpu_to_le32(name_len);
		fibdinfo->EaSize = 0;
		fibdinfo->UniqueId = cpu_to_le64(smb_kstat->kstat->ino);
		fibdinfo->ShortNameLength =
			smb_get_shortname(conn, d_info->name,
					&(fibdinfo->ShortName[0]));
		fibdinfo->Reserved = 0;
		fibdinfo->Reserved2 = cpu_to_le16(0);

		memcpy(fibdinfo->FileName, utfname, name_len);
		fibdinfo->FileName[name_len] = 0;
		fibdinfo->FileName[name_len + 1] = 0;
		fibdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	default:
		cifsd_err("%s: failed\n", __func__);
		return -EOPNOTSUPP;
	}

	if (utfname) {
		d_info->num_entry = d_info->data_count;
		d_info->data_count += next_entry_offset;
		d_info->out_buf_len -= next_entry_offset;
		d_info->bufptr = (char *)d_info->bufptr + next_entry_offset;
		kfree(utfname);
	}
	cifsd_debug("info_level : %d, buf_len :%d,"
			" next_offset : %d, data_count : %d\n",
			info_level, d_info->out_buf_len,
			next_entry_offset, d_info->data_count);

	return 0;
}

static int smb_populate_dot_dotdot_entries(struct connection *conn,
	__u8 file_info_class, struct cifsd_file *dir,
	struct cifsd_dir_info *d_info, char *search_patten)
{
	int i, rc = 0;

	for (i = 0; i < 2; i++) {
		struct kstat kstat;
		struct smb_kstat smb_kstat;

		if (!dir->dot_dotdot[i]) { /* fill dot entry info */
			if (i == 0)
				d_info->name = ".";
			else
				d_info->name = "..";

			if (!is_matched(d_info->name, search_patten)) {
				dir->dot_dotdot[i] = 1;
				continue;
			}

			generic_fillattr(PARENT_INODE(dir), &kstat);

			smb_kstat.kstat = &kstat;
			rc = smb2_populate_readdir_entry(conn, file_info_class,
				d_info, &smb_kstat);
			if (rc)
				break;

			if (d_info->out_buf_len <= 0)
				break;

			dir->dot_dotdot[i] = 1;
		}
	}

	return rc;
}

/**
 * smb2_query_dir() - handler for smb2 readdir i.e. query dir command
 * @smb_work:	smb work containing query dir request buffer
 *
 * Return:	0
 */
int smb2_query_dir(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_query_directory_req *req;
	struct smb2_query_directory_rsp *rsp, *rsp_org;
	struct smb_dirent *de;
	struct cifsd_file *dir_fp;
	struct cifsd_dir_info d_info;
	int reclen = 0;
	int rc = 0;
	struct kstat kstat;
	struct smb_kstat smb_kstat;
	char *dirpath, *srch_ptr = NULL, *path = NULL;
	unsigned char srch_flag;
	struct smb_readdir_data r_data = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 30)
		.ctx.actor = smb_filldir,
#endif
	};

	req = (struct smb2_query_directory_req *)smb_work->buf;
	rsp = (struct smb2_query_directory_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_directory_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_directory_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 33) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	dir_fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!dir_fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		rc = -ENOENT;
		goto err_out2;
	}

	if (!(dir_fp->daccess & FILE_LIST_DIRECTORY_LE)) {
		cifsd_err("no right to enumerate directory (%s)\n",
			FP_FILENAME(dir_fp));
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		rc = -EACCES;
		goto err_out2;
	}

	if (!S_ISDIR(file_inode(dir_fp->filp)->i_mode)) {
		cifsd_err("can't do query dir for a file\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out2;
	}

	srch_flag = req->Flags;
	srch_ptr = smb_strndup_from_utf16(req->Buffer,
			le32_to_cpu(req->FileNameLength), 1,
			conn->local_nls);
	if (IS_ERR(srch_ptr)) {
		cifsd_debug("Search Pattern not found\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out2;
	} else
		cifsd_debug("Search pattern is %s\n", srch_ptr);

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		cifsd_err("Failed to allocate memory\n");
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		rc = -ENOMEM;
		kfree(srch_ptr);
		goto err_out2;
	}

	dirpath = d_path(&(dir_fp->filp->f_path), path, PATH_MAX);
	if (IS_ERR(dirpath)) {
		cifsd_err("Failed to get complete dir path\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = PTR_ERR(dirpath);
		goto err_out;
	}
	cifsd_debug("Directory name is %s\n", dirpath);

	if (!dir_fp->readdir_data.dirent) {
		dir_fp->readdir_data.dirent =
			(void *)__get_free_page(GFP_KERNEL);
		if (!dir_fp->readdir_data.dirent) {
			cifsd_err("Failed to allocate memory\n");
			rsp->hdr.Status = NT_STATUS_NO_MEMORY;
			rc = -ENOMEM;
			goto err_out;
		}
		dir_fp->readdir_data.used = 0;
		dir_fp->readdir_data.full = 0;
		dir_fp->dirent_offset = 0;
	}

	if (srch_flag & SMB2_REOPEN) {
		cifsd_debug("Reopen the directory\n");
		filp_close(dir_fp->filp, NULL);
		dir_fp->filp = filp_open(dirpath, O_RDONLY, 0666);
		if (!dir_fp->filp) {
			cifsd_debug("Reopening dir failed\n");
			rc = -EINVAL;
			goto err_out;
		}
		dir_fp->readdir_data.used = 0;
		dir_fp->dirent_offset = 0;
	}

	if (srch_flag & SMB2_RESTART_SCANS) {
		cifsd_debug("SMB2 RESTART SCANS\n");
		generic_file_llseek(dir_fp->filp, 0, SEEK_SET);
		dir_fp->readdir_data.used = 0;
		dir_fp->dirent_offset = 0;
	}

	if (srch_flag & SMB2_INDEX_SPECIFIED && le32_to_cpu(req->FileIndex)) {
		cifsd_debug("specified index\n");
		generic_file_llseek(dir_fp->filp, le32_to_cpu(req->FileIndex),
			SEEK_SET);
		dir_fp->readdir_data.used = 0;
		dir_fp->dirent_offset = le32_to_cpu(req->FileIndex);
	}

	r_data.dirent = dir_fp->readdir_data.dirent;
	memset(&d_info, 0, sizeof(struct cifsd_dir_info));
	d_info.bufptr = (char *)rsp->Buffer;
	d_info.out_buf_len = min_t(int, (SMBMaxBufSize + MAX_HEADER_SIZE(conn) -
		(get_rfc1002_length(rsp_org) + 4)),
		le32_to_cpu(req->OutputBufferLength)) -
		sizeof(struct smb2_query_directory_rsp);

	if (!(srch_flag & SMB2_RETURN_SINGLE_ENTRY)) {
		/*
		 * reserve dot and dotdot entries in head of buffer
		 * in first response
		 */
		rc = smb_populate_dot_dotdot_entries(conn,
			req->FileInformationClass, dir_fp, &d_info, srch_ptr);
		if (rc)
			goto err_out;
	}

	while (d_info.out_buf_len > 0) {
		if (dir_fp->dirent_offset >= dir_fp->readdir_data.used) {
			dir_fp->dirent_offset = 0;
			r_data.used = 0;
			r_data.full = 0;
			rc = smb_vfs_readdir(dir_fp->filp, smb_filldir,
					&r_data);
			if (rc < 0) {
				cifsd_debug("err : %d\n", rc);
				goto err_out;
			}

			dir_fp->readdir_data.used = r_data.used;
			dir_fp->readdir_data.full = r_data.full;
			if (!dir_fp->readdir_data.used) {
				free_page((unsigned long)
						(dir_fp->readdir_data.dirent));
				dir_fp->readdir_data.dirent = NULL;
				break;
			}

			de = (struct smb_dirent *)
				((char *)dir_fp->readdir_data.dirent);
		} else {
			de = (struct smb_dirent *)
				((char *)dir_fp->readdir_data.dirent +
				 dir_fp->dirent_offset);
		}

		reclen = ALIGN(sizeof(struct smb_dirent) + de->namelen,
				sizeof(__le64));
		dir_fp->dirent_offset += reclen;

		smb_kstat.kstat = &kstat;
		d_info.name = read_next_entry(smb_work, &smb_kstat, de,
			dirpath);
		if (IS_ERR(d_info.name)) {
			rc = PTR_ERR(d_info.name);
			cifsd_debug("Err while dirent read rc = %d\n", rc);
			rc = 0;
			continue;
		}

		/* dot and dotdot entries are already reserved */
		if (!strcmp(".", d_info.name) || !strcmp("..", d_info.name))
			continue;

		if (is_matched(d_info.name, srch_ptr)) {
			rc = smb2_populate_readdir_entry(conn,
				req->FileInformationClass, &d_info, &smb_kstat);
			if (rc)	{
				kfree(d_info.name);
				goto err_out;
			}

			/* server MUST only return the first search result */
			if (srch_flag & SMB2_RETURN_SINGLE_ENTRY) {
				kfree(d_info.name);
				break;
			}
		}

		kfree(d_info.name);

	}

	if (d_info.out_buf_len < 0)
		dir_fp->dirent_offset -= reclen;

	if (!d_info.data_count) {
		if (smb_work->next_smb2_rcv_hdr_off)
			rsp->hdr.Status = 0;
		else if (rsp->hdr.Status == 0) {
			dir_fp->dot_dotdot[0] = dir_fp->dot_dotdot[1] = 0;
			rsp->hdr.Status = STATUS_NO_MORE_FILES;
		}
		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(0);
		rsp->OutputBufferLength = cpu_to_le32(0);
		rsp->Buffer[0] = 0;
		inc_rfc1001_len(rsp_org, 9);
	} else {
		((FILE_DIRECTORY_INFO *)
		 ((char *)rsp->Buffer + d_info.num_entry))->NextEntryOffset = 0;

		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(72);
		rsp->OutputBufferLength = cpu_to_le32(d_info.data_count);
		inc_rfc1001_len(rsp_org, 8 + d_info.data_count);
	}

	kfree(path);
	kfree(srch_ptr);
	return 0;

err_out:
	cifsd_err("error while processing smb2 query dir rc = %d\n", rc);
	kfree(path);
	kfree(srch_ptr);

err_out2:
	if (dir_fp && dir_fp->readdir_data.dirent) {
		free_page((unsigned long)
			(dir_fp->readdir_data.dirent));
		dir_fp->readdir_data.dirent = NULL;
	}

	if (rsp->hdr.Status == 0)
		rsp->hdr.Status = NT_STATUS_NOT_IMPLEMENTED;
	smb2_set_err_rsp(smb_work);

	return 0;
}

#ifdef CONFIG_CIFSD_ACL
/**
 * smb2_get_info_sec() - handler for smb2 query info command
 * @smb_work:   smb work containing query info request buffer
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_get_info_sec(struct smb_work *smb_work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	struct file *filp;
	int rc = 0;
	struct cifs_ntsd *pntsd;
	struct inode *inode;
	int out_len;

	req = (struct smb2_query_info_req *)smb_work->buf;
	rsp = (struct smb2_query_info_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_info_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_info_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	}

	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	filp = fp->filp;
	inode = GET_FP_INODE(fp);

	pntsd = (struct cifs_ntsd *) rsp->Buffer;

	out_len = build_sec_desc(pntsd, le32_to_cpu(req->AdditionalInformation),
		inode);

	rsp->OutputBufferLength = out_len;
	inc_rfc1001_len(rsp_org, out_len);

	return rc;
}
#endif

/**
 * smb2_query_info() - handler for smb2 query info command
 * @smb_work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_query_info(struct smb_work *smb_work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp, *rsp_org;
	int rc = 0;

	req = (struct smb2_query_info_req *)smb_work->buf;
	rsp = (struct smb2_query_info_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_info_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_info_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);

	}

	cifsd_debug("GOT query info request\n");

	if (req->StructureSize != 41) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		cifsd_debug("GOT SMB2_O_INFO_FILE\n");
		rc = smb2_get_info_file(smb_work);
		break;
	case SMB2_O_INFO_FILESYSTEM:
		cifsd_debug("GOT SMB2_O_INFO_FILESYSTEM\n");
		rc = smb2_get_info_filesystem(smb_work);
		break;
#ifdef CONFIG_CIFSD_ACL
	case SMB2_O_INFO_SECURITY:
		cifsd_debug("GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_get_info_sec(smb_work);
		break;
#endif
	default:
		cifsd_debug("InfoType %d not supported yet\n", req->InfoType);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		rc = -EOPNOTSUPP;
	}

	if (rc < 0) {
		if (rc == -EACCES)
			rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		else if (rsp->hdr.Status == 0)
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		smb2_set_err_rsp(smb_work);

		cifsd_debug("error while processing smb2 query rc = %d\n",
			      rc);
		return rc;
	}
	rsp->StructureSize = cpu_to_le16(9);
	rsp->OutputBufferOffset = cpu_to_le16(72);
	inc_rfc1001_len(rsp_org, 8);
	return 0;
}

/**
 * smb2_close_pipe() - handler for closing IPC pipe
 * @smb_work:	smb work containing close request buffer
 *
 * Return:	0
 */
static int smb2_close_pipe(struct smb_work *smb_work)
{
	struct cifsd_pipe *pipe_desc;
	uint64_t id;
	int rc = 0;

	struct smb2_close_req *req = (struct smb2_close_req *)smb_work->buf;
	struct smb2_close_rsp *rsp = (struct smb2_close_rsp *)smb_work->rsp_buf;

	id = le64_to_cpu(req->VolatileFileId);
	pipe_desc = get_pipe_desc(smb_work->sess, id);
	if (!pipe_desc) {
		cifsd_debug("Pipe not opened or invalid in Pipe id\n");
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
		return 0;
	}
	rsp->StructureSize = cpu_to_le16(60);
	rsp->Flags = 0;
	rsp->Reserved = 0;
	rsp->CreationTime = 0;
	rsp->LastAccessTime = 0;
	rsp->LastWriteTime = 0;
	rsp->ChangeTime = 0;
	rsp->AllocationSize = 0;
	rsp->EndOfFile = 0;
	rsp->Attributes = 0;
	inc_rfc1001_len(rsp, 60);

	if (!rc) {
		rc = cifsd_sendmsg(smb_work->sess,
				CIFSD_KEVENT_DESTROY_PIPE,
				pipe_desc->pipe_type, 0, NULL, 0);
		if (rc)
			cifsd_err("failed to send event, err %d\n", rc);
	}

	rc = close_pipe_id(smb_work->sess, pipe_desc->pipe_type);
	if (rc < 0) {
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
	}

	return 0;
}

/**
 * smb2_close() - handler for smb2 close file command
 * @smb_work:	smb work containing close request buffer
 *
 * Return:	0
 */
int smb2_close(struct smb_work *smb_work)
{
	uint64_t volatile_id = -1, persistent_id = -1, sess_id;
	struct smb2_close_req *req = (struct smb2_close_req *)smb_work->buf;
	struct smb2_close_rsp *rsp = (struct smb2_close_rsp *)smb_work->rsp_buf;
	struct smb2_close_rsp *rsp_org;
	struct connection *conn = smb_work->conn;
	struct cifsd_file *fp;
	int err = 0;

	rsp_org = rsp;
	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_close_req *)((char *)req +
					smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_close_rsp *)((char *)rsp +
					smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 24) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (smb_work->tcon->share->is_pipe == true) {
		cifsd_debug("IPC pipe close request\n");
		return smb2_close_pipe(smb_work);
	}

	sess_id = le64_to_cpu(req->hdr.SessionId);
	if (le32_to_cpu(req->hdr.Flags) &
			SMB2_FLAGS_RELATED_OPERATIONS)
		sess_id = smb_work->cur_local_sess_id;

	smb_work->cur_local_sess_id = 0;
	if (check_session_id(conn, sess_id))
		smb_work->cur_local_sess_id = sess_id;
	else {
		rsp->hdr.Status = NT_STATUS_USER_SESSION_DELETED;
		if (le32_to_cpu(req->hdr.Flags) &
				SMB2_FLAGS_RELATED_OPERATIONS)
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		err = -EBADF;
		goto out;
	}

	if (smb_work->next_smb2_rcv_hdr_off &&
			le64_to_cpu(req->VolatileFileId) == -1) {
		if (!smb_work->cur_local_fid) {
			/* file open failed, return EINVAL */
			cifsd_debug("file open was failed\n");
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			err = -EBADF;
			goto out;
		} else if (smb_work->cur_local_fid == -1) {
			/* file already closed, return FILE_CLOSED */
			cifsd_debug("file already closed\n");
			rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
			err = -EBADF;
			goto out;
		} else {
			cifsd_debug("Compound request assigning stored FID = %llu: %llu\n",
					smb_work->cur_local_fid,
					smb_work->cur_local_pfid);
			volatile_id = smb_work->cur_local_fid;
			persistent_id = smb_work->cur_local_pfid;

			/* file closed, stored id is not valid anymore */
			smb_work->cur_local_fid = -1;
			smb_work->cur_local_pfid = -1;
		}
	} else {
		volatile_id = le64_to_cpu(req->VolatileFileId);
		persistent_id = le64_to_cpu(req->PersistentFileId);
	}
	cifsd_debug("volatile_id = %llu persistent_id = %llu\n",
			volatile_id, persistent_id);

	fp = get_fp(smb_work, volatile_id, persistent_id);
	if (!fp) {
		cifsd_debug("Invalid id for close: %llu\n", volatile_id);
		err = -EINVAL;
		goto out;
	}

	err = close_id(smb_work->sess, volatile_id, persistent_id);
	if (err)
		goto out;

	rsp->StructureSize = cpu_to_le16(60);
	rsp->Flags = 0;
	rsp->Reserved = 0;
	rsp->CreationTime = 0;
	rsp->LastAccessTime = 0;
	rsp->LastWriteTime = 0;
	rsp->ChangeTime = 0;
	rsp->AllocationSize = 0;
	rsp->EndOfFile = 0;
	rsp->Attributes = 0;

out:
	if (err) {
		if (rsp->hdr.Status == 0)
			rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		smb2_set_err_rsp(smb_work);
	} else {
		conn->stats.open_files_count--;
		inc_rfc1001_len(rsp_org, 60);
	}

	return 0;
}

/**
 * smb2_echo() - handler for smb2 echo(ping) command
 * @smb_work:	smb work containing echo request buffer
 *
 * Return:	0
 */
int smb2_echo(struct smb_work *smb_work)
{
	struct smb2_echo_req *req = (struct smb2_echo_req *)smb_work->buf;
	struct smb2_echo_rsp *rsp = (struct smb2_echo_rsp *)smb_work->rsp_buf;

	if (req->StructureSize != 4) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	inc_rfc1001_len(rsp, 4);

	return 0;
}

/**
 * smb2_get_ea() - handler for smb2 get extended attribute command
 * @smb_work:	smb work containing query info command buffer
 * @path:	path of file/dir to query info command
 * @rq:		get extended attribute request
 * @resp:	response buffer pointer
 * @resp_org:	base response buffer pointer in case of chained response
 *
 * Return:	0 on success, otherwise error
 */
int smb2_get_ea(struct smb_work *smb_work, struct path *path,
		void *rq, void *resp, void *resp_org)
{
	struct connection *conn = smb_work->conn;
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp_org, *rsp;
	struct smb2_ea_info *eainfo, *prev_eainfo;
	char *name, *ptr, *xattr_list = NULL, *buf;
	int rc, name_len, value_len, xattr_list_len;
	ssize_t buf_free_len, alignment_bytes, next_offset, rsp_data_cnt = 0;
	struct smb2_ea_info_req *ea_req = NULL;

	req = (struct smb2_query_info_req *)rq;
	rsp = (struct smb2_query_info_rsp *)resp;
	rsp_org = (struct smb2_query_info_rsp *)resp_org;

	/* single EA entry is requested with given user.* name */
	if (req->InputBufferLength)
		ea_req = (struct smb2_ea_info_req *)req->Buffer;
	else {
		/* need to send all EAs, if no specific EA is requested*/
		if (req->Flags & SL_RETURN_SINGLE_ENTRY)
			cifsd_debug("Ambiguous, all EAs are requested but"
				"need to send single EA entry in rsp"
				"flags 0x%x\n", le32_to_cpu(req->Flags));
	}

	buf_free_len = SMBMaxBufSize + MAX_HEADER_SIZE(conn) -
		(get_rfc1002_length(rsp_org) + 4)
		- sizeof(struct smb2_query_info_rsp);

	if (le32_to_cpu(req->OutputBufferLength) < buf_free_len)
		buf_free_len = le32_to_cpu(req->OutputBufferLength);

	rc = smb_vfs_listxattr(path->dentry, &xattr_list, XATTR_LIST_MAX);
	if (rc < 0) {
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		goto out;
	} else if (!rc) { /* there is no EA in the file */
		cifsd_debug("no ea data in the file\n");
		goto done;
	}
	xattr_list_len = rc;

	ptr = (char *)rsp->Buffer;
	eainfo = (struct smb2_ea_info *)ptr;
	prev_eainfo = eainfo;
	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {

		cifsd_debug("%s, len %zd\n", name, strlen(name));
		/*
		 * CIFS does not support EA other than user.* namespace,
		 * still keep the framework generic, to list other attrs
		 * in future.
		 */
		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			continue;

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], CREATION_TIME_PREFIX,
					CREATION_TIME_PREFIX_LEN))
			continue;

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
					STREAM_PREFIX_LEN))
			continue;

		if (req->InputBufferLength &&
				(strncmp(&name[XATTR_USER_PREFIX_LEN],
					 ea_req->name, ea_req->EaNameLength)))
			continue;

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN],
			FILE_ATTRIBUTE_PREFIX, FILE_ATTRIBUTE_PREFIX_LEN))
			continue;

		name_len = strlen(name);
		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			name_len -= XATTR_USER_PREFIX_LEN;

		ptr = (char *)(&eainfo->name + name_len + 1);
		buf_free_len -= (offsetof(struct smb2_ea_info, name) +
				name_len + 1);
		/* bailout if xattr can't fit in buf_free_len */
		value_len = smb_vfs_getxattr(path->dentry, name, &buf, 1);
		if (value_len <= 0) {
			rc = -ENOENT;
			rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
			goto out;
		}

		buf_free_len -= value_len;
		if (buf_free_len < 0) {
			kvfree(buf);
			break;
		}

		memcpy(ptr, buf, value_len);
		kvfree(buf);

		ptr += value_len;
		eainfo->Flags = 0;
		eainfo->EaNameLength = name_len;

		if (!strncmp(name, XATTR_USER_PREFIX,
			XATTR_USER_PREFIX_LEN))
			strncpy(eainfo->name, &name[XATTR_USER_PREFIX_LEN],
					name_len);
		else
			strncpy(eainfo->name, name, name_len);

		eainfo->name[name_len] = '\0';
		eainfo->EaValueLength = cpu_to_le16(value_len);
		next_offset = offsetof(struct smb2_ea_info, name) +
			name_len + 1 + value_len;

		/* align next xattr entry at 4 byte bundary */
		alignment_bytes = ((next_offset + 3) & ~3) - next_offset;
		if (alignment_bytes) {
			memset(ptr, '\0', alignment_bytes);
			ptr += alignment_bytes;
			next_offset += alignment_bytes;
			buf_free_len -= alignment_bytes;
		}
		eainfo->NextEntryOffset = cpu_to_le32(next_offset);
		prev_eainfo = eainfo;
		eainfo = (struct smb2_ea_info *)ptr;
		rsp_data_cnt += next_offset;

		if (req->InputBufferLength) {
			cifsd_debug("single entry requested\n");
			break;
		}
	}

	/* no more ea entries */
	prev_eainfo->NextEntryOffset = 0;
done:
	rc = 0;
	rsp->OutputBufferLength = cpu_to_le32(rsp_data_cnt);
	inc_rfc1001_len(rsp_org, rsp_data_cnt);
out:
	if (xattr_list)
		vfree(xattr_list);
	return rc;
}

/**
 * smb2_info_file_pipe() - handler for smb2 query info on IPC pipe
 * @smb_work:	smb work containing query info command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_get_info_file_pipe(struct smb_work *smb_work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp;
	struct smb2_file_standard_info *sinfo;
	struct cifsd_pipe *pipe_desc;
	uint64_t id;

	req = (struct smb2_query_info_req *)smb_work->buf;
	rsp = (struct smb2_query_info_rsp *)smb_work->rsp_buf;

	if (req->FileInfoClass != FILE_STANDARD_INFORMATION) {
		cifsd_debug("smb2_info_file_pipe for %u not supported\n",
			    req->FileInfoClass);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		return -EOPNOTSUPP;
	}

	cifsd_debug("smb2 query info IPC pipe\n");
	/* Windows can sometime send query file info request on
	 * pipe without opening it, checking error condition here */
	id = le64_to_cpu(req->VolatileFileId);
	pipe_desc = get_pipe_desc(smb_work->sess, id);
	if (!pipe_desc) {
		cifsd_debug("Pipe not opened or invalid in Pipe id\n");
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		return -EINVAL;
	}


	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;

	sinfo->AllocationSize = cpu_to_le64(4096);
	sinfo->EndOfFile = cpu_to_le64(0);
	sinfo->NumberOfLinks = cpu_to_le32(1);
	sinfo->DeletePending = 1;
	sinfo->Directory = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_standard_info));
	inc_rfc1001_len(rsp,
			sizeof(struct smb2_file_standard_info));

	return 0;
}

/**
 * buffer_check_err() - helper function to check buffer errors
 * @reqOutputBufferLength:	max buffer length expected in command response
 * @rsp:		query info response buffer contains output buffer length
 * @infoclass_size:	query info class response buffer size
 *
 * Return:	0 on success, otherwise error
 */
int buffer_check_err(int reqOutputBufferLength, struct smb2_query_info_rsp *rsp,
							int infoclass_size)
{
	if (reqOutputBufferLength < rsp->OutputBufferLength) {
		if (reqOutputBufferLength < infoclass_size) {
			cifsd_err("Invalid Buffer Size Requested\n");
			rsp->hdr.Status = NT_STATUS_INFO_LENGTH_MISMATCH;
			rsp->hdr.smb2_buf_length = cpu_to_be32(
						sizeof(struct smb2_hdr) - 4);
			return -EINVAL;
		} else{
			cifsd_err("Buffer Overflow\n");
			rsp->hdr.Status = NT_STATUS_BUFFER_OVERFLOW;
			rsp->hdr.smb2_buf_length = cpu_to_be32(
						sizeof(struct smb2_hdr) - 4
						+ reqOutputBufferLength);
			rsp->OutputBufferLength = cpu_to_le32(
							reqOutputBufferLength);
			return 0;
		}
	}
	return 0;
}

/**
 * smb2_get_info_file() - handler for smb2 query info command
 * @smb_work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_get_info_file(struct smb_work *smb_work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	struct connection *conn = smb_work->conn;
	int fileinfoclass = 0;
	struct file *filp;
	struct kstat stat;
	int rc = 0;
	int file_infoclass_size;
	struct inode *inode;

	req = (struct smb2_query_info_req *)smb_work->buf;
	rsp = (struct smb2_query_info_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_info_req *)((char *)req +
					smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_info_rsp *)((char *)rsp +
					smb_work->next_smb2_rsp_hdr_off);
	}

	if (smb_work->tcon->share->is_pipe == true) {
		/* smb2 info file called for pipe */
		return smb2_get_info_file_pipe(smb_work);
	}

	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	filp = fp->filp;
	inode = filp->f_path.dentry->d_inode;
	generic_fillattr(inode, &stat);
	fileinfoclass = req->FileInfoClass;

	switch (fileinfoclass) {
	case FILE_ACCESS_INFORMATION:
	{
		struct smb2_file_access_info *file_info;

		file_info = (struct smb2_file_access_info *)rsp->Buffer;

		file_info->AccessFlags = fp->daccess;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_access_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_access_info));
		file_infoclass_size = FILE_ACCESS_INFORMATION_SIZE;
		break;
	}
	case FILE_BASIC_INFORMATION:
	{
		struct smb2_file_all_info *basic_info;

		if (!(fp->daccess & (FILE_READ_ATTRIBUTES_LE |
			FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to read the attributes : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}
		basic_info = (struct smb2_file_all_info *)rsp->Buffer;

		basic_info->CreationTime = cpu_to_le64(fp->create_time);
		basic_info->LastAccessTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.atime));
		basic_info->LastWriteTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.mtime));
		basic_info->ChangeTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.ctime));
		basic_info->Attributes = fp->fattr;
		basic_info->Pad1 = 0;
		rsp->OutputBufferLength =
			cpu_to_le32(offsetof(struct smb2_file_all_info,
						AllocationSize));
		inc_rfc1001_len(rsp_org, offsetof(struct smb2_file_all_info,
					AllocationSize));
		file_infoclass_size = FILE_BASIC_INFORMATION_SIZE;
		break;
	}
	case FILE_STANDARD_INFORMATION:
	{
		struct smb2_file_standard_info *sinfo;
		unsigned int delete_pending;

		sinfo = (struct smb2_file_standard_info *)rsp->Buffer;
		delete_pending = fp->f_mfp->m_flags & S_DEL_ON_CLS;

		sinfo->AllocationSize = cpu_to_le64(inode->i_blocks);
		sinfo->EndOfFile = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.size);
		sinfo->NumberOfLinks = FP_INODE(fp)->i_nlink - delete_pending;
		sinfo->DeletePending = delete_pending;
		sinfo->Directory = S_ISDIR(stat.mode) ? 1 : 0;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_standard_info));
		inc_rfc1001_len(rsp_org,
				sizeof(struct smb2_file_standard_info));
		file_infoclass_size = FILE_STANDARD_INFORMATION_SIZE;
		break;
	}
	case FILE_ALIGNMENT_INFORMATION:
	{
		struct smb2_file_alignment_info *file_info;

		file_info = (struct smb2_file_alignment_info *)rsp->Buffer;
		file_info->AlignmentRequirement = 0;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_alignment_info));
		inc_rfc1001_len(rsp_org,
				sizeof(struct smb2_file_alignment_info));
		file_infoclass_size = FILE_ALIGNMENT_INFORMATION_SIZE;
		break;
	}
	case FILE_ALL_INFORMATION:
	{
		struct smb2_file_all_info *file_info;
		char *filename;
		int uni_filename_len;
		unsigned int delete_pending;

		if (!(fp->daccess & (FILE_READ_ATTRIBUTES_LE |
			FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to read the attributes : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}

		filename = convert_to_nt_pathname(fp->filename,
			smb_work->tcon->share->path);
		if (!filename)
			return -ENOMEM;
		cifsd_debug("filename = %s\n", filename);
		delete_pending = fp->f_mfp->m_flags & S_DEL_ON_CLS;
		file_info = (struct smb2_file_all_info *)rsp->Buffer;

		file_info->CreationTime = cpu_to_le64(fp->create_time);
		file_info->LastAccessTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.atime));
		file_info->LastWriteTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.mtime));
		file_info->ChangeTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.ctime));
		file_info->Attributes = fp->fattr;
		file_info->Pad1 = 0;
		file_info->AllocationSize = cpu_to_le64(inode->i_blocks);
		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.size);
		file_info->NumberOfLinks =
			FP_INODE(fp)->i_nlink - delete_pending;
		file_info->DeletePending = delete_pending;
		file_info->Directory = S_ISDIR(stat.mode) ? 1 : 0;
		file_info->Pad2 = 0;
		file_info->IndexNumber = cpu_to_le64(stat.ino);
		file_info->EASize = 0;
		file_info->AccessFlags = cpu_to_le32(0x00000080);
		file_info->CurrentByteOffset = cpu_to_le64(filp->f_pos);
		file_info->Mode = fp->coption;
		file_info->AlignmentRequirement = 0;
		uni_filename_len = smbConvertToUTF16(
				(__le16 *)file_info->FileName,
				filename, PATH_MAX,
				conn->local_nls, 0);

		uni_filename_len *= 2;
		file_info->FileNameLength = cpu_to_le32(uni_filename_len);

		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_all_info) +
				    uni_filename_len - 1);
		inc_rfc1001_len(rsp_org, le32_to_cpu(rsp->OutputBufferLength));
		file_infoclass_size = FILE_ALL_INFORMATION_SIZE;

		kfree(filename);
		break;
	}
	case FILE_ALTERNATE_NAME_INFORMATION:
	{
		struct smb2_file_alt_name_info *file_info;
		char *filename;
		int uni_filename_len;

		filename = (char *)FP_FILENAME(fp);

		file_info = (struct smb2_file_alt_name_info *)rsp->Buffer;
		uni_filename_len = smb_get_shortname(conn, filename,
				file_info->FileName);
		file_info->FileNameLength = cpu_to_le32(uni_filename_len);

		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_alt_name_info) +
				    uni_filename_len);
		inc_rfc1001_len(rsp_org, le32_to_cpu(rsp->OutputBufferLength));
		file_infoclass_size = FILE_ALTERNATE_NAME_INFORMATION_SIZE;

		break;
	}
	case FILE_STREAM_INFORMATION:
	{
		struct smb2_file_stream_info *file_info;
		char *stream_name, *xattr_list = NULL, *stream_buf;
		char *stream_type;
		struct path *path = &filp->f_path;
		ssize_t xattr_list_len;
		int nbytes = 0, streamlen, next;

		file_info = (struct smb2_file_stream_info *)rsp->Buffer;

		xattr_list_len = smb_vfs_listxattr(path->dentry, &xattr_list,
				XATTR_LIST_MAX);
		if (xattr_list_len < 0) {
			goto out;
		} else if (!xattr_list_len) {
			cifsd_debug("empty xattr in the file\n");
			goto out;
		}

		for (stream_name = xattr_list;
			stream_name - xattr_list < xattr_list_len;
			stream_name += strlen(stream_name) + 1) {
			cifsd_debug("%s, len %zd\n",
					stream_name, strlen(stream_name));

			if (strncmp(&stream_name[XATTR_USER_PREFIX_LEN],
				STREAM_PREFIX, STREAM_PREFIX_LEN))
				continue;

			streamlen = strlen(stream_name) - (XATTR_USER_PREFIX_LEN
				+ STREAM_PREFIX_LEN);

			if (fp->stream.type == 2) {
				streamlen += 17;
				stream_type = "$INDEX_ALLOCATION";
			} else {
				streamlen += 5;
				stream_type = "$DATA";
			}

			stream_buf = kmalloc(streamlen + 1, GFP_KERNEL);
			if (!stream_buf)
				break;

			streamlen = snprintf(stream_buf, streamlen + 1,
				":%s:%s", &stream_name[XATTR_NAME_STREAM_LEN],
				stream_type);

			file_info = (struct smb2_file_stream_info *)
				&rsp->Buffer[nbytes];
			streamlen  = smbConvertToUTF16(
					(__le16 *)file_info->StreamName,
					stream_buf,
					streamlen, conn->local_nls, 0);
			streamlen *= 2;
			kfree(stream_buf);
			file_info->StreamNameLength = cpu_to_le32(streamlen);
			file_info->StreamSize =
				cpu_to_le64(streamlen);
			file_info->StreamAllocationSize =
				cpu_to_le64(XATTR_SIZE_MAX);

			next = sizeof(struct smb2_file_stream_info)
				+ streamlen;
			nbytes += next;
			file_info->NextEntryOffset = cpu_to_le32(next);
		}

		/* last entry offset should be 0 */
		file_info->NextEntryOffset = 0;
out:
		if (xattr_list)
			vfree(xattr_list);

		rsp->OutputBufferLength = nbytes;
		inc_rfc1001_len(rsp_org, cpu_to_le32(rsp->OutputBufferLength));
		file_infoclass_size = FILE_STREAM_INFORMATION_SIZE;
		break;
	}
	case FILE_INTERNAL_INFORMATION:
	{
		struct smb2_file_internal_info *file_info;

		file_info = (struct smb2_file_internal_info *)rsp->Buffer;

		file_info->IndexNumber = cpu_to_le64(stat.ino);
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_internal_info));
		inc_rfc1001_len(rsp_org,
				sizeof(struct smb2_file_internal_info));
		file_infoclass_size = FILE_INTERNAL_INFORMATION_SIZE;
		break;
	}
	case FILE_NETWORK_OPEN_INFORMATION:
	{
		struct smb2_file_ntwrk_info *file_info;

		if (!(fp->daccess & (FILE_READ_ATTRIBUTES_LE |
			FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to read the attributes : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}

		file_info = (struct smb2_file_ntwrk_info *)rsp->Buffer;

		file_info->CreationTime = cpu_to_le64(fp->create_time);
		file_info->LastAccessTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.atime));
		file_info->LastWriteTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.mtime));
		file_info->ChangeTime =
			cpu_to_le64(cifs_UnixTimeToNT(stat.ctime));
		file_info->Attributes = fp->fattr;
		file_info->AllocationSize = cpu_to_le64(inode->i_blocks);
		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.size);
		file_info->Reserved = cpu_to_le32(0);
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_ntwrk_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_ntwrk_info));
		file_infoclass_size = FILE_NETWORK_OPEN_INFORMATION_SIZE;
		break;
	}
	case FILE_EA_INFORMATION:
	{
		struct smb2_file_ea_info *file_info;
		file_info = (struct smb2_file_ea_info *)rsp->Buffer;

		file_info->EASize = 0;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_ea_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_ea_info));
		file_infoclass_size = FILE_EA_INFORMATION_SIZE;
		break;
	}
	case FILE_FULL_EA_INFORMATION:
	{
		if (!(fp->daccess & (FILE_READ_EA_LE | FILE_GENERIC_READ_LE |
			FILE_MAXIMAL_ACCESS_LE | FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to read the extented attributes : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}

		rc = smb2_get_ea(smb_work, &filp->f_path, req, rsp, rsp_org);
		file_infoclass_size = FILE_FULL_EA_INFORMATION_SIZE;
		if (rc < 0)
			return rc;
		break;
	}
	case FILE_POSITION_INFORMATION:
	{
		struct smb2_file_pos_info *file_info;
		file_info = (struct smb2_file_pos_info *)rsp->Buffer;

		file_info->CurrentByteOffset = cpu_to_le64(filp->f_pos);
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_pos_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_pos_info));
		file_infoclass_size = FILE_POSITION_INFORMATION_SIZE;
		break;
	}
	case FILE_MODE_INFORMATION:
	{
		struct smb2_file_mode_info *file_info;

		file_info = (struct smb2_file_mode_info *)rsp->Buffer;
		file_info->Mode = fp->coption & FILE_MODE_INFO_MASK;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_mode_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_mode_info));
		file_infoclass_size = FILE_MODE_INFORMATION_SIZE;
		break;
	}
	case FILE_COMPRESSION_INFORMATION:
	{
		struct smb2_file_comp_info *file_info;

		file_info = (struct smb2_file_comp_info *)rsp->Buffer;
		file_info->CompressedFileSize = cpu_to_le64(stat.blocks << 9);
		file_info->CompressionFormat = COMPRESSION_FORMAT_NONE;
		file_info->CompressionUnitShift = 0;
		file_info->ChunkShift = 0;
		file_info->ClusterShift = 0;
		memset(&file_info->Reserved[0], 0, 3);

		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_comp_info));
		inc_rfc1001_len(rsp_org, sizeof(struct smb2_file_comp_info));
		file_infoclass_size = FILE_COMPRESSION_INFORMATION_SIZE;
		break;
	}
	case FILE_ATTRIBUTE_TAG_INFORMATION:
	{
		struct smb2_file_attr_tag_info *file_info;

		file_info = (struct smb2_file_attr_tag_info *)rsp->Buffer;
		file_info->FileAttributes = fp->fattr;
		file_info->ReparseTag = 0;
		rsp->OutputBufferLength =
			cpu_to_le32(sizeof(struct smb2_file_attr_tag_info));
		inc_rfc1001_len(rsp_org,
			sizeof(struct smb2_file_attr_tag_info));
		file_infoclass_size = FILE_ATTRIBUTE_TAG_INFORMATION_SIZE;
		break;
	}

	default:
		cifsd_debug("fileinfoclass %d not supported yet\n",
			fileinfoclass);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		return -EOPNOTSUPP;
	}
	rc = buffer_check_err(req->OutputBufferLength, rsp,
					file_infoclass_size);
	return rc;
}

/**
 * fsTypeSearch() - get fs type string from fs magic number
 * @fs_type:		array of fs types
 * @magic_number:	match the magic number for fs type
 * @SIZE:		size of fs type table
 *
 * Return:	index of fs type
 */
inline int fsTypeSearch(struct fs_type_info fs_type[],
					int magic_number, int SIZE)
{
	int i;
	int dfault = 40;	/* setting MSDOS as default files system*/
	for (i = 0; i < SIZE; i++) {
		if (fs_type[i].magic_number == magic_number)
			return i;
	}
	return dfault;
}

/**
 * smb2_get_info_filesystem() - handler for smb2 query info command
 * @smb_work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 * TODO: need to implement STATUS_INFO_LENGTH_MISMATCH error handling
 */
int smb2_get_info_filesystem(struct smb_work *smb_work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp, *rsp_org;
	struct connection *conn = smb_work->conn;
	int fsinfoclass = 0;
	struct kstatfs stfs;
	struct cifsd_share *share;
	struct path path;
	int rc = 0, len;
	int fs_infoclass_size = 0;
	int fs_type_idx;

	req = (struct smb2_query_info_req *)smb_work->buf;
	rsp = (struct smb2_query_info_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_info_req *)((char *)req +
					smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_info_rsp *)((char *)rsp +
					smb_work->next_smb2_rsp_hdr_off);
	}

	share = find_matching_share(req->hdr.Id.SyncId.TreeId);
	if (!share)
		return -ENOENT;

	rc = smb_kern_path(share->path, LOOKUP_FOLLOW, &path, 0);

	if (rc) {
		cifsd_err("cannot create vfs path\n");
		rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
		return rc;
	}

	rc = vfs_statfs(&path, &stfs);
	if (rc) {
		cifsd_err("cannot do stat of path %s\n", share->path);
		rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
		path_put(&path);
		return rc;
	}

	fsinfoclass = req->FileInfoClass;

	switch (fsinfoclass) {
	case FS_DEVICE_INFORMATION:
		{
			FILE_SYSTEM_DEVICE_INFO *fs_info;

			fs_info = (FILE_SYSTEM_DEVICE_INFO *)rsp->Buffer;

			fs_info->DeviceType = cpu_to_le32(stfs.f_type);
			fs_info->DeviceCharacteristics = (0x00000020);
			rsp->OutputBufferLength = cpu_to_le32(8);
			inc_rfc1001_len(rsp_org, 8);
			fs_infoclass_size = FS_DEVICE_INFORMATION_SIZE;
			break;
		}
	case FS_ATTRIBUTE_INFORMATION:
		{
			FILE_SYSTEM_ATTRIBUTE_INFO *fs_info;

			fs_info = (FILE_SYSTEM_ATTRIBUTE_INFO *)rsp->Buffer;
			fs_info->Attributes = cpu_to_le32(0x0001002f);
			fs_info->MaxPathNameComponentLength =
				cpu_to_le32(stfs.f_namelen);
			fs_type_idx = fsTypeSearch(fs_type, stfs.f_type,
							FS_TYPE_SUPPORT_SIZE);
			len = smbConvertToUTF16((__le16 *)
							fs_info->FileSystemName,
					fs_type[fs_type_idx].fs_name, PATH_MAX,
							conn->local_nls, 0);
			len = len * 2;
			fs_info->FileSystemNameLen = len;
			rsp->OutputBufferLength = cpu_to_le32(sizeof
					(FILE_SYSTEM_ATTRIBUTE_INFO) -2 + len);
			inc_rfc1001_len(rsp_org,
				sizeof(FILE_SYSTEM_ATTRIBUTE_INFO) - 2 + len);
			fs_infoclass_size = FS_ATTRIBUTE_INFORMATION_SIZE;
			break;
		}
	case FS_VOLUME_INFORMATION:
		{
			FILE_SYSTEM_VOL_INFO *fsvinfo;
			fsvinfo = (FILE_SYSTEM_VOL_INFO *)(rsp->Buffer);
			fsvinfo->VolumeCreationTime = 0;
			/* Taking dummy value of serial number*/
			fsvinfo->SerialNumber = cpu_to_le32(0xbc3ac512);
			len = smbConvertToUTF16((__le16 *)fsvinfo->VolumeLabel,
				share->sharename, PATH_MAX,
					conn->local_nls, 0);
			len = len * 2;
			fsvinfo->VolumeLabelSize = cpu_to_le32(len);
			fsvinfo->Reserved = 0;
			rsp->OutputBufferLength =
				cpu_to_le32(sizeof(FILE_SYSTEM_VOL_INFO)
								- 2 + len);
			inc_rfc1001_len(rsp_org, sizeof(FILE_SYSTEM_VOL_INFO)
								+ len - 2);
			fs_infoclass_size = FS_VOLUME_INFORMATION_SIZE;
			break;
		}
	case FS_SIZE_INFORMATION:
		{
			FILE_SYSTEM_INFO *fs_size_info;
			unsigned short logical_sector_size;

			fs_size_info = (FILE_SYSTEM_INFO *)(rsp->Buffer);
			logical_sector_size =
				get_logical_sector_size(path.dentry->d_inode);

			fs_size_info->TotalAllocationUnits =
						cpu_to_le64(stfs.f_blocks);
			fs_size_info->FreeAllocationUnits =
						cpu_to_le64(stfs.f_bfree);
			fs_size_info->SectorsPerAllocationUnit =
						cpu_to_le32(stfs.f_bsize >> 9);
			fs_size_info->BytesPerSector =
				cpu_to_le32(logical_sector_size);
			rsp->OutputBufferLength = cpu_to_le32(24);
			inc_rfc1001_len(rsp_org, 24);
			fs_infoclass_size = FS_SIZE_INFORMATION_SIZE;
			break;
		}
	case FS_FULL_SIZE_INFORMATION:
		{
			struct smb2_fs_full_size_info *fs_fullsize_info;
			unsigned short logical_sector_size;

			fs_fullsize_info =
				(struct smb2_fs_full_size_info *)(rsp->Buffer);
			logical_sector_size =
				get_logical_sector_size(path.dentry->d_inode);

			fs_fullsize_info->TotalAllocationUnits =
						cpu_to_le64(stfs.f_blocks);
			fs_fullsize_info->CallerAvailableAllocationUnits =
						cpu_to_le64(stfs.f_bavail);
			fs_fullsize_info->ActualAvailableAllocationUnits =
						cpu_to_le64(stfs.f_bfree);
			fs_fullsize_info->SectorsPerAllocationUnit =
						cpu_to_le32(stfs.f_bsize >> 9);
			fs_fullsize_info->BytesPerSector =
				cpu_to_le32(logical_sector_size);
			rsp->OutputBufferLength = cpu_to_le32(32);
			inc_rfc1001_len(rsp_org, 32);
			fs_infoclass_size = FS_FULL_SIZE_INFORMATION_SIZE;
			break;
		}
	case FS_OBJECT_ID_INFORMATION:
		{
			unsigned char objid[16];
			struct object_id_info *obj_info;

			obj_info = (struct object_id_info *)(rsp->Buffer);

			if (smb_work->sess->usr->passkey[0]) {
				smb_E_md4hash(smb_work->sess->usr->passkey,
					objid, conn->local_nls);
				memcpy(obj_info->objid, objid, 16);
			} else
				memset(obj_info->objid, 0, 16);

			obj_info->extended_info.magic = EXTENDED_INFO_MAGIC;
			obj_info->extended_info.version = 1;
			obj_info->extended_info.release = 1;
			obj_info->extended_info.rel_date = 0;
			memcpy(obj_info->extended_info.version_string,
				"1.1.0", STRING_LENGTH);
			rsp->OutputBufferLength = cpu_to_le32(64);
			inc_rfc1001_len(rsp_org, 64);
			fs_infoclass_size = FS_OBJECT_ID_INFORMATION_SIZE;
			break;
		}
	case FS_SECTOR_SIZE_INFORMATION:
		{
			struct smb3_fs_ss_info *ss_info;
			struct smb2_fs_sector_size fs_ss;

			ss_info = (struct smb3_fs_ss_info *)(rsp->Buffer);
			get_smb2_sector_size(path.dentry->d_inode, &fs_ss);

			ss_info->LogicalBytesPerSector =
				cpu_to_le32(fs_ss.logical_sector_size);
			ss_info->PhysicalBytesPerSectorForAtomicity =
				cpu_to_le32(fs_ss.physical_sector_size);
			ss_info->PhysicalBytesPerSectorForPerf =
				cpu_to_le32(fs_ss.optimal_io_size);
			ss_info->FSEffPhysicalBytesPerSectorForAtomicity =
				cpu_to_le32(fs_ss.optimal_io_size);
			ss_info->Flags = cpu_to_le32(
				SSINFO_FLAGS_ALIGNED_DEVICE |
				SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
			ss_info->ByteOffsetForSectorAlignment = 0;
			ss_info->ByteOffsetForPartitionAlignment = 0;
			rsp->OutputBufferLength = cpu_to_le32(28);
			inc_rfc1001_len(rsp_org, 28);
			fs_infoclass_size = FS_SECTOR_SIZE_INFORMATION_SIZE;
			break;
		}
	case FS_CONTROL_INFORMATION:
		{
			/*
			 * TODO : The current implementation is based on
			 * test result with win7(NTFS) server. It's need to
			 * modify this to get valid Quota values
			 * from Linux kernel
			 */

			 struct smb2_fs_control_info *fs_control_info;

			 fs_control_info =
				(struct smb2_fs_control_info *)(rsp->Buffer);
			 fs_control_info->FreeSpaceStartFiltering = 0;
			 fs_control_info->FreeSpaceThreshold = 0;
			 fs_control_info->FreeSpaceStopFiltering = 0;
			 fs_control_info->DefaultQuotaThreshold =
				0xFFFFFFFFFFFFFFFF;
			 fs_control_info->DefaultQuotaLimit =
				0xFFFFFFFFFFFFFFFF;
			 fs_control_info->Padding = 0;
			 rsp->OutputBufferLength = cpu_to_le32(48);
			 inc_rfc1001_len(rsp_org, 48);
			 fs_infoclass_size = FS_CONTROL_INFORMATION_SIZE;

			 break;
		}
	default:
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		path_put(&path);
		return -1;
	}
	rc = buffer_check_err(req->OutputBufferLength, rsp,
					fs_infoclass_size);
	path_put(&path);
	return rc;

}

#ifdef CONFIG_CIFSD_ACL
/**
 * smb2_set_info_sec() - handler for smb2 set info command
 * @smb_work:   smb work containing set info command buffer
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_set_info_sec(struct smb_work *smb_work)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp;
	struct cifsd_file *fp;
	struct cifsd_sess *sess = smb_work->sess;
	uint64_t id, pid;
	int rc = 0;
	struct file *filp;
	struct inode *inode;
	struct cifs_ntsd *pntsd;
	struct cifsd_fattr fattr;
	int addition_info;

	req = (struct smb2_set_info_req *)smb_work->buf;
	rsp = (struct smb2_set_info_rsp *)smb_work->rsp_buf;

	id = le64_to_cpu(req->VolatileFileId);
	pid = le64_to_cpu(req->PersistentFileId);
	fp = get_fp(smb_work, id, pid);
	if (!fp) {
		cifsd_debug("Invalid id for close: %llu\n", id);
		return -ENOENT;
	}

	filp = fp->filp;
	inode = filp->f_path.dentry->d_inode;

	cifsd_err("Update SMB2_CREATE_SD_BUFFER\n");
	pntsd = (struct cifs_ntsd *) req->Buffer;

	addition_info = le32_to_cpu(req->AdditionalInformation);

	if ((addition_info & (OWNER_SECINFO | GROUP_SECINFO)) &&
			(!(fp->daccess & FILE_WRITE_OWNER_LE))) {
		rc = -EPERM;
		goto out;
	}

	if ((addition_info & DACL_SECINFO) &&
			(!(fp->daccess & FILE_WRITE_DAC_LE))) {
		rc = -EPERM;
		goto out;
	}

	parse_sec_desc(pntsd, le32_to_cpu(req->BufferLength), &fattr);

	cifsd_fattr_to_inode(inode, &fattr);
out:
	return rc;
}
#endif

/**
 * smb2_set_info() - handler for smb2 set info command handler
 * @smb_work:	smb work containing set info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_set_info(struct smb_work *smb_work)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp;
	int rc = 0;

	req = (struct smb2_set_info_req *)smb_work->buf;
	rsp = (struct smb2_set_info_rsp *)smb_work->rsp_buf;

	if (le16_to_cpu(req->StructureSize) != 33) {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		return 0;
	}
	cifsd_debug("%s: Recieved set info request\n", __func__);
	rsp->StructureSize = cpu_to_le16(33);

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		cifsd_debug("GOT SMB2_O_INFO_FILE\n");
		rc = smb2_set_info_file(smb_work);
		break;
#ifdef CONFIG_CIFSD_ACL
	case SMB2_O_INFO_SECURITY:
		cifsd_debug("GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_set_info_sec(smb_work);
		break;
#endif
	default:
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
	}

	if (rc < 0) {
		if (rc == -EACCES)
			rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		else if (rc == -EINVAL)
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		else if (rc == -ESHARE)
			rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
		else if (rc == -ENOENT)
			rsp->hdr.Status = NT_STATUS_OBJECT_NAME_INVALID;
		else if (rsp->hdr.Status == 0)
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		smb2_set_err_rsp(smb_work);

		cifsd_debug("error while processing smb2 query rc = %d\n",
			      rc);
	}

	rsp->StructureSize = cpu_to_le16(2);
	inc_rfc1001_len(rsp, 2);
	return rc;
}

/**
 * smb2_set_ea() - handler for setting extended attributes using set
 *		info command
 * @eabuf:	set info command buffer
 * @path:	dentry path for get ea
 *
 * Return:	0 on success, otherwise error
 */
int smb2_set_ea(struct smb2_ea_info *eabuf, struct path *path)
{
	char *attr_name = NULL, *value;
	int rc = 0;
	int next = 0;

	do {
		cifsd_debug("name : <%s>, name_len : %u, value_len : %u, next : %u\n",
				eabuf->name, eabuf->EaNameLength,
				le16_to_cpu(eabuf->EaValueLength),
				le32_to_cpu(eabuf->NextEntryOffset));

		if (eabuf->EaNameLength >
				(XATTR_NAME_MAX - XATTR_USER_PREFIX_LEN))
			return -EINVAL;

		attr_name = kmalloc(XATTR_NAME_MAX + 1, GFP_KERNEL);
		if (!attr_name) {
			rc = -ENOMEM;
			goto out;
		}

		memcpy(attr_name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);
		memcpy(&attr_name[XATTR_USER_PREFIX_LEN], eabuf->name,
				eabuf->EaNameLength);
		attr_name[XATTR_USER_PREFIX_LEN + eabuf->EaNameLength] = '\0';
		value = (char *)&eabuf->name + eabuf->EaNameLength + 1;

		if (!eabuf->EaValueLength) {
			rc = smb_find_cont_xattr(path, attr_name,
				XATTR_USER_PREFIX_LEN + eabuf->EaNameLength,
				NULL, 0);

			/* delete the EA only when it exits */
			if (rc > 0) {
				rc = smb_vfs_remove_xattr(path, attr_name);

				if (rc < 0) {
					cifsd_err("remove xattr failed(%d)\n",
						rc);
					break;
				}
			}

			/* if the EA doesn't exist, just do nothing. */
			rc = 0;
		} else {
			rc = smb_vfs_setxattr(NULL, path, attr_name, value,
				le16_to_cpu(eabuf->EaValueLength), 0);

			if (rc < 0) {
				cifsd_err("smb_vfs_setxattr is failed(%d)\n",
					rc);
				break;
			}
		}

		next = le32_to_cpu(eabuf->NextEntryOffset);
		eabuf = (struct smb2_ea_info *)((char *)eabuf + next);
	} while (next != 0);

out:
	kfree(attr_name);
	return rc;
}

/**
 * smb2_create_link() - handler for creating hardlink using smb2
 *		set info command
 * @smb_work:	smb work containing set info command buffer
 * @filp:	file pointer of source file
 *
 * Return:	0 on success, otherwise error
 */
int smb2_create_link(struct smb_work *smb_work, struct file *filp)
{
	struct smb2_set_info_req *req = NULL;
	struct smb2_set_info_rsp *rsp = NULL;
	struct smb2_file_link_info *file_info = NULL;
	char *link_name = NULL, *target_name = NULL, *pathname = NULL;
	struct path path;
	bool file_present = true;
	int rc;

	req = (struct smb2_set_info_req *)smb_work->buf;
	rsp = (struct smb2_set_info_rsp *)smb_work->rsp_buf;
	file_info = (struct smb2_file_link_info *)req->Buffer;

	cifsd_debug("setting FILE_LINK_INFORMATION\n");
	pathname = kmalloc(PATH_MAX, GFP_NOFS);
	if (!pathname) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		return -ENOMEM;
	}

	link_name = smb2_get_name(file_info->FileName,
			le32_to_cpu(file_info->FileNameLength),
			smb_work);
	if (IS_ERR(link_name) || S_ISDIR(file_inode(filp)->i_mode)) {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto out;
	}

	cifsd_debug("link name is %s\n", link_name);
	target_name = d_path(&filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(target_name)) {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = PTR_ERR(target_name);
		goto out;
	}

	cifsd_debug("target name is %s\n", target_name);
	rc = smb_kern_path(link_name, 0, &path, 0);
	if (rc)
		file_present = false;
	else
		path_put(&path);

	if (file_info->ReplaceIfExists) {
		if (file_present) {
			rc = smb_vfs_remove_file(link_name);
			if (rc) {
				rsp->hdr.Status =
					NT_STATUS_INVALID_PARAMETER;
				cifsd_debug("cannot delete %s\n",
						link_name);
				goto out;
			}
		}
	} else {
		if (file_present) {
			rsp->hdr.Status =
				NT_STATUS_OBJECT_NAME_COLLISION;
			cifsd_debug("link already exists\n");
			goto out;
		}
	}

	rc = smb_vfs_link(target_name, link_name);
	if (rc)
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;

out:
	if (!IS_ERR(link_name))
		smb_put_name(link_name);
	kfree(pathname);
	return rc;
}

/**
 * smb2_rename() - handler for rename using smb2 setinfo command
 * @smb_work:	smb work containing set info command buffer
 * @filp:	file pointer of source file
 * @old_fid:	file id of source file
 *
 * Return:	0 on success, otherwise error
 */
int smb2_rename(struct smb_work *smb_work, struct file *filp, int old_fid)
{
	struct smb2_set_info_req *req = NULL;
	struct smb2_set_info_rsp *rsp = NULL;
	struct smb2_file_rename_info *file_info = NULL;
	char *new_name = NULL, *abs_oldname = NULL, *old_name = NULL;
	char *tmp_name = NULL, *pathname = NULL;
	struct path path;
	bool file_present = true;
	int rc;

	req = (struct smb2_set_info_req *)smb_work->buf;
	rsp = (struct smb2_set_info_rsp *)smb_work->rsp_buf;
	file_info = (struct smb2_file_rename_info *)req->Buffer;

	cifsd_debug("setting FILE_RENAME_INFO\n");
	pathname = kmalloc(PATH_MAX, GFP_NOFS);
	if (!pathname) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		return -ENOMEM;
	}

	abs_oldname = d_path(&filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(abs_oldname)) {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = PTR_ERR(old_name);
		goto out;
	}
	old_name = strrchr(abs_oldname, '/');
	if (old_name && old_name[1] != '\0')
		old_name++;
	else {
		cifsd_debug("can't get last component in path %s\n",
				abs_oldname);
		rc = -ENOENT;
		goto out;
	}

	new_name = smb2_get_name(file_info->FileName,
			le32_to_cpu(file_info->FileNameLength),
			smb_work);
	if (IS_ERR(new_name)) {
		rc = PTR_ERR(new_name);
		goto out;
	}


	if (strchr(new_name, ':')) {
		int s_type;
		char *xattr_stream_name, *stream_name = NULL;
		size_t xattr_stream_size;
		int len;

		rc = parse_stream_name(new_name, &stream_name, &s_type);
		if (rc < 0)
			goto out;

		len = strlen(new_name);
		if (new_name[len - 1] != '/') {
			cifsd_err("not allow base filename in rename\n");
			rc = -ESHARE;
			goto out;
		}

		xattr_stream_size = construct_xattr_stream_name(stream_name,
			&xattr_stream_name);

		rc = smb_store_cont_xattr(&filp->f_path, xattr_stream_name,
				NULL, 0);
		if (rc < 0) {
			cifsd_err("failed to store stream name in xattr, rc :%d\n",
					rc);
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto out;
		}

		goto out;
	}

	tmp_name = kmalloc(PATH_MAX, GFP_NOFS);
	if (!tmp_name) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		rc = -ENOMEM;
		goto out;
	}
	strncpy(tmp_name, new_name, strlen(new_name) + 1);
	cifsd_debug("new name %s\n", new_name);
	rc = smb_kern_path(tmp_name, 0, &path, 1);
	if (rc)
		file_present = false;
	else
		path_put(&path);

	if (file_info->ReplaceIfExists) {
		if (file_present) {
			rc = smb_vfs_remove_file(tmp_name);
			if (rc) {
				if (rc == -ENOTEMPTY)
					rsp->hdr.Status =
						NT_STATUS_DIRECTORY_NOT_EMPTY;
				else
					rsp->hdr.Status =
						NT_STATUS_INVALID_PARAMETER;
				cifsd_debug("cannot delete %s, rc %d\n",
						new_name, rc);
				goto out;
			}
		}
	} else {
		if (file_present &&
				strncmp(old_name, path.dentry->d_name.name,
					strlen(old_name))) {
			rc = -EEXIST;
			rsp->hdr.Status =
				NT_STATUS_OBJECT_NAME_COLLISION;
			cifsd_debug("cannot rename already existing file\n");
			goto out;
		}
	}

	rc = smb_vfs_rename(smb_work->sess, NULL, new_name, old_fid);
	if (rc == -ESHARE)
		rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
	else if (rc == -ENOTEMPTY)
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
	else if (rc < 0)
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;

out:
	kfree(pathname);
	kfree(tmp_name);
	if (!IS_ERR(new_name))
		smb_put_name(new_name);
	return rc;
}

/**
 * smb2_set_info_file() - handler for smb2 set info command
 * @smb_work:	smb work containing set info command buffer
 *
 * Return:	0 on success, otherwise error
 * TODO: need to implement an error handling for STATUS_INFO_LENGTH_MISMATCH
 */
int smb2_set_info_file(struct smb_work *smb_work)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp;
	struct cifsd_file *fp;
	struct cifsd_sess *sess = smb_work->sess;
	uint64_t id, pid;
	int rc = 0;
	struct file *filp;
	struct inode *inode;

	req = (struct smb2_set_info_req *)smb_work->buf;
	rsp = (struct smb2_set_info_rsp *)smb_work->rsp_buf;

	id = le64_to_cpu(req->VolatileFileId);
	pid = le64_to_cpu(req->PersistentFileId);
	fp = get_fp(smb_work, id, pid);
	if (!fp) {
		cifsd_debug("Invalid id for close: %llu\n", id);
		return -ENOENT;
	}

	filp = fp->filp;
	inode = filp->f_path.dentry->d_inode;

	switch (req->FileInfoClass) {
	case FILE_BASIC_INFORMATION:
	{
		struct smb2_file_all_info *file_info;
		struct iattr attrs;
		struct iattr temp_attrs;

		if (!(fp->daccess & (FILE_WRITE_ATTRIBUTES_LE |
			FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write the attributes : 0x%x\n",
				fp->daccess);
			rc = -EACCES;
			goto out;
		}

		file_info = (struct smb2_file_all_info *)req->Buffer;
		attrs.ia_valid = 0;

		if (le64_to_cpu(file_info->CreationTime)) {
			struct cifsd_share *share = smb_work->tcon->share;

			fp->create_time = le64_to_cpu(file_info->CreationTime);
			if (get_attr_store_dos(&share->config.attr)) {
				rc = smb_store_cont_xattr(&fp->filp->f_path,
					XATTR_NAME_CREATION_TIME,
					(void *)&fp->create_time,
					CREATIOM_TIME_LEN);
				if (rc) {
					cifsd_debug("failed to set creation time\n");
					rsp->hdr.Status =
						NT_STATUS_INVALID_PARAMETER;
					smb2_set_err_rsp(smb_work);
					goto out;
				}
			}
		}

		if (le64_to_cpu(file_info->LastAccessTime)) {
			attrs.ia_atime = cifs_NTtimeToUnix(
					le64_to_cpu(file_info->LastAccessTime));
			attrs.ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);
		}

		if (le64_to_cpu(file_info->ChangeTime)) {
			temp_attrs.ia_ctime = attrs.ia_ctime =
			cifs_NTtimeToUnix(le64_to_cpu(file_info->ChangeTime));
			attrs.ia_valid |= ATTR_CTIME;
		} else
			temp_attrs.ia_ctime = inode->i_ctime;

		if (le64_to_cpu(file_info->LastWriteTime)) {
			attrs.ia_mtime = cifs_NTtimeToUnix(
					le64_to_cpu(file_info->LastWriteTime));
			attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
		}

		if (le32_to_cpu(file_info->Attributes)) {
			unsigned long *config_attr;

			if (!S_ISDIR(file_inode(filp)->i_mode)
				&& file_info->Attributes == ATTR_DIRECTORY) {
				cifsd_err("can't change a file to a directory\n");
				rc = -EINVAL;
				goto out;
			}

			config_attr = &smb_work->tcon->share->config.attr;
			fp->fattr = file_info->Attributes;
			if (get_attr_store_dos(config_attr)) {
				rc = smb_store_cont_xattr(&fp->filp->f_path,
						XATTR_NAME_FILE_ATTRIBUTE,
						(void *)&fp->fattr,
						FILE_ATTRIBUTE_LEN);

				if (rc)
					cifsd_debug("failed to store file attribute in EA\n");

				rc = 0;
			}
		}

		/*
		 * HACK : set ctime here to avoid ctime changed
		 * when file_info->ChangeTime is zero.
		 */
		 attrs.ia_ctime = temp_attrs.ia_ctime;
		 attrs.ia_valid |= ATTR_CTIME;

		if (attrs.ia_valid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 37)
			struct dentry *dentry = fp->filp->f_path.dentry;
			struct inode *inode = dentry->d_inode;
#else
			struct inode *inode = FP_INODE(fp);
#endif
			if (IS_IMMUTABLE(inode) || IS_APPEND(inode)) {
				rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
				smb2_set_err_rsp(smb_work);
				rc = -EPERM;
				goto out;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 37)
			rc = setattr_prepare(dentry, &attrs);
#else
			rc = inode_change_ok(inode, &attrs);
#endif
			if (rc) {
				rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
				smb2_set_err_rsp(smb_work);
				goto out;
			}

			setattr_copy(inode, &attrs);
			mark_inode_dirty(inode);
		}
		break;
	}
	case FILE_ALLOCATION_INFORMATION:
	{
		/*
		 * TODO : It's working fine only when store dos attributes
		 * is not yes. need to implement a logic which works
		 * properly with any smb.conf option
		 */

		struct smb2_file_alloc_info *file_alloc_info;
		loff_t alloc_size;
		unsigned short logical_sector_size;

		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
			FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write data : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}

		file_alloc_info = (struct smb2_file_alloc_info *)req->Buffer;
		alloc_size = le64_to_cpu(file_alloc_info->AllocationSize);
		logical_sector_size = get_logical_sector_size(inode);

		if (alloc_size > inode->i_blocks) {
			rc = smb_vfs_alloc_size(sess->conn, fp,
				alloc_size*logical_sector_size);

			if (rc) {
				cifsd_err("smb_vfs_alloc_size is failed : %d\n",
					rc);
				return rc;
			}
		} else {
			rc = smb_vfs_truncate(sess, NULL, id,
				alloc_size*logical_sector_size);

			if (rc) {
				cifsd_err("truncate failed! fid %llu err %d\n",
					id, rc);
				return rc;
			}
		}

		break;
	}
	case FILE_END_OF_FILE_INFORMATION:
	{
		struct smb2_file_eof_info *file_eof_info;
		loff_t newsize;

		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
			FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write data : 0x%x\n",
				fp->daccess);
			rc = -EACCES;
			goto out;
		}

		file_eof_info = (struct smb2_file_eof_info *)req->Buffer;

		newsize = le64_to_cpu(file_eof_info->EndOfFile);

		if (newsize != i_size_read(inode)) {
			rc = smb_vfs_truncate(sess, NULL, id, newsize);
			if (rc) {
				cifsd_err("truncate failed! fid %llu err %d\n",
						id, rc);
				if (rc == -EAGAIN)
					rsp->hdr.Status =
						NT_STATUS_FILE_LOCK_CONFLICT;
				else
					rsp->hdr.Status =
						NT_STATUS_INVALID_HANDLE;
				smb2_set_err_rsp(smb_work);
				goto out;
			}

			cifsd_debug("fid %llu truncated to newsize %lld\n",
					id, newsize);
		}
		break;
	}
	case FILE_RENAME_INFORMATION:
	{
		struct cifsd_file *parent_fp;

		if (!(fp->daccess & (FILE_DELETE_LE |
			FILE_MAXIMAL_ACCESS_LE | FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to delete : 0x%x\n", fp->daccess);
			rc = -EACCES;
			goto out;
		}

		if (fp->is_stream)
			goto next;

		parent_fp = find_fp_using_inode(PARENT_INODE(fp));
		if (parent_fp) {
			if (parent_fp->daccess & FILE_DELETE_LE) {
				cifsd_err("parent dir is opened with delete access\n");
				rc = -ESHARE;
				goto out;
			}

			if (!(parent_fp->saccess & FILE_SHARE_DELETE_LE)) {
				cifsd_err("parent dir is opened without share delete\n");
				rc = -ESHARE;
				goto out;
			}
		}
next:
		rc = smb2_rename(smb_work, filp, id);
		break;
	}
	case FILE_LINK_INFORMATION:
		rc = smb2_create_link(smb_work, fp->filp);
		break;
	case FILE_DISPOSITION_INFORMATION:
	{
		struct smb2_file_disposition_info *file_info;

		if (!(fp->daccess & (FILE_DELETE_LE |
			FILE_MAXIMAL_ACCESS_LE | FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to delete : 0x%x\n", fp->daccess);
			rc = -EACCES;
			goto out;
		}

		file_info = (struct smb2_file_disposition_info *)req->Buffer;
		if (file_info->DeletePending) {
			if (S_ISDIR(fp->filp->f_path.dentry->
				d_inode->i_mode) && !is_dir_empty(fp)) {
				rsp->hdr.Status = NT_STATUS_DIRECTORY_NOT_EMPTY;
				rc = -1;
			} else
				fp->f_mfp->m_flags |= S_DEL_ON_CLS;
		} else
			fp->f_mfp->m_flags &= ~S_DEL_ON_CLS;
		break;
	}
	case FILE_FULL_EA_INFORMATION:
	{
		struct smb2_set_info_req *req;

		if (!(fp->daccess & (FILE_WRITE_EA_LE | FILE_GENERIC_WRITE_LE |
			FILE_MAXIMAL_ACCESS_LE | FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write the extended attributes : 0x%x\n",
				fp->daccess);
			rc = -EACCES;
			goto out;
		}

		req = (struct smb2_set_info_req *)smb_work->buf;
		rc = smb2_set_ea((struct smb2_ea_info *)(req->Buffer),
			&filp->f_path);
		break;
	}
	case FILE_POSITION_INFORMATION:
	{
		struct smb2_file_pos_info *file_info;
		loff_t current_byte_offset;
		unsigned short sector_size;

		file_info = (struct smb2_file_pos_info *)req->Buffer;
		current_byte_offset = le64_to_cpu(file_info->CurrentByteOffset);
		sector_size = get_logical_sector_size(inode);

		if (current_byte_offset < 0 ||
			(fp->coption == FILE_NO_INTERMEDIATE_BUFFERING_LE &&
			current_byte_offset & (sector_size-1))) {
			cifsd_err("CurrentByteOffset is not valid : %llu\n",
				current_byte_offset);
			rc = -EINVAL;
			goto out;
		}

		filp->f_pos = current_byte_offset;

		break;
	}
	case FILE_MODE_INFORMATION:
	{
		struct smb2_file_mode_info *file_info;
		__le32 mode;

		file_info = (struct smb2_file_mode_info *)req->Buffer;
		mode = file_info->Mode;

		if ((mode & (~FILE_MODE_INFO_MASK)) ||
			(mode & FILE_SYNCHRONOUS_IO_ALERT_LE
			&& mode & FILE_SYNCHRONOUS_IO_NONALERT_LE)) {
			cifsd_err("Mode is not valid : 0x%x\n",
				le32_to_cpu(mode));
			rc = -EINVAL;
			goto out;
		}

		/*
		 * TODO : need to implement consideration for
		 * FILE_SYNCHRONOUS_IO_ALERT and FILE_SYNCHRONOUS_IO_NONALERT
		 */
		smb_vfs_set_fadvise(fp->filp, le32_to_cpu(mode));
		fp->coption = mode;

		break;
	}
	default:
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		cifsd_err("Unimplemented Fileinfoclass :%d\n",
			    req->FileInfoClass);
		rc = -1;
	}

out:
	return rc;
}

/**
 * smb2_read_pipe() - handler for smb2 read from IPC pipe
 * @smb_work:	smb work containing read IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_read_pipe(struct smb_work *smb_work)
{
	int ret = 0, nbytes = 0;
	char *data_buf;
	uint64_t id;
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp;
	unsigned int read_len;
	struct cifsd_uevent *ev;
	struct cifsd_pipe *pipe_desc;
	req = (struct smb2_read_req *)smb_work->buf;
	rsp = (struct smb2_read_rsp *)smb_work->rsp_buf;

	read_len = le32_to_cpu(req->Length);
	data_buf = (char *)(rsp->Buffer);
	id = le64_to_cpu(req->VolatileFileId);
	pipe_desc = get_pipe_desc(smb_work->sess, id);

	if (!pipe_desc) {
		cifsd_debug("Pipe not opened or invalid in Pipe id\n");
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
		return ret;
	}

	ret = cifsd_sendmsg(smb_work->sess, CIFSD_KEVENT_READ_PIPE,
			pipe_desc->pipe_type, 0, NULL, read_len);
	if (ret)
		cifsd_err("failed to send event, err %d\n", ret);
	else {
		ev = &pipe_desc->ev;
		nbytes = ev->u.r_pipe_rsp.read_count;
		if (ev->error < 0 || !nbytes) {
			cifsd_err("Pipe data not present\n");
			rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
			smb2_set_err_rsp(smb_work);
			return -EINVAL;
		}

		memcpy(data_buf, pipe_desc->rsp_buf, nbytes);
		smb_work->sess->ev_state = NETLINK_REQ_COMPLETED;
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 80;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	inc_rfc1001_len(rsp, 16 + nbytes);
	return 0;
}

/**
 * smb2_read() - handler for smb2 read from file
 * @smb_work:	smb work containing read command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_read(struct smb_work *smb_work)
{
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	loff_t offset;
	size_t length, mincount;
	ssize_t nbytes = 0;
	int err = 0;

	req = (struct smb2_read_req *)smb_work->buf;
	rsp = (struct smb2_read_rsp *)smb_work->rsp_buf;

	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_read_req *)((char *)req +
					smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_read_rsp *)((char *)rsp +
					smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 49) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (smb_work->tcon->share->is_pipe == true) {
		cifsd_debug("IPC pipe read request\n");
		return smb2_read_pipe(smb_work);
	}

	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
			le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	offset = le32_to_cpu(req->Offset);
	length = le32_to_cpu(req->Length);
	mincount = le32_to_cpu(req->MinimumCount);

	if (length > CIFS_DEFAULT_IOSIZE) {
		cifsd_debug("read size(%zu) exceeds max size(%u)\n",
				length, CIFS_DEFAULT_IOSIZE);
		cifsd_debug("limiting read size to max size(%u)\n",
				CIFS_DEFAULT_IOSIZE);
		length = CIFS_DEFAULT_IOSIZE;
	}

	cifsd_debug("filename %s, offset %lld, len %zu\n", FP_FILENAME(fp),
		offset, length);
	nbytes = smb_vfs_read(smb_work->sess, fp,
			&smb_work->rdata_buf, length, &offset);
	if (nbytes < 0) {
		err = nbytes;
		goto out;
	}

	if ((nbytes == 0 && length != 0) || nbytes < mincount) {
		kvfree(smb_work->rdata_buf);
		smb_work->rdata_buf = NULL;
		rsp->hdr.Status = NT_STATUS_END_OF_FILE;
		smb2_set_err_rsp(smb_work);
		return 0;
	}

	cifsd_debug("nbytes %zu, offset %lld mincount %zu\n",
						nbytes, offset, mincount);

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 80;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	inc_rfc1001_len(rsp_org, 16);
	smb_work->rrsp_hdr_size = get_rfc1002_length(rsp_org) + 4;
	smb_work->rdata_cnt = nbytes;
	inc_rfc1001_len(rsp_org, nbytes);
	return 0;

out:
	if (err) {
		if (err == -EISDIR)
			rsp->hdr.Status = NT_STATUS_INVALID_DEVICE_REQUEST;
		else if (err == -EAGAIN)
			rsp->hdr.Status = NT_STATUS_FILE_LOCK_CONFLICT;
		else if (err == -ENOENT)
			rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		else if (err == -EACCES)
			rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		else if (err == -ESHARE)
			rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
		else
			rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;

		smb2_set_err_rsp(smb_work);
	}
	return err;
}

/**
 * smb2_write_pipe() - handler for smb2 write on IPC pipe
 * @smb_work:	smb work containing write IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_write_pipe(struct smb_work *smb_work)
{
	struct smb2_write_req *req;
	struct smb2_write_rsp *rsp;
	uint64_t id = 0;
	int err = 0, ret = 0;
	char *data_buf;
	size_t length;
	struct cifsd_uevent *ev;
	struct cifsd_pipe *pipe_desc;

	req = (struct smb2_write_req *)smb_work->buf;
	rsp = (struct smb2_write_rsp *)smb_work->rsp_buf;

	length = le32_to_cpu(req->Length);
	id = le64_to_cpu(req->VolatileFileId);
	pipe_desc = get_pipe_desc(smb_work->sess, id);

	if (!pipe_desc) {
		cifsd_debug("Pipe not opened or invalid in Pipe id\n");
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
		return ret;
	}

	if (le16_to_cpu(req->DataOffset) ==
			(offsetof(struct smb2_write_req, Buffer) - 4)) {
		data_buf = (char *)&req->Buffer[0];
	} else {
		if ((le16_to_cpu(req->DataOffset) > get_rfc1002_length(req)) ||
				(le16_to_cpu(req->DataOffset) +
				 length > get_rfc1002_length(req))) {
			cifsd_err("invalid write data offset %u, smb_len %u\n",
					le16_to_cpu(req->DataOffset),
					get_rfc1002_length(req));
			err = -EINVAL;
			goto out;
		}

		data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
				le16_to_cpu(req->DataOffset));
	}

	ret = cifsd_sendmsg(smb_work->sess, CIFSD_KEVENT_WRITE_PIPE,
			pipe_desc->pipe_type, length, data_buf, 0);
	if (ret)
		cifsd_err("failed to send event, err %d\n", ret);
	else {
		ev = &pipe_desc->ev;
		ret = ev->error;
		if (ret == -EOPNOTSUPP) {
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
			smb2_set_err_rsp(smb_work);
			return ret;
		} else if (ret) {
			rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
			smb2_set_err_rsp(smb_work);
			return ret;
		}

		length = ev->u.w_pipe_rsp.write_count;
		smb_work->sess->ev_state = NETLINK_REQ_COMPLETED;
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 0;
	rsp->Reserved = 0;
	rsp->DataLength = le32_to_cpu(length);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	inc_rfc1001_len(rsp, 16);
	return 0;
out:
	if (err) {
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
	}

	return err;
}

/**
 * smb2_write() - handler for smb2 write from file
 * @smb_work:	smb work containing write command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_write(struct smb_work *smb_work)
{
	struct smb2_write_req *req;
	struct smb2_write_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	loff_t offset;
	size_t length;
	ssize_t nbytes;
	char *data_buf;
	bool writethrough = false;
	int err = 0;

	req = (struct smb2_write_req *)smb_work->buf;
	rsp = (struct smb2_write_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_write_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_write_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 49) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (smb_work->tcon->share->is_pipe == true) {
		cifsd_debug("IPC pipe write request\n");
		return smb2_write_pipe(smb_work);
	}

	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
			le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	offset = le64_to_cpu(req->Offset);
	length = le32_to_cpu(req->Length);

	if (le16_to_cpu(req->DataOffset) ==
			(offsetof(struct smb2_write_req, Buffer) - 4)) {
		data_buf = (char *)&req->Buffer[0];
	} else {
		if ((le16_to_cpu(req->DataOffset) > get_rfc1002_length(req)) ||
				(le16_to_cpu(req->DataOffset) +
				 length > get_rfc1002_length(req))) {
			cifsd_err("invalid write data offset %u, smb_len %u\n",
					le16_to_cpu(req->DataOffset),
					get_rfc1002_length(req));
			err = -EINVAL;
			goto out;
		}

		data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
				le16_to_cpu(req->DataOffset));
	}

	cifsd_debug("flags %u\n", le32_to_cpu(req->Flags));
	if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_THROUGH)
		writethrough = true;

	cifsd_debug("filename %s, offset %lld, len %zu\n", FP_FILENAME(fp),
		offset, length);
	err = smb_vfs_write(smb_work->sess, fp, data_buf, length, &offset,
			writethrough, &nbytes);
	if (err < 0)
		goto out;

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 0;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	inc_rfc1001_len(rsp_org, 16);
	return 0;

out:
	if (err == -EAGAIN)
		rsp->hdr.Status = NT_STATUS_FILE_LOCK_CONFLICT;
	else if (err == -ENOSPC || err == -EFBIG)
		rsp->hdr.Status = NT_STATUS_DISK_FULL;
	else if (err == -ENOENT)
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
	else if (err == -EACCES)
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
	else if (err == -ESHARE)
		rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
	else
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;

	smb2_set_err_rsp(smb_work);
	return err;
}

/**
 * smb2_flush() - handler for smb2 flush file - fsync
 * @smb_work:	smb work containing flush command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_flush(struct smb_work *smb_work)
{
	struct smb2_flush_req *req;
	struct smb2_flush_rsp *rsp;
	int err;

	req = (struct smb2_flush_req *)smb_work->buf;
	rsp = (struct smb2_flush_rsp *)smb_work->rsp_buf;

	if (req->StructureSize != 24) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	cifsd_debug("SMB2_FLUSH called for fid %llu\n",
			le64_to_cpu(req->VolatileFileId));

	err = smb_vfs_fsync(smb_work->sess,
		le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (err)
		goto out;

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	inc_rfc1001_len(rsp, 4);
	return 0;

out:
	if (err) {
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(smb_work);
	}

	return err;
}

/**
 * smb2_cancel() - handler for smb2 cancel command
 * @smb_work:	smb work containing cancel command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_cancel(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_hdr *hdr = (struct smb2_hdr *)smb_work->buf;
	struct smb2_hdr *work_hdr;
	struct smb_work *work = NULL;
	struct list_head *tmp;
	int canceled = 0;

	cifsd_debug("smb2 cancel called on mid %llu\n", hdr->MessageId);

	if (hdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {
		spin_lock(&conn->request_lock);
		list_for_each(tmp, &conn->async_requests) {
			work = list_entry(tmp, struct smb_work, request_entry);
			work_hdr = (struct smb2_hdr *)work->buf;
			if (work->async->async_id ==
				le64_to_cpu(hdr->Id.AsyncId)) {
				cifsd_debug("smb2 with AsyncId %llu cancelled command = 0x%x\n",
					hdr->Id.AsyncId, work_hdr->Command);
				if (work->async->async_status == ASYNC_PROG)
					work->async->async_status =
						ASYNC_CANCEL;
				break;
			}
		}
		spin_unlock(&conn->request_lock);
	} else {
		spin_lock(&conn->request_lock);
		list_for_each(tmp, &conn->requests) {
			work = list_entry(tmp, struct smb_work, request_entry);
			work_hdr = (struct smb2_hdr *)work->buf;
			if (work_hdr->MessageId == hdr->MessageId) {
				cifsd_debug("smb2 with mid %llu cancelled command = 0x%x\n",
					hdr->MessageId, work_hdr->Command);
				canceled = 1;
				break;
			}
		}
		spin_unlock(&conn->request_lock);

		if (canceled)
			cancel_work_sync(&work->work);
	}

	/* For SMB2_CANCEL command itself send no response*/
	smb_work->send_no_response = 1;

	return 0;

}

struct file_lock *smb_flock_init(struct file *f)
{
	struct file_lock *fl;

	fl = locks_alloc_lock();
	if (!fl)
		goto out;

	locks_init_lock(fl);

	fl->fl_owner = f;
	fl->fl_pid = current->tgid;
	fl->fl_file = f;
	fl->fl_flags = FL_POSIX;
	fl->fl_ops = NULL;
	fl->fl_lmops = NULL;

out:
	return fl;
}

static struct cifsd_lock *smb2_lock_init(struct file_lock *flock,
	unsigned int cmd, int flags, struct list_head *lock_list)
{
	struct cifsd_lock *lock;

	lock = kzalloc(sizeof(struct cifsd_lock), GFP_KERNEL);
	if (!lock)
		return NULL;

	lock->cmd = cmd;
	lock->fl = flock;
	lock->start = flock->fl_start;
	lock->end = flock->fl_end;
	lock->flags = flags;
	if (lock->start == lock->end)
		lock->zero_len = 1;
	INIT_LIST_HEAD(&lock->llist);
	INIT_LIST_HEAD(&lock->glist);
	INIT_LIST_HEAD(&lock->flist);
	list_add_tail(&lock->llist, lock_list);

	return lock;
}

/**
 * smb2_lock() - handler for smb2 file lock command
 * @smb_work:	smb work containing lock command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_lock(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_lock_req *req;
	struct smb2_lock_rsp *rsp;
	struct smb2_lock_element *lock_ele;
	struct cifsd_file *fp = NULL;
	struct file_lock *flock = NULL;
	struct file *filp = NULL;
	int lock_count;
	int flags = 0;
	unsigned int cmd = 0;
	int err = 0, i;
	uint64_t lock_length;
	struct cifsd_lock *smb_lock = NULL, *cmp_lock, *tmp;
	int nolock = 0;
	LIST_HEAD(lock_list);
	LIST_HEAD(rollback_list);
	int prior_lock = 0;

	req = (struct smb2_lock_req *)smb_work->buf;
	rsp = (struct smb2_lock_rsp *)smb_work->rsp_buf;

	if (le16_to_cpu(req->StructureSize) != 48) {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		goto out2;
	}

	cifsd_debug("Recieved lock request\n");
	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		cifsd_debug("Invalid file id for lock : %llu\n",
				le64_to_cpu(req->VolatileFileId));
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		goto out2;
	}

	filp = fp->filp;
	lock_count = le16_to_cpu(req->LockCount);
	lock_ele = req->locks;

	cifsd_debug("lock count is %d\n", lock_count);
	if (!lock_count)  {
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		goto out2;
	}

	for (i = 0; i < lock_count; i++) {
		flags = le32_to_cpu(lock_ele[i].Flags);

		flock = smb_flock_init(filp);
		if (!flock) {
			rsp->hdr.Status = NT_STATUS_LOCK_NOT_GRANTED;
			goto out;
		}

		/* Checking for wrong flag combination during lock request*/
		switch (flags) {
		case SMB2_LOCKFLAG_SHARED:
			cifsd_debug("received shared request\n");
			if (!(filp->f_mode & FMODE_READ)) {
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
				goto out;
			}
			cmd = F_SETLKW;
			flock->fl_type = F_RDLCK;
			flock->fl_flags |= FL_SLEEP;
			break;
		case SMB2_LOCKFLAG_EXCLUSIVE:
			cifsd_debug("received exclusive request\n");
			if (!(filp->f_mode & FMODE_WRITE)) {
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
				goto out;
			}
			cmd = F_SETLKW;
			flock->fl_type = F_WRLCK;
			flock->fl_flags |= FL_SLEEP;
			break;
		case SMB2_LOCKFLAG_SHARED|SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
			cifsd_debug("received shared & fail immediately request\n");
			if (!(filp->f_mode & FMODE_READ)) {
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
				goto out;
			}
			cmd = F_SETLK;
			flock->fl_type = F_RDLCK;
			break;
		case SMB2_LOCKFLAG_EXCLUSIVE|SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
			cifsd_debug("received exclusive & fail immediately request\n");
			if (!(filp->f_mode & FMODE_WRITE)) {
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
				goto out;
			}
			cmd = F_SETLK;
			flock->fl_type = F_WRLCK;
			break;
		case SMB2_LOCKFLAG_UNLOCK:
			cifsd_debug("received unlock request\n");
			flock->fl_type = F_UNLCK;
			cmd = 0;
			break;
		default:
			flags = 0;
		}

		flock->fl_start = le64_to_cpu(lock_ele[i].Offset);
		if (flock->fl_start > OFFSET_MAX) {
			cifsd_err("Invalid lock range requested\n");
			rsp->hdr.Status = NT_STATUS_INVALID_LOCK_RANGE;
			goto out;
		}

		lock_length = le64_to_cpu(lock_ele[i].Length);
		if (lock_length > 0) {
			if ((loff_t)lock_length >
					OFFSET_MAX - flock->fl_start) {
				cifsd_err("Invalid lock range requested\n");
				rsp->hdr.Status = NT_STATUS_INVALID_LOCK_RANGE;
				goto out;
			}
		} else
			lock_length = 0;

		flock->fl_end = flock->fl_start + lock_length;

		if (flock->fl_end < flock->fl_start) {
			cifsd_err("the end offset(%llx) is smaller than the start offset(%llx)\n",
				flock->fl_end, flock->fl_start);
			rsp->hdr.Status = NT_STATUS_INVALID_LOCK_RANGE;
			goto out;
		}

		/* Check conflict locks in one request */
		list_for_each_entry(cmp_lock, &lock_list, llist) {
			if (cmp_lock->fl->fl_start <= flock->fl_start &&
					cmp_lock->fl->fl_end >= flock->fl_end) {
				if (cmp_lock->fl->fl_type != F_UNLCK &&
					flock->fl_type != F_UNLCK) {
					cifsd_err("conflict two locks in one request\n");
					rsp->hdr.Status =
						NT_STATUS_INVALID_PARAMETER;
					goto out;
				}
			}
		}

		smb_lock = smb2_lock_init(flock, cmd, flags, &lock_list);
		if (!smb_lock) {
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {
		if (!(smb_lock->flags & SMB2_LOCKFLAG_MASK)) {
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}

		if ((prior_lock & (SMB2_LOCKFLAG_EXCLUSIVE |
				SMB2_LOCKFLAG_SHARED) &&
			smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) ||
			(prior_lock == SMB2_LOCKFLAG_UNLOCK &&
				 !(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK))) {
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}

		prior_lock = smb_lock->flags;

		if (!(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) &&
			!(smb_lock->flags & SMB2_LOCKFLAG_FAIL_IMMEDIATELY))
			goto no_check_gl;

		nolock = 1;
		/* check locks in global list */
		list_for_each_entry(cmp_lock, &global_lock_list, glist) {
			if (file_inode(cmp_lock->fl->fl_file) !=
				file_inode(smb_lock->fl->fl_file))
				continue;

			if (smb_lock->fl->fl_type == F_UNLCK) {
				if (cmp_lock->fl->fl_file ==
					smb_lock->fl->fl_file &&
					cmp_lock->start == smb_lock->start &&
					cmp_lock->end == smb_lock->end &&
					!cmp_lock->work) {
					nolock = 0;
					locks_free_lock(cmp_lock->fl);
					list_del(&cmp_lock->glist);
					list_del(&cmp_lock->flist);
					kfree(cmp_lock);
					break;
				}
				continue;
			}

			if (cmp_lock->fl->fl_file == smb_lock->fl->fl_file) {
				if (smb_lock->flags & SMB2_LOCKFLAG_SHARED)
					continue;
			} else {
				if (cmp_lock->flags & SMB2_LOCKFLAG_SHARED)
					continue;
			}

			/* check zero byte lock range */
			if (cmp_lock->zero_len && !smb_lock->zero_len &&
				cmp_lock->start > smb_lock->start &&
				cmp_lock->start < smb_lock->end) {
				cifsd_err("previous lock conflict with zero byte lock range\n");
				rsp->hdr.Status = NT_STATUS_LOCK_NOT_GRANTED;
					goto out;
			}

			if (smb_lock->zero_len && !cmp_lock->zero_len &&
				smb_lock->start > cmp_lock->start &&
				smb_lock->start < cmp_lock->end) {
				cifsd_err("current lock conflict with zero byte lock range\n");
				rsp->hdr.Status = NT_STATUS_LOCK_NOT_GRANTED;
					goto out;
			}

			if (((cmp_lock->start <= smb_lock->start &&
				cmp_lock->end > smb_lock->start) ||
				(cmp_lock->start < smb_lock->end &&
				cmp_lock->end >= smb_lock->end)) &&
				!cmp_lock->zero_len && !smb_lock->zero_len) {
				cifsd_err("Not allow lock operation on exclusive lock range\n");
				rsp->hdr.Status =
					NT_STATUS_LOCK_NOT_GRANTED;
				goto out;
			}
		}

		if (smb_lock->fl->fl_type == F_UNLCK && nolock) {
			cifsd_err("Try to unlock nolocked range\n");
			rsp->hdr.Status = NT_STATUS_RANGE_NOT_LOCKED;
			goto out;
		}

no_check_gl:
		if (smb_lock->zero_len) {
			err = 0;
			goto skip;
		}

		flock = smb_lock->fl;
		list_del(&smb_lock->llist);
retry:
		err = smb_vfs_lock(filp, smb_lock->cmd, flock);
skip:
		if (flags & SMB2_LOCKFLAG_UNLOCK) {
			if (!err)
				cifsd_debug("File unlocked\n");
			else if (err == -ENOENT) {
				rsp->hdr.Status = NT_STATUS_NOT_LOCKED;
				goto out;
			}
			locks_free_lock(flock);
			kfree(smb_lock);
		} else {
			if (err == FILE_LOCK_DEFERRED) {
				spinlock_t *rq_lock = &conn->request_lock;
				struct async_info *async;

				cifsd_debug("would have to wait for getting"
						" lock\n");
				smb_lock->work = smb_work;
				list_add_tail(&smb_lock->glist,
					&global_lock_list);
				list_add(&smb_lock->llist, &rollback_list);
				list_add(&smb_lock->flist, &fp->lock_list);

				smb2_send_interim_resp(smb_work);
wait:
				err = wait_event_interruptible_timeout(
						flock->fl_wait,	!flock->fl_next,
						msecs_to_jiffies(10));
				spin_lock(rq_lock);
				async = smb_work->async;
				if (async->async_status == ASYNC_CANCEL ||
					async->async_status == ASYNC_CLOSE) {
					posix_unblock_lock(flock);
					list_del(&smb_lock->llist);
					list_del(&smb_lock->glist);
					locks_free_lock(flock);

					if (async->async_status ==
							ASYNC_CANCEL) {
						rsp->hdr.Status =
							NT_STATUS_CANCELLED;
						list_del(&smb_lock->flist);
						kfree(smb_lock);
						spin_unlock(rq_lock);
						goto out;
					}
					rsp->hdr.Status =
						NT_STATUS_RANGE_NOT_LOCKED;
					kfree(smb_lock);
					spin_unlock(rq_lock);
					goto out2;
				}
				spin_unlock(rq_lock);

				if (err) {
					list_del(&smb_lock->llist);
					list_del(&smb_lock->glist);
					list_del(&smb_lock->flist);
					goto retry;
				} else
					goto wait;
			} else if (!err) {
				list_add_tail(&smb_lock->glist,
					&global_lock_list);
				list_add(&smb_lock->llist, &rollback_list);
				list_add(&smb_lock->flist, &fp->lock_list);
				cifsd_debug("successful in taking lock\n");
			} else {
				rsp->hdr.Status = NT_STATUS_LOCK_NOT_GRANTED;
				goto out;
			}
		}
	}

	if (oplocks_enable && atomic_read(&fp->f_mfp->op_count) > 1)
		smb_break_all_oplock(smb_work, fp);

	rsp->StructureSize = cpu_to_le16(4);
	cifsd_debug("successful in taking lock\n");
	rsp->hdr.Status = NT_STATUS_OK;
	rsp->Reserved = 0;
	inc_rfc1001_len(rsp, 4);

	return err;

out:
	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {
		locks_free_lock(smb_lock->fl);
		list_del(&smb_lock->llist);
		kfree(smb_lock);
	}

	list_for_each_entry_safe(smb_lock, tmp, &rollback_list, llist) {
		struct file_lock *rlock = NULL;

		rlock = smb_flock_init(filp);
		rlock->fl_type = F_UNLCK;
		rlock->fl_start = smb_lock->start;
		rlock->fl_end = smb_lock->end;

		err = smb_vfs_lock(filp, 0, rlock);
		if (err)
			cifsd_err("rollback unlock fail : %d\n", err);
		list_del(&smb_lock->llist);
		list_del(&smb_lock->glist);
		list_del(&smb_lock->flist);
		locks_free_lock(smb_lock->fl);
		locks_free_lock(rlock);
		kfree(smb_lock);
	}
out2:
	cifsd_err("failed in taking lock(flags : %x)\n", flags);
	smb2_set_err_rsp(smb_work);
	return 0;
}

/**
 * smb2_ioctl() - handler for smb2 ioctl command
 * @smb_work:	smb work containing ioctl command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_ioctl(struct smb_work *smb_work)
{
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp, *rsp_org;
	int cnt_code, nbytes = 0;
	int out_buf_len;
	char *data_buf;
	uint64_t id = -1;
	int ret = 0;
	struct connection *conn = smb_work->conn;
	struct cifsd_uevent *ev;
	struct cifsd_pipe *pipe_desc;

	req = (struct smb2_ioctl_req *)smb_work->buf;
	rsp = (struct smb2_ioctl_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_ioctl_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_ioctl_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
		if (le64_to_cpu(req->VolatileFileId) == -1) {
			cifsd_debug("Compound request assigning stored FID = %llu\n",
					smb_work->cur_local_fid);
			id = smb_work->cur_local_fid;
		}
	}

	if (req->StructureSize != 57) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (id == -1)
		id = le64_to_cpu(req->VolatileFileId);

	cnt_code = le32_to_cpu(req->CntCode);
	out_buf_len = le32_to_cpu(req->maxoutputresp);
	out_buf_len = min(NETLINK_CIFSD_MAX_PAYLOAD, out_buf_len);
	data_buf = (char *)&req->Buffer[0];

	switch (cnt_code) {
	case FSCTL_DFS_GET_REFERRALS:
	case FSCTL_DFS_GET_REFERRALS_EX:
		/* Not support DFS yet */
		rsp->hdr.Status = NT_STATUS_FS_DRIVER_REQUIRED;
		goto out;
	case FSCTL_CREATE_OR_GET_OBJECT_ID:
	{
		struct file_object_buf_type1_ioctl_rsp *obj_buf;

		nbytes = sizeof(struct file_object_buf_type1_ioctl_rsp);
		obj_buf = (struct file_object_buf_type1_ioctl_rsp *)
			&rsp->Buffer[0];

		/*
		 * TODO: This is dummy implementation to pass smbtorture
		 * Need to check correct response later
		 */
		memset(obj_buf->ObjectId, 0x0, 16);
		memset(obj_buf->BirthVolumeId, 0x0, 16);
		memset(obj_buf->BirthObjectId, 0x0, 16);
		memset(obj_buf->DomainId, 0x0, 16);

		break;
	}
	case FSCTL_PIPE_TRANSCEIVE:
		if (rsp->hdr.Id.SyncId.TreeId != 1) {
			cifsd_debug("Not Pipe transceive\n");
			goto out;
		}

		pipe_desc = get_pipe_desc(smb_work->sess, id);
		if (!pipe_desc) {
			cifsd_debug("Pipe not opened or invalid in Pipe id\n");
			goto out;
		}

		ret = cifsd_sendmsg(smb_work->sess, CIFSD_KEVENT_IOCTL_PIPE,
				pipe_desc->pipe_type,
				le32_to_cpu(req->inputcount), data_buf,
				out_buf_len);
		if (ret)
			cifsd_err("failed to send event, err %d\n", ret);
		else {
			ev = &pipe_desc->ev;
			nbytes = ev->u.i_pipe_rsp.data_count;
			ret = ev->error;
			if (ret == -EOPNOTSUPP) {
				rsp->hdr.Status =
					NT_STATUS_NOT_SUPPORTED;
				goto out;
			} else if (ret) {
				rsp->hdr.Status =
					NT_STATUS_INVALID_PARAMETER;
				goto out;
			}

			if (nbytes > out_buf_len) {
				rsp->hdr.Status =
					NT_STATUS_BUFFER_OVERFLOW;
				nbytes = out_buf_len;
			} else if (!nbytes) {
				cifsd_err("Pipe data not present\n");
				rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
				goto out;
			}

			memcpy((char *)rsp->Buffer, pipe_desc->rsp_buf,
					nbytes);
			smb_work->sess->ev_state = NETLINK_REQ_COMPLETED;
		}

		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	{
		struct validate_negotiate_info_req *neg_req;
		struct validate_negotiate_info_rsp *neg_rsp;
		int ret, start_index;

#ifdef CONFIG_CIFS_SMB2_SERVER
		start_index = SMB311_PROT;
#else
		start_index = CIFS_PROT;
#endif

		neg_req = (struct validate_negotiate_info_req *)&req->Buffer[0];
		ret = find_matching_smb2_dialect(start_index, neg_req->Dialects,
					le16_to_cpu(neg_req->DialectCount));
		if (ret == BAD_PROT_ID || ret != conn->dialect)
			goto out;

		if (strncmp(neg_req->Guid, conn->ClientGUID,
				SMB2_CLIENT_GUID_SIZE))
			goto out;

		if (neg_req->SecurityMode != conn->cli_sec_mode)
			goto out;

		if (neg_req->Capabilities != conn->cli_cap)
			goto out;

		nbytes = sizeof(struct validate_negotiate_info_rsp);
		neg_rsp = (struct validate_negotiate_info_rsp *)&rsp->Buffer[0];
		neg_rsp->Capabilities = cpu_to_le32(conn->srv_cap);
		memset(neg_rsp->Guid, 0, SMB2_CLIENT_GUID_SIZE);
		neg_rsp->SecurityMode = cpu_to_le16(conn->srv_sec_mode);
		neg_rsp->Dialect = cpu_to_le16(conn->dialect);

		rsp->PersistentFileId = cpu_to_le64(0xFFFFFFFFFFFFFFFF);
		rsp->VolatileFileId = cpu_to_le64(0xFFFFFFFFFFFFFFFF);
		break;
	}
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
	{
		struct network_interface_info_ioctl_rsp *nii_rsp = NULL;
		struct net_device *netdev;
		struct sockaddr_storage_rsp *sockaddr_storage;
		unsigned int speed, flags;

		rtnl_lock();
		for_each_netdev(&init_net, netdev) {
			if (unlikely(!netdev)) {
				rtnl_unlock();
				goto out;
			}

			if (netdev->type == ARPHRD_LOOPBACK)
				continue;

			flags = dev_get_flags(netdev);
			if (!(flags & IFF_RUNNING))
				continue;

			nii_rsp = (struct network_interface_info_ioctl_rsp *)
					&rsp->Buffer[nbytes];
			nii_rsp->IfIndex = cpu_to_le32(netdev->ifindex);

			/* TODO: specify the RDMA capabilities */
			if (netdev->num_tx_queues > 1)
				nii_rsp->Capability = RSS_CAPABLE;
			else
				nii_rsp->Capability = 0;

			nii_rsp->Next = cpu_to_le32(152);
			nii_rsp->Reserved = 0;

			if (netdev->ethtool_ops->get_settings) {
				struct ethtool_cmd cmd;

				netdev->ethtool_ops->get_settings(netdev, &cmd);
				speed = cmd.speed;
			}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			else if (netdev->ethtool_ops->get_link_ksettings) {
				struct ethtool_link_ksettings cmd;

				netdev->ethtool_ops->get_link_ksettings(netdev,
					&cmd);
				speed = cmd.base.speed;
			}
#endif
			else {
				cifsd_err("%s speed is unknown, defaulting to 100\n",
					netdev->name);
				speed = 1000;
			}

			nii_rsp->LinkSpeed = cpu_to_le64(speed * 1000000);

			sockaddr_storage = (struct sockaddr_storage_rsp *)
						nii_rsp->SockAddr_Storage;

			memset(sockaddr_storage, 0, 128);

			if (conn->family == PF_INET) {
				struct in_device *idev;

				sockaddr_storage->Family =
					cpu_to_le16(INTERNETWORK);
				sockaddr_storage->addr4.Port = 0;

				idev = __in_dev_get_rtnl(netdev);
				if (!idev)
					continue;
				for_primary_ifa(idev) {
					sockaddr_storage->addr4.IPv4address =
						cpu_to_le32(ifa->ifa_address);
					break;
				} endfor_ifa(idev);
			} else {
				struct inet6_dev *idev6;
				struct inet6_ifaddr *ifa;
				__u8 *ipv6_addr =
					sockaddr_storage->addr6.IPv6address;

				sockaddr_storage->Family =
					cpu_to_le16(INTERNETWORKV6);
				sockaddr_storage->addr6.Port = 0;
				sockaddr_storage->addr6.FlowInfo = 0;

				idev6 = __in6_dev_get(netdev);
				if (!idev6)
					continue;

				list_for_each_entry(ifa, &idev6->addr_list,
						if_list) {
					if (ifa->flags & (IFA_F_TENTATIVE |
							IFA_F_DEPRECATED))
						continue;
					memcpy(ipv6_addr, ifa->addr.s6_addr,
						16);
					break;
				}
				sockaddr_storage->addr6.ScopeId = 0;
			}

			nbytes +=
				sizeof(struct network_interface_info_ioctl_rsp);
		}
		rtnl_unlock();

		/* zero if this is last one */
		if (nii_rsp)
			nii_rsp->Next = 0;

		if (!nbytes) {
			rsp->hdr.Status = NT_STATUS_BUFFER_TOO_SMALL;
			goto out;
		}

		rsp->PersistentFileId = cpu_to_le64(0xFFFFFFFFFFFFFFFF);
		rsp->VolatileFileId = cpu_to_le64(0xFFFFFFFFFFFFFFFF);

		break;
	}
	default:
		cifsd_debug("not implemented yet ioctl command 0x%x\n",
				cnt_code);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}
	rsp->CntCode = cpu_to_le32(cnt_code);
	rsp->inputcount = cpu_to_le32(0);
	rsp->inputoffset = cpu_to_le32(112);
	rsp->outputoffset = cpu_to_le32(112);
	rsp->outputcount = cpu_to_le32(nbytes);
	rsp->StructureSize = cpu_to_le16(49);
	rsp->Reserved = cpu_to_le16(0);
	rsp->flags = cpu_to_le32(0);
	rsp->Reserved2 = cpu_to_le32(0);
	inc_rfc1001_len(rsp_org, 48 + nbytes);

	if (!smb_work->sess->sign && cnt_code ==
		FSCTL_VALIDATE_NEGOTIATE_INFO) {
		if (conn->ops->is_sign_req &&
			conn->ops->is_sign_req(smb_work, SMB2_IOCTL_HE) &&
			conn->dialect >= SMB30_PROT_ID) {
			struct channel *chann;

			chann = lookup_chann_list(smb_work->sess);
			ret = conn->ops->compute_signingkey(smb_work->sess,
				chann->smb3signingkey, SMB3_SIGN_KEY_SIZE);
			if (ret)
				cifsd_err("SMB3 sesskey generation failed\n");
			else
				conn->ops->set_sign_rsp(smb_work);
		}
	}

	return 0;

out:
	if (rsp->hdr.Status == 0)
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
	smb2_set_err_rsp(smb_work);
	return 0;
}

/**
 * smb20_oplock_break() - handler for smb2.0 oplock break command
 * @smb_work:	smb work containing oplock break command buffer
 *
 * Return:	0
 */
int smb20_oplock_break(struct smb_work *smb_work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;
	struct cifsd_file *fp;
	struct oplock_info *opinfo = NULL;
	int err = 0, ret = 0;
	uint64_t volatile_id, persistent_id;
	char req_oplevel = 0, rsp_oplevel = 0;
	unsigned int oplock_change_type;

	req = (struct smb2_oplock_break *)smb_work->buf;
	rsp = (struct smb2_oplock_break *)smb_work->rsp_buf;
	volatile_id = le64_to_cpu(req->VolatileFid);
	persistent_id = le64_to_cpu(req->PersistentFid);
	req_oplevel = req->OplockLevel;
	cifsd_debug("SMB2_OPLOCK_BREAK v_id %llu, p_id %llu request oplock level %d\n",
			volatile_id, persistent_id, req_oplevel);

	mutex_lock(&lease_list_lock);
	fp = get_fp(smb_work, volatile_id, persistent_id);
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		goto err_out;
	}

	opinfo = fp->f_opinfo;
	if (opinfo == NULL) {
		cifsd_err("unexpected null oplock_info\n");
		rsp->hdr.Status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		goto err_out;
	}

	if (opinfo->level == SMB2_OPLOCK_LEVEL_NONE) {
		rsp->hdr.Status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		goto err_out;
	}

	if (opinfo->op_state == OPLOCK_STATE_NONE) {
		cifsd_err("unexpected oplock state 0x%x\n", opinfo->op_state);
		rsp->hdr.Status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	if (((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)) &&
			((req_oplevel != SMB2_OPLOCK_LEVEL_II) &&
			 (req_oplevel != SMB2_OPLOCK_LEVEL_NONE))) {
		err = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		oplock_change_type = OPLOCK_WRITE_TO_NONE;
	} else if ((opinfo->level == SMB2_OPLOCK_LEVEL_II) &&
			(req_oplevel != SMB2_OPLOCK_LEVEL_NONE)) {
		err = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		oplock_change_type = OPLOCK_READ_TO_NONE;
	} else if ((req_oplevel == SMB2_OPLOCK_LEVEL_II) ||
			(req_oplevel == SMB2_OPLOCK_LEVEL_NONE)) {
		err = NT_STATUS_INVALID_DEVICE_STATE;
		if (((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)) &&
			(req_oplevel == SMB2_OPLOCK_LEVEL_II)) {
			oplock_change_type = OPLOCK_WRITE_TO_READ;
		} else if (((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
			|| (opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)) &&
			(req_oplevel == SMB2_OPLOCK_LEVEL_NONE)) {
			oplock_change_type = OPLOCK_WRITE_TO_NONE;
		} else if ((opinfo->level == SMB2_OPLOCK_LEVEL_II) &&
				(req_oplevel == SMB2_OPLOCK_LEVEL_NONE)) {
			oplock_change_type = OPLOCK_READ_TO_NONE;
		} else
			oplock_change_type = 0;
	} else
		oplock_change_type = 0;

	switch (oplock_change_type) {
	case OPLOCK_WRITE_TO_READ:
		ret = opinfo_write_to_read(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_II;
		break;
	case OPLOCK_WRITE_TO_NONE:
		ret = opinfo_write_to_none(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case OPLOCK_READ_TO_NONE:
		ret = opinfo_read_to_none(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	default:
		cifsd_err("unknown oplock change 0x%x -> 0x%x\n",
				opinfo->level, rsp_oplevel);
	}

	opinfo->op_state = OPLOCK_STATE_NONE;
	wake_up_interruptible(&opinfo->oplock_q);

	if (ret < 0) {
		rsp->hdr.Status = err;
		goto err_out;
	}
	mutex_unlock(&lease_list_lock);

	rsp->StructureSize = cpu_to_le16(24);
	rsp->OplockLevel = rsp_oplevel;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->VolatileFid = cpu_to_le64(volatile_id);
	rsp->PersistentFid = cpu_to_le64(persistent_id);
	inc_rfc1001_len(rsp, 24);
	return 0;

err_out:
	mutex_unlock(&lease_list_lock);
	smb2_set_err_rsp(smb_work);
	return 0;
}

static int check_lease_state(struct lease *lease, __le32 req_state)
{
	if ((lease->new_state ==
		(SMB2_LEASE_READ_CACHING | SMB2_LEASE_HANDLE_CACHING))
		&& !(req_state & SMB2_LEASE_WRITE_CACHING)) {
		lease->new_state = req_state;
		return 0;
	}

	if (lease->new_state == req_state)
		return 0;

	return 1;
}

/**
 * smb21_lease_break() - handler for smb2.1 lease break command
 * @smb_work:	smb work containing lease break command buffer
 *
 * Return:	0
 */
int smb21_lease_break(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct smb2_lease_ack *req, *rsp;
	struct oplock_info *opinfo;
	int err = 0, ret = 0;
	unsigned int lease_change_type;
	__le32 lease_state;
	struct lease *lease;

	req = (struct smb2_lease_ack *)smb_work->buf;
	rsp = (struct smb2_lease_ack *)smb_work->rsp_buf;

	cifsd_debug("smb21 lease break, lease state(0x%x)\n",
			req->LeaseState);
	mutex_lock(&lease_list_lock);
	opinfo = lookup_lease_in_table(conn, req->LeaseKey);
	if (opinfo == NULL) {
		cifsd_debug("file not opened\n");
		rsp->hdr.Status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}
	lease = opinfo->o_lease;

	if (opinfo->op_state == OPLOCK_STATE_NONE) {
		cifsd_err("unexpected lease break state 0x%x\n",
				opinfo->op_state);
		rsp->hdr.Status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	if (check_lease_state(lease, req->LeaseState)) {
		rsp->hdr.Status = NT_STATUS_REQUEST_NOT_ACCEPTED;
		cifsd_debug("req lease state : 0x%x,  expected lease state : 0x%x\n",
				lease->new_state, req->LeaseState);
		goto err_out;
	}

	if (!atomic_read(&opinfo->breaking_cnt)) {
		rsp->hdr.Status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	/* check for bad lease state */
	if (req->LeaseState & (~(SMB2_LEASE_READ_CACHING |
					SMB2_LEASE_HANDLE_CACHING))) {
		err = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		if (lease->state & SMB2_LEASE_WRITE_CACHING)
			lease_change_type = OPLOCK_WRITE_TO_NONE;
		else
			lease_change_type = OPLOCK_READ_TO_NONE;
		cifsd_debug("handle bad lease state 0x%x -> 0x%x\n",
				lease->state, req->LeaseState);
	} else if ((lease->state == SMB2_LEASE_READ_CACHING) &&
			(req->LeaseState != SMB2_LEASE_NONE)) {
		err = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		lease_change_type = OPLOCK_READ_TO_NONE;
		cifsd_debug("handle bad lease state 0x%x -> 0x%x\n",
				lease->state, req->LeaseState);
	} else {
		/* valid lease state changes */
		err = NT_STATUS_INVALID_DEVICE_STATE;
		if (req->LeaseState == SMB2_LEASE_NONE) {
			if (lease->state & SMB2_LEASE_WRITE_CACHING)
				lease_change_type = OPLOCK_WRITE_TO_NONE;
			else
				lease_change_type = OPLOCK_READ_TO_NONE;
		} else if (req->LeaseState & SMB2_LEASE_READ_CACHING) {
			if (lease->state & SMB2_LEASE_WRITE_CACHING)
				lease_change_type = OPLOCK_WRITE_TO_READ;
			else
				lease_change_type = OPLOCK_READ_HANDLE_TO_READ;
		} else
			lease_change_type = 0;
	}

	switch (lease_change_type) {
	case OPLOCK_WRITE_TO_READ:
		ret = opinfo_write_to_read(opinfo);
		break;
	case OPLOCK_READ_HANDLE_TO_READ:
		ret = opinfo_read_handle_to_read(opinfo);
		break;
	case OPLOCK_WRITE_TO_NONE:
		ret = opinfo_write_to_none(opinfo);
		break;
	case OPLOCK_READ_TO_NONE:
		ret = opinfo_read_to_none(opinfo);
		break;
	default:
		cifsd_debug("unknown lease change 0x%x -> 0x%x\n",
				lease->state, req->LeaseState);
	}

	lease_state = lease->state;
	atomic_dec(&opinfo->breaking_cnt);
	opinfo->op_state = OPLOCK_STATE_NONE;
	wake_up_interruptible(&opinfo->oplock_q);

	if (ret < 0) {
		rsp->hdr.Status = err;
		goto err_out;
	}

	mutex_unlock(&lease_list_lock);
	rsp->StructureSize = cpu_to_le16(36);
	rsp->Reserved = 0;
	rsp->Flags = 0;
	memcpy(rsp->LeaseKey, req->LeaseKey, 16);
	rsp->LeaseState = lease_state;
	rsp->LeaseDuration = 0;
	inc_rfc1001_len(rsp, 36);
	return 0;

err_out:
	mutex_unlock(&lease_list_lock);
	smb2_set_err_rsp(smb_work);
	return 0;
}

/**
 * smb2_oplock_break() - dispatcher for smb2.0 and 2.1 oplock/lease break
 * @smb_work:	smb work containing oplock/lease break command buffer
 *
 * Return:	0
 */
int smb2_oplock_break(struct smb_work *smb_work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;
	int err;

	req = (struct smb2_oplock_break *)smb_work->buf;
	rsp = (struct smb2_oplock_break *)smb_work->rsp_buf;

	switch (le16_to_cpu(req->StructureSize)) {
	case OP_BREAK_STRUCT_SIZE_20:
		err = smb20_oplock_break(smb_work);
		break;
	case OP_BREAK_STRUCT_SIZE_21:
		err = smb21_lease_break(smb_work);
		break;
	default:
		cifsd_debug("invalid break cmd %d\n", req->StructureSize);
		err = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}

	if (err)
		goto err_out;

	return 0;

err_out:
	rsp->hdr.Status = err;
	smb2_set_err_rsp(smb_work);
	return 0;
}

#ifdef CONFIG_SMB2_NOTIFY_SUPPORT
/**
 * smb2_notify() - handler for smb2 notify request
 * @smb_work:	smb work containing notify command buffer
 *
 * Return:		0
 */
int smb2_notify(struct smb_work *smb_work)
{
	struct smb2_notify_req *req;
	struct smb2_notify_rsp *rsp, *rsp_org;
	struct cifsd_file *fp, *prev_fp;
	struct notification *notify_req;
	struct notification *request;
	struct smb_work *work;
	int rc = 0;
	char *path;
	char *path_buf = NULL;
	int path_len = 0;
	struct smb2_inotify_req_info inotify_req_info;

	req = (struct smb2_notify_req *)smb_work->buf;
	rsp = (struct smb2_notify_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_notify_req *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_notify_rsp *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 32) {
		cifsd_err("malformed packet\n");
		goto out1;
	}

	if (smb_work->next_smb2_rcv_hdr_off &&
			le32_to_cpu(req->hdr.NextCommand)) {
		rsp->hdr.Status = NT_STATUS_INTERNAL_ERROR;
		goto out2;
	}

	fp = get_fp(smb_work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		rc = -ENOENT;
		goto out2;
	}

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		rc = -ENOENT;
		goto out2;
	}

	notify_req = kmalloc(sizeof(struct notification), GFP_KERNEL);
	if (!notify_req) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		rc = -ENOENT;
		goto out2;
	}
	notify_req->work = smb_work;

	hash_for_each_possible(smb_work->sess->notify_table, prev_fp,
		notify_node, (unsigned long)FP_INODE(fp)) {
		if (FP_INODE(fp) == FP_INODE(prev_fp)) {
			list_add_tail(&notify_req->queuelist, &prev_fp->queue);
			goto out1;
		}
	}

	path = d_path(&(fp->filp->f_path), path_buf, PATH_MAX);
	if (IS_ERR(path)) {
		cifsd_err("Failed to get complete dir path\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = PTR_ERR(path);
		kfree(path_buf);
		goto out2;
	}
	path_len = strlen(path);

	INIT_LIST_HEAD(&fp->queue);
	list_add_tail(&notify_req->queuelist, &fp->queue);

	while (!list_empty(&fp->queue)) {
		request = list_first_entry_or_null(&fp->queue,
			struct notification, queuelist);
		if (!request)
			continue;
		list_del_init(&request->queuelist);

		work = request->work;
		smb2_send_interim_resp(work);
		req = (struct smb2_notify_req *)work->buf;
		rsp = (struct smb2_notify_rsp *)work->rsp_buf;
		rsp_org = rsp;

		/* TODO : implement recursive monitoring */
		inotify_req_info.watch_tree_flag = 0;
		inotify_req_info.CompletionFilter = req->CompletionFileter;
		inotify_req_info.path_len = path_len;

		rc = cifsd_sendmsg_notify(work->sess,
			sizeof(inotify_req_info)+path_len,
			&inotify_req_info, path);

		rsp->hdr.Status = NT_STATUS_OK;
		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(72);
		rsp->OutputBufferLength =
		work->sess->inotify_res->output_buffer_length;

		memcpy(rsp->Buffer,
			&(work->sess->inotify_res->file_notify_info[0]),
			sizeof(struct FileNotifyInformation) + NAME_MAX);
		inc_rfc1001_len(rsp_org, 8 + rsp->OutputBufferLength);
		smb_send_rsp(work);
		kfree(path_buf);
		kfree(work->sess->inotify_res);
	}

out1:
	smb_work->send_no_response = 1;
	return 0;

out2:
	if (rsp->hdr.Status == 0)
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
	smb2_set_err_rsp(smb_work);
	return rc;
}
#else

/**
 * smb2_notify() - handler for smb2 notify request
 * @smb_work:   smb work containing notify command buffer
 *
 * Return:      0
 */
int smb2_notify(struct smb_work *smb_work)
{
	struct smb2_notify_req *req;
	struct smb2_notify_rsp *rsp, *rsp_org;

	req = (struct smb2_notify_req *)smb_work->buf;
	rsp = (struct smb2_notify_rsp *)smb_work->rsp_buf;
	rsp_org = rsp;

	if (smb_work->next_smb2_rcv_hdr_off) {
	req = (struct smb2_notify_req *)((char *)req +
		smb_work->next_smb2_rcv_hdr_off);
	rsp = (struct smb2_notify_rsp *)((char *)rsp +
		smb_work->next_smb2_rsp_hdr_off);
	}

	if (req->StructureSize != 32) {
		cifsd_err("malformed packet\n");
		smb_work->send_no_response = 1;
		return 0;
	}

	if (smb_work->next_smb2_rcv_hdr_off &&
		le32_to_cpu(req->hdr.NextCommand)) {
		rsp->hdr.Status = NT_STATUS_INTERNAL_ERROR;
		smb2_set_err_rsp(smb_work);
		return 0;
	}

	rsp->hdr.Status = NT_STATUS_OK;
	rsp->StructureSize = cpu_to_le16(9);
	rsp->OutputBufferLength = cpu_to_le32(0);
	rsp->OutputBufferOffset = cpu_to_le16(0);
	rsp->Buffer[0] = 0;
	inc_rfc1001_len(rsp_org, 9);

	return 0;
}
#endif

/**
 * smb2_is_sign_req() - handler for checking packet signing status
 * @work:smb work containing notify command buffer
 *
 * Return:	1 if packed is signed, 0 otherwise
 */
int smb2_is_sign_req(struct smb_work *work, unsigned int command)
{
	struct smb2_hdr *rcv_hdr2 = (struct smb2_hdr *)work->buf;

	if ((rcv_hdr2->Flags & SMB2_FLAGS_SIGNED) &&
			command != SMB2_NEGOTIATE_HE &&
			command != SMB2_SESSION_SETUP_HE &&
			command != SMB2_OPLOCK_BREAK_HE)
		return 1;

	/* send session setup auth phase signed response */
	if (command == SMB2_SESSION_SETUP_HE &&
			work->sess && work->sess->valid)
		return 1;

	return 0;
}

/**
 * smb2_check_sign_req() - handler for req packet sign processing
 * @work:   smb work containing notify command buffer
 *
 * Return:	1 on success, 0 otherwise
 */
int smb2_check_sign_req(struct smb_work *work)
{
	struct smb2_hdr *rcv_hdr2 = (struct smb2_hdr *)work->buf;
	char signature_req[SMB2_SIGNATURE_SIZE];
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec iov[1];

	memcpy(signature_req, rcv_hdr2->Signature, SMB2_SIGNATURE_SIZE);
	memset(rcv_hdr2->Signature, 0, SMB2_SIGNATURE_SIZE);

	iov[0].iov_base = rcv_hdr2->ProtocolId;
	iov[0].iov_len = be32_to_cpu(rcv_hdr2->smb2_buf_length);

	if (smb2_sign_smbpdu(work->sess, iov, 1, signature))
		return 0;

	if (memcmp(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
		cifsd_debug("bad smb2 signature\n");
		return 0;
	}

	return 1;
}

/**
 * smb2_set_sign_rsp() - handler for rsp packet sign procesing
 * @work:   smb work containing notify command buffer
 *
 */
void smb2_set_sign_rsp(struct smb_work *work)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *)work->rsp_buf;
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec iov[2];
	int n_vec = 1;

	rsp_hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(rsp_hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	iov[0].iov_base = rsp_hdr->ProtocolId;
	iov[0].iov_len = be32_to_cpu(rsp_hdr->smb2_buf_length);

	if (work->rdata_buf) {
		iov[0].iov_len -= work->rdata_cnt;

		iov[1].iov_base = work->rdata_buf;
		iov[1].iov_len = work->rdata_cnt;
		n_vec++;
	}

	if (!smb2_sign_smbpdu(work->sess, iov, n_vec, signature))
		memcpy(rsp_hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_check_sign_req() - handler for req packet sign processing
 * @work:   smb work containing notify command buffer
 *
 * Return:	1 on success, 0 otherwise
 */
int smb3_check_sign_req(struct smb_work *work)
{
	struct smb2_hdr *hdr, *hdr_org;
	struct channel *chann;
	char signature_req[SMB2_SIGNATURE_SIZE];
	char signature[SMB2_CMACAES_SIZE];
	struct kvec iov[1];
	size_t len;

	chann = lookup_chann_list(work->sess);
	if (!chann)
		return 0;

	hdr_org = hdr = (struct smb2_hdr *)work->buf;
	if (work->next_smb2_rcv_hdr_off)
		hdr = (struct smb2_hdr *)((char *)hdr_org +
				work->next_smb2_rcv_hdr_off);

	if (!le32_to_cpu(hdr->NextCommand) &&
			!work->next_smb2_rcv_hdr_off)
		len = be32_to_cpu(hdr_org->smb2_buf_length);
	else if (le32_to_cpu(hdr->NextCommand))
		len = le32_to_cpu(hdr->NextCommand);
	else
		len = be32_to_cpu(hdr_org->smb2_buf_length) -
			work->next_smb2_rcv_hdr_off;

	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	iov[0].iov_base = hdr->ProtocolId;
	iov[0].iov_len = len;

	if (smb3_sign_smbpdu(chann, iov, 1, signature))
		return 0;

	if (memcmp(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
		cifsd_debug("bad smb2 signature\n");
		return 0;
	}

	return 1;
}

/**
 * smb3_set_sign_rsp() - handler for rsp packet sign procesing
 * @work:   smb work containing notify command buffer
 *
 */
void smb3_set_sign_rsp(struct smb_work *work)
{
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)work->buf;
	struct smb2_hdr *hdr, *hdr_org;
	struct channel *chann;
	char signature[SMB2_CMACAES_SIZE];
	struct kvec iov[2];
	int n_vec = 1;
	size_t len;

	chann = lookup_chann_list(work->sess);
	if (!chann)
		return;

	hdr_org = hdr = (struct smb2_hdr *)work->rsp_buf;
	if (work->next_smb2_rsp_hdr_off)
		hdr = (struct smb2_hdr *)((char *)hdr_org +
				work->next_smb2_rsp_hdr_off);

	req_hdr = (struct smb2_hdr *)((char *)req_hdr +
			work->next_smb2_rcv_hdr_off);

	if (!work->next_smb2_rsp_hdr_off) {
		len = get_rfc1002_length(hdr_org);
		if (le32_to_cpu(req_hdr->NextCommand)) {
			/* Align the length to 8Byte  */
			len = ((len + 7) & ~7);
		}
	} else {
		len = get_rfc1002_length(hdr_org) -
			work->next_smb2_rsp_hdr_off;
		/* Align the length to 8Byte  */
		len = ((len + 7) & ~7);
	}

	if (le32_to_cpu(req_hdr->NextCommand))
		hdr->NextCommand = cpu_to_le32(len);

	hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	iov[0].iov_base = hdr->ProtocolId;
	iov[0].iov_len = len;
	if (work->rdata_buf) {
		iov[0].iov_len -= work->rdata_cnt;
		iov[1].iov_base = work->rdata_buf;
		iov[1].iov_len = work->rdata_cnt;
		n_vec++;
	}

	if (!smb3_sign_smbpdu(chann, iov, n_vec, signature))
		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_preauth_hash_rsp() - handler for computing preauth hash on response
 * @work:   smb work containing response buffer
 *
 */
void smb3_preauth_hash_rsp(struct smb_work *smb_work)
{
	struct connection *conn = smb_work->conn;
	struct cifsd_sess *sess = smb_work->sess;
	struct smb2_hdr *req = (struct smb2_hdr *)smb_work->buf;
	struct smb2_hdr *rsp = (struct smb2_hdr *)smb_work->rsp_buf;

	if (smb_work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_hdr *)((char *)req +
				smb_work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_hdr *)((char *)rsp +
				smb_work->next_smb2_rsp_hdr_off);
	}

	if (le16_to_cpu(req->Command) == SMB2_NEGOTIATE_HE)
		calc_preauth_integrity_hash(conn, (char *)rsp,
			conn->Preauth_HashValue);

	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE) {
		if (rsp->Status == NT_STATUS_MORE_PROCESSING_REQUIRED)
			calc_preauth_integrity_hash(conn, (char *)rsp,
					sess->Preauth_HashValue);
	}
}
