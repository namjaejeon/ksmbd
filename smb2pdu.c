// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <crypto/aead.h>

#include "glob.h"
#include "export.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "cifsacl.h"

#include "auth.h"
#include "asn1.h"
#include "buffer_pool.h"
#include "transport_tcp.h"
#include "transport_ipc.h"
#include "vfs.h"
#include "fh.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/cifsd_ida.h"

bool multi_channel_enable;
bool encryption_enable;

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
static inline int check_session_id(struct cifsd_tcp_conn *conn, uint64_t id)
{
	struct cifsd_session *sess;

	if (id == 0 || id == -1)
		return 0;

	sess = cifsd_session_lookup(conn, id);
	if (sess)
		return 1;
	cifsd_err("Invalid user session id: %llu\n", id);
	return 0;
}

struct channel *lookup_chann_list(struct cifsd_session *sess)
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
int smb2_get_cifsd_tcon(struct cifsd_work *work)
{
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)REQUEST_BUF(work);

	work->tcon = NULL;
	if ((work->conn->ops->get_cmd_val(work) == SMB2_TREE_CONNECT_HE) ||
		(work->conn->ops->get_cmd_val(work) ==  SMB2_CANCEL_HE) ||
		(work->conn->ops->get_cmd_val(work) ==  SMB2_LOGOFF_HE)) {
		cifsd_debug("skip to check tree connect request\n");
		return 0;
	}

	if (list_empty(&work->sess->tree_conn_list)) {
		cifsd_debug("NO tree connected\n");
		return -1;
	}

	work->tcon = cifsd_tree_conn_lookup(work->sess,
				le32_to_cpu(req_hdr->Id.SyncId.TreeId));
	if (!work->tcon) {
		cifsd_err("Invalid tid %d\n", req_hdr->Id.SyncId.TreeId);
		return -1;
	}

	return 1;
}

/**
 * smb2_set_err_rsp() - set error response code on smb response
 * @work:	smb work containing response buffer
 */
void smb2_set_err_rsp(struct cifsd_work *work)
{
	char *rsp = RESPONSE_BUF(work);
	struct smb2_err_rsp *err_rsp;

	if (work->next_smb2_rcv_hdr_off)
		err_rsp = (struct smb2_err_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	else
		err_rsp = (struct smb2_err_rsp *)rsp;

	if (err_rsp->hdr.Status != cpu_to_le32(NT_STATUS_STOPPED_ON_SYMLINK)) {
		err_rsp->StructureSize =
			cpu_to_le16(SMB2_ERROR_STRUCTURE_SIZE2);
		err_rsp->ErrorContextCount = 0;
		err_rsp->Reserved = 0;
		err_rsp->ByteCount = 0;
		err_rsp->ErrorData[0] = 0;
		inc_rfc1001_len(rsp, SMB2_ERROR_STRUCTURE_SIZE2);
	}
}

/**
 * is_smb2_neg_cmd() - is it smb2 negotiation command
 * @work:	smb work containing smb header
 *
 * Return:      1 if smb2 negotiation command, otherwise 0
 */
int is_smb2_neg_cmd(struct cifsd_work *work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)REQUEST_BUF(work);

	/* is it SMB2 header ? */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
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
 * @work:	smb work containing smb response buffer
 *
 * Return:      1 if smb2 response, otherwise 0
 */
int is_smb2_rsp(struct cifsd_work *work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)RESPONSE_BUF(work);

	/* is it SMB2 header ? */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return 0;

	/* make sure it is response not request message */
	if (!(hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
		return 0;

	return 1;
}

/**
 * get_smb2_cmd_val() - get smb command code from smb header
 * @work:	smb work containing smb request buffer
 *
 * Return:      smb2 request command value
 */
int get_smb2_cmd_val(struct cifsd_work *work)
{
	struct smb2_hdr *rcv_hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	if (work->next_smb2_rcv_hdr_off)
		rcv_hdr = (struct smb2_hdr *)((char *)rcv_hdr
					+ work->next_smb2_rcv_hdr_off);
	return le16_to_cpu(rcv_hdr->Command);
}

/**
 * set_smb2_rsp_status() - set error response code on smb2 header
 * @work:	smb work containing response buffer
 */
void set_smb2_rsp_status(struct cifsd_work *work, unsigned int err)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *) RESPONSE_BUF(work);
	if (work->next_smb2_rcv_hdr_off)
		rsp_hdr = (struct smb2_hdr *)((char *)rsp_hdr
					+ work->next_smb2_rsp_hdr_off);
	rsp_hdr->Status = cpu_to_le32(err);
	smb2_set_err_rsp(work);
}

/**
 * init_smb2_neg_rsp() - initialize smb2 response for negotiate command
 * @work:	smb work containing smb request buffer
 *
 * smb2 negotiate response is sent in reply of smb1 negotiate command for
 * dialect auto-negotiation.
 */
int init_smb2_neg_rsp(struct cifsd_work *work)
{
	struct smb2_hdr *rsp_hdr;
	struct smb2_negotiate_rsp *rsp;
	struct cifsd_tcp_conn *conn = work->conn;
	struct timespec64 ts64;

	if (!conn->need_neg)
		return -EINVAL;
	if (!(conn->dialect >= SMB20_PROT_ID &&
		conn->dialect <= SMB311_PROT_ID))
		return -EINVAL;

	rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);

	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);

	rsp_hdr->smb2_buf_length =
		cpu_to_be32(HEADER_SIZE_NO_BUF_LEN(conn));

	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
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

	rsp = (struct smb2_negotiate_rsp *)RESPONSE_BUF(work);

	WARN_ON(cifsd_tcp_good(work));

	rsp->StructureSize = cpu_to_le16(65);
	cifsd_debug("conn->dialect 0x%x\n", conn->dialect);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/* Not setting conn guid rsp->ServerGUID, as it
	 * not used by client for identifying connection */
	rsp->Capabilities = 0;
	/* Default Max Message Size till SMB2.0, 64K*/
	rsp->MaxTransactSize = SMBMaxBufSize;
	rsp->MaxReadSize = SMBMaxBufSize;
	rsp->MaxWriteSize = SMBMaxBufSize;

	getnstimeofday64(&ts64);
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(
						timespec64_to_timespec(ts64)));
	rsp->ServerStartTime = 0;

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);
	cifsd_copy_gss_neg_header(((char *)(&rsp->hdr) +
		sizeof(rsp->hdr.smb2_buf_length)) + rsp->SecurityBufferOffset);
	inc_rfc1001_len(rsp, sizeof(struct smb2_negotiate_rsp) -
		sizeof(struct smb2_hdr) - sizeof(rsp->Buffer) +
		AUTH_GSS_LENGTH);
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	conn->use_spnego = true;

	cifsd_tcp_set_need_negotiate(work);
	rsp->hdr.CreditRequest = cpu_to_le16(2);
	return 0;
}

/**
 * init_chained_smb2_rsp() - initialize smb2 chained response
 * @work:	smb work containing smb response buffer
 */
void init_chained_smb2_rsp(struct cifsd_work *work)
{
	struct smb2_hdr *req;
	struct smb2_hdr *rsp;
	struct smb2_hdr *rsp_hdr;
	struct smb2_hdr *rcv_hdr;
	int next_hdr_offset = 0;
	int len, new_len;


	req = (struct smb2_hdr *)(REQUEST_BUF(work) +
				  work->next_smb2_rcv_hdr_off);
	rsp = (struct smb2_hdr *)(RESPONSE_BUF(work) +
				  work->next_smb2_rsp_hdr_off);

	/* Len of this response = updated RFC len - offset of previous cmd
	   in the compound rsp */

	/* Storing the current local FID which may be needed by subsequent
	   command in the compound request */
	if (le16_to_cpu(req->Command) == SMB2_CREATE &&
			le32_to_cpu(rsp->Status) == NT_STATUS_OK) {
		work->cur_local_fid =
			le64_to_cpu(((struct smb2_create_rsp *)rsp)->
				VolatileFileId);
		work->cur_local_pfid =
			le64_to_cpu(((struct smb2_create_rsp *)rsp)->
				PersistentFileId);
		work->cur_local_sess_id = rsp->SessionId;
	}

	len = get_rfc1002_length(RESPONSE_BUF(work)) -
				 work->next_smb2_rsp_hdr_off;

	next_hdr_offset = le32_to_cpu(req->NextCommand);

	/* Align the length to 8Byte  */
	new_len = ((len + 7) & ~7);
	inc_rfc1001_len(RESPONSE_BUF(work), ((sizeof(struct smb2_hdr) - 4)
			+ new_len - len));
	rsp->NextCommand = cpu_to_le32(new_len);

	work->next_smb2_rcv_hdr_off += next_hdr_offset;
	work->next_smb2_rsp_hdr_off += new_len;
	cifsd_debug("Compound req new_len = %d rcv off = %d rsp off = %d\n",
		      new_len, work->next_smb2_rcv_hdr_off,
		      work->next_smb2_rsp_hdr_off);

	rsp_hdr = (struct smb2_hdr *)(((char *)RESPONSE_BUF(work) +
					work->next_smb2_rsp_hdr_off));
	rcv_hdr = (struct smb2_hdr *)(((char *)REQUEST_BUF(work) +
					work->next_smb2_rcv_hdr_off));

	if (!(le32_to_cpu(rcv_hdr->Flags) & SMB2_FLAGS_RELATED_OPERATIONS)) {
		cifsd_debug("related flag should be set\n");
		work->cur_local_fid = -1;
		work->cur_local_pfid = -1;
	}
	memset((char *)rsp_hdr + 4, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = rcv_hdr->ProtocolId;
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
 * @work:	smb work containing smb request buffer
 *
 * Return:      true if chained request, otherwise false
 */
bool is_chained_smb2_message(struct cifsd_work *work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	unsigned int len;

	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return false;

	hdr = (struct smb2_hdr *)(REQUEST_BUF(work) +
			work->next_smb2_rcv_hdr_off);
	if (le32_to_cpu(hdr->NextCommand) > 0) {
		cifsd_debug("got SMB2 chained command\n");
		init_chained_smb2_rsp(work);
		return true;
	} else if (work->next_smb2_rcv_hdr_off) {
		/*
		 * This is last request in chained command,
		 * align response to 8 byte
		 */
		len = ((get_rfc1002_length(RESPONSE_BUF(work)) + 7) & ~7);
		len = len - get_rfc1002_length(RESPONSE_BUF(work));
		if (len) {
			cifsd_debug("padding len %u\n", len);
			inc_rfc1001_len(RESPONSE_BUF(work), len);
			if (HAS_AUX_PAYLOAD(work))
				work->aux_payload_sz += len;
		}
	}
	return false;
}

/**
 * init_smb2_rsp_hdr() - initialize smb2 response
 * @work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int init_smb2_rsp_hdr(struct cifsd_work *work)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	struct smb2_hdr *rcv_hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	struct cifsd_tcp_conn *conn = work->conn;
	int next_hdr_offset = 0;

	next_hdr_offset = le32_to_cpu(rcv_hdr->NextCommand);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);

	rsp_hdr->smb2_buf_length = cpu_to_be32(HEADER_SIZE_NO_BUF_LEN(conn));
	rsp_hdr->ProtocolId = rcv_hdr->ProtocolId;
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

	work->type = SYNC;
	if (work->async_id) {
		cifds_release_id(conn->async_ida, work->async_id);
		work->async_id = 0;
	}

	return 0;
}

/**
 * smb2_allocate_rsp_buf() - allocate smb2 response buffer
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise -ENOMEM
 */
int smb2_allocate_rsp_buf(struct cifsd_work *work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	struct smb2_query_info_req *req;
	size_t small_sz = MAX_CIFS_SMALL_BUFFER_SIZE;
	size_t large_sz = SMBMaxBufSize + MAX_SMB2_HDR_SIZE;
	size_t sz = small_sz;
	int cmd = le16_to_cpu(hdr->Command);

	req = (struct smb2_query_info_req *)REQUEST_BUF(work);

	if (cmd == SMB2_READ || cmd == SMB2_IOCTL_HE ||
			cmd == SMB2_QUERY_DIRECTORY_HE)
		sz = large_sz;

	if (cmd == SMB2_QUERY_INFO_HE) {
		if (req->InfoType == SMB2_O_INFO_FILE &&
			(req->FileInfoClass == FILE_FULL_EA_INFORMATION ||
				req->FileInfoClass == FILE_ALL_INFORMATION))
			sz = large_sz;
	}

	/* allocate large response buf for chained commands */
	if (le32_to_cpu(hdr->NextCommand) > 0)
		sz = large_sz;

	work->response_buf = cifsd_alloc_response(sz);
	work->response_sz = sz;

	if (!RESPONSE_BUF(work)) {
		cifsd_err("Failed to allocate %zu bytes buffer\n", sz);
		return -ENOMEM;
	}

	return 0;
}

/**
 * smb2_set_rsp_credits() - set number of credits in response buffer
 * @work:	smb work containing smb response buffer
 */
void smb2_set_rsp_credits(struct cifsd_work *work)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	struct cifsd_tcp_conn *conn = work->conn;
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
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_check_user_session(struct cifsd_work *work)
{
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	struct cifsd_tcp_conn *conn = work->conn;
	unsigned int cmd = conn->ops->get_cmd_val(work);
	unsigned long long sess_id;

	work->sess = NULL;
	/*
	 * ECHO, KEEP_ALIVE, SMB2_NEGOTIATE, SMB2_SESSION_SETUP command does not
	 * require a session id, so no need to validate user session's for these
	 * commands.
	 */
	if (cmd == SMB2_ECHO || cmd == SMB2_NEGOTIATE ||
			cmd == SMB2_SESSION_SETUP)
		return 0;

	if (!cifsd_tcp_good(work))
		return -EINVAL;

	sess_id = le64_to_cpu(req_hdr->SessionId);
	/* Check for validity of user session */
	work->sess = cifsd_session_lookup(conn, sess_id);
	if (work->sess)
		return 1;
	cifsd_debug("Invalid user session, Uid %llu\n", sess_id);
	return -EINVAL;
}

static void destroy_previous_session(uint64_t id)
{
	cifsd_session_destroy(cifsd_session_lookup_slowpath(id));
}

/**
 * smb2_get_name() - get filename string from on the wire smb format
 * @src:	source buffer
 * @maxlen:	maxlen of source string
 * @work:	smb work containing smb request buffer
 *
 * Return:      matching converted filename on success, otherwise error ptr
 */
char *
smb2_get_name(struct cifsd_share_config *share,
	      const char *src,
	      const int maxlen,
	      struct nls_table *local_nls)
{
	char *name, *unixname;

	name = smb_strndup_from_utf16(src, maxlen, 1,
			local_nls);
	if (IS_ERR(name)) {
		cifsd_err("failed to get name %ld\n", PTR_ERR(name));
		return name;
	}

	/* change it to absolute unix name */
	convert_delimiter(name, 0);

	unixname = convert_to_unix_name(share, name);
	kfree(name);
	if (!unixname) {
		cifsd_err("can not convert absolute name\n");
		return ERR_PTR(-ENOMEM);
	}

	cifsd_debug("absoulte name = %s\n", unixname);
	return unixname;
}

/**
 * smb2_put_name() - free memory allocated for filename
 * @name:	filename pointer to be freed
 */
static void smb2_put_name(void *name)
{
	if (!IS_ERR(name))
		kfree(name);
}

int setup_async_work(struct cifsd_work *work, void (*fn)(void **), void **arg)
{
	struct smb2_hdr *rsp_hdr;
	struct cifsd_tcp_conn *conn = work->conn;
	int id;

	rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;

	id = cifds_acquire_async_msg_id(conn->async_ida);
	if (id < 0) {
		cifsd_err("Failed to alloc async message id\n");
		return id;
	}
	work->type = ASYNC;
	rsp_hdr->Id.AsyncId = work->async_id = cpu_to_le64(id);

	cifsd_debug("Send interim Response to inform asynchronous request id : %lld\n",
			work->async_id);

	work->cancel_fn = fn;
	work->cancel_argv = arg;

	spin_lock(&conn->request_lock);
	list_del_init(&work->request_entry);
	list_add_tail(&work->request_entry,
		&conn->async_requests);
	spin_unlock(&conn->request_lock);

	return 0;
}

void smb2_send_interim_resp(struct cifsd_work *work, __le32 status)
{
	struct smb2_hdr *rsp_hdr;

	rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	smb2_set_err_rsp(work);
	rsp_hdr->Status = status;

	work->multiRsp = 1;
	cifsd_tcp_write(work);
	work->multiRsp = 0;
}

/**
 * smb2_get_dos_mode() - get file mode in dos format from unix mode
 * @stat:	kstat containing file mode
 *
 * Return:      converted dos mode
 */
static __le32 smb2_get_dos_mode(struct kstat *stat, __le32 attribute)
{
	__le32 attr = 0;

	attr = (attribute & 0x00005137) | ATTR_ARCHIVE;

	if (S_ISDIR(stat->mode))
		attr = ATTR_DIRECTORY;
	else
		attr &= ~(ATTR_DIRECTORY);

	return attr;
}

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
assemble_neg_contexts(struct cifsd_tcp_conn *conn,
	struct smb2_negotiate_rsp *rsp)
{
	/* +4 is to account for the RFC1001 len field */
	char *pneg_ctxt = (char *)rsp +
			le32_to_cpu(rsp->NegotiateContextOffset) + 4;

	cifsd_debug("assemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt,
		conn->preauth_info->Preauth_HashId);
	rsp->NegotiateContextCount = cpu_to_le16(1);
	inc_rfc1001_len(rsp,
		AUTH_GSS_PADDING + sizeof(struct smb2_preauth_neg_context));

	if (conn->preauth_info->CipherId) {
		cifsd_debug("assemble SMB2_ENCRYPTION_CAPABILITIES context\n");
		/* Add 2 to size to round to 8 byte boundary */
		pneg_ctxt += sizeof(struct smb2_preauth_neg_context) + 2;
		build_encrypt_ctxt(
			(struct smb2_encryption_neg_context *)pneg_ctxt,
			conn->preauth_info->CipherId);
		rsp->NegotiateContextCount = cpu_to_le16(2);
		/* Subtract 2 to remove unused Ciphers[1] */
		inc_rfc1001_len(rsp,
			2 + sizeof(struct smb2_encryption_neg_context) - 2);
	}
}

static int
decode_preauth_ctxt(struct cifsd_tcp_conn *conn,
	struct smb2_preauth_neg_context *pneg_ctxt)
{
	int err = NT_STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;

	if (pneg_ctxt->HashAlgorithms ==
			SMB2_PREAUTH_INTEGRITY_SHA512) {
		conn->preauth_info->Preauth_HashId =
			SMB2_PREAUTH_INTEGRITY_SHA512;
		err = NT_STATUS_OK;
	}

	return err;
}

static void
decode_encrypt_ctxt(struct cifsd_tcp_conn *conn,
	struct smb2_encryption_neg_context *pneg_ctxt)
{
	int i;
	int cph_cnt = pneg_ctxt->CipherCount;

	conn->preauth_info->CipherId = 0;

	if (!encryption_enable)
		return;

	/* Support only AES CCM cipher now */
	for (i = 0; i < cph_cnt; i++) {
		if (pneg_ctxt->Ciphers[i] ==
			SMB2_ENCRYPTION_AES128_CCM) {
			cifsd_debug("Cipher ID = SMB2_ENCRYPTION_AES128_CCM\n");
			conn->preauth_info->CipherId =
				SMB2_ENCRYPTION_AES128_CCM;
			break;
		}
	}
}

static int
deassemble_neg_contexts(struct cifsd_tcp_conn *conn,
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
			if (conn->preauth_info->Preauth_HashId)
				break;

			status = decode_preauth_ctxt(conn,
				(struct smb2_preauth_neg_context *)pneg_ctxt);
			pneg_ctxt +=
				sizeof(struct smb2_preauth_neg_context) + 2;
			ContextType = (__le16 *)pneg_ctxt;
		} else if (*ContextType == SMB2_ENCRYPTION_CAPABILITIES) {
			cifsd_debug("deassemble SMB2_ENCRYPTION_CAPABILITIES context\n");
			if (conn->preauth_info->CipherId)
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
 * smb2_handle_negotiate() - handler for smb2 negotiate command
 * @work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int smb2_handle_negotiate(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_negotiate_req *req;
	struct smb2_negotiate_rsp *rsp;
	unsigned int limit;
	int rc = 0, err;
	struct timespec64 ts64;

	cifsd_debug("Recieved negotiate request\n");

	req = (struct smb2_negotiate_req *)REQUEST_BUF(work);
	rsp = (struct smb2_negotiate_rsp *)RESPONSE_BUF(work);

	conn->need_neg = false;
	if (cifsd_tcp_good(work)) {
		cifsd_err("conn->tcp_status is already in CifsGood State\n");
		work->send_no_response = 1;
		return rc;
	}

	if (req->DialectCount == 0) {
		cifsd_err("malformed packet\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out;
	}

	conn->cli_cap = req->Capabilities;
	switch (conn->dialect) {
	case SMB311_PROT_ID:
		conn->preauth_info =
			kzalloc(sizeof(struct preauth_integrity_info),
			GFP_KERNEL);
		if (!conn->preauth_info) {
			rc = -ENOMEM;
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		}

		err = deassemble_neg_contexts(conn, req);
		if (err != NT_STATUS_OK) {
			cifsd_err("deassemble_neg_contexts error(0x%x)\n", err);
			rsp->hdr.Status = err;
			rc = -EINVAL;
			goto err_out;
		}

		rc = init_smb3_11_server(conn);
		if (rc < 0) {
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			goto err_out;
		}

		cifsd_gen_preauth_integrity_hash(conn, REQUEST_BUF(work),
			conn->preauth_info->Preauth_HashValue);
		rsp->NegotiateContextOffset =
			cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
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
		cifsd_init_smb2_server_common(conn);
		break;
	case SMB2X_PROT_ID:
	case BAD_PROT_ID:
	default:
		cifsd_err("Server dialect :0x%x not supported\n", conn->dialect);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		rc = -EINVAL;
		goto err_out;
	}
	rsp->Capabilities = conn->srv_cap;

	/* For stats */
	conn->connection_type = conn->dialect;
	/* Default message size limit 64K till SMB2.0, no LargeMTU*/
	limit = SMBMaxBufSize;

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

	getnstimeofday64(&ts64);
	rsp->SystemTime = cpu_to_le64(cifs_UnixTimeToNT(
						timespec64_to_timespec(ts64)));

	rsp->ServerStartTime = 0;
	cifsd_debug("negotiate context offset %d, count %d\n",
		le32_to_cpu(rsp->NegotiateContextOffset),
		le16_to_cpu(rsp->NegotiateContextCount));

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);
	cifsd_copy_gss_neg_header(((char *)(&rsp->hdr) +
		sizeof(rsp->hdr.smb2_buf_length)) + rsp->SecurityBufferOffset);
	inc_rfc1001_len(rsp, sizeof(struct smb2_negotiate_rsp) -
		sizeof(struct smb2_hdr) - sizeof(rsp->Buffer) +
		AUTH_GSS_LENGTH);
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	conn->use_spnego = true;

	if ((server_conf.signing == CIFSD_CONFIG_OPT_AUTO ||
			server_conf.signing == CIFSD_CONFIG_OPT_DISABLED) &&
		req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
		conn->sign = true;
	else if (server_conf.signing == CIFSD_CONFIG_OPT_MANDATORY) {
		server_conf.enforced_signing = true;
		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
		conn->sign = true;
	}

	conn->srv_sec_mode = rsp->SecurityMode;
	cifsd_tcp_set_need_negotiate(work);

err_out:
	if (rc < 0)
		smb2_set_err_rsp(work);

	return rc;
}

static int match_conn_by_dialect(struct cifsd_tcp_conn *conn, void *arg)
{
	struct cifsd_tcp_conn *curr = (struct cifsd_tcp_conn *)arg;

	cifsd_debug("Connection.ClientGUID %*phN, Dialect %x\n",
		SMB2_CLIENT_GUID_SIZE, conn->ClientGUID, conn->dialect);

	if (!memcmp(conn->ClientGUID, curr->ClientGUID, SMB2_CLIENT_GUID_SIZE))
		if (conn->dialect != curr->dialect)
			return 1;

	return 0;
}

static struct preauth_session *get_preauth_session(struct cifsd_tcp_conn *conn,
		uint64_t sess_id)
{
	struct preauth_session *p_sess;

	list_for_each_entry(p_sess, &conn->preauth_sess_table, list_entry)
		if (p_sess->sess_id == sess_id)
			return p_sess;

	p_sess = kmalloc(sizeof(struct preauth_session), GFP_KERNEL);
	if (!p_sess)
		return NULL;
	p_sess->sess_id = sess_id;
	memcpy(p_sess->Preauth_HashValue,
		conn->preauth_info->Preauth_HashValue,
		PREAUTH_HASHVALUE_SIZE);
	list_add(&p_sess->list_entry, &conn->preauth_sess_table);

	return p_sess;
}

/**
 * smb2_sess_setup() - handler for smb2 session setup command
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_sess_setup(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_sess_setup_req *req;
	struct smb2_sess_setup_rsp *rsp;
	struct cifsd_session *sess;
	NEGOTIATE_MESSAGE *negblob;
	struct channel *chann = NULL;
	int rc = 0;
	unsigned char *spnego_blob;
	u16 spnego_blob_len;
	char *neg_blob;
	int neg_blob_len;
	struct preauth_session *p_sess = NULL;
	bool binding_flags = false;

	req = (struct smb2_sess_setup_req *)REQUEST_BUF(work);
	rsp = (struct smb2_sess_setup_rsp *)RESPONSE_BUF(work);

	cifsd_debug("Received request for session setup\n");

	rsp->StructureSize = cpu_to_le16(9);
	rsp->SessionFlags = 0;
	rsp->SecurityBufferOffset = cpu_to_le16(72);
	rsp->SecurityBufferLength = 0;
	inc_rfc1001_len(rsp, 9);

	if (!req->hdr.SessionId) {
		/* Check for previous session */
		if (le64_to_cpu(req->PreviousSessionId))
			destroy_previous_session(
					le64_to_cpu(req->PreviousSessionId));

		sess = cifsd_smb2_session_create();
		if (sess == NULL) {
			rc = -ENOMEM;
			goto out_err;
		}
		rsp->hdr.SessionId = cpu_to_le64(sess->id);
		cifsd_session_register(conn, sess);
	} else {
		if (multi_channel_enable &&
			req->hdr.Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
			sess = cifsd_session_lookup_slowpath(
					le64_to_cpu(req->hdr.SessionId));
			if (!(sess && sess->valid)) {
				rc = -ENOENT;
				rsp->hdr.Status =
					NT_STATUS_USER_SESSION_DELETED;
				goto out_err;
			}

			if (!(req->hdr.Flags & SMB2_FLAGS_SIGNED)) {
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

			sess = cifsd_session_lookup(conn,
					le64_to_cpu(req->hdr.SessionId));
			if (!sess) {
				rc = -EINVAL;
				rsp->hdr.Status =
					NT_STATUS_REQUEST_NOT_ACCEPTED;
				goto out_err;
			}

			if (conn->dialect >= SMB311_PROT_ID) {
				p_sess = get_preauth_session(conn,
					le64_to_cpu(req->hdr.SessionId));
				if (!p_sess) {
					rc = -EINVAL;
					rsp->hdr.Status =
						NT_STATUS_INVALID_PARAMETER;
					goto out_err;
				}
			}

			binding_flags = true;
		} else {
			sess = cifsd_session_lookup(conn,
					le64_to_cpu(req->hdr.SessionId));
			if (!sess) {
				rc = -ENOENT;
				rsp->hdr.Status =
					NT_STATUS_USER_SESSION_DELETED;
				goto out_err;
			}
		}
	}
	work->sess = sess;

	if (sess->state & SMB2_SESSION_EXPIRED)
		sess->state = SMB2_SESSION_IN_PROGRESS;

	negblob = (NEGOTIATE_MESSAGE *)((char *)&req->hdr.ProtocolId +
			le16_to_cpu(req->SecurityBufferOffset));

	if (conn->use_spnego) {
		rc = cifsd_decode_negTokenInit((char *)negblob,
				le16_to_cpu(req->SecurityBufferLength), conn);
		if (!rc) {
			cifsd_debug("negTokenInit parse err %d\n", rc);
			/* If failed, it might be negTokenTarg */
			rc = cifsd_decode_negTokenTarg((char *)negblob,
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

	if (conn->dialect == SMB311_PROT_ID) {
		__u8 *preauth_hashvalue;

		if (p_sess)
			preauth_hashvalue = p_sess->Preauth_HashValue;
		else {
			if (negblob->MessageType == NtLmNegotiate) {
				if (!sess->Preauth_HashValue) {
					sess->Preauth_HashValue =
						kmalloc(PREAUTH_HASHVALUE_SIZE,
						GFP_KERNEL);
					if (!sess->Preauth_HashValue) {
						rc = -ENOMEM;
						goto out_err;
					}
				}
				memcpy(sess->Preauth_HashValue,
					conn->preauth_info->Preauth_HashValue,
					PREAUTH_HASHVALUE_SIZE);
			}
			preauth_hashvalue = sess->Preauth_HashValue;
		}
		cifsd_gen_preauth_integrity_hash(conn, REQUEST_BUF(work),
			preauth_hashvalue);
	}

	if (negblob->MessageType == NtLmNegotiate) {
		CHALLENGE_MESSAGE *chgblob;

		cifsd_debug("negotiate phase\n");
		rc = cifsd_decode_ntlmssp_neg_blob(negblob,
			le16_to_cpu(req->SecurityBufferLength),
			sess);
		if (rc)
			goto out_err;

		chgblob = (CHALLENGE_MESSAGE *)((char *)&rsp->hdr.ProtocolId +
				rsp->SecurityBufferOffset);
		memset(chgblob, 0, sizeof(CHALLENGE_MESSAGE));

		if (conn->use_spnego) {
			int sz;

			sz = sizeof(struct _NEGOTIATE_MESSAGE) +
				(strlen(cifsd_netbios_name()) * 2 + 1 + 4) * 6;
			neg_blob = kzalloc(sz, GFP_KERNEL);
			if (!neg_blob) {
				rc = -ENOMEM;
				goto out_err;
			}
			chgblob = (CHALLENGE_MESSAGE *)neg_blob;
			neg_blob_len = cifsd_build_ntlmssp_challenge_blob(
					chgblob,
					sess);
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

			memcpy((char *)&rsp->hdr.ProtocolId +
					rsp->SecurityBufferOffset, spnego_blob,
					spnego_blob_len);
			rsp->SecurityBufferLength =
				cpu_to_le16(spnego_blob_len);
			kfree(spnego_blob);
			kfree(neg_blob);
		} else {
			neg_blob_len = cifsd_build_ntlmssp_challenge_blob(
					chgblob,
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
				((char *)&req->hdr.ProtocolId +
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
		sess->user = cifsd_alloc_user(username);
		if (!sess->user) {
			cifsd_debug("user (%s) is not present in database or guest account is not set\n",
				username);
			kfree(username);
			rc = -EINVAL;
			rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
			goto out_err;
		}
		kfree(username);

		if (user_guest(sess->user)) {
			if (conn->sign) {
				cifsd_debug("Guest login not allowed when signing enabled\n");
				rc = -EACCES;
				rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
				goto out_err;
			}

			rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST;
			sess->is_guest = true;
			if (test_user_flag(sess->user,
					   CIFSD_USER_FLAG_ANONYMOUS)) {
				rsp->SessionFlags = SMB2_SESSION_FLAG_IS_NULL;
				sess->is_anonymous = true;
				sess->is_guest	= false;
			}
		} else {
			rc = cifsd_decode_ntlmssp_auth_blob(authblob,
				le16_to_cpu(req->SecurityBufferLength),
				sess);
			if (rc) {
				set_user_flag(sess->user,
					      CIFSD_USER_FLAG_BAD_PASSWORD);
				cifsd_debug("authentication failed\n");
				rc = -EINVAL;
				rsp->hdr.Status = NT_STATUS_LOGON_FAILURE;
				goto out_err;
			}

			if (!sess->sign && ((req->SecurityMode &
				SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
				(conn->sign || server_conf.enforced_signing) ||
				(conn->dialect >= SMB30_PROT_ID))) {
				if (conn->ops->generate_signingkey) {
					rc = conn->ops->generate_signingkey(
						sess, binding_flags,
						p_sess->Preauth_HashValue);
					if (rc) {
						cifsd_debug("SMB3 signing key generation failed\n");
						rsp->hdr.Status =
							NT_STATUS_LOGON_FAILURE;
						goto out_err;
					}
				}
				sess->sign = true;
			}

			if (conn->srv_cap & SMB2_GLOBAL_CAP_ENCRYPTION &&
					conn->ops->generate_encryptionkey) {
				rc = conn->ops->generate_encryptionkey(sess);
				if (rc) {
					cifsd_debug("SMB3 encryption key generation failed\n");
					rsp->hdr.Status =
						NT_STATUS_LOGON_FAILURE;
					goto out_err;
				}
				sess->enc = true;
				rsp->SessionFlags =
					SMB2_SESSION_FLAG_ENCRYPT_DATA;
				/*
				 * signing is disable if encryption is enable
				 * on this session
				 */
				sess->sign = false;
			}

		}

		if (conn->dialect > SMB20_PROT_ID)
			if (cifsd_tcp_for_each_conn(match_conn_by_dialect,
				conn)) {
				cifsd_err("fail to verify the dialect\n");

				rc = -EPERM;
				rsp->hdr.Status =
					NT_STATUS_USER_SESSION_DELETED;
				goto out_err;
			}

		if (conn->use_spnego) {
			if (build_spnego_ntlmssp_auth_blob(&spnego_blob,
					&spnego_blob_len, 0)) {
				rc = -ENOMEM;
				goto out_err;
			}

			memcpy((char *)&rsp->hdr.ProtocolId +
				rsp->SecurityBufferOffset,
				spnego_blob, spnego_blob_len);
			rsp->SecurityBufferLength =
				cpu_to_le16(spnego_blob_len);
			kfree(spnego_blob);
			inc_rfc1001_len(rsp, rsp->SecurityBufferLength);
		}

		cifsd_tcp_set_good(work);
		sess->state = SMB2_SESSION_VALID;
		work->sess = sess;
		kfree(sess->Preauth_HashValue);
		sess->Preauth_HashValue = NULL;
	} else {
		cifsd_err("%s Invalid phase\n", __func__);
		rc = -EINVAL;
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
	}

out_err:
	if (conn->use_spnego && conn->mechToken) {
		kfree(conn->mechToken);
		conn->mechToken = NULL;
	}

	if (rc < 0 && sess) {
		cifsd_session_destroy(sess);
		work->sess = NULL;
	}

	return rc;
}

/**
 * smb2_tree_connect() - handler for smb2 tree connect command
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_tree_connect(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_tree_connect_req *req;
	struct smb2_tree_connect_rsp *rsp;
	struct cifsd_session *sess = work->sess;
	char *treename = NULL, *name = NULL;
	struct cifsd_tree_conn_status status;
	struct cifsd_share_config *share;

	req = (struct smb2_tree_connect_req *)REQUEST_BUF(work);
	rsp = (struct smb2_tree_connect_rsp *)RESPONSE_BUF(work);

	treename = smb_strndup_from_utf16(req->Buffer, req->PathLength,
					  true, conn->local_nls);
	if (IS_ERR(treename)) {
		cifsd_err("treename is NULL\n");
		status.ret = CIFSD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	name = extract_sharename(treename);
	if (IS_ERR(name)) {
		kfree(treename);
		status.ret = CIFSD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	cifsd_debug("tree connect request for tree %s treename %s\n",
		      name, treename);

	status = cifsd_tree_conn_connect(sess, name);
	if (status.ret == CIFSD_TREE_CONN_STATUS_OK)
		rsp->hdr.Id.SyncId.TreeId = status.tree_conn->id;
	else
		goto out_err1;

	share = status.tree_conn->share_conf;
	if (test_share_config_flag(share, CIFSD_SHARE_FLAG_PIPE)) {
		cifsd_debug("IPC share path request\n");
		rsp->ShareType = SMB2_SHARE_TYPE_PIPE;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_EXECUTE_LE | FILE_READ_ATTRIBUTES_LE |
			FILE_DELETE_LE | FILE_READ_CONTROL_LE |
			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			FILE_SYNCHRONIZE_LE;
	} else {
		rsp->ShareType = SMB2_SHARE_TYPE_DISK;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			FILE_WRITE_EA_LE | FILE_EXECUTE_LE | FILE_DELETE_CHILD |
			FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
			FILE_DELETE_LE | FILE_READ_CONTROL_LE |
			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			FILE_SYNCHRONIZE_LE;
	}

	status.tree_conn->maximal_access = le32_to_cpu(rsp->MaximalAccess);

	kfree(treename);
	kfree(name);
out_err1:
	rsp->StructureSize = cpu_to_le16(16);
	rsp->Capabilities = 0;
	rsp->Reserved = 0;
	/* default manual caching */
	rsp->ShareFlags = SMB2_SHAREFLAG_MANUAL_CACHING;
	inc_rfc1001_len(rsp, 16);

	switch (status.ret) {
	case CIFSD_TREE_CONN_STATUS_OK:
		rsp->hdr.Status = NT_STATUS_OK;
		break;
	case CIFSD_TREE_CONN_STATUS_NO_SHARE:
		rsp->hdr.Status = NT_STATUS_BAD_NETWORK_PATH;
		break;
	case -ENOMEM:
	case CIFSD_TREE_CONN_STATUS_NOMEM:
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		break;
	case CIFSD_TREE_CONN_STATUS_TOO_MANY_CONNS:
	case CIFSD_TREE_CONN_STATUS_TOO_MANY_SESSIONS:
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		break;
	case -EINVAL:
	case CIFSD_TREE_CONN_STATUS_ERROR:
		if (IS_ERR(treename) || IS_ERR(name))
			rsp->hdr.Status = NT_STATUS_BAD_NETWORK_NAME;
		else
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
	}
	return status.ret;
}

/**
 * smb2_create_open_flags() - convert smb open flags to unix open flags
 * @file_present:	is file already present
 * @access:		file access flags
 * @disposition:	file disposition flags
 * @work:	smb work containing smb request buffer
 *
 * Return:      file open flags
 */
static int smb2_create_open_flags(bool file_present, __le32 access,
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
 * @work:	smb work containing request buffer
 *
 * Return:      0
 */
int smb2_tree_disconnect(struct cifsd_work *work)
{
	struct smb2_tree_disconnect_req *req;
	struct smb2_tree_disconnect_rsp *rsp;
	struct cifsd_session *sess = work->sess;
	struct cifsd_tree_connect *tcon = work->tcon;

	req = (struct smb2_tree_disconnect_req *)REQUEST_BUF(work);
	rsp = (struct smb2_tree_disconnect_rsp *)RESPONSE_BUF(work);

	rsp->StructureSize = cpu_to_le16(4);
	inc_rfc1001_len(rsp, 4);

	cifsd_debug("%s : request\n", __func__);

	if (!tcon) {
		cifsd_debug("Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);
		rsp->hdr.Status = NT_STATUS_NETWORK_NAME_DELETED;
		smb2_set_err_rsp(work);
		return 0;
	}

	close_opens_from_fibtable(sess, tcon);
	cifsd_tree_conn_disconnect(sess, tcon);
	return 0;
}

/**
 * smb2_session_logoff() - handler for session log off request
 * @work:	smb work containing request buffer
 *
 * Return:      0
 */
int smb2_session_logoff(struct cifsd_work *work)
{

	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_logoff_req *req;
	struct smb2_logoff_rsp *rsp;
	struct cifsd_session *sess = work->sess;

	req = (struct smb2_logoff_req *)REQUEST_BUF(work);
	rsp = (struct smb2_logoff_rsp *)RESPONSE_BUF(work);

	rsp->StructureSize = cpu_to_le16(4);
	inc_rfc1001_len(rsp, 4);

	cifsd_debug("%s : request\n", __func__);

	/* Got a valid session, set connection state */
	WARN_ON(sess->conn != conn);

	/* setting CifsExiting here may race with start_tcp_sess */
	cifsd_tcp_set_need_reconnect(work);

	destroy_fidtable(sess);

	cifsd_tcp_conn_wait_idle(conn);

	if (cifsd_tree_conn_session_logoff(sess)) {
		cifsd_debug("Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);
		rsp->hdr.Status = NT_STATUS_NETWORK_NAME_DELETED;
		smb2_set_err_rsp(work);
		return 0;
	}

	sess->valid = 0;
	sess->state = SMB2_SESSION_EXPIRED;

	cifsd_free_user(sess->user);
	sess->user = NULL;

	/* let start_tcp_sess free connection info now */
	cifsd_tcp_set_need_negotiate(work);
	return 0;
}

/**
 * create_smb2_pipe() - create IPC pipe
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
static int create_smb2_pipe(struct cifsd_work *work)
{
	struct smb2_create_rsp *rsp;
	struct smb2_create_req *req;
	int id;
	int err;
	char *name;

	rsp = (struct smb2_create_rsp *)RESPONSE_BUF(work);
	req = (struct smb2_create_req *)REQUEST_BUF(work);

	name = smb_strndup_from_utf16(req->Buffer, req->NameLength, 1,
				work->conn->local_nls);
	if (IS_ERR(name)) {
		rsp->hdr.Status = NT_STATUS_NO_MEMORY;
		err = PTR_ERR(name);
		goto out;
	}

	id = cifsd_session_rpc_open(work->sess, name);
	if (id < 0)
		cifsd_err("Unable to open RPC pipe: %d\n", id);

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

out:
	smb2_set_err_rsp(work);
	return err;
}

#define DURABLE_RECONN_V2	1
#define DURABLE_RECONN		2
#define DURABLE_REQ_V2		3
#define DURABLE_REQ		4
#define APP_INSTANCE_ID		5

struct durable_info {
	struct cifsd_file *fp;
	int type;
	int reconnected;
	int persistent;
	int timeout;
	char *CreateGuid;
	char *app_id;
};

static int parse_durable_handle_context(struct cifsd_tcp_conn *conn,
	struct smb2_create_req *req, struct lease_ctx_info *lc,
	struct durable_info *d_info)
{
	struct create_context *context;
	int i, err = 0;
	uint64_t persistent_id = 0;
	int req_op_level;
	char *durable_arr[] = {"DH2C", "DHnC", "DH2Q", "DHnQ",
		SMB2_CREATE_APP_INSTANCE_ID};

	req_op_level = req->RequestedOplockLevel;
	for (i = 1; i <= 5; i++) {
		context = smb2_find_context_vals(req, durable_arr[i - 1]);
		if (IS_ERR(context)) {
			err = PTR_ERR(context);
			if (err == -EINVAL) {
				cifsd_err("bad name length\n");
				goto out;
			}
			err = 0;
			continue;
		}

		switch (i) {
		case DURABLE_RECONN_V2:
		{
			struct create_durable_reconn_v2_req *recon_v2;

			recon_v2 =
				(struct create_durable_reconn_v2_req *)context;
			persistent_id = le64_to_cpu(
					recon_v2->Fid.PersistentFileId);
			d_info->fp = cifsd_get_global_fp(persistent_id);
			if (!d_info->fp) {
				cifsd_err("Failed to get Durable handle state\n");
				err = -EBADF;
				goto out;
			}

			if (memcmp(d_info->fp->create_guid,
				recon_v2->CreateGuid,
				SMB2_CREATE_GUID_SIZE)) {
				err = -EBADF;
				goto out;
			}
			d_info->type = i;
			d_info->reconnected = 1;
			cifsd_debug("reconnect v2 Persistent-id from reconnect = %llu\n",
					persistent_id);
			break;
		}
		case DURABLE_RECONN:
		{
			struct create_durable_reconn_req *recon;

			if (d_info->type == DURABLE_RECONN_V2 ||
				d_info->type == DURABLE_REQ_V2) {
				err = -EINVAL;
				goto out;
			}

			recon =
				(struct create_durable_reconn_req *)context;
			persistent_id = le64_to_cpu(
					recon->Data.Fid.PersistentFileId);
			d_info->fp = cifsd_get_global_fp(persistent_id);
			if (!d_info->fp) {
				cifsd_err("Failed to get Durable handle state\n");
				err = -EBADF;
				goto out;
			}
			d_info->type = i;
			d_info->reconnected = 1;
			cifsd_debug("reconnect Persistent-id from reconnect = %llu\n",
					persistent_id);
			break;
		}
		case DURABLE_REQ_V2:
		{
			struct create_durable_req_v2 *durable_v2_blob;

			if (d_info->type == DURABLE_RECONN ||
				d_info->type == DURABLE_RECONN_V2) {
				err = -EINVAL;
				goto out;
			}

			durable_v2_blob =
				(struct create_durable_req_v2 *)context;
			cifsd_debug("Request for durable v2 open\n");
			d_info->fp =
				lookup_fp_clguid(durable_v2_blob->CreateGuid);
			if (d_info->fp) {
				if (!memcmp(conn->ClientGUID,
					d_info->fp->client_guid,
					SMB2_CLIENT_GUID_SIZE)) {
					if (!(le32_to_cpu(req->hdr.Flags) &
						SMB2_FLAGS_REPLAY_OPERATIONS)) {
						err = -EMFILE;
						goto out;
					}

					d_info->fp->conn = conn;
					d_info->reconnected = 1;
					goto out;
				}
			}
			if (((lc &&
				(lc->req_state & SMB2_LEASE_HANDLE_CACHING)) ||
				(req_op_level == SMB2_OPLOCK_LEVEL_BATCH))) {
				d_info->CreateGuid =
					durable_v2_blob->CreateGuid;
				d_info->persistent =
					le32_to_cpu(durable_v2_blob->Flags);
				d_info->timeout =
					le32_to_cpu(durable_v2_blob->Timeout);
				d_info->type = i;
			}
			break;
		}
		case DURABLE_REQ:
			if (d_info->type == DURABLE_RECONN)
				goto out;
			if (d_info->type == DURABLE_RECONN_V2 ||
				d_info->type == DURABLE_REQ_V2) {
				err = -EINVAL;
				goto out;
			}

			if (((lc &&
				(lc->req_state & SMB2_LEASE_HANDLE_CACHING)) ||
				(req_op_level == SMB2_OPLOCK_LEVEL_BATCH))) {
				cifsd_debug("Request for durable open\n");
				d_info->type = i;
			}
			break;
		case APP_INSTANCE_ID:
		{
			struct create_app_inst_id *app_inst_id;
			struct cifsd_file *fp;

			app_inst_id = (struct create_app_inst_id *)context;
			fp = lookup_fp_app_id(app_inst_id->AppInstanceId);
			if (fp)
				close_id(fp->sess, fp->volatile_id,
						fp->persistent_id);
			d_info->app_id = app_inst_id->AppInstanceId;
			break;
		}
		default:
			break;
		}
	}

out:

	return err;
}

/**
 * smb2_set_ea() - handler for setting extended attributes using set
 *		info command
 * @eabuf:	set info command buffer
 * @path:	dentry path for get ea
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_set_ea(struct smb2_ea_info *eabuf, struct path *path)
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
			rc = cifsd_vfs_casexattr_len(path->dentry,
						     attr_name,
						     XATTR_USER_PREFIX_LEN +
						     eabuf->EaNameLength);

			/* delete the EA only when it exits */
			if (rc > 0) {
				rc = cifsd_vfs_remove_xattr(path->dentry,
							    attr_name);

				if (rc < 0) {
					cifsd_err("remove xattr failed(%d)\n",
						rc);
					break;
				}
			}

			/* if the EA doesn't exist, just do nothing. */
			rc = 0;
		} else {
			rc = cifsd_vfs_setxattr(path->dentry, attr_name, value,
					le16_to_cpu(eabuf->EaValueLength), 0);
			if (rc < 0) {
				cifsd_err("cifsd_vfs_setxattr is failed(%d)\n",
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

static inline int check_context_err(void *ctx, char *str)
{
	int err;

	err = PTR_ERR(ctx);
	cifsd_debug("find context %s err %d\n", str, err);

	if (err == -EINVAL) {
		cifsd_err("bad name length\n");
		return err;
	}

	return 0;
}

/**
 * smb2_open() - handler for smb file open request
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_open(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct cifsd_session *sess = work->sess;
	struct cifsd_tree_connect *tcon = work->tcon;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp, *rsp_org;
	struct path path, lpath;
	struct cifsd_share_config *share;
	struct cifsd_inode *ci = NULL, *f_parent_ci;
	struct cifsd_file *fp = NULL;
	struct file *filp = NULL, *lfilp = NULL;
	struct kstat stat;
	struct create_context *context;
	struct lease_ctx_info *lc = NULL;
	struct create_context *lease_ccontext = NULL, *durable_ccontext = NULL,
		*mxac_ccontext = NULL, *disk_id_ccontext = NULL;
	struct create_ea_buf_req *ea_buf = NULL;
	umode_t mode = 0;
	__le32 *next_ptr = NULL;
	uint64_t persistent_id = 0;
	int req_op_level = 0, open_flags = 0, file_info = 0;
	int volatile_id = 0;
	int rc = 0, len = 0;
	int maximal_access = 0, contxt_cnt = 0, query_disk_id = 0;
	int xattr_stream_size = 0, s_type = 0, store_stream = 0;
	int next_off = 0;
	char *name = NULL, *lname = NULL, *pathname = NULL;
	char *stream_name = NULL, *xattr_stream_name = NULL;
	bool file_present = false, created = false, islink = false;
	struct durable_info d_info;
	int share_ret, need_truncate = 0;
	unsigned int tree_id;
	u64 time;

	req = (struct smb2_create_req *)REQUEST_BUF(work);
	rsp = (struct smb2_create_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_create_req *)((char *)req +
					work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_create_rsp *)((char *)rsp +
					work->next_smb2_rsp_hdr_off);
	}

	if (le32_to_cpu(req->hdr.NextCommand) &&
			!work->next_smb2_rcv_hdr_off &&
			(le32_to_cpu(req->hdr.Flags) &
			 SMB2_FLAGS_RELATED_OPERATIONS)) {
		cifsd_debug("invalid flag in chained command\n");
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
		return -EINVAL;
	}

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_PIPE)) {
		cifsd_debug("IPC pipe create request\n");
		return create_smb2_pipe(work);
	}

	tree_id = req->hdr.Id.SyncId.TreeId;
	if (req->NameLength) {
		struct cifsd_tree_connect *tree_conn;

		tree_conn = cifsd_tree_conn_lookup(sess, tree_id);
		if (!tree_conn) {
			rc = -ENOENT;
			goto err_out1;
		}

		if ((req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&
			*(char *)req->Buffer == '\\') {
			cifsd_err("not allow directory name included leadning slash\n");
			rc = -EINVAL;
			goto err_out1;
		}

		name = smb2_get_name(tree_conn->share_conf,
				     req->Buffer,
				     req->NameLength,
				     work->conn->local_nls);
		if (IS_ERR(name)) {
			rc = PTR_ERR(name);
			if (rc != -ENOMEM)
				rc = -ENOENT;
			goto err_out1;
		}
	} else {
		share = tcon->share_conf;
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

	if (cifsd_share_veto_filename(tcon->share_conf, name)) {
		rc = -ENOENT;
		cifsd_debug("file(%s) open is not allowed by setting as veto file\n",
			name);
		goto err_out1;
	}

	req_op_level = req->RequestedOplockLevel;
	memset(&d_info, 0, sizeof(struct durable_info));
	if (durable_enable && req->CreateContextsOffset) {
		lc = parse_lease_state(req);
		rc = parse_durable_handle_context(conn, req, lc, &d_info);
		if (rc) {
			cifsd_err("error parsing durable handle context\n");
			goto err_out1;
		}

		if (d_info.reconnected) {
			fp = d_info.fp;
			rc = smb2_check_durable_oplock(d_info.fp, lc, name);
			if (rc)
				goto err_out;
			rc = cifsd_reconnect_durable_fp(sess, d_info.fp, tcon);
			if (rc)
				goto err_out;
			file_info = FILE_OPENED;
			fp = d_info.fp;
			goto reconnected;
		}
	} else {
		if (oplocks_enable && req_op_level == SMB2_OPLOCK_LEVEL_LEASE)
			lc = parse_lease_state(req);
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

	if (req->CreateContextsOffset) {
		/* Parse non-durable handle create contexts */
		context = smb2_find_context_vals(req, SMB2_CREATE_EA_BUFFER);
		if (IS_ERR(context)) {
			rc = check_context_err(context, SMB2_CREATE_EA_BUFFER);
			if (rc < 0)
				goto err_out1;
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
			rc = check_context_err(context,
				SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST);
			if (rc < 0)
				goto err_out1;
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
			rc = check_context_err(context,
				SMB2_CREATE_TIMEWARP_REQUEST);
			if (rc < 0)
				goto err_out1;
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
		rc = cifsd_vfs_kern_path(name, 0, &path, 1);
	} else {
		/*
		* Use LOOKUP_FOLLOW to follow the path of
		* symlink in path buildup
		*/
		rc = cifsd_vfs_kern_path(name, LOOKUP_FOLLOW, &path, 1);
		if (rc) { /* Case for broken link ?*/
			rc = cifsd_vfs_kern_path(name, 0, &path, 1);
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
		cifsd_debug("open() argument is a directory: %s, %x\n",
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

	if (durable_enable && file_present)
		file_present = close_disconnected_handle(path.dentry->d_inode);

	if (test_tree_conn_flag(tcon, CIFSD_TREE_CONN_FLAG_WRITABLE))
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
				rc = cifsd_vfs_mkdir(name, mode);
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
				rc = cifsd_vfs_create(name, mode);
				if (rc) {
					rsp->hdr.Status =
						NT_STATUS_UNEXPECTED_IO_ERROR;
					kfree(name);
					return rc;
				}
			}

			rc = cifsd_vfs_kern_path(name, 0, &path, 0);
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
			if (test_tree_conn_flag(tcon,
					CIFSD_TREE_CONN_FLAG_WRITABLE)) {
				cifsd_debug("returning as file does not exist\n");
				rsp->hdr.Status =
					NT_STATUS_OBJECT_NAME_NOT_FOUND;
			} else {
				cifsd_debug("returning as user does not have permission to write\n");
				rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
			}
			smb2_set_err_rsp(work);
			return 0;
		}
	}

	f_parent_ci = cifsd_inode_lookup_by_vfsinode(path.dentry->d_parent->d_inode);
	if (f_parent_ci) {
		if (f_parent_ci->m_flags & S_DEL_PENDING) {
			atomic_dec(&f_parent_ci->m_count);
			rc = -EBUSY;
			goto err_out;
		}
		atomic_dec(&f_parent_ci->m_count);
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
		rc = cifsd_vfs_kern_path(lname, 0, &lpath, 0);
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

	cifsd_vfs_set_fadvise(filp, le32_to_cpu(req->CreateOptions));

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
	INIT_LIST_HEAD(&fp->blocked_works);

	/* Get Persistent-ID */
	persistent_id = cifsd_insert_in_global_table(sess, fp);
	if (persistent_id < 0) {
		cifsd_err("persistent id insert failed\n");
		rc = -ENOMEM;
		goto err_out;
	}
	fp->persistent_id = persistent_id;

	if (stream_name) {
		xattr_stream_size = construct_xattr_stream_name(stream_name,
			&xattr_stream_name);

		fp->is_stream = true;
		fp->stream.name = xattr_stream_name;
		fp->stream.type = s_type;
		fp->stream.size = xattr_stream_size;

		/* Check if there is stream prefix in xattr space */
		rc = cifsd_vfs_casexattr_len(path.dentry,
					     xattr_stream_name,
					     xattr_stream_size);
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

	fp->f_ci = ci = cifsd_inode_get(fp);
	if (!ci) {
		rc = -ENOMEM;
		goto err_out;
	}

	if (req->CreateContextsOffset) {
		struct create_alloc_size_req *az_req;

		az_req = (struct create_alloc_size_req *)
				smb2_find_context_vals(req,
				SMB2_CREATE_ALLOCATION_SIZE);
		if (IS_ERR(az_req)) {
			rc = check_context_err(az_req,
				SMB2_CREATE_ALLOCATION_SIZE);
			if (rc < 0)
				goto err_out1;
		} else {
			loff_t alloc_size = le64_to_cpu(az_req->AllocationSize);
			int err;

			cifsd_debug("request smb2 create allocate size : %llu\n",
				alloc_size);
			err = cifsd_vfs_alloc_size(work, fp, alloc_size);
			if (err < 0)
				cifsd_debug("cifsd_vfs_alloc_size is failed : %d\n",
					err);
		}

		context = smb2_find_context_vals(req,
				SMB2_CREATE_QUERY_ON_DISK_ID);
		if (IS_ERR(context)) {
			rc = check_context_err(context,
				SMB2_CREATE_QUERY_ON_DISK_ID);
			if (rc < 0)
				goto err_out1;
		} else {
			cifsd_debug("get query on disk id context\n");
			query_disk_id = 1;
		}

#ifdef CONFIG_CIFSD_ACL
		context = smb2_find_context_vals(req, SMB2_CREATE_SD_BUFFER);
		if (IS_ERR(context)) {
			rc = check_context_err(context, SMB2_CREATE_SD_BUFFER);
			if (rc < 0)
				goto err_out1;
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

	fp->attrib_only = !(req->DesiredAccess & ~(FILE_READ_ATTRIBUTES_LE |
			FILE_WRITE_ATTRIBUTES_LE | FILE_SYNCHRONIZE_LE));
	if (!S_ISDIR(file_inode(filp)->i_mode) && open_flags & O_TRUNC
		&& !fp->attrib_only && !stream_name) {
		if (oplocks_enable)
			smb_break_all_oplock(work, fp);
		need_truncate = 1;
	}

	generic_fillattr(path.dentry->d_inode, &stat);

	/* Check delete pending among previous fp before oplock break */
	if (ci->m_flags & S_DEL_PENDING) {
		rc = -EBUSY;
		goto err_out;
	}

	share_ret = smb_check_shared_mode(fp->filp, fp);
	if (!oplocks_enable || (req_op_level == SMB2_OPLOCK_LEVEL_LEASE &&
		!(conn->srv_cap & SMB2_GLOBAL_CAP_LEASING))) {
		if (share_ret < 0 && !S_ISDIR(FP_INODE(fp)->i_mode)) {
			rc = share_ret;
			goto err_out;
		}
	} else {
		if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE) {
			req_op_level = smb2_map_lease_to_oplock(lc->req_state);
			cifsd_debug("lease req for(%s) req oplock state 0x%x, lease state 0x%x\n",
					name, req_op_level, lc->req_state);
			rc = find_same_lease_key(sess, ci, lc);
			if (rc)
				goto err_out;
		}

		rc = smb_grant_oplock(work, req_op_level,
			persistent_id, fp, tree_id, lc, share_ret);
		if (rc < 0)
			goto err_out;
	}

	if (le32_to_cpu(req->CreateOptions) & FILE_DELETE_ON_CLOSE_LE) {
		if (fp->is_stream)
			ci->m_flags |= S_DEL_ON_CLS_STREAM;
		else {
			fp->delete_on_close = 1;
			if (file_info == F_CREATED)
				fp->f_ci->m_flags |= S_DEL_ON_CLS;
		}
	}

	if (need_truncate) {
		rc = vfs_truncate(&path, 0);
		if (rc) {
			cifsd_err("vfs_truncate failed, rc %d\n", rc);
			goto err_out;
		}

		/* Don't truncate stream names on stream name */
		rc = cifsd_vfs_truncate_xattr(path.dentry, stream_name != NULL);
		if (rc) {
			cifsd_err("cifsd_vfs_truncate_xattr is failed, rc %d\n",
					rc);
			goto err_out;
		}
	}

	spin_lock(&ci->m_lock);
	/* Add fp to master fp list. */
	list_add(&fp->node, &ci->m_fp_list);
	spin_unlock(&ci->m_lock);

	if ((file_info != FILE_OPENED) && !S_ISDIR(file_inode(filp)->i_mode)) {
		/* Create default data stream in xattr */
		cifsd_vfs_setxattr(path.dentry, XATTR_NAME_STREAM,
				   NULL, 0, 0);
	}

	if (store_stream) {
		rc = cifsd_vfs_setxattr(path.dentry, xattr_stream_name,
					NULL, 0, 0);
		if (rc < 0) {
			cifsd_err("failed to store stream name in xattr, rc :%d\n",
					rc);
		}
		file_info = FILE_CREATED;
		rc = 0;
	}

	if (created) {
		i_uid_write(FP_INODE(fp), user_uid(sess->user));
		i_gid_write(FP_INODE(fp), user_gid(sess->user));
	}

	fp->create_time = cifs_UnixTimeToNT(from_kern_timespec(stat.ctime));
	if (!created) {
		if (test_share_config_flag(tcon->share_conf,
					   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
			char *create_time = NULL;

			rc = cifsd_vfs_getxattr(path.dentry,
						XATTR_NAME_CREATION_TIME,
						&create_time);

			if (rc > 0)
				fp->create_time = *((__u64 *)create_time);

			cifsd_free(create_time);
			rc = 0;
		}
	} else {
		if (test_share_config_flag(tcon->share_conf,
					   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
			rc = cifsd_vfs_setxattr(path.dentry,
						XATTR_NAME_CREATION_TIME,
						(void *)&fp->create_time,
						CREATIOM_TIME_LEN,
						0);
			if (rc)
				cifsd_debug("failed to store creation time in EA\n");
			rc = 0;
		}
	}

	fp->fattr = cpu_to_le32(smb2_get_dos_mode(&stat,
		le32_to_cpu(req->FileAttributes)));

	if (!created) {
		fp->fattr &= ~(FILE_ATTRIBUTE_HIDDEN_LE | FILE_ATTRIBUTE_SYSTEM_LE);

		/* get FileAttributes from XATTR_NAME_FILE_ATTRIBUTE */
		if (test_share_config_flag(tcon->share_conf,
					   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
			char *file_attribute = NULL;

			rc = cifsd_vfs_getxattr(path.dentry,
						XATTR_NAME_FILE_ATTRIBUTE,
						&file_attribute);
			if (rc > 0)
				fp->fattr = *((__le32 *)file_attribute);

			cifsd_free(file_attribute);
			rc = 0;
		}
	} else {
		/* set XATTR_NAME_FILE_ATTRIBUTE with req->FileAttributes */
		if (test_share_config_flag(tcon->share_conf,
					   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
			rc = cifsd_vfs_setxattr(path.dentry,
						XATTR_NAME_FILE_ATTRIBUTE,
						(void *)&fp->fattr,
						FILE_ATTRIBUTE_LEN,
						0);
			if (rc)
				cifsd_debug("failed to store file attribute in EA\n");
			rc = 0;
		}
	}

	memcpy(fp->client_guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);

	if (d_info.type) {
		if (d_info.type == DURABLE_REQ_V2 &&
			d_info.persistent)
			fp->is_persistent = 1;
		else
			fp->is_durable = 1;

		if (d_info.type == DURABLE_REQ_V2) {
			memcpy(fp->create_guid, d_info.CreateGuid,
				SMB2_CREATE_GUID_SIZE);
			if (d_info.timeout)
				fp->durable_timeout = d_info.timeout;
			else
				fp->durable_timeout = 1600;
			if (d_info.app_id)
				memcpy(fp->app_instance_id,
					d_info.app_id, 16);
		}
	}

reconnected:
	generic_fillattr(FP_INODE(fp), &stat);

	rsp->StructureSize = cpu_to_le16(89);
	rsp->OplockLevel = fp->f_opinfo != NULL ? fp->f_opinfo->level : 0;
	rsp->Reserved = 0;
	rsp->CreateAction = file_info;
	rsp->CreationTime = cpu_to_le64(fp->create_time);
	time = cifs_UnixTimeToNT(from_kern_timespec(stat.atime));
	rsp->LastAccessTime = cpu_to_le64(time);
	time = cifs_UnixTimeToNT(from_kern_timespec(stat.mtime));
	rsp->LastWriteTime = cpu_to_le64(time);
	time = cifs_UnixTimeToNT(from_kern_timespec(stat.ctime));
	rsp->ChangeTime = cpu_to_le64(time);
	rsp->AllocationSize = S_ISDIR(stat.mode) ? 0 :
		cpu_to_le64(stat.blocks << 9);
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

	if (d_info.type == DURABLE_REQ || d_info.type == DURABLE_REQ_V2) {
		durable_ccontext = (struct create_context *)(rsp->Buffer +
			rsp->CreateContextsLength);
		contxt_cnt++;
		if (d_info.type == DURABLE_REQ) {
			create_durable_rsp_buf(rsp->Buffer +
				rsp->CreateContextsLength);
			rsp->CreateContextsLength +=
				cpu_to_le32(conn->vals->create_durable_size);
			inc_rfc1001_len(rsp_org,
				conn->vals->create_durable_size);
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
			stat.ino, tcon->id);
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
		else if (rc == -EPERM)
			rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
		else if (rc == -EBUSY)
			rsp->hdr.Status = NT_STATUS_DELETE_PENDING;
		else if (rc == -EBADF)
			rsp->hdr.Status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		else if (rc == -EMFILE)
			rsp->hdr.Status = NT_STATUS_DUPLICATE_OBJECTID;
		else if (rc == -ENXIO)
			rsp->hdr.Status = NT_STATUS_NO_SUCH_DEVICE;
		if (!rsp->hdr.Status)
			rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;

		if (ci && atomic_dec_and_test(&ci->m_count))
			cifsd_inode_free(ci);
		if (volatile_id > 0) {
			delete_id_from_fidtable(sess, volatile_id);
			cifsd_close_id(&sess->fidtable, volatile_id);
		}
		if (filp && !IS_ERR(filp))
			filp_close(filp, (struct files_struct *)filp);

		smb2_set_err_rsp(work);
	} else
		conn->stats.open_files_count++;

	return 0;
}

/**
 * smb2_populate_readdir_entry() - encode directory entry in smb2 response buffer
 * @conn:	TCP server instance of connection
 * @info_level:	smb information level
 * @d_info:	structure included variables for query dir
 * @cifsd_kstat:	cifsd wrapper of dirent stat information
 *
 * if directory has many entries, find first can't read it fully.
 * find next might be called multiple times to read remaining dir entries
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_populate_readdir_entry(struct cifsd_tcp_conn *conn,
	int info_level, struct cifsd_dir_info *d_info,
	struct cifsd_kstat *cifsd_kstat)
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
			&d_info->data_count, 7, false);
		if (!utfname)
			break;

		ffdinfo = (FILE_FULL_DIRECTORY_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		ffdinfo->FileNameLength = cpu_to_le32(name_len);
		ffdinfo->EaSize = 0;

		memcpy(ffdinfo->FileName, utfname, name_len);
		ffdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_BOTH_DIRECTORY_INFORMATION:
	{
		FILE_BOTH_DIRECTORY_INFO *fbdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_BOTH_DIRECTORY_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7, false);
		if (!utfname)
			break;
		fbdinfo = (FILE_BOTH_DIRECTORY_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		fbdinfo->FileNameLength = cpu_to_le32(name_len);
		fbdinfo->EaSize = 0;
		fbdinfo->ShortNameLength = cifsd_extract_shortname(conn,
						d_info->name,
						&(fbdinfo->ShortName[0]));
		fbdinfo->Reserved = 0;

		memcpy(fbdinfo->FileName, utfname, name_len);
		fbdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_DIRECTORY_INFORMATION:
	{
		FILE_DIRECTORY_INFO *fdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_DIRECTORY_INFO), conn->local_nls, &name_len,
			&next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7, false);
		if (!utfname)
			break;

		fdinfo = (FILE_DIRECTORY_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		fdinfo->FileNameLength = cpu_to_le32(name_len);

		memcpy(fdinfo->FileName, utfname, name_len);
		fdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILE_NAMES_INFORMATION:
	{
		FILE_NAMES_INFO *fninfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_NAMES_INFO), conn->local_nls, &name_len,
			&next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7, false);
		if (!utfname)
			break;

		fninfo = (FILE_NAMES_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		fninfo->FileNameLength = cpu_to_le32(name_len);

		memcpy(fninfo->FileName, utfname, name_len);
		fninfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILEID_FULL_DIRECTORY_INFORMATION:
	{
		SEARCH_ID_FULL_DIR_INFO *dinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(SEARCH_ID_FULL_DIR_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7, false);
		if (!utfname)
			break;

		dinfo = (SEARCH_ID_FULL_DIR_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		dinfo->FileNameLength = cpu_to_le32(name_len);
		dinfo->EaSize = 0;
		dinfo->Reserved = 0;
		dinfo->UniqueId = cpu_to_le64(cifsd_kstat->kstat->ino);

		memcpy(dinfo->FileName, utfname, name_len);
		dinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	{
		FILE_ID_BOTH_DIRECTORY_INFO *fibdinfo;

		utfname = convname_updatenextoffset(d_info->name, PATH_MAX,
			sizeof(FILE_ID_BOTH_DIRECTORY_INFO), conn->local_nls,
			&name_len, &next_entry_offset, &d_info->out_buf_len,
			&d_info->data_count, 7, false);
		if (!utfname)
			break;

		fibdinfo = (FILE_ID_BOTH_DIRECTORY_INFO *)
				cifsd_vfs_init_kstat(&d_info->bufptr, cifsd_kstat);
		fibdinfo->FileNameLength = cpu_to_le32(name_len);
		fibdinfo->EaSize = 0;
		fibdinfo->UniqueId = cpu_to_le64(cifsd_kstat->kstat->ino);
		fibdinfo->ShortNameLength = cifsd_extract_shortname(conn,
						d_info->name,
						&(fibdinfo->ShortName[0]));
		fibdinfo->Reserved = 0;
		fibdinfo->Reserved2 = cpu_to_le16(0);

		memcpy(fibdinfo->FileName, utfname, name_len);
		fibdinfo->NextEntryOffset = next_entry_offset;
		break;
	}
	default:
		cifsd_err("%s: failed\n", __func__);
		return -EOPNOTSUPP;
	}

	if (utfname) {
		d_info->last_entry_offset = d_info->data_count;
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

/**
 * smb2_query_dir() - handler for smb2 readdir i.e. query dir command
 * @work:	smb work containing query dir request buffer
 *
 * Return:	0
 */
int smb2_query_dir(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_query_directory_req *req;
	struct smb2_query_directory_rsp *rsp, *rsp_org;
	struct cifsd_share_config *share = work->tcon->share_conf;
	struct cifsd_dirent *de;
	struct cifsd_file *dir_fp;
	struct cifsd_dir_info d_info;
	int reclen = 0;
	int rc = 0;
	struct kstat kstat;
	struct cifsd_kstat cifsd_kstat;
	char *dirpath, *srch_ptr = NULL, *path = NULL;
	unsigned char srch_flag;
	struct cifsd_readdir_data r_data = {
		.ctx.actor = cifsd_fill_dirent,
	};

	req = (struct smb2_query_directory_req *)REQUEST_BUF(work);
	rsp = (struct smb2_query_directory_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_directory_req *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_directory_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	}

	dir_fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
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
		rc = cifsd_populate_dot_dotdot_entries(conn,
						req->FileInformationClass,
						dir_fp,
						&d_info,
						srch_ptr,
						smb2_populate_readdir_entry);
		if (rc)
			goto err_out;
	}

	while (d_info.out_buf_len > 0) {
		if (dir_fp->dirent_offset >= dir_fp->readdir_data.used) {
			dir_fp->dirent_offset = 0;
			r_data.used = 0;
			r_data.full = 0;
			rc = cifsd_vfs_readdir(dir_fp->filp,
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

			de = (struct cifsd_dirent *)
				((char *)dir_fp->readdir_data.dirent);
		} else {
			de = (struct cifsd_dirent *)
				((char *)dir_fp->readdir_data.dirent +
				 dir_fp->dirent_offset);
		}

		reclen = ALIGN(sizeof(struct cifsd_dirent) + de->namelen,
				sizeof(__le64));
		dir_fp->dirent_offset += reclen;

		cifsd_kstat.kstat = &kstat;
		d_info.name = cifsd_vfs_readdir_name(work, &cifsd_kstat, de,
			dirpath);
		if (IS_ERR(d_info.name)) {
			rc = PTR_ERR(d_info.name);
			cifsd_debug("Err while dirent read rc = %d\n", rc);
			rc = 0;
			continue;
		}

		/* dot and dotdot entries are already reserved */
		if (!strcmp(".", d_info.name) || !strcmp("..", d_info.name)) {
			kfree(d_info.name);
			continue;
		}

		if (cifsd_share_veto_filename(share, d_info.name)) {
			cifsd_debug("file(%s) is invisible by setting as veto file\n",
				d_info.name);
			continue;
		}

		if (is_matched(d_info.name, srch_ptr)) {
			rc = smb2_populate_readdir_entry(conn,
				req->FileInformationClass, &d_info, &cifsd_kstat);
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
		if (srch_flag & SMB2_RETURN_SINGLE_ENTRY)
			rsp->hdr.Status = NT_STATUS_NO_SUCH_FILE;
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
		((char *)rsp->Buffer + d_info.last_entry_offset))
		->NextEntryOffset = 0;

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
	smb2_set_err_rsp(work);

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
static int buffer_check_err(int reqOutputBufferLength,
	struct smb2_query_info_rsp *rsp, int infoclass_size)
{
	if (reqOutputBufferLength < rsp->OutputBufferLength) {
		if (reqOutputBufferLength < infoclass_size) {
			cifsd_err("Invalid Buffer Size Requested\n");
			rsp->hdr.Status = NT_STATUS_INFO_LENGTH_MISMATCH;
			rsp->hdr.smb2_buf_length = cpu_to_be32(
						sizeof(struct smb2_hdr) - 4);
			return -EINVAL;
		} else {
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

static void get_standard_info_pipe(struct smb2_query_info_rsp *rsp)
{
	struct smb2_file_standard_info *sinfo;

	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;

	sinfo->AllocationSize = cpu_to_le64(4096);
	sinfo->EndOfFile = cpu_to_le64(0);
	sinfo->NumberOfLinks = cpu_to_le32(1);
	sinfo->DeletePending = 1;
	sinfo->Directory = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_standard_info));
	inc_rfc1001_len(rsp, sizeof(struct smb2_file_standard_info));
}

static void get_internal_info_pipe(struct smb2_query_info_rsp *rsp,
	uint64_t num)
{
	struct smb2_file_internal_info *file_info;

	file_info = (struct smb2_file_internal_info *)rsp->Buffer;

	/* any unique number */
	file_info->IndexNumber = cpu_to_le64(num | (1ULL << 63));
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_internal_info));
	inc_rfc1001_len(rsp, sizeof(struct smb2_file_internal_info));
}

/**
 * smb2_info_file_pipe() - handler for smb2 query info on IPC pipe
 * @work:	smb work containing query info command buffer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_get_info_file_pipe(struct cifsd_session *sess,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp)
{
	uint64_t id;
	int rc;

	cifsd_debug("smb2 query info IPC pipe of FileInfoClass %u, FileId 0x%llx\n",
		req->FileInfoClass, req->VolatileFileId);

	/*
	 * Windows can sometime send query file info request on
	 * pipe without opening it, checking error condition here
	 */
	id = le64_to_cpu(req->VolatileFileId);
	if (!cifsd_session_rpc_method(sess, id)) {
		cifsd_debug("Unknown RPC pipe id: %llu\n", id);
		return -ENOENT;
	}

	switch (req->FileInfoClass) {
	case FILE_STANDARD_INFORMATION:
		get_standard_info_pipe(rsp);
		rc = buffer_check_err(req->OutputBufferLength, rsp,
			FILE_STANDARD_INFORMATION_SIZE);
		break;
	case FILE_INTERNAL_INFORMATION:
		get_internal_info_pipe(rsp, req->VolatileFileId);
		rc = buffer_check_err(req->OutputBufferLength, rsp,
			FILE_INTERNAL_INFORMATION_SIZE);
		break;
	default:
		cifsd_err("smb2_info_file_pipe for %u not supported\n",
			req->FileInfoClass);
		rc = -EOPNOTSUPP;
	}
	return rc;
}

/**
 * smb2_get_ea() - handler for smb2 get extended attribute command
 * @work:	smb work containing query info command buffer
 * @path:	path of file/dir to query info command
 * @rq:		get extended attribute request
 * @resp:	response buffer pointer
 * @resp_org:	base response buffer pointer in case of chained response
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_get_ea(struct cifsd_tcp_conn *conn, struct path *path,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp,
	void *rsp_org)
{
	struct smb2_ea_info *eainfo, *prev_eainfo;
	char *name, *ptr, *xattr_list = NULL, *buf;
	int rc, name_len, value_len, xattr_list_len;
	ssize_t buf_free_len, alignment_bytes, next_offset, rsp_data_cnt = 0;
	struct smb2_ea_info_req *ea_req = NULL;

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

	rc = cifsd_vfs_listxattr(path->dentry, &xattr_list, XATTR_LIST_MAX);
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
		value_len = cifsd_vfs_getxattr(path->dentry, name, &buf);
		if (value_len <= 0) {
			rc = -ENOENT;
			rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
			goto out;
		}

		buf_free_len -= value_len;
		if (buf_free_len < 0) {
			cifsd_free(buf);
			break;
		}

		memcpy(ptr, buf, value_len);
		cifsd_free(buf);

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
 * smb2_get_info_file() - handler for smb2 query info command
 * @work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_get_info_file(struct cifsd_work *work,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp,
	void *rsp_org)
{
	struct cifsd_file *fp;
	struct cifsd_tcp_conn *conn = work->conn;
	int fileinfoclass = 0;
	struct file *filp;
	struct kstat stat;
	int rc = 0;
	int file_infoclass_size;
	struct inode *inode;
	u64 time;

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_PIPE)) {
		/* smb2 info file called for pipe */
		return smb2_get_info_file_pipe(work->sess, req, rsp);
	}

	fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp)
		return -ENOENT;

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
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.atime));
		basic_info->LastAccessTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.mtime));
		basic_info->LastWriteTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.ctime));
		basic_info->ChangeTime = cpu_to_le64(time);
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
		delete_pending = fp->f_ci->m_flags & S_DEL_PENDING;

		sinfo->AllocationSize = cpu_to_le64(inode->i_blocks << 9);
		sinfo->EndOfFile = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.size);
		sinfo->NumberOfLinks = get_nlink(&stat) - delete_pending;
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
			work->tcon->share_conf->path);
		if (!filename)
			return -ENOMEM;
		cifsd_debug("filename = %s\n", filename);
		delete_pending = fp->f_ci->m_flags & S_DEL_PENDING;
		file_info = (struct smb2_file_all_info *)rsp->Buffer;

		file_info->CreationTime = cpu_to_le64(fp->create_time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.atime));
		file_info->LastAccessTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.mtime));
		file_info->LastWriteTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.ctime));
		file_info->ChangeTime = cpu_to_le64(time);
		file_info->Attributes = fp->fattr;
		file_info->Pad1 = 0;
		file_info->AllocationSize = cpu_to_le64(inode->i_blocks << 9);
		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.size);
		file_info->NumberOfLinks = get_nlink(&stat) - delete_pending;
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
		uni_filename_len = cifsd_extract_shortname(conn,
							filename,
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
		int nbytes = 0, streamlen, stream_name_len, next;

		file_info = (struct smb2_file_stream_info *)rsp->Buffer;

		xattr_list_len = cifsd_vfs_listxattr(path->dentry, &xattr_list,
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

			stream_name_len = streamlen = strlen(stream_name) -
				(XATTR_USER_PREFIX_LEN + STREAM_PREFIX_LEN);

			if (fp->stream.type == 2) {
				streamlen += 17;
				stream_type = "$INDEX_ALLOCATION";
			} else {
				streamlen += 5;
				stream_type = "$DATA";
			}

			/* plus :: size */
			streamlen += 2;
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
				cpu_to_le64(stream_name_len);
			file_info->StreamAllocationSize =
				cpu_to_le64(stream_name_len);

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
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.atime));
		file_info->LastAccessTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.mtime));
		file_info->LastWriteTime = cpu_to_le64(time);
		time = cifs_UnixTimeToNT(from_kern_timespec(stat.ctime));
		file_info->ChangeTime = cpu_to_le64(time);
		file_info->Attributes = fp->fattr;
		file_info->AllocationSize = cpu_to_le64(inode->i_blocks << 9);
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

		rc = smb2_get_ea(work->conn, &filp->f_path, req, rsp,
			rsp_org);
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
static inline int fsTypeSearch(struct fs_type_info fs_type[],
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
 * @work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 * TODO: need to implement STATUS_INFO_LENGTH_MISMATCH error handling
 */
static int smb2_get_info_filesystem(struct cifsd_session *sess,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp,
	void *rsp_org)
{
	struct cifsd_tcp_conn *conn = sess->conn;
	struct cifsd_tree_connect *tree_conn;
	int fsinfoclass = 0;
	struct kstatfs stfs;
	struct cifsd_share_config *share;
	struct path path;
	int rc = 0, len;
	int fs_infoclass_size = 0;
	int fs_type_idx;

	tree_conn = cifsd_tree_conn_lookup(sess,
					   req->hdr.Id.SyncId.TreeId);
	if (!tree_conn)
		return -ENOENT;

	share = tree_conn->share_conf;
	rc = cifsd_vfs_kern_path(share->path, LOOKUP_FOLLOW, &path, 0);
	if (rc) {
		cifsd_err("cannot create vfs path\n");
		return -EIO;
	}

	rc = vfs_statfs(&path, &stfs);
	if (rc) {
		cifsd_err("cannot do stat of path %s\n", share->path);
		path_put(&path);
		return -EIO;
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
				share->name, PATH_MAX,
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
				cifsd_vfs_logical_sector_size(path.dentry->d_inode);

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
				cifsd_vfs_logical_sector_size(path.dentry->d_inode);

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

			if (!user_guest(sess->user)) {
				smb_E_md4hash(user_passkey(sess->user),
					objid, conn->local_nls);
				memcpy(obj_info->objid, objid, 16);
			} else
				memset(obj_info->objid, 0, 16);

			obj_info->extended_info.magic = EXTENDED_INFO_MAGIC;
			obj_info->extended_info.version = 1;
			obj_info->extended_info.release = 1;
			obj_info->extended_info.rel_date = 0;
			strncpy(obj_info->extended_info.version_string,
					"1.1.0", STRING_LENGTH);
			rsp->OutputBufferLength = cpu_to_le32(64);
			inc_rfc1001_len(rsp_org, 64);
			fs_infoclass_size = FS_OBJECT_ID_INFORMATION_SIZE;
			break;
		}
	case FS_SECTOR_SIZE_INFORMATION:
		{
			struct smb3_fs_ss_info *ss_info;
			struct cifsd_fs_sector_size fs_ss;

			ss_info = (struct smb3_fs_ss_info *)(rsp->Buffer);
			cifsd_vfs_smb2_sector_size(path.dentry->d_inode, &fs_ss);

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
		path_put(&path);
		return -EOPNOTSUPP;
	}
	rc = buffer_check_err(req->OutputBufferLength, rsp,
					fs_infoclass_size);
	path_put(&path);
	return rc;

}

#ifdef CONFIG_CIFSD_ACL
/**
 * smb2_get_info_sec() - handler for smb2 query info command
 * @work:   smb work containing query info request buffer
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_get_info_sec(struct cifsd_work *work,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp,
	void *rsp_org)
{
	struct cifsd_file *fp;
	struct file *filp;
	int rc = 0;
	struct cifs_ntsd *pntsd;
	struct inode *inode;
	int out_len;

	fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
		le64_to_cpu(req->PersistentFileId));
	if (!fp)
		return -ENOENT;

	filp = fp->filp;
	inode = GET_FP_INODE(fp);

	pntsd = (struct cifs_ntsd *) rsp->Buffer;

	out_len = build_sec_desc(pntsd, le32_to_cpu(req->AdditionalInformation),
		inode);

	rsp->OutputBufferLength = out_len;
	inc_rfc1001_len(rsp_org, out_len);

	return rc;
}
#else

static int smb2_get_info_sec(struct cifsd_work *work,
	struct smb2_query_info_req *req, struct smb2_query_info_rsp *rsp,
	void *rsp_org)
{
	int rc = 0;
	struct cifs_ntsd *pntsd;
	int out_len;

	pntsd = (struct cifs_ntsd *) rsp->Buffer;
	out_len = sizeof(struct cifs_ntsd);

	pntsd->revision = 1;
	pntsd->type = 0x9000;
	pntsd->osidoffset = 0;
	pntsd->gsidoffset = 0;
	pntsd->sacloffset = 0;
	pntsd->dacloffset = 0;

	rsp->OutputBufferLength = out_len;
	inc_rfc1001_len(rsp_org, out_len);

	return rc;
}
#endif

/**
 * smb2_query_info() - handler for smb2 query info command
 * @work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_query_info(struct cifsd_work *work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp, *rsp_org;
	struct cifsd_session *sess = work->sess;
	int rc = 0;

	req = (struct smb2_query_info_req *)REQUEST_BUF(work);
	rsp = (struct smb2_query_info_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_query_info_req *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_query_info_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	}

	cifsd_debug("GOT query info request\n");

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		cifsd_debug("GOT SMB2_O_INFO_FILE\n");
		rc = smb2_get_info_file(work, req, rsp, (void *)rsp_org);
		break;
	case SMB2_O_INFO_FILESYSTEM:
		cifsd_debug("GOT SMB2_O_INFO_FILESYSTEM\n");
		rc = smb2_get_info_filesystem(sess, req, rsp, (void *)rsp_org);
		break;
	case SMB2_O_INFO_SECURITY:
		cifsd_debug("GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_get_info_sec(work, req, rsp, (void *)rsp_org);
		break;
	default:
		cifsd_debug("InfoType %d not supported yet\n", req->InfoType);
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		rc = -EOPNOTSUPP;
	}

	if (rc < 0) {
		if (rc == -EACCES)
			rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
		else if (rc == -ENOENT)
			rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		else if (rc == -EIO)
			rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
		else if (rc == -EOPNOTSUPP || rsp->hdr.Status == 0)
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
		smb2_set_err_rsp(work);

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
 * @work:	smb work containing close request buffer
 *
 * Return:	0
 */
static int smb2_close_pipe(struct cifsd_work *work)
{
	uint64_t id;

	struct smb2_close_req *req =
		(struct smb2_close_req *)REQUEST_BUF(work);
	struct smb2_close_rsp *rsp =
		(struct smb2_close_rsp *)RESPONSE_BUF(work);

	id = le64_to_cpu(req->VolatileFileId);
	cifsd_session_rpc_close(work->sess, id);

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
	return 0;
}

/**
 * smb2_close() - handler for smb2 close file command
 * @work:	smb work containing close request buffer
 *
 * Return:	0
 */
int smb2_close(struct cifsd_work *work)
{
	uint64_t volatile_id = -1, persistent_id = -1, sess_id;
	struct smb2_close_req *req =
		(struct smb2_close_req *)REQUEST_BUF(work);
	struct smb2_close_rsp *rsp =
		(struct smb2_close_rsp *)RESPONSE_BUF(work);
	struct smb2_close_rsp *rsp_org;
	struct cifsd_tcp_conn *conn = work->conn;
	struct cifsd_file *fp;
	int err = 0;

	rsp_org = rsp;
	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_close_req *)((char *)req +
					work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_close_rsp *)((char *)rsp +
					work->next_smb2_rsp_hdr_off);
	}

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_PIPE)) {
		cifsd_debug("IPC pipe close request\n");
		return smb2_close_pipe(work);
	}

	sess_id = le64_to_cpu(req->hdr.SessionId);
	if (le32_to_cpu(req->hdr.Flags) &
			SMB2_FLAGS_RELATED_OPERATIONS)
		sess_id = work->cur_local_sess_id;

	work->cur_local_sess_id = 0;
	if (check_session_id(conn, sess_id))
		work->cur_local_sess_id = sess_id;
	else {
		rsp->hdr.Status = NT_STATUS_USER_SESSION_DELETED;
		if (le32_to_cpu(req->hdr.Flags) &
				SMB2_FLAGS_RELATED_OPERATIONS)
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
		err = -EBADF;
		goto out;
	}

	if (work->next_smb2_rcv_hdr_off &&
			le64_to_cpu(req->VolatileFileId) == -1) {
		if (!work->cur_local_fid) {
			/* file open failed, return EINVAL */
			cifsd_debug("file open was failed\n");
			rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
			err = -EBADF;
			goto out;
		} else if (work->cur_local_fid == -1) {
			/* file already closed, return FILE_CLOSED */
			cifsd_debug("file already closed\n");
			rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
			err = -EBADF;
			goto out;
		} else {
			cifsd_debug("Compound request assigning stored FID = %llu: %llu\n",
					work->cur_local_fid,
					work->cur_local_pfid);
			volatile_id = work->cur_local_fid;
			persistent_id = work->cur_local_pfid;

			/* file closed, stored id is not valid anymore */
			work->cur_local_fid = -1;
			work->cur_local_pfid = -1;
		}
	} else {
		volatile_id = le64_to_cpu(req->VolatileFileId);
		persistent_id = le64_to_cpu(req->PersistentFileId);
	}
	cifsd_debug("volatile_id = %llu persistent_id = %llu\n",
			volatile_id, persistent_id);

	fp = get_fp(work, volatile_id, persistent_id);
	if (!fp) {
		cifsd_debug("Invalid id for close: %llu\n", volatile_id);
		err = -EINVAL;
		goto out;
	}

	err = close_id(work->sess, volatile_id, persistent_id);
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
		smb2_set_err_rsp(work);
	} else {
		conn->stats.open_files_count--;
		inc_rfc1001_len(rsp_org, 60);
	}

	return 0;
}

/**
 * smb2_echo() - handler for smb2 echo(ping) command
 * @work:	smb work containing echo request buffer
 *
 * Return:	0
 */
int smb2_echo(struct cifsd_work *work)
{
	struct smb2_echo_rsp *rsp =
		(struct smb2_echo_rsp *)RESPONSE_BUF(work);

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	inc_rfc1001_len(rsp, 4);

	return 0;
}

#ifdef CONFIG_CIFSD_ACL
/**
 * smb2_set_info_sec() - handler for smb2 set info command
 * @work:   smb work containing set info command buffer
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_set_info_sec(struct cifsd_file *fp, int addition_info
	char *buffer, int buf_len)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp;
	struct cifsd_file *fp;
	uint64_t id, pid;
	int rc = 0;
	struct inode *inode;
	struct cifs_ntsd *pntsd;
	struct cifsd_fattr fattr;
	int addition_info;

	inode = fp->filp->f_path.dentry->d_inode;

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
 * smb2_rename() - handler for rename using smb2 setinfo command
 * @work:	smb work containing set info command buffer
 * @filp:	file pointer of source file
 * @old_fid:	file id of source file
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_rename(struct cifsd_file *fp,
		       struct smb2_file_rename_info *file_info,
		       struct nls_table *local_nls)
{
	struct cifsd_share_config *share = fp->tcon->share_conf;
	char *new_name = NULL, *abs_oldname = NULL, *old_name = NULL;
	char *tmp_name = NULL, *pathname = NULL;
	struct path path;
	bool file_present = true;
	int rc;

	cifsd_debug("setting FILE_RENAME_INFO\n");
	pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname) {
		return -ENOMEM;
	}

	abs_oldname = d_path(&fp->filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(abs_oldname)) {
		rc = -EINVAL;
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

	new_name = smb2_get_name(share,
				 file_info->FileName,
				 le32_to_cpu(file_info->FileNameLength),
				 local_nls);
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

		rc = cifsd_vfs_setxattr(fp->filp->f_path.dentry,
					xattr_stream_name,
					NULL, 0, 0);
		if (rc < 0) {
			cifsd_err("failed to store stream name in xattr, rc :%d\n",
					rc);
			rc = -EINVAL;
			goto out;
		}

		goto out;
	}

	tmp_name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp_name) {
		rc = -ENOMEM;
		goto out;
	}
	strncpy(tmp_name, new_name, PATH_MAX);
	tmp_name[PATH_MAX - 1] = 0x00;
	cifsd_debug("new name %s\n", new_name);
	rc = cifsd_vfs_kern_path(tmp_name, 0, &path, 1);
	if (rc)
		file_present = false;
	else
		path_put(&path);

	if (cifsd_share_veto_filename(share, tmp_name)) {
		rc = -ENOENT;
		cifsd_debug("file(%s) rename is not allowed by setting as veto file\n",
			tmp_name);
		goto out;
	}

	if (file_info->ReplaceIfExists) {
		if (file_present) {
			rc = cifsd_vfs_remove_file(tmp_name);
			if (rc) {
				if (rc != -ENOTEMPTY)
					rc = -EINVAL;
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
			cifsd_debug("cannot rename already existing file\n");
			goto out;
		}
	}

	rc = cifsd_vfs_rename(NULL, new_name, fp);
out:
	kfree(pathname);
	kfree(tmp_name);
	if (!IS_ERR(new_name))
		smb2_put_name(new_name);
	return rc;
}

/**
 * smb2_create_link() - handler for creating hardlink using smb2
 *		set info command
 * @work:	smb work containing set info command buffer
 * @filp:	file pointer of source file
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_create_link(struct cifsd_share_config *share,
			    struct smb2_file_link_info *file_info,
			    struct file *filp,
			    struct nls_table *local_nls)
{
	char *link_name = NULL, *target_name = NULL, *pathname = NULL;
	struct path path;
	bool file_present = true;
	int rc;

	cifsd_debug("setting FILE_LINK_INFORMATION\n");
	pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname)
		return -ENOMEM;

	link_name = smb2_get_name(share,
				  file_info->FileName,
				  le32_to_cpu(file_info->FileNameLength),
				  local_nls);
	if (IS_ERR(link_name) || S_ISDIR(file_inode(filp)->i_mode)) {
		rc = -EINVAL;
		goto out;
	}

	cifsd_debug("link name is %s\n", link_name);
	target_name = d_path(&filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(target_name)) {
		rc = -EINVAL;
		goto out;
	}

	cifsd_debug("target name is %s\n", target_name);
	rc = cifsd_vfs_kern_path(link_name, 0, &path, 0);
	if (rc)
		file_present = false;
	else
		path_put(&path);

	if (file_info->ReplaceIfExists) {
		if (file_present) {
			rc = cifsd_vfs_remove_file(link_name);
			if (rc) {
				rc = -EINVAL;
				cifsd_debug("cannot delete %s\n",
						link_name);
				goto out;
			}
		}
	} else {
		if (file_present) {
			rc = -EEXIST;
			cifsd_debug("link already exists\n");
			goto out;
		}
	}

	rc = cifsd_vfs_link(target_name, link_name);
	if (rc)
		rc = -EINVAL;
out:
	if (!IS_ERR(link_name))
		smb2_put_name(link_name);
	kfree(pathname);
	return rc;
}

/**
 * smb2_set_info_file() - handler for smb2 set info command
 * @work:	smb work containing set info command buffer
 *
 * Return:	0 on success, otherwise error
 * TODO: need to implement an error handling for STATUS_INFO_LENGTH_MISMATCH
 */
static int smb2_set_info_file(struct cifsd_work *work, struct cifsd_file *fp,
	int info_class, char *buffer, struct cifsd_share_config *share)
{
	struct cifsd_session *sess = work->sess;
	struct nls_table *local_nls = sess->conn->local_nls;
	int rc = 0;
	struct file *filp;
	struct inode *inode;

	filp = fp->filp;
	inode = file_inode(filp);

	switch (info_class) {
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

		file_info = (struct smb2_file_all_info *)buffer;
		attrs.ia_valid = 0;

		if (le64_to_cpu(file_info->CreationTime)) {
			fp->create_time = le64_to_cpu(file_info->CreationTime);
			if (test_share_config_flag(share,
					CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
				rc = cifsd_vfs_setxattr(filp->f_path.dentry,
						XATTR_NAME_CREATION_TIME,
						(void *)&fp->create_time,
						CREATIOM_TIME_LEN, 0);
				if (rc) {
					cifsd_debug("failed to set creation time\n");
					rc = -EINVAL;
					goto out;
				}
			}
		}

		if (le64_to_cpu(file_info->LastAccessTime)) {
			attrs.ia_atime = to_kern_timespec(cifs_NTtimeToUnix(
					le64_to_cpu(file_info->LastAccessTime)));
			attrs.ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);
		}

		if (le64_to_cpu(file_info->ChangeTime)) {
			temp_attrs.ia_ctime =
				to_kern_timespec(cifs_NTtimeToUnix(
					le64_to_cpu(file_info->ChangeTime)));
			attrs.ia_ctime = temp_attrs.ia_ctime;
			attrs.ia_valid |= ATTR_CTIME;
		} else
			temp_attrs.ia_ctime = inode->i_ctime;

		if (le64_to_cpu(file_info->LastWriteTime)) {
			attrs.ia_mtime = to_kern_timespec(cifs_NTtimeToUnix(
					le64_to_cpu(file_info->LastWriteTime)));
			attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
		}

		if (le32_to_cpu(file_info->Attributes)) {
			struct kstat stat;

			if (!S_ISDIR(inode->i_mode)
				&& file_info->Attributes == ATTR_DIRECTORY) {
				cifsd_err("can't change a file to a directory\n");
				rc = -EINVAL;
				goto out;
			}

			generic_fillattr(inode, &stat);
			fp->fattr = cpu_to_le32(smb2_get_dos_mode(&stat,
					le32_to_cpu(file_info->Attributes)));
			if (test_share_config_flag(share,
					CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
				rc = cifsd_vfs_setxattr(filp->f_path.dentry,
						XATTR_NAME_FILE_ATTRIBUTE,
						(void *)&fp->fattr,
						FILE_ATTRIBUTE_LEN, 0);
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
			struct dentry *dentry = filp->f_path.dentry;
			struct inode *inode = dentry->d_inode;
#else
			struct inode *inode = FP_INODE(fp);
#endif
			if (IS_IMMUTABLE(inode) || IS_APPEND(inode)) {
				rc = -EACCES;
				goto out;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
			rc = setattr_prepare(dentry, &attrs);
#else
			rc = inode_change_ok(inode, &attrs);
#endif
			if (rc) {
				rc = -EINVAL;
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
		loff_t alloc_blks;

		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
			FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write data : 0x%x\n",
				fp->daccess);
			return -EACCES;
		}

		file_alloc_info = (struct smb2_file_alloc_info *)buffer;
		alloc_blks = (le64_to_cpu(file_alloc_info->AllocationSize)
				+ 511) >> 9;

		if (alloc_blks > inode->i_blocks) {
			rc = cifsd_vfs_alloc_size(work, fp,
					alloc_blks * 512);
			if (rc) {
				cifsd_err("cifsd_vfs_alloc_size is failed : %d\n",
					rc);
				return rc;
			}
		} else if (alloc_blks < inode->i_blocks) {
			loff_t size;

			/*
			 * Allocation size could be smaller than original one
			 * which means allocated blocks in file should be
			 * deallocated. use truncate to cut out it, but inode
			 * size is also updated with truncate offset.
			 * inode size is retained by backup inode size.
			 */
			size = i_size_read(inode);
			rc = cifsd_vfs_truncate(work, NULL, fp,
					alloc_blks * 512);
			if (rc) {
				cifsd_err("truncate failed! filename : %s, err %d\n",
					fp->filename, rc);
				return rc;
			}
			if (size < alloc_blks * 512)
				i_size_write(inode, size);
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

		file_eof_info = (struct smb2_file_eof_info *)buffer;

		newsize = le64_to_cpu(file_eof_info->EndOfFile);

		if (newsize != i_size_read(inode)) {
			rc = cifsd_vfs_truncate(work, NULL, fp, newsize);
			if (rc) {
				cifsd_err("truncate failed! filename : %s err %d\n",
						fp->filename, rc);
				if (rc != -EAGAIN)
					rc = -EBADF;
				goto out;
			}

			cifsd_debug("filename : %s truncated to newsize %lld\n",
					fp->filename, newsize);
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
		rc = smb2_rename(fp,
				 (struct smb2_file_rename_info *)buffer,
				 local_nls);
		break;
	}
	case FILE_LINK_INFORMATION:
		rc = smb2_create_link(work->tcon->share_conf,
				      (struct smb2_file_link_info *)buffer,
				      filp,
				      local_nls);
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

		file_info = (struct smb2_file_disposition_info *)buffer;
		if (file_info->DeletePending) {
			if (S_ISDIR(inode->i_mode) && !cifsd_vfs_empty_dir(fp))
				rc = -EBUSY;
			else
				fp->f_ci->m_flags |= S_DEL_PENDING;
		} else
			fp->f_ci->m_flags &= ~S_DEL_PENDING;
		break;
	}
	case FILE_FULL_EA_INFORMATION:
	{
		if (!(fp->daccess & (FILE_WRITE_EA_LE | FILE_GENERIC_WRITE_LE |
			FILE_MAXIMAL_ACCESS_LE | FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write the extended attributes : 0x%x\n",
				fp->daccess);
			rc = -EACCES;
			goto out;
		}

		rc = smb2_set_ea((struct smb2_ea_info *)buffer,
			&filp->f_path);
		break;
	}
	case FILE_POSITION_INFORMATION:
	{
		struct smb2_file_pos_info *file_info;
		loff_t current_byte_offset;
		unsigned short sector_size;

		file_info = (struct smb2_file_pos_info *)buffer;
		current_byte_offset = le64_to_cpu(file_info->CurrentByteOffset);
		sector_size = cifsd_vfs_logical_sector_size(inode);

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

		file_info = (struct smb2_file_mode_info *)buffer;
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
		cifsd_vfs_set_fadvise(fp->filp, le32_to_cpu(mode));
		fp->coption = mode;

		break;
	}
	default:
		cifsd_err("Unimplemented Fileinfoclass :%d\n", info_class);
		rc = -EOPNOTSUPP;
	}

out:
	return rc;
}

/**
 * smb2_set_info() - handler for smb2 set info command handler
 * @work:	smb work containing set info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_set_info(struct cifsd_work *work)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	uint64_t id, pid;
	int rc = 0;

	req = (struct smb2_set_info_req *)REQUEST_BUF(work);
	rsp = (struct smb2_set_info_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_set_info_req *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_set_info_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	}

	cifsd_debug("%s: Received set info request\n", __func__);
	rsp->StructureSize = cpu_to_le16(33);

	id = le64_to_cpu(req->VolatileFileId);
	pid = le64_to_cpu(req->PersistentFileId);
	fp = get_fp(work, id, pid);
	if (!fp) {
		cifsd_debug("Invalid id for close: %llu\n", id);
		rc = -ENOENT;
		goto err_out;
	}

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		cifsd_debug("GOT SMB2_O_INFO_FILE\n");
		rc = smb2_set_info_file(work, fp, req->FileInfoClass,
					req->Buffer, work->tcon->share_conf);
		break;
#ifdef CONFIG_CIFSD_ACL
	case SMB2_O_INFO_SECURITY:
		cifsd_debug("GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_set_info_sec(fp,
			le32_to_cpu(req->AdditionalInformation), req->Buffer,
			le32_to_cpu(req->BufferLength));
		break;
#endif
	default:
		rc = -EOPNOTSUPP;
	}

	if (rc < 0)
		goto err_out;

	rsp->StructureSize = cpu_to_le16(2);
	inc_rfc1001_len(rsp_org, 2);

	return 0;

err_out:
	if (rc == -EACCES || rc == -ENOTEMPTY || rc == -EPERM)
		rsp->hdr.Status = NT_STATUS_ACCESS_DENIED;
	else if (rc == -EINVAL)
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
	else if (rc == -ESHARE)
		rsp->hdr.Status = NT_STATUS_SHARING_VIOLATION;
	else if (rc == -ENOENT)
		rsp->hdr.Status = NT_STATUS_OBJECT_NAME_INVALID;
	else if (rc == -EBUSY)
		rsp->hdr.Status = NT_STATUS_DIRECTORY_NOT_EMPTY;
	else if (rc == -EAGAIN)
		rsp->hdr.Status = NT_STATUS_FILE_LOCK_CONFLICT;
	else if (rc == -EBADF)
		rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
	else if (rc == -EEXIST)
		rsp->hdr.Status = NT_STATUS_OBJECT_NAME_COLLISION;
	else if (rsp->hdr.Status == 0 || rc == -EOPNOTSUPP)
		rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
	smb2_set_err_rsp(work);

	cifsd_debug("error while processing smb2 query rc = %d\n",
			rc);
	return rc;
}

/**
 * smb2_read_pipe() - handler for smb2 read from IPC pipe
 * @work:	smb work containing read IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_read_pipe(struct cifsd_work *work)
{
	int nbytes = 0;
	char *data_buf;
	uint64_t id;
	unsigned int read_len;
	struct cifsd_rpc_command *rpc_resp;
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp;

	req = (struct smb2_read_req *)REQUEST_BUF(work);
	rsp = (struct smb2_read_rsp *)RESPONSE_BUF(work);

	read_len = le32_to_cpu(req->Length);
	data_buf = (char *)(rsp->Buffer);
	id = le64_to_cpu(req->VolatileFileId);

	rpc_resp = cifsd_rpc_read(work->sess, id);
	if (rpc_resp) {
		if (rpc_resp->flags != CIFSD_RPC_OK) {
			rsp->hdr.Status = NT_STATUS_UNEXPECTED_IO_ERROR;
			smb2_set_err_rsp(work);
			cifsd_free(rpc_resp);
			return -EINVAL;
		}

		memcpy(data_buf, rpc_resp->payload, rpc_resp->payload_sz);
		nbytes = rpc_resp->payload_sz;
		cifsd_free(rpc_resp);
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
 * @work:	smb work containing read command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_read(struct cifsd_work *work)
{
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp, *rsp_org;
	struct cifsd_file *fp;
	loff_t offset;
	size_t length, mincount;
	ssize_t nbytes = 0;
	int err = 0;

	req = (struct smb2_read_req *)REQUEST_BUF(work);
	rsp = (struct smb2_read_rsp *)RESPONSE_BUF(work);

	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_read_req *)((char *)req +
					work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_read_rsp *)((char *)rsp +
					work->next_smb2_rsp_hdr_off);
	}

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_PIPE)) {
		cifsd_debug("IPC pipe read request\n");
		return smb2_read_pipe(work);
	}

	fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
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

	work->aux_payload_buf = cifsd_alloc_response(length);
	if (!work->aux_payload_buf) {
		err = nbytes;
		goto out;
	}

	nbytes = cifsd_vfs_read(work, fp, length, &offset);
	if (nbytes < 0) {
		err = nbytes;
		goto out;
	}

	if ((nbytes == 0 && length != 0) || nbytes < mincount) {
		cifsd_free_response(AUX_PAYLOAD(work));
		INIT_AUX_PAYLOAD(work);
		rsp->hdr.Status = NT_STATUS_END_OF_FILE;
		smb2_set_err_rsp(work);
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
	work->resp_hdr_sz = get_rfc1002_length(rsp_org) + 4;
	work->aux_payload_sz = nbytes;
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

		smb2_set_err_rsp(work);
	}
	return err;
}

/**
 * smb2_write_pipe() - handler for smb2 write on IPC pipe
 * @work:	smb work containing write IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_write_pipe(struct cifsd_work *work)
{
	struct smb2_write_req *req;
	struct smb2_write_rsp *rsp;
	struct cifsd_rpc_command *rpc_resp;
	uint64_t id = 0;
	int err = 0, ret = 0;
	char *data_buf;
	size_t length;

	req = (struct smb2_write_req *)REQUEST_BUF(work);
	rsp = (struct smb2_write_rsp *)RESPONSE_BUF(work);

	length = le32_to_cpu(req->Length);
	id = le64_to_cpu(req->VolatileFileId);

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

	rpc_resp = cifsd_rpc_write(work->sess, id, data_buf, length);
	if (rpc_resp) {
		if (rpc_resp->flags == CIFSD_RPC_ENOTIMPLEMENTED) {
			rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
			cifsd_free(rpc_resp);
			goto out;
		}
		if (rpc_resp->flags != CIFSD_RPC_OK) {
			rsp->hdr.Status = NT_STATUS_INVALID_HANDLE;
			smb2_set_err_rsp(work);
			cifsd_free(rpc_resp);
			return ret;
		}
		cifsd_free(rpc_resp);
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
		smb2_set_err_rsp(work);
	}

	return err;
}

/**
 * smb2_write() - handler for smb2 write from file
 * @work:	smb work containing write command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_write(struct cifsd_work *work)
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

	req = (struct smb2_write_req *)REQUEST_BUF(work);
	rsp = (struct smb2_write_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_write_req *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_write_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	}

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_PIPE)) {
		cifsd_debug("IPC pipe write request\n");
		return smb2_write_pipe(work);
	}

	fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
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
	err = cifsd_vfs_write(work, fp, data_buf, length, &offset,
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

	smb2_set_err_rsp(work);
	return err;
}

/**
 * smb2_flush() - handler for smb2 flush file - fsync
 * @work:	smb work containing flush command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_flush(struct cifsd_work *work)
{
	struct smb2_flush_req *req;
	struct smb2_flush_rsp *rsp;
	int err;

	req = (struct smb2_flush_req *)REQUEST_BUF(work);
	rsp = (struct smb2_flush_rsp *)RESPONSE_BUF(work);

	cifsd_debug("SMB2_FLUSH called for fid %llu\n",
			le64_to_cpu(req->VolatileFileId));

	err = cifsd_vfs_fsync(work,
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
		smb2_set_err_rsp(work);
	}

	return err;
}

/**
 * smb2_cancel() - handler for smb2 cancel command
 * @work:	smb work containing cancel command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_cancel(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_hdr *hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	struct smb2_hdr *chdr;
	struct cifsd_work *cancel_work = NULL;
	struct list_head *tmp;
	int canceled = 0;
	struct list_head *command_list;

	cifsd_debug("smb2 cancel called on mid %llu\n", hdr->MessageId);

	if (hdr->Flags & SMB2_FLAGS_ASYNC_COMMAND)
		command_list = &conn->async_requests;
	else
		command_list = &conn->requests;

	spin_lock(&conn->request_lock);
	list_for_each(tmp, command_list) {
		cancel_work = list_entry(tmp, struct cifsd_work,
				request_entry);
		chdr = (struct smb2_hdr *)REQUEST_BUF(cancel_work);
		if (cancel_work->type == ASYNC) {
			if (cancel_work->async_id !=
					le64_to_cpu(hdr->Id.AsyncId))
				continue;
			cifsd_debug("smb2 with AsyncId %llu cancelled command = 0x%x\n",
					hdr->Id.AsyncId, chdr->Command);
		} else {
			if (chdr->MessageId != hdr->MessageId)
				continue;
			cifsd_debug("smb2 with mid %llu cancelled command = 0x%x\n",
				hdr->MessageId, chdr->Command);
		}
		canceled = 1;
		break;
	}
	spin_unlock(&conn->request_lock);

	if (canceled) {
		cancel_work->state = WORK_STATE_CANCELLED;
		cancel_work->cancel_fn(cancel_work->cancel_argv);
	}

	/* For SMB2_CANCEL command itself send no response*/
	work->send_no_response = 1;
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
	list_add_tail(&lock->llist, lock_list);

	return lock;
}

void smb2_remove_blocked_lock(void **argv)
{
	struct file_lock *flock = (struct file_lock *)argv[0];

	posix_unblock_lock(flock);
	wake_up(&flock->fl_wait);
}

static inline bool lock_defer_pending(struct file_lock *fl)
{
	return waitqueue_active(&fl->fl_wait);
}

/**
 * smb2_lock() - handler for smb2 file lock command
 * @work:	smb work containing lock command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_lock(struct cifsd_work *work)
{
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

	req = (struct smb2_lock_req *)REQUEST_BUF(work);
	rsp = (struct smb2_lock_rsp *)RESPONSE_BUF(work);

	cifsd_debug("Recieved lock request\n");
	fp = get_fp(work, le64_to_cpu(req->VolatileFileId),
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
					!lock_defer_pending(cmp_lock->fl)) {
					nolock = 0;
					locks_free_lock(cmp_lock->fl);
					list_del(&cmp_lock->glist);
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
		err = cifsd_vfs_lock(filp, smb_lock->cmd, flock);
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
				void **argv;

				cifsd_debug("would have to wait for getting"
						" lock\n");
				list_add_tail(&smb_lock->glist,
					&global_lock_list);
				list_add(&smb_lock->llist, &rollback_list);

				argv = kmalloc(sizeof(void *), GFP_KERNEL);
				if (!argv) {
					err = -ENOMEM;
					goto out;
				}
				argv[0] = flock;

				err = setup_async_work(work,
					smb2_remove_blocked_lock, argv);
				if (err) {
					rsp->hdr.Status =
					   NT_STATUS_INSUFFICIENT_RESOURCES;
					goto out;
				}
				spin_lock(&fp->f_lock);
				list_add(&work->fp_entry, &fp->blocked_works);
				spin_unlock(&fp->f_lock);

				smb2_send_interim_resp(work, NT_STATUS_PENDING);

				err = wait_event_interruptible(flock->fl_wait,
					!flock->fl_next);

				if (work->state == WORK_STATE_CANCELLED ||
					work->state == WORK_STATE_CLOSED) {
					list_del(&smb_lock->llist);
					list_del(&smb_lock->glist);
					locks_free_lock(flock);

					if (work->state ==
						WORK_STATE_CANCELLED) {
						spin_lock(&fp->f_lock);
						list_del(&work->fp_entry);
						spin_unlock(&fp->f_lock);
						rsp->hdr.Status =
							NT_STATUS_CANCELLED;
						kfree(smb_lock);
						smb2_send_interim_resp(work,
							NT_STATUS_CANCELLED);
						work->send_no_response = 1;
						goto out;
					}
					init_smb2_rsp_hdr(work);
					smb2_set_err_rsp(work);
					rsp->hdr.Status =
						NT_STATUS_RANGE_NOT_LOCKED;
					kfree(smb_lock);
					goto out2;
				}

				list_del(&smb_lock->llist);
				list_del(&smb_lock->glist);
				spin_lock(&fp->f_lock);
				list_del(&work->fp_entry);
				spin_unlock(&fp->f_lock);
				goto retry;
			} else if (!err) {
				list_add_tail(&smb_lock->glist,
					&global_lock_list);
				list_add(&smb_lock->llist, &rollback_list);
				cifsd_debug("successful in taking lock\n");
			} else {
				rsp->hdr.Status = NT_STATUS_LOCK_NOT_GRANTED;
				goto out;
			}
		}
	}

	if (oplocks_enable && atomic_read(&fp->f_ci->op_count) > 1)
		smb_break_all_oplock(work, fp);

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

		err = cifsd_vfs_lock(filp, 0, rlock);
		if (err)
			cifsd_err("rollback unlock fail : %d\n", err);
		list_del(&smb_lock->llist);
		list_del(&smb_lock->glist);
		locks_free_lock(smb_lock->fl);
		locks_free_lock(rlock);
		kfree(smb_lock);
	}
out2:
	cifsd_err("failed in taking lock(flags : %x)\n", flags);
	smb2_set_err_rsp(work);
	return 0;
}

/**
 * smb2_ioctl() - handler for smb2 ioctl command
 * @work:	smb work containing ioctl command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_ioctl(struct cifsd_work *work)
{
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp, *rsp_org;
	int cnt_code, nbytes = 0;
	int out_buf_len;
	char *data_buf;
	uint64_t id = -1;
	struct cifsd_tcp_conn *conn = work->conn;
	struct cifsd_rpc_command *rpc_resp;

	req = (struct smb2_ioctl_req *)REQUEST_BUF(work);
	rsp = (struct smb2_ioctl_rsp *)RESPONSE_BUF(work);
	rsp_org = rsp;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_ioctl_req *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_ioctl_rsp *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
		if (le64_to_cpu(req->VolatileFileId) == -1) {
			cifsd_debug("Compound request assigning stored FID = %llu\n",
					work->cur_local_fid);
			id = work->cur_local_fid;
		}
	}

	if (id == -1)
		id = le64_to_cpu(req->VolatileFileId);

	cnt_code = le32_to_cpu(req->CntCode);
	out_buf_len = le32_to_cpu(req->MaxOutputResponse);
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
		/* @FIXME */
		if (rsp->hdr.Id.SyncId.TreeId != 0) {
			cifsd_debug("Not Pipe transceive\n");
			goto out;
		}

		rpc_resp = cifsd_rpc_ioctl(work->sess, id,
					   data_buf,
					   le32_to_cpu(req->InputCount));
		if (rpc_resp) {
			if (rpc_resp->flags == CIFSD_RPC_ENOTIMPLEMENTED) {
				rsp->hdr.Status = NT_STATUS_NOT_SUPPORTED;
				cifsd_free(rpc_resp);
				goto out;
			}

			if (rpc_resp->flags != CIFSD_RPC_OK) {
				rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
				cifsd_free(rpc_resp);
				goto out;
			}

			nbytes = rpc_resp->payload_sz;
			if (rpc_resp->payload_sz > out_buf_len) {
				rsp->hdr.Status = NT_STATUS_BUFFER_OVERFLOW;
				nbytes = out_buf_len;
			}

			if (!rpc_resp->payload_sz) {
				rsp->hdr.Status =
					NT_STATUS_UNEXPECTED_IO_ERROR;
				cifsd_free(rpc_resp);
				goto out;
			}

			memcpy((char *)rsp->Buffer, rpc_resp->payload,
					nbytes);
			cifsd_free(rpc_resp);
		}
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	{
		struct validate_negotiate_info_req *neg_req;
		struct validate_negotiate_info_rsp *neg_rsp;
		int ret;

		neg_req = (struct validate_negotiate_info_req *)&req->Buffer[0];
		ret = cifsd_lookup_dialect_by_id(neg_req->Dialects,
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			if (netdev->ethtool_ops->get_link_ksettings) {
				struct ethtool_link_ksettings cmd;

				netdev->ethtool_ops->get_link_ksettings(netdev,
					&cmd);
				speed = cmd.base.speed;
			}
#else
			if (netdev->ethtool_ops->get_settings) {
				struct ethtool_cmd cmd;

				netdev->ethtool_ops->get_settings(netdev, &cmd);
				speed = cmd.speed;
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

			if (conn->peer_addr.ss_family == PF_INET) {
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
	rsp->InputCount = cpu_to_le32(0);
	rsp->InputOffset = cpu_to_le32(112);
	rsp->OutputOffset = cpu_to_le32(112);
	rsp->OutputCount = cpu_to_le32(nbytes);
	rsp->StructureSize = cpu_to_le16(49);
	rsp->Reserved = cpu_to_le16(0);
	rsp->Flags = cpu_to_le32(0);
	rsp->Reserved2 = cpu_to_le32(0);
	inc_rfc1001_len(rsp_org, 48 + nbytes);

	return 0;

out:
	if (rsp->hdr.Status == 0)
		rsp->hdr.Status = NT_STATUS_INVALID_PARAMETER;
	smb2_set_err_rsp(work);
	return 0;
}

/**
 * smb20_oplock_break() - handler for smb2.0 oplock break command
 * @work:	smb work containing oplock break command buffer
 *
 * Return:	0
 */
int smb20_oplock_break(struct cifsd_work *work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;
	struct cifsd_file *fp;
	struct oplock_info *opinfo = NULL;
	int err = 0, ret = 0;
	uint64_t volatile_id, persistent_id;
	char req_oplevel = 0, rsp_oplevel = 0;
	unsigned int oplock_change_type;

	req = (struct smb2_oplock_break *)REQUEST_BUF(work);
	rsp = (struct smb2_oplock_break *)RESPONSE_BUF(work);
	volatile_id = le64_to_cpu(req->VolatileFid);
	persistent_id = le64_to_cpu(req->PersistentFid);
	req_oplevel = req->OplockLevel;
	cifsd_debug("SMB2_OPLOCK_BREAK v_id %llu, p_id %llu request oplock level %d\n",
			volatile_id, persistent_id, req_oplevel);

	fp = get_fp(work, volatile_id, persistent_id);
	if (!fp) {
		rsp->hdr.Status = NT_STATUS_FILE_CLOSED;
		smb2_set_err_rsp(work);
		return 0;
	}

	opinfo = opinfo_get(fp);
	if (opinfo == NULL) {
		cifsd_err("unexpected null oplock_info\n");
		rsp->hdr.Status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		smb2_set_err_rsp(work);
		return 0;
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

	opinfo_put(opinfo);
	rsp->StructureSize = cpu_to_le16(24);
	rsp->OplockLevel = rsp_oplevel;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->VolatileFid = cpu_to_le64(volatile_id);
	rsp->PersistentFid = cpu_to_le64(persistent_id);
	inc_rfc1001_len(rsp, 24);
	return 0;

err_out:
	opinfo_put(opinfo);
	smb2_set_err_rsp(work);
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
 * @work:	smb work containing lease break command buffer
 *
 * Return:	0
 */
static int smb21_lease_break(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_lease_ack *req, *rsp;
	struct oplock_info *opinfo;
	int err = 0, ret = 0;
	unsigned int lease_change_type;
	__le32 lease_state;
	struct lease *lease;

	req = (struct smb2_lease_ack *)REQUEST_BUF(work);
	rsp = (struct smb2_lease_ack *)RESPONSE_BUF(work);

	cifsd_debug("smb21 lease break, lease state(0x%x)\n",
			req->LeaseState);
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
	opinfo_put(opinfo);

	if (ret < 0) {
		rsp->hdr.Status = err;
		goto err_out;
	}

	rsp->StructureSize = cpu_to_le16(36);
	rsp->Reserved = 0;
	rsp->Flags = 0;
	memcpy(rsp->LeaseKey, req->LeaseKey, 16);
	rsp->LeaseState = lease_state;
	rsp->LeaseDuration = 0;
	inc_rfc1001_len(rsp, 36);
	return 0;

err_out:
	smb2_set_err_rsp(work);
	return 0;
}

/**
 * smb2_oplock_break() - dispatcher for smb2.0 and 2.1 oplock/lease break
 * @work:	smb work containing oplock/lease break command buffer
 *
 * Return:	0
 */
int smb2_oplock_break(struct cifsd_work *work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;
	int err;

	req = (struct smb2_oplock_break *)REQUEST_BUF(work);
	rsp = (struct smb2_oplock_break *)RESPONSE_BUF(work);

	switch (le16_to_cpu(req->StructureSize)) {
	case OP_BREAK_STRUCT_SIZE_20:
		err = smb20_oplock_break(work);
		break;
	case OP_BREAK_STRUCT_SIZE_21:
		err = smb21_lease_break(work);
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
	smb2_set_err_rsp(work);
	return 0;
}

/**
 * smb2_notify() - handler for smb2 notify request
 * @cifsd_work:   smb work containing notify command buffer
 *
 * Return:      0
 */
int smb2_notify(struct cifsd_work *cifsd_work)
{
	struct smb2_notify_req *req;
	struct smb2_notify_rsp *rsp, *rsp_org;

	req = (struct smb2_notify_req *)REQUEST_BUF(cifsd_work);
	rsp = (struct smb2_notify_rsp *)RESPONSE_BUF(cifsd_work);
	rsp_org = rsp;

	if (cifsd_work->next_smb2_rcv_hdr_off) {
	req = (struct smb2_notify_req *)((char *)req +
		cifsd_work->next_smb2_rcv_hdr_off);
	rsp = (struct smb2_notify_rsp *)((char *)rsp +
		cifsd_work->next_smb2_rsp_hdr_off);
	}

	if (cifsd_work->next_smb2_rcv_hdr_off &&
		le32_to_cpu(req->hdr.NextCommand)) {
		rsp->hdr.Status = NT_STATUS_INTERNAL_ERROR;
		smb2_set_err_rsp(cifsd_work);
		return 0;
	}

	/*
	 * Win7 send peoridically query_dir command if cifsd just response
	 * with NT_STATUS_NOT_IMPLEMENTED status. If SMB2_WATCH_TREE flags
	 * is set in change notify command, cifsd send async response with
	 * STATUS PENDING to avoid peoridical query_dir.
	 */
	if (le16_to_cpu(req->Flags) == SMB2_WATCH_TREE) {
		smb2_send_interim_resp(cifsd_work, NT_STATUS_PENDING);
		cifsd_work->send_no_response = 1;
	} else {
		smb2_set_err_rsp(cifsd_work);
		rsp->hdr.Status = NT_STATUS_NOT_IMPLEMENTED;
	}

	return 0;
}

/**
 * smb2_is_sign_req() - handler for checking packet signing status
 * @work:smb work containing notify command buffer
 *
 * Return:	1 if packed is signed, 0 otherwise
 */
int smb2_is_sign_req(struct cifsd_work *work, unsigned int command)
{
	struct smb2_hdr *rcv_hdr2 = (struct smb2_hdr *)REQUEST_BUF(work);

	if ((rcv_hdr2->Flags & SMB2_FLAGS_SIGNED) &&
			command != SMB2_NEGOTIATE_HE &&
			command != SMB2_SESSION_SETUP_HE &&
			command != SMB2_OPLOCK_BREAK_HE)
		return 1;

	/* send session setup auth phase signed response */
	if (work->sess->sign && command == SMB2_SESSION_SETUP_HE &&
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
int smb2_check_sign_req(struct cifsd_work *work)
{
	struct smb2_hdr *rcv_hdr2 = (struct smb2_hdr *)REQUEST_BUF(work);
	char signature_req[SMB2_SIGNATURE_SIZE];
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec iov[1];

	memcpy(signature_req, rcv_hdr2->Signature, SMB2_SIGNATURE_SIZE);
	memset(rcv_hdr2->Signature, 0, SMB2_SIGNATURE_SIZE);

	iov[0].iov_base = (char *)&rcv_hdr2->ProtocolId;
	iov[0].iov_len = be32_to_cpu(rcv_hdr2->smb2_buf_length);

	if (cifsd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, 1,
		signature))
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
void smb2_set_sign_rsp(struct cifsd_work *work)
{
	struct smb2_hdr *rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec iov[2];
	int n_vec = 1;

	rsp_hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(rsp_hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	iov[0].iov_base = (char *)&rsp_hdr->ProtocolId;
	iov[0].iov_len = be32_to_cpu(rsp_hdr->smb2_buf_length);

	if (HAS_AUX_PAYLOAD(work)) {
		iov[0].iov_len -= AUX_PAYLOAD_SIZE(work);

		iov[1].iov_base = AUX_PAYLOAD(work);
		iov[1].iov_len = AUX_PAYLOAD_SIZE(work);
		n_vec++;
	}

	if (!cifsd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, n_vec,
		signature))
		memcpy(rsp_hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_check_sign_req() - handler for req packet sign processing
 * @work:   smb work containing notify command buffer
 *
 * Return:	1 on success, 0 otherwise
 */
int smb3_check_sign_req(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn;
	char *signing_key;
	struct smb2_hdr *hdr, *hdr_org;
	struct channel *chann;
	char signature_req[SMB2_SIGNATURE_SIZE];
	char signature[SMB2_CMACAES_SIZE];
	struct kvec iov[1];
	size_t len;

	hdr_org = hdr = (struct smb2_hdr *)REQUEST_BUF(work);
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

	if (le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {
		signing_key = work->sess->smb3signingkey;
		conn = work->sess->conn;
	} else {
		chann = lookup_chann_list(work->sess);
		if (!chann)
			return 0;
		signing_key = chann->smb3signingkey;
		conn = chann->conn;
	}

	if (!signing_key) {
		cifsd_err("SMB3 signing key is not generated\n");
		return 0;
	}

	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	iov[0].iov_base = (char *)&hdr->ProtocolId;
	iov[0].iov_len = len;

	if (cifsd_sign_smb3_pdu(conn, signing_key, iov, 1, signature))
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
void smb3_set_sign_rsp(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn;
	struct smb2_hdr *req_hdr = (struct smb2_hdr *)REQUEST_BUF(work);
	struct smb2_hdr *hdr, *hdr_org;
	struct channel *chann;
	char signature[SMB2_CMACAES_SIZE];
	struct kvec iov[2];
	int n_vec = 1;
	size_t len;
	char *signing_key;

	hdr_org = hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
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

	if (le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {
		signing_key = work->sess->smb3signingkey;
		conn = work->sess->conn;
	} else {
		chann = lookup_chann_list(work->sess);
		if (!chann)
			return;
		signing_key = chann->smb3signingkey;
		conn = chann->conn;
	}

	if (!signing_key)
		return;

	if (le32_to_cpu(req_hdr->NextCommand))
		hdr->NextCommand = cpu_to_le32(len);

	hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	iov[0].iov_base = (char *)&hdr->ProtocolId;
	iov[0].iov_len = len;
	if (HAS_AUX_PAYLOAD(work)) {
		iov[0].iov_len -= AUX_PAYLOAD_SIZE(work);
		iov[1].iov_base = AUX_PAYLOAD(work);
		iov[1].iov_len = AUX_PAYLOAD_SIZE(work);
		n_vec++;
	}

	if (!cifsd_sign_smb3_pdu(conn, signing_key, iov, n_vec, signature))
		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_preauth_hash_rsp() - handler for computing preauth hash on response
 * @work:   smb work containing response buffer
 *
 */
void smb3_preauth_hash_rsp(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct cifsd_session *sess = work->sess;
	struct smb2_hdr *req = (struct smb2_hdr *)REQUEST_BUF(work);
	struct smb2_hdr *rsp = (struct smb2_hdr *)RESPONSE_BUF(work);

	if (conn->dialect != SMB311_PROT_ID)
		return;

	if (work->next_smb2_rcv_hdr_off) {
		req = (struct smb2_hdr *)((char *)req +
				work->next_smb2_rcv_hdr_off);
		rsp = (struct smb2_hdr *)((char *)rsp +
				work->next_smb2_rsp_hdr_off);
	}

	if (le16_to_cpu(req->Command) == SMB2_NEGOTIATE_HE)
		cifsd_gen_preauth_integrity_hash(conn, (char *)rsp,
			conn->preauth_info->Preauth_HashValue);

	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE &&
			rsp->Status == NT_STATUS_MORE_PROCESSING_REQUIRED) {
		__u8 *hash_value;

		if (multi_channel_enable &&
				conn->dialect >= SMB311_PROT_ID &&
				req->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
			struct preauth_session *preauth_sess;

			preauth_sess = get_preauth_session(conn,
					le64_to_cpu(req->SessionId));
			hash_value = preauth_sess->Preauth_HashValue;
		} else
			hash_value = sess->Preauth_HashValue;

		cifsd_gen_preauth_integrity_hash(conn, (char *)rsp,
				hash_value);
	}
}

struct cifs_crypt_result {
	int err;
	struct completion completion;
};

static void cifs_crypt_complete(struct crypto_async_request *req, int err)
{
	struct cifs_crypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static int smb2_get_enc_key(struct cifsd_tcp_conn *conn, __u64 ses_id,
	int enc, u8 *key)
{
	struct cifsd_session *sess;
	u8 *ses_enc_key;

	sess = cifsd_session_lookup(conn, ses_id);
	if (!sess)
		return 1;

	ses_enc_key = enc ? sess->smb3encryptionkey :
		sess->smb3decryptionkey;
	memcpy(key, ses_enc_key, SMB3_SIGN_KEY_SIZE);

	return 0;
}

int smb3_crypto_aead_allocate(struct cifsd_tcp_conn *conn)
{
	struct crypto_aead *tfm;

	if (!conn->secmech.ccmaesencrypt) {
		tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			cifsd_err("%s: Failed to alloc encrypt aead\n",
					__func__);
			return PTR_ERR(tfm);
		}
		conn->secmech.ccmaesencrypt = tfm;
	}

	if (!conn->secmech.ccmaesdecrypt) {
		tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			crypto_free_aead(conn->secmech.ccmaesencrypt);
			conn->secmech.ccmaesencrypt = NULL;
			cifsd_err("%s: Failed to alloc decrypt aead\n",
					__func__);
			return PTR_ERR(tfm);
		}
		conn->secmech.ccmaesdecrypt = tfm;
	}

	return 0;
}

struct smb_rqst {
	struct kvec	*rq_iov;	/* array of kvecs */
	unsigned int	rq_nvec;	/* number of kvecs in array */
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static struct scatterlist *init_sg(struct smb_rqst *rqst, u8 *sign)
{
	struct scatterlist *sg;
	unsigned int i = 0, sg_len = rqst->rq_nvec;

	sg = kmalloc_array(sg_len, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg)
		return NULL;

	sg_init_table(sg, sg_len);
	for (i = 0; i < sg_len - 1; i++)
		sg_set_buf(&sg[i], rqst->rq_iov[i + 1].iov_base,
			rqst->rq_iov[i + 1].iov_len);
	sg_set_buf(&sg[sg_len - 1], sign, SMB2_SIGNATURE_SIZE);
	return sg;
}
#else
static struct scatterlist *init_sg(struct smb_rqst *rqst, u8 *sign)
{
	struct scatterlist *sg;
	unsigned int i = 0, sg_len = rqst->rq_nvec + 1;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 24;

	sg = kmalloc_array(sg_len, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg)
		return NULL;

	sg_init_table(sg, sg_len);
	sg_set_buf(&sg[0], rqst->rq_iov[0].iov_base + 24, assoc_data_len);
	for (i = 1; i < sg_len - 1; i++)
		sg_set_buf(&sg[i], rqst->rq_iov[i].iov_base,
			rqst->rq_iov[i].iov_len);
	sg_set_buf(&sg[sg_len - 1], sign, SMB2_SIGNATURE_SIZE);
	return sg;
}
#endif

int crypt_message(struct cifsd_tcp_conn *conn, struct smb_rqst *rqst, int enc)
{
	struct smb2_transform_hdr *tr_hdr =
		(struct smb2_transform_hdr *)rqst->rq_iov[0].iov_base;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 24;
	int rc = 0;
	struct scatterlist *sg;
	u8 sign[SMB2_SIGNATURE_SIZE] = {};
	u8 key[SMB3_SIGN_KEY_SIZE];
	struct aead_request *req;
	char *iv;
	unsigned int iv_len;
	struct cifs_crypt_result result = {0, };
	struct crypto_aead *tfm;
	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	struct scatterlist assoc;
#endif

	init_completion(&result.completion);

	rc = smb2_get_enc_key(conn, tr_hdr->SessionId, enc, key);
	if (rc) {
		cifsd_err("%s: Could not get %scryption key\n", __func__,
				enc ? "en" : "de");
		return 0;
	}

	rc = smb3_crypto_aead_allocate(conn);
	if (rc) {
		cifsd_err("%s: crypto alloc failed\n", __func__);
		return rc;
	}

	tfm = enc ? conn->secmech.ccmaesencrypt :
		conn->secmech.ccmaesdecrypt;
	rc = crypto_aead_setkey(tfm, key, SMB3_SIGN_KEY_SIZE);
	if (rc) {
		cifsd_err("%s: Failed to set aead key %d\n", __func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifsd_err("%s: Failed to set authsize %d\n", __func__, rc);
		return rc;
	}

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		cifsd_err("%s: Failed to alloc aead request", __func__);
		return -ENOMEM;
	}

	if (!enc) {
		memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);
		crypt_len += SMB2_SIGNATURE_SIZE;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	sg_init_one(&assoc, rqst->rq_iov[0].iov_base + 24, assoc_data_len);
#endif

	sg = init_sg(rqst, sign);
	if (!sg) {
		cifsd_err("%s: Failed to init sg", __func__);
		rc = -ENOMEM;
		goto free_req;
	}

	iv_len = crypto_aead_ivsize(tfm);
	iv = kzalloc(iv_len, GFP_KERNEL);
	if (!iv) {
		cifsd_err("%s: Failed to alloc IV", __func__);
		rc = -ENOMEM;
		goto free_sg;
	}
	iv[0] = 3;
	memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES128CMM_NONCE);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	aead_request_set_assoc(req, &assoc, assoc_data_len);
	aead_request_set_crypt(req, sg, sg, crypt_len, iv);
#else
	aead_request_set_crypt(req, sg, sg, crypt_len, iv);
	aead_request_set_ad(req, assoc_data_len);
#endif
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			cifs_crypt_complete, &result);

	rc = enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	if (rc == -EINPROGRESS || rc == -EBUSY) {
		wait_for_completion(&result.completion);
		rc = result.err;
	}

	if (!rc && enc)
		memcpy(&tr_hdr->Signature, sign, SMB2_SIGNATURE_SIZE);

	kfree(iv);
free_sg:
	kfree(sg);
free_req:
	kfree(req);
	return rc;
}

static void fill_transform_hdr(struct smb2_transform_hdr *tr_hdr, char *old_buf)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)old_buf;
	unsigned int orig_len = get_rfc1002_length(old_buf);

	memset(tr_hdr, 0, sizeof(struct smb2_transform_hdr));
	tr_hdr->ProtocolId = SMB2_TRANSFORM_PROTO_NUM;
	tr_hdr->OriginalMessageSize = cpu_to_le32(orig_len);
	tr_hdr->Flags = cpu_to_le16(0x01);
	get_random_bytes(&tr_hdr->Nonce, SMB3_AES128CMM_NONCE);
	memcpy(&tr_hdr->SessionId, &hdr->SessionId, 8);
	inc_rfc1001_len(tr_hdr, sizeof(struct smb2_transform_hdr) - 4);
	inc_rfc1001_len(tr_hdr, orig_len);
}

int smb3_encrypt_resp(struct cifsd_work *work)
{
	char *buf = RESPONSE_BUF(work);
	struct smb2_transform_hdr *tr_hdr;
	struct kvec *iov;
	struct smb_rqst rqst = {NULL};
	int rc = -ENOMEM;
	int buf_size = 0, rq_nvec = 2 + (HAS_AUX_PAYLOAD(work) ? 1 : 0);

	tr_hdr = cifsd_alloc_response(sizeof(struct smb2_transform_hdr));
	if (!tr_hdr)
		return rc;

	/* fill transform header */
	fill_transform_hdr(tr_hdr, buf);

	iov = kmalloc_array(rq_nvec, sizeof(struct kvec), GFP_KERNEL);
	if (!iov) {
		kfree(tr_hdr);
		return rc;
	}

	iov[0].iov_base = tr_hdr;
	iov[0].iov_len = sizeof(struct smb2_transform_hdr);
	buf_size += iov[0].iov_len - 4;

	iov[1].iov_base = buf + 4;
	iov[1].iov_len = get_rfc1002_length(buf);
	rqst.rq_iov = iov;
	rqst.rq_nvec = rq_nvec;

	if (HAS_AUX_PAYLOAD(work)) {
		iov[1].iov_len = RESP_HDR_SIZE(work);

		iov[2].iov_base = AUX_PAYLOAD(work);
		iov[2].iov_len = AUX_PAYLOAD_SIZE(work);
		buf_size += iov[2].iov_len;
	}
	buf_size += iov[1].iov_len;
	work->resp_hdr_sz = iov[1].iov_len;

	rc = crypt_message(work->conn, &rqst, 1);
	if (rc)
		return rc;

	memmove(buf, iov[1].iov_base, iov[1].iov_len);
	tr_hdr->smb2_buf_length = cpu_to_be32(buf_size);
	work->tr_buf = tr_hdr;

	return rc;
}

int smb3_is_transform_hdr(void *buf)
{
	struct smb2_transform_hdr *trhdr = buf;

	return trhdr->ProtocolId == SMB2_TRANSFORM_PROTO_NUM;
}

int smb3_decrypt_req(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct cifsd_session *sess;
	char *buf = REQUEST_BUF(work);
	struct smb2_hdr *hdr;
	unsigned int pdu_length = get_rfc1002_length(buf);
	struct kvec iov[2];
	struct smb_rqst rqst = {NULL};
	unsigned int buf_data_size = pdu_length + 4 -
		sizeof(struct smb2_transform_hdr);
	struct smb2_transform_hdr *tr_hdr = (struct smb2_transform_hdr *)buf;
	unsigned int orig_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
	int rc = 0;

	sess = cifsd_session_lookup(conn, le64_to_cpu(tr_hdr->SessionId));
	if (!sess) {
		cifsd_err("invalid session id(%llx) in transform header\n",
		le64_to_cpu(tr_hdr->SessionId));
		return -ECONNABORTED;
	}

	if (pdu_length + 4 < sizeof(struct smb2_transform_hdr) +
			sizeof(struct smb2_hdr)) {
		cifsd_err("Transform message is too small (%u)\n",
				pdu_length);
		return -ECONNABORTED;
	}

	if (pdu_length + 4 < orig_len + sizeof(struct smb2_transform_hdr)) {
		cifsd_err("Transform message is broken\n");
		return -ECONNABORTED;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(struct smb2_transform_hdr);
	iov[1].iov_base = buf + sizeof(struct smb2_transform_hdr);
	iov[1].iov_len = buf_data_size;

	rqst.rq_iov = iov;
	rqst.rq_nvec = 2;

	rc = crypt_message(conn, &rqst, 0);
	if (rc)
		return rc;

	memmove(buf + 4, iov[1].iov_base, buf_data_size);
	hdr = (struct smb2_hdr *)buf;
	hdr->smb2_buf_length = cpu_to_be32(buf_data_size);

	return rc;
}
