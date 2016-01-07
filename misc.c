/*
 *   fs/cifssrv/misc.c
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

static struct {
	int index;
	char *name;
	__u16 prot_id;
} protocols[] = {
	{CIFS_PROT, "\2NT LM 0.12", 0},
#ifdef CONFIG_CIFS_SMB2_SERVER
	{SMB2_PROT, "\2SMB 2.002", SMB20_PROT_ID},
	{SMB21_PROT, "\2SMB 2.1", SMB21_PROT_ID},
	{SMB2X_PROT, "\2SMB 2.???", SMB2X_PROT_ID},
	{SMB30_PROT, "\2SMB 3.0", SMB30_PROT_ID},
#endif
};

/**
 * check_smb_hdr() - check for valid smb request header
 * @smb:	smb header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 * TODO: properly check client authetication and tree authentication
 *
 * Return:      0 on success, otherwise 1
 */
static int check_smb_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {
		cifssrv_debug("Bad protocol string signature header 0x%x\n",
			*(unsigned int *)smb->Protocol);
		return 1;
	} else
		cifssrv_debug("got SMB\n");

	/* if it's not a response then accept */
	/* TODO : check for oplock break */
	if (!(smb->Flags & SMBFLG_RESPONSE))
		return 0;

	cifssrv_debug("Server sent request, not response\n");
	return 1;
}

/**
 * check_smb2_hdr() - helper function to check for valid smb2 request header
 * @smb:	smb2 header to be checked
 *
 * Return:      0 on success, otherwise 1
 */
static int check_smb2_hdr(struct smb2_hdr *smb)
{
	if (!(smb->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
		return 0;

	cifssrv_debug("Server sent request, not response\n");
	return 1;
}

/**
 * check_smb2_hdr() - check for valid smb2 request header
 * @buf:	smb2 header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 *
 * Return:      0 on success, otherwise 1
 */
int check_smb_message(char *buf)
{

	if (*(__le32 *)((struct smb2_hdr *)buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {

		cifssrv_debug("got SMB2 command\n");
		return check_smb2_hdr((struct smb2_hdr *)buf);

	}

	return check_smb_hdr((struct smb_hdr *)buf);

}

/**
 * add_request_to_queue() - check a request for addition to pending smb work
 *				queue
 * @smb_work:	smb request work
 *
 * Return:      true if not add to queue, otherwise false
 */
bool add_request_to_queue(struct smb_work *smb_work)
{
	struct tcp_server_info *server = smb_work->server;

	if (*(__le32 *)((struct smb2_hdr *)smb_work->buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {
		if (server->ops->get_cmd_val(smb_work) != SMB2_CANCEL)
			return true;
	} else {
		if (server->ops->get_cmd_val(smb_work) != SMB_COM_NT_CANCEL)
			return true;
	}

	return false;
}

/**
 * dump_smb_msg() - print smb packet for debugging
 * @buf:		smb packet
 * @smb_buf_length:	packet print length
 *
 */
void dump_smb_msg(void *buf, int smb_buf_length)
{
	int i, j;
	char debug_line[17];
	unsigned char *buffer = buf;

	if (likely(cifssrv_debug_enable != 2))
		return;

	for (i = 0, j = 0; i < smb_buf_length; i++, j++) {
		if (i % 8 == 0) {
			/* have reached the beginning of line */
			cifssrv_debug("| ");
			j = 0;
		}
		cifssrv_debug("%0#4x ", buffer[i]);
		debug_line[2 * j] = ' ';
		if (isprint(buffer[i]))
			debug_line[1 + (2 * j)] = buffer[i];
		else
			debug_line[1 + (2 * j)] = '_';

		if (i % 8 == 7) {
			/* reached end of line, time to print ascii */
			debug_line[16] = 0;
			cifssrv_debug(" | %s\n", debug_line);
		}
	}
	for (; j < 8; j++) {
		cifssrv_debug("     ");
		debug_line[2 * j] = ' ';
		debug_line[1 + (2 * j)] = ' ';
	}
	cifssrv_debug(" | %s\n", debug_line);
	return;
}

/**
 * switch_req_buf() - switch to big request buffer
 * @server:     TCP server instance of connection
 *
 * Return:      0 on success, otherwise -ENOMEM
 */
int switch_req_buf(struct tcp_server_info *server)
{
	char *buf = server->smallbuf;
	unsigned int pdu_length = get_rfc1002_length(buf);
	unsigned int hdr_len;

#ifdef CONFIG_CIFS_SMB2_SERVER
	hdr_len = MAX_SMB2_HDR_SIZE;
#else
	hdr_len = MAX_CIFS_HDR_SIZE;
#endif

	/* request can fit in large request buffer i.e. < 64K */
	if (pdu_length <= SMBMaxBufSize + hdr_len - 4) {
		cifssrv_debug("switching to large buffer\n");
		server->large_buf = true;
		memcpy(server->bigbuf, buf, server->total_read);
	} else if (pdu_length <= CIFS_DEFAULT_IOSIZE + hdr_len - 4) {
		/* allocate big buffer for large write request i.e. > 64K */
		server->wbuf = vmalloc(CIFS_DEFAULT_IOSIZE + hdr_len);
		if (!server->wbuf) {
			cifssrv_debug("failed to alloc mem\n");
			return -ENOMEM;
		}
		memcpy(server->wbuf, buf, server->total_read);

		/* as wbuf is used for request, free both small and big buf */
		mempool_free(server->smallbuf, cifssrv_sm_req_poolp);
		mempool_free(server->bigbuf, cifssrv_req_poolp);
		server->large_buf = false;
		server->smallbuf = NULL;
		server->bigbuf = NULL;
	} else {
		cifssrv_debug("SMB request too long (%u bytes)\n", pdu_length);
		return -ECONNABORTED;
	}

	return 0;
}

/**
 * switch_rsp_buf() - switch to large response buffer
 * @smb_work:	smb request work
 *
 * Return:      0 on success, otherwise -ENOMEM
 */
int switch_rsp_buf(struct smb_work *smb_work)
{
	char *buf;
	if (smb_work->rsp_large_buf) {
		cifssrv_debug("already using rsp_large_buf\n");
		return 0;
	}

	buf = mempool_alloc(cifssrv_rsp_poolp, GFP_NOFS);
	if (!buf) {
		cifssrv_debug("failed to alloc mem\n");
		return -ENOMEM;
	}

	/* free small buf and switch to large rsp buffer */
	cifssrv_debug("switching to large rsp buf\n");
	memcpy(buf, smb_work->rsp_buf, MAX_CIFS_SMALL_BUFFER_SIZE);
	mempool_free(smb_work->rsp_buf, cifssrv_sm_rsp_poolp);

	smb_work->rsp_buf = buf;
	smb_work->rsp_large_buf = true;
	return 0;
}

/**
 * is_smb_request() - check for valid smb request type
 * @server:     TCP server instance of connection
 * @type:	smb request type
 *
 * Return:      true on success, otherwise false
 */
bool is_smb_request(struct tcp_server_info *server, unsigned char type)
{
	switch (type) {
	case RFC1002_SESSION_MESSAGE:
		/* Regular SMB request */
		return true;
	case RFC1002_SESSION_KEEP_ALIVE:
		cifssrv_debug("RFC 1002 session keep alive\n");
		break;
	default:
		cifssrv_debug("RFC 1002 unknown request type 0x%x\n", type);
	}

	return false;
}

/**
 * negotiate_dialect() - negotiate smb dialect with smb client
 * @buf:	smb header
 *
 * Return:     protocol index on success, otherwise bad protocol id error
 */
int negotiate_dialect(void *buf)
{
	int byte_count, count, i, smb1_index, start_index;
	char *dialects = NULL;

#ifdef CONFIG_CIFS_SMB2_SERVER
	start_index = SMB30_PROT;
#else
	start_index = CIFS_PROT;
#endif

	if (*(__le32 *)((struct smb_hdr *)buf)->Protocol ==
			SMB1_PROTO_NUMBER) {
		/* SMB1 neg protocol */
		NEGOTIATE_REQ *req = (NEGOTIATE_REQ *)buf;
		for (i = start_index; i >= CIFS_PROT; i--) {
			byte_count = le16_to_cpu(req->ByteCount);
			dialects = req->DialectsArray;
			smb1_index = 0;

			while (byte_count) {
				count = strlen(dialects);
				cifssrv_debug("client requested dialect %s\n",
						dialects);
				if (!strncmp(dialects, protocols[i].name,
							count)) {
					cifssrv_debug("selected %s dialect\n",
							protocols[i].name);
					if (i == CIFS_PROT)
						return smb1_index;
					else
						return protocols[i].prot_id;
				}
				byte_count -= (++count);
				dialects += count;
				smb1_index++;
			}
		}
	} else if (*(__le32 *)((struct smb2_hdr *)buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		/* SMB2 neg protocol */
		struct smb2_negotiate_req *req;
		req = (struct smb2_negotiate_req *)buf;
		for (i = start_index; i >= SMB2_PROT; i--) {
			count = le16_to_cpu(req->DialectCount);

			while (--count >= 0) {
				cifssrv_debug("client requested dialect 0x%x\n",
					le16_to_cpu(req->Dialects[count]));
				if (le16_to_cpu(req->Dialects[count]) ==
						protocols[i].prot_id) {
					cifssrv_debug("selected %s dialect\n",
							protocols[i].name);
					return protocols[i].prot_id;
				}
			}
		}
#endif
	}
	return BAD_PROT_ID;
}
