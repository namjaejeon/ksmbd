// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "smb_common.h"
#include "server.h"

/* @FIXME */
#include "transport_tcp.h"

struct smb_protocol {
	int		index;
	char		*name;
	char		*prot;
	__u16		prot_id;
};

static struct smb_protocol protocols[] = {
// ifdef SMB1
	{CIFSD_SMB1_PROT,	"\2NT LM 0.12",	"NT1",	CIFSD_SMB10_PROT_ID},
// endif

	{CIFSD_SMB2_PROT,	"\2SMB 2.002",	"SMB2_02",CIFSD_SMB20_PROT_ID},
	{CIFSD_SMB21_PROT,	"\2SMB 2.1",	"SMB2_10",CIFSD_SMB21_PROT_ID},
	{CIFSD_SMB2X_PROT,	"\2SMB 2.???",	"SMB2_22",CIFSD_SMB2X_PROT_ID},
	{CIFSD_SMB30_PROT,	"\2SMB 3.0",	"SMB3_00",CIFSD_SMB30_PROT_ID},
	{CIFSD_SMB302_PROT,	"\2SMB 3.02",	"SMB3_02",CIFSD_SMB302_PROT_ID},
	{CIFSD_SMB311_PROT,	"\2SMB 3.1.1",	"SMB3_11",CIFSD_SMB311_PROT_ID},
};

inline int cifsd_min_protocol(void)
{
	return protocols[0].index;
}

inline int cifsd_max_protocol(void)
{
	return protocols[ARRAY_SIZE(protocols) - 1].index;
}

int get_protocol_idx(char *str)
{
	int res = -1, i;
	int protocol_index = protocols[ARRAY_SIZE(protocols) - 1].index;
	int len = strlen(str);

	for (i = 0; i <= protocol_index; i++) {
		if (!strncmp(str, protocols[i].prot, len)) {
			cifsd_debug("selected %s dialect i = %d\n",
				protocols[i].prot, i);
			res = protocols[i].index;
			break;
		}
	}
	return res;
}

/**
 * check_message() - check for valid smb2 request header
 * @buf:       smb2 header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 *
 * Return:      0 on success, otherwise 1
 */
int check_message(struct cifsd_work *work)
{
	struct smb2_hdr *smb2_hdr = REQUEST_BUF(work);

	if (smb2_hdr->ProtocolId == SMB2_PROTO_NUMBER) {
		cifsd_debug("got SMB2 command\n");
		return smb2_check_message(work);
	}

	return smb1_check_message(work);
}

/**
 * is_smb_request() - check for valid smb request type
 * @conn:     TCP server instance of connection
 * @type:	smb request type
 *
 * Return:      true on success, otherwise false
 */
bool is_smb_request(struct cifsd_tcp_conn *conn)
{
	int type = *(char *)conn->request_buf;

	switch (type) {
	case RFC1002_SESSION_MESSAGE:
		/* Regular SMB request */
		return true;
	case RFC1002_SESSION_KEEP_ALIVE:
		cifsd_debug("RFC 1002 session keep alive\n");
		break;
	default:
		cifsd_debug("RFC 1002 unknown request type 0x%x\n", type);
	}

	return false;
}

/* @FIXME rework this code */
int find_matching_smb1_dialect(int start_index, char *cli_dialects,
		__le16 byte_count)
{
	int i, smb1_index, cli_count, bcount, dialect_id = CIFSD_BAD_PROT_ID;
	char *dialects = NULL;

	if (unlikely(start_index >= ARRAY_SIZE(protocols))) {
		cifsd_err("bad start_index %d\n", start_index);
		return dialect_id;
	}

	for (i = start_index; i >= CIFSD_SMB1_PROT; i--) {
		smb1_index = 0;
		bcount = le16_to_cpu(byte_count);
		dialects = cli_dialects;

		while (bcount) {
			cli_count = strlen(dialects);
			cifsd_debug("client requested dialect %s\n",
					dialects);
			if (!strncmp(dialects, protocols[i].name,
						cli_count)) {
				if (i >= server_conf.min_protocol &&
					i <= server_conf.max_protocol) {
					cifsd_debug("selected %s dialect\n",
							protocols[i].name);
					if (i == CIFSD_SMB1_PROT)
						dialect_id = smb1_index;
					else
						dialect_id =
						protocols[i].prot_id;
				}
				goto out;
			}
			bcount -= (++cli_count);
			dialects += cli_count;
			smb1_index++;
		}
	}

out:
	return dialect_id;
}

/* @FIXME rework this code */
#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * find_matching_smb2_dialect() - find the greatest dialect between dialects
 * client and server support.
 * @start_index:	start protocol id for lookup
 * @cli_dialects:	client dialects
 * @srv_dialects:	server dialects
 * @directs_count:	client dialect count
 *
 * Return:      0
 */
int find_matching_smb2_dialect(int start_index, __le16 *cli_dialects,
	__le16 dialects_count)
{
	int i, dialect_id = CIFSD_BAD_PROT_ID;
	int count;

	for (i = start_index; i >= CIFSD_SMB2_PROT; i--) {
		count = le16_to_cpu(dialects_count);
		while (--count >= 0) {
			cifsd_debug("client requested dialect 0x%x\n",
				le16_to_cpu(cli_dialects[count]));
			if (le16_to_cpu(cli_dialects[count]) ==
					protocols[i].prot_id) {
				if (i >= server_conf.min_protocol &&
					i <= server_conf.max_protocol) {
					cifsd_debug("selected %s dialect\n",
							protocols[i].name);
					dialect_id = protocols[i].prot_id;
				}
				goto out;
			}
		}
	}

out:
	return dialect_id;
}
#endif

/**
 * negotiate_dialect() - negotiate smb dialect with smb client
 * @buf:	smb header
 *
 * Return:     protocol index on success, otherwise bad protocol id error
 */
int negotiate_dialect(void *buf)
{
	int start_index, ret = CIFSD_BAD_PROT_ID;

/* @FIXME rework this code */

#ifdef CONFIG_CIFS_SMB2_SERVER
	start_index = CIFSD_SMB311_PROT;
#else
	start_index = CIFSD_SMB1_PROT;
#endif

	if (*(__le32 *)((struct smb_hdr *)buf)->Protocol ==
			SMB1_PROTO_NUMBER) {
		/* SMB1 neg protocol */
		NEGOTIATE_REQ *req = (NEGOTIATE_REQ *)buf;
		ret = find_matching_smb1_dialect(start_index,
			req->DialectsArray, le16_to_cpu(req->ByteCount));
	} else if (((struct smb2_hdr *)buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		/* SMB2 neg protocol */
		struct smb2_negotiate_req *req;
		req = (struct smb2_negotiate_req *)buf;
		ret = find_matching_smb2_dialect(start_index, req->Dialects,
			le16_to_cpu(req->DialectCount));
#endif
	}

	return ret;
}
