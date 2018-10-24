// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "smb_common.h"
#include "server.h"

#include "smb1pdu.h"
#include "smb2pdu.h"

/* @FIXME */
#include "transport_tcp.h"

#ifdef CIFS_INSECURE_SERVER
#define CIFSD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb_hdr))
#else
#define CIFSD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb2_hdr))
#endif

struct smb_protocol {
	int		index;
	char		*name;
	char		*prot;
	__u16		prot_id;
};

static struct smb_protocol smb1_protos[] = {
#ifdef CIFS_INSECURE_SERVER
	{
		CIFSD_SMB1_PROT,
		"\2NT LM 0.12",
		"NT1",
		CIFSD_SMB10_PROT_ID
	},
#else
	{
		CIFSD_SMB1_PROT,
		"",
		"",
		-1
	},
#endif
};

static struct smb_protocol smb2_protos[] = {
#ifdef CIFS_INSECURE_SERVER
	{
		CIFSD_SMB2_PROT,
		"\2SMB 2.002",
		"SMB2_02",
		CIFSD_SMB20_PROT_ID
	},
#endif
	{
		CIFSD_SMB21_PROT,
		"\2SMB 2.1",
		"SMB2_10",
		CIFSD_SMB21_PROT_ID
	},
	{
		CIFSD_SMB2X_PROT,
		"\2SMB 2.???",
		"SMB2_22",
		CIFSD_SMB2X_PROT_ID
	},
	{
		CIFSD_SMB30_PROT,
		"\2SMB 3.0",
		"SMB3_00",
		CIFSD_SMB30_PROT_ID
	},
	{
		CIFSD_SMB302_PROT,
		"\2SMB 3.02",
		"SMB3_02",
		CIFSD_SMB302_PROT_ID
	},
	{
		CIFSD_SMB311_PROT,
		"\2SMB 3.1.1",
		"SMB3_11",
		CIFSD_SMB311_PROT_ID
	},
};

inline int cifsd_min_protocol(void)
{
#ifdef CIFS_INSECURE_SERVER
	return smb1_protos[0].index;
#else
	return smb2_protos[0].index;
#endif
}

inline int cifsd_max_protocol(void)
{
	return smb2_protos[ARRAY_SIZE(smb2_protos) - 1].index;
}

static int __lookup_proto_idx(char *str, struct smb_protocol *list, int offt)
{
	int len = strlen(str);

	while (offt >= 0) {
		if (!strncmp(str, list[offt].prot, len)) {
			cifsd_debug("selected %s dialect idx = %d\n",
					list[offt].prot, offt);
			return list[offt].index;
		}
		offt--;
	}
	return -1;
}

int get_protocol_idx(char *str)
{
	int idx;

	idx = __lookup_proto_idx(str,
				 smb2_protos,
				 ARRAY_SIZE(smb2_protos) - 1);
	if (idx != -EINVAL)
		return idx;

	return __lookup_proto_idx(str,
				  smb1_protos,
				  ARRAY_SIZE(smb1_protos) - 1);
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

static bool supported_protocol(int idx)
{
	return (server_conf.min_protocol <= idx &&
			idx <= server_conf.max_protocol);
}

#ifdef CIFS_INSECURE_SERVER
static int cifsd_lookup_insecure_dialect(char *cli_dialects, __le16 byte_count)
{
	int i, smb1_index, cli_count, bcount;
	char *dialects = NULL;

	for (i = ARRAY_SIZE(smb1_protos) - 1; i >= 0; i--) {
		smb1_index = 0;
		bcount = le16_to_cpu(byte_count);
		dialects = cli_dialects;

		while (bcount) {
			cli_count = strlen(dialects);
			cifsd_debug("client requested dialect %s\n",
					dialects);
			if (!strncmp(dialects, smb1_protos[i].name,
						cli_count)) {
				if (supported_protocol(i)) {
					cifsd_debug("selected %s dialect\n",
							smb1_protos[i].name);
					if (i == CIFSD_SMB1_PROT)
						return smb1_index;
					return smb1_protos[i].prot_id;
				}
			}
			bcount -= (++cli_count);
			dialects += cli_count;
			smb1_index++;
		}
	}

	return CIFSD_BAD_PROT_ID;
}
#else
static int cifsd_lookup_insecure_dialect(char *cli_dialects, __le16 byte_count)
{
	return CIFSD_BAD_PROT_ID;
}
#endif

int cifsd_lookup_smb2_dialect(__le16 *cli_dialects, __le16 dialects_count)
{
	int i;
	int count;

	for (i = ARRAY_SIZE(smb2_protos) - 1; i >= 0; i--) {
		count = le16_to_cpu(dialects_count);
		while (--count >= 0) {
			cifsd_debug("client requested dialect 0x%x\n",
				le16_to_cpu(cli_dialects[count]));
			if (le16_to_cpu(cli_dialects[count]) !=
					smb2_protos[i].prot_id)
				continue;

			if (supported_protocol(i)) {
				cifsd_debug("selected %s dialect\n",
					smb2_protos[i].name);
				return smb2_protos[i].prot_id;
			}
		}
	}

	return CIFSD_BAD_PROT_ID;
}

int cifsd_negotiate_smb_dialect(void *buf)
{
	int proto;
 
	proto = ((struct smb2_hdr *)buf)->ProtocolId;
	if (proto == SMB2_PROTO_NUMBER) {
		struct smb2_negotiate_req *req;

		req = (struct smb2_negotiate_req *)buf;
		return cifsd_lookup_smb2_dialect(req->Dialects,
					le16_to_cpu(req->DialectCount));
	}

	proto = *(__le32 *)((struct smb_hdr *)buf)->Protocol;
	if (proto == SMB1_PROTO_NUMBER) {
		NEGOTIATE_REQ *req;

		req = (NEGOTIATE_REQ *)buf;
		return cifsd_lookup_insecure_dialect(req->DialectsArray,
					le16_to_cpu(req->ByteCount));
	}

	return CIFSD_BAD_PROT_ID;
}

void cifsd_init_smb_server(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;

	if (!conn->need_neg)
		return;

	if (is_smb2_neg_cmd(work)) {
		init_smb2_0_server(conn);
		return;
	}

	init_smb1_server(conn);
	if (conn->ops->get_cmd_val(work) != SMB_COM_NEGOTIATE)
		conn->need_neg = false;
}

bool cifsd_pdu_size_has_room(unsigned int pdu)
{
	return (pdu >= CIFSD_MIN_SUPPORTED_HEADER_SIZE - 4);
}
