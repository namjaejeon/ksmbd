// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "glob.h"
#include "asn1.h"
#include "nterr.h"
#include "smb1pdu.h"
#include "smb_common.h"
#include "mgmt/user_session.h"

/**
 * check_smb_hdr() - check for valid smb request header
 * @smb:        smb header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 * TODO: properly check client authetication and tree authentication
 *
 * Return:      0 on success, otherwise 1
 */
static int check_smb1_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {
		cifsd_debug("Bad protocol string signature header 0x%x\n",
				*(unsigned int *)smb->Protocol);
		return 1;
	} else
		cifsd_debug("got SMB\n");

	/* if it's not a response then accept */
	/* TODO : check for oplock break */
	if (!(smb->Flags & SMBFLG_RESPONSE))
		return 0;

	cifsd_debug("Server sent request, not response\n");
	return 1;
}

int smb1_check_message(struct cifsd_work *work)
{
	struct smb_hdr *hdr = (struct smb_hdr *)REQUEST_BUF(work);

	if (check_smb1_hdr(hdr))
		return 1;

	return 0;
}

int smb_negotiate_request(struct cifsd_work *work)
{
	return cifsd_smb_negotiate_common(work, SMB_COM_NEGOTIATE);
}
