/*
 *   fs/cifssrv/auth.c
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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/xattr.h>

#include "glob.h"
#include "export.h"

/**
 * int process_ntlmv2() - NTLMv2 authentication handler
 * @server:	TCP server instance of connection
 * @pv2:	NTLMv2 challenge response
 * @usr:	user details
 * @dname:	domain name
 * @blen:	NTLMv2 blob length
 * @local_nls:	nls table to convert char to unicode
 *
 * Return:	0 on success, error number on error
 */
int process_ntlmv2(struct tcp_server_info *server, char *pv2,
		struct cifssrv_usr *usr, char *dname, int blen,
		struct nls_table *local_nls)
{
	struct ntlmv2_resp *v2data;
	struct crypto_shash *hmacmd5 = NULL;
	struct sdesc *sdeschmacmd5 = NULL;
	__le16 *user = NULL;
	wchar_t *domain = NULL;
	char *construct = NULL;
	int len;
	int rc = 0;
	char ntlmv2_hash[CIFS_ENCPWD_SIZE];
	char ntlmv2_rsp[CIFS_HMAC_MD5_HASH_SIZE];

	hmacmd5 = crypto_alloc_shash("hmac(md5)", 0, 0);
	if (IS_ERR(hmacmd5)) {
		cifssrv_debug("could not allocate crypto hmacmd5\n");
		return PTR_ERR(hmacmd5);
	}

	len = sizeof(struct shash_desc) + crypto_shash_descsize(hmacmd5);
	sdeschmacmd5 = kmalloc(len, GFP_KERNEL);
	if (!sdeschmacmd5) {
		crypto_free_shash(hmacmd5);
		return -ENOMEM;
	}
	sdeschmacmd5->shash.tfm = hmacmd5;
	sdeschmacmd5->shash.flags = 0x0;

	v2data = (struct ntlmv2_resp *)pv2;

	rc = crypto_shash_setkey(hmacmd5, usr->passkey, CIFS_ENCPWD_SIZE);
	if (rc) {
		cifssrv_debug("%s: Could not set NT Hash as a key\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	rc = crypto_shash_init(&sdeschmacmd5->shash);
	if (rc) {
		cifssrv_debug("%s: could not init hmacmd5\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	/* convert user_name to unicode */
	len = strlen(usr->name);
	user = kzalloc(2 + (len * 2), GFP_KERNEL);
	if (!user) {
		rc = -ENOMEM;
		goto EXIT;
	}

	if (len) {
		len = smb_strtoUTF16(user, usr->name, len, local_nls);
		UniStrupr(user);
	} else
		memset(user, '\0', 2);

	rc = crypto_shash_update(&sdeschmacmd5->shash, (char *)user, 2 * len);
	if (rc) {
		cifssrv_debug("%s: Could not update with user\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	/* convert domainName to unicode and uppercase */
	len = strlen(dname);
	domain = kzalloc(2 + (len * 2), GFP_KERNEL);
	if (!domain) {
		cifssrv_debug("%s:%d memory allocation failed\n",
				__func__, __LINE__);
		rc = -ENOMEM;
		goto EXIT;
	}

	len = smb_strtoUTF16((__le16 *)domain, dname, len,
			local_nls);

	rc = crypto_shash_update(&sdeschmacmd5->shash, (char *)domain, 2 * len);
	if (rc) {
		cifssrv_debug("%s: Could not update with domain\n",
				__func__);
		rc = -EINVAL;
		goto EXIT;
	}

	rc = crypto_shash_final(&sdeschmacmd5->shash, ntlmv2_hash);
	if (rc) {
		cifssrv_debug("%s: Could not generate md5 hash\n",
				__func__);
		rc = -EINVAL;
		goto EXIT;
	}

	rc = crypto_shash_setkey(hmacmd5, ntlmv2_hash, CIFS_HMAC_MD5_HASH_SIZE);
	if (rc) {
		cifssrv_debug("%s: Could not set NTLMV2 Hash as a key\n",
				__func__);
		rc = -EINVAL;
		goto EXIT;
	}

	rc = crypto_shash_init(&sdeschmacmd5->shash);
	if (rc) {
		cifssrv_debug("%s: could not init hmacmd5\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	len = 8 + blen;
	construct = kzalloc(len, GFP_KERNEL);
	if (!construct) {
		cifssrv_debug("%s:%d memory allocation failed\n",
				__func__, __LINE__);
		rc = -EINVAL;
		goto EXIT;
	}

	memcpy(construct, server->cryptkey, CIFS_CRYPTO_KEY_SIZE);
	memcpy(construct+8, (char *)(&v2data->blob_signature), blen);

	rc = crypto_shash_update(&sdeschmacmd5->shash, construct, len);
	if (rc) {
		cifssrv_debug("%s: Could not update with response\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	rc = crypto_shash_final(&sdeschmacmd5->shash, ntlmv2_rsp);
	if (rc) {
		cifssrv_debug("%s: Could not generate md5 hash\n", __func__);
		rc = -EINVAL;
		goto EXIT;
	}

	if (!memcmp(v2data->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE))
		rc = 0;
	else
		rc = 1;

EXIT:
	crypto_free_shash(hmacmd5);
	kfree(sdeschmacmd5);
	kfree(user);
	kfree(domain);
	kfree(construct);

	return rc;
}

/**
 * build_ntlmssp_challenge_blob() - helper function to construct negotiate blob
 * @chgblob:	challenge blob source pointer to initialize
 * @rsp:	response header pointer to be updated
 * @server:	TCP server instance of connection
 *
 */
void build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
		struct smb2_sess_setup_rsp *rsp,
		struct tcp_server_info *server) {
	TargetInfo attr;
	int len, off;
	int attrs = 0;
	int names = 0;
	__le16 type;
	__le16 name[8];

	*(__le64 *)chgblob->Signature = NTLMSSP_SIGNATURE_VAL;
	chgblob->MessageType = NtLmChallenge;

	len = smb_strtoUTF16(name, netbios_name, strlen(netbios_name),
			server->local_nls);
	chgblob->TargetName.Length = UNICODE_LEN(len);
	chgblob->TargetName.MaximumLength = chgblob->TargetName.Length;
	chgblob->TargetName.BufferOffset = sizeof(CHALLENGE_MESSAGE);

	off = rsp->SecurityBufferOffset +
		chgblob->TargetName.BufferOffset;
	/* start from rsp->hdr.ProtocolId */
	memcpy((char *)&rsp->hdr + 4 + off, name, UNICODE_LEN(len));

	chgblob->NegotiateFlags = NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_REQUEST_TARGET |
		NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_56;

	/* initialize random server challenge */
	get_random_bytes(server->cryptkey, sizeof(__u64));
	memcpy(chgblob->Challenge, server->cryptkey,
			CIFS_CRYPTO_KEY_SIZE);

	rsp->SecurityBufferLength = sizeof(CHALLENGE_MESSAGE) +
		UNICODE_LEN(len);

	/* update target info list for NetBIOS settings */
	for (type = NetBIOS_COMP_NAME; type <= NetBIOS_DOMAIN_NAME;
			type++) {
		attr.Type = type;
		attr.Length = UNICODE_LEN(len);
		off += UNICODE_LEN(len);
		memcpy(rsp->hdr.ProtocolId + off, &attr, sizeof(TargetInfo));
		attrs++;
		off += sizeof(TargetInfo);
		memcpy(rsp->hdr.ProtocolId + off, name, UNICODE_LEN(len));
		names++;
	}

	/* update target info list for DNS settings */
	for (type = DNS_COMP_NAME; type <= DNS_DOMAIN_NAME; type++) {
		attr.Type = type;
		attr.Length = 0;

		if (type == DNS_COMP_NAME)
			off += UNICODE_LEN(len);
		else
			off += sizeof(TargetInfo);

		memcpy(rsp->hdr.ProtocolId + off, &attr, sizeof(TargetInfo));
		attrs++;
	}

	attr.Type = 0;
	attr.Length = 0;
	off += sizeof(TargetInfo);
	memcpy(rsp->hdr.ProtocolId + off, &attr, sizeof(TargetInfo));
	attrs++;

	chgblob->TargetInfoArray.Length = sizeof(TargetInfo)*attrs +
		(UNICODE_LEN(len))*names;
	chgblob->TargetInfoArray.MaximumLength =
		chgblob->TargetInfoArray.Length;
	chgblob->TargetInfoArray.BufferOffset =
		chgblob->TargetName.BufferOffset + UNICODE_LEN(len);
}
