/*
 *   fs/cifssrv/auth.c
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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/xattr.h>

#include "glob.h"
#include "export.h"

static int crypto_hmacmd5_alloc(struct tcp_server_info *server)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (server->secmech.sdeschmacmd5)
		return 0;

	server->secmech.hmacmd5 = crypto_alloc_shash("hmac(md5)", 0, 0);
	if (IS_ERR(server->secmech.hmacmd5)) {
		cifssrv_debug("could not allocate crypto hmacmd5\n");
		rc = PTR_ERR(server->secmech.hmacmd5);
		server->secmech.hmacmd5 = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(server->secmech.hmacmd5);
	server->secmech.sdeschmacmd5 = kmalloc(size, GFP_KERNEL);
	if (!server->secmech.sdeschmacmd5) {
		crypto_free_shash(server->secmech.hmacmd5);
		server->secmech.hmacmd5 = NULL;
		return -ENOMEM;
	}
	server->secmech.sdeschmacmd5->shash.tfm = server->secmech.hmacmd5;
	server->secmech.sdeschmacmd5->shash.flags = 0x0;

	return 0;
}

static int calc_ntlmv2_hash(struct tcp_server_info *server, char *username,
		char *passkey, char *ntlmv2_hash, char *dname)
{
	int ret, len;
	wchar_t *domain;
	__le16 *uniname;

	if (!server->secmech.sdeschmacmd5) {
		cifssrv_debug("can't generate ntlmv2 hash\n");
		return -1;
	}

	ret = crypto_shash_setkey(server->secmech.hmacmd5, passkey,
			CIFS_ENCPWD_SIZE);
	if (ret) {
		cifssrv_debug("Could not set NT Hash as a key\n");
		return ret;
	}

	ret = crypto_shash_init(&server->secmech.sdeschmacmd5->shash);
	if (ret) {
		cifssrv_debug("could not init hmacmd5\n");
		return ret;
	}

	/* convert user_name to unicode */
	len = strlen(username);
	uniname = kzalloc(2 + UNICODE_LEN(len), GFP_KERNEL);
	if (!uniname) {
		ret = -ENOMEM;
		return ret;
	}

	if (len) {
		len = smb_strtoUTF16(uniname, username, len, server->local_nls);
		UniStrupr(uniname);
	}

	ret = crypto_shash_update(&server->secmech.sdeschmacmd5->shash,
			(char *)uniname, UNICODE_LEN(len));
	if (ret) {
		cifssrv_debug("Could not update with user\n");
		return ret;
	}

	/* Convert domain name or server name to unicode and uppercase */
	len = strlen(dname);
	domain = kzalloc(2 + UNICODE_LEN(len), GFP_KERNEL);
	if (!domain) {
		cifssrv_debug("memory allocation failed\n");
		ret = -ENOMEM;
		return ret;
	}

	len = smb_strtoUTF16((__le16 *)domain, dname, len, server->local_nls);

	ret = crypto_shash_update(&server->secmech.sdeschmacmd5->shash,
					(char *)domain, UNICODE_LEN(len));
	if (ret) {
		cifssrv_debug("Could not update with domain\n");
		return ret;
	}

	ret = crypto_shash_final(&server->secmech.sdeschmacmd5->shash,
			ntlmv2_hash);
	if (ret) {
		cifssrv_debug("Could not generate md5 hash\n");
	}

	return ret;
}

/**
 * process_ntlmv() - NTLM authentication handler
 * @server:	TCP server instance of connection
 * @pw_buf:	NTLM challenge response
 * @passkey:	user password
 *
 * Return:	0 on success, error number on error
 */
int process_ntlm(struct tcp_server_info *server, char *pw_buf, char *passkey)
{
	int rc;
	unsigned char p21[21];
	char key[CIFS_AUTH_RESP_SIZE];

	memset(p21, '\0', 21);
	memcpy(p21, passkey, CIFS_NTHASH_SIZE);
	rc = E_P24(p21, server->ntlmssp.cryptkey, key);
	if (rc) {
		cifssrv_err("password processing failed\n");
		return rc;
	}

	if (strncmp(pw_buf, key, CIFS_AUTH_RESP_SIZE) != 0) {
		cifssrv_debug("ntlmv1 authentication failed\n");
		rc = -EINVAL;
	} else
		cifssrv_debug("ntlmv1 authentication pass\n");

	return rc;
}

/**
 * process_ntlmv2() - NTLMv2 authentication handler
 * @server:		TCP server instance of connection
 * @ntlmv2:		NTLMv2 challenge response
 * @blen:		NTLMv2 blob length
 * @domain_name:	domain name
 * @usr:		user details
 *
 * Return:	0 on success, error number on error
 */
int process_ntlmv2(struct tcp_server_info *server, struct ntlmv2_resp *ntlmv2,
		int blen, char *domain_name, struct cifssrv_usr *usr)
{
	char ntlmv2_hash[CIFS_ENCPWD_SIZE];
	char ntlmv2_rsp[CIFS_HMAC_MD5_HASH_SIZE];
	char *construct;
	int rc, len;

	rc = crypto_hmacmd5_alloc(server);
	if (rc) {
		cifssrv_debug("could not crypto alloc hmacmd5 rc %d\n", rc);
		goto out;
	}

	if (domain_name == netbios_name)
		rc = calc_ntlmv2_hash(server, usr->name, usr->passkey,
			ntlmv2_hash, netbios_name);
	else
		rc = calc_ntlmv2_hash(server, usr->name, usr->passkey,
			ntlmv2_hash, domain_name);

	if (rc) {
		cifssrv_debug("could not get v2 hash rc %d\n", rc);
		goto out;
	}

	rc = crypto_shash_setkey(server->secmech.hmacmd5, ntlmv2_hash,
						CIFS_HMAC_MD5_HASH_SIZE);
	if (rc) {
		cifssrv_debug("Could not set NTLMV2 Hash as a key\n");
		goto out;
	}

	rc = crypto_shash_init(&server->secmech.sdeschmacmd5->shash);
	if (rc) {
		cifssrv_debug("Could not init hmacmd5\n");
		goto out;
	}

	len = CIFS_CRYPTO_KEY_SIZE + blen;
	construct = kzalloc(len, GFP_KERNEL);
	if (!construct) {
		cifssrv_debug("Memory allocation failed\n");
		rc = -ENOMEM;
		goto out;
	}

	memcpy(construct, server->ntlmssp.cryptkey, CIFS_CRYPTO_KEY_SIZE);
	memcpy(construct + CIFS_CRYPTO_KEY_SIZE,
		(char *)(&ntlmv2->blob_signature), blen);

	rc = crypto_shash_update(&server->secmech.sdeschmacmd5->shash,
			construct, len);
	if (rc) {
		cifssrv_debug("Could not update with response\n");
		goto out;
	}

	rc = crypto_shash_final(&server->secmech.sdeschmacmd5->shash,
			ntlmv2_rsp);
	if (rc) {
		cifssrv_debug("Could not generate md5 hash\n");
		goto out;
	}

	rc = memcmp(ntlmv2->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE);
out:
	return rc;
}

/**
 * decode_ntlmssp_authenticate_blob() - helper function to construct
 * authenticate blob
 * @authblob:	authenticate blob source pointer
 * @usr:	user details
 * @server:	TCP server instance of connection
 *
 * Return:	0 on success, error number on error
 */
int decode_ntlmssp_authenticate_blob(AUTHENTICATE_MESSAGE *authblob,
		int blob_len, struct cifssrv_usr *usr,
		struct tcp_server_info *server)
{
	char *domain_name;

	if (blob_len < sizeof(AUTHENTICATE_MESSAGE)) {
		cifssrv_debug("negotiate blob len %d too small\n", blob_len);
		return -EINVAL;
	}

	if (memcmp(authblob->Signature, "NTLMSSP", 8)) {
		cifssrv_debug("blob signature incorrect %s\n",
				authblob->Signature);
		return -EINVAL;
	}

	/* process NTLM authentication */
	if (authblob->NtChallengeResponse.Length == CIFS_AUTH_RESP_SIZE) {
		return process_ntlm(server, (char *)authblob +
			authblob->NtChallengeResponse.BufferOffset,
			usr->passkey);
	}

	/* TODO : use domain name that imported from configuration file */
	domain_name = smb_strndup_from_utf16(
			(const char *)authblob +
			authblob->DomainName.BufferOffset,
			authblob->DomainName.Length, true,
			server->local_nls);

	/* process NTLMv2 authentication */
	return process_ntlmv2(server, (struct ntlmv2_resp *)((char *)authblob +
		authblob->NtChallengeResponse.BufferOffset),
		authblob->NtChallengeResponse.Length - CIFS_ENCPWD_SIZE,
		domain_name, usr);
}

/**
 * decode_ntlmssp_negotiate_blob() - helper function to construct negotiate blob
 * @negblob:	negotiate blob source pointer
 * @rsp:	response header pointer to be updated
 * @server:	TCP server instance of connection
 *
 */
int decode_ntlmssp_negotiate_blob(NEGOTIATE_MESSAGE *negblob,
		int blob_len, struct tcp_server_info *server)
{
	if (blob_len < sizeof(NEGOTIATE_MESSAGE)) {
		cifssrv_debug("negotiate blob len %d too small\n", blob_len);
		return -EINVAL;
	}

	if (memcmp(negblob->Signature, "NTLMSSP", 8)) {
		cifssrv_debug("blob signature incorrect %s\n",
				negblob->Signature);
		return -EINVAL;
	}

	server->ntlmssp.client_flags = negblob->NegotiateFlags;

	if (negblob->NegotiateFlags & NTLMSSP_NEGOTIATE_56) {
		/* TBD: area for session sign/seal */
	}

	return 0;
}

/**
 * build_ntlmssp_challenge_blob() - helper function to construct challenge blob
 * @chgblob:	challenge blob source pointer to initialize
 * @rsp:	response header pointer to be updated
 * @server:	TCP server instance of connection
 *
 */
unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
		struct tcp_server_info *server)
{
	TargetInfo *tinfo;
	__le16 name[8];
	__u8 *target_name;
	unsigned int len, flags, blob_len, type;

	memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);
	chgblob->MessageType = NtLmChallenge;

	flags = NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;

	if (server->ntlmssp.client_flags & NTLMSSP_REQUEST_TARGET)
		flags |= NTLMSSP_REQUEST_TARGET;

	chgblob->NegotiateFlags = cpu_to_le32(flags);

	len = smb_strtoUTF16(name, netbios_name, strlen(netbios_name),
			server->local_nls);
	len = UNICODE_LEN(len);
	chgblob->TargetName.Length = cpu_to_le16(len);
	chgblob->TargetName.MaximumLength = cpu_to_le16(len);
	chgblob->TargetName.BufferOffset =
			cpu_to_le32(sizeof(CHALLENGE_MESSAGE));

	/* Initialize random server challenge */
	get_random_bytes(server->ntlmssp.cryptkey, sizeof(__u64));
	memcpy(chgblob->Challenge, server->ntlmssp.cryptkey,
		CIFS_CRYPTO_KEY_SIZE);

	/* Add Target Information to security buffer */
	chgblob->TargetInfoArray.BufferOffset =
		chgblob->TargetName.BufferOffset + len;

	target_name = (__u8 *)chgblob + chgblob->TargetName.BufferOffset;
	memcpy(target_name, name, len);
	blob_len = cpu_to_le16(sizeof(CHALLENGE_MESSAGE) + len);
	tinfo = (TargetInfo *)(target_name + len);

	chgblob->TargetInfoArray.Length = 0;
	/* Add target info list for NetBIOS/DNS settings */
	for (type = NTLMSSP_AV_NB_COMPUTER_NAME;
		type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {
		tinfo->Type = type;
		tinfo->Length = len;
		memcpy(tinfo->Content, name, len);
		tinfo = (TargetInfo *)((char *)tinfo + 4 + len);
		chgblob->TargetInfoArray.Length += cpu_to_le16(4 + len);
	}

	/* Add terminator subblock */
	tinfo->Type = 0;
	tinfo->Length = 0;
	chgblob->TargetInfoArray.Length += cpu_to_le16(4);

	chgblob->TargetInfoArray.MaximumLength =
			chgblob->TargetInfoArray.Length;
	blob_len += chgblob->TargetInfoArray.Length;
	cifssrv_debug("NTLMSSP SecurityBufferLength %d\n", blob_len);
	return blob_len;
}
