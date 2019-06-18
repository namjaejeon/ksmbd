// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/uio.h>
#include <linux/xattr.h>
#include <crypto/aead.h>

#include "auth.h"
#include "glob.h"

#include "encrypt.h"
#include "server.h"
#include "smb_common.h"
#include "transport_tcp.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

/*
 * Fixed format data defining GSS header and fixed string
 * "not_defined_in_RFC4178@please_ignore".
 * So sec blob data in neg phase could be generated statically.
 */
static char NEGOTIATE_GSS_HEADER[AUTH_GSS_LENGTH] = {
	0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
	0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
	0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
	0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a,
	0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f,
	0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
	0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43,
	0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65,
	0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
	0x72, 0x65
};

void cifsd_copy_gss_neg_header(void *buf)
{
	memcpy(buf, NEGOTIATE_GSS_HEADER, AUTH_GSS_LENGTH);
}

static inline void free_hmacmd5(struct cifsd_tcp_conn *conn)
{
	crypto_free_shash(conn->secmech.hmacmd5);
	conn->secmech.hmacmd5 = NULL;
	kfree(conn->secmech.sdeschmacmd5);
	conn->secmech.sdeschmacmd5 = NULL;
}

static inline void free_hmacsha256(struct cifsd_tcp_conn *conn)
{
	crypto_free_shash(conn->secmech.hmacsha256);
	conn->secmech.hmacsha256 = NULL;
	kfree(conn->secmech.sdeschmacsha256);
	conn->secmech.sdeschmacsha256 = NULL;
}

static inline void free_cmacaes(struct cifsd_tcp_conn *conn)
{
	crypto_free_shash(conn->secmech.cmacaes);
	conn->secmech.cmacaes = NULL;
	kfree(conn->secmech.sdesccmacaes);
	conn->secmech.sdesccmacaes = NULL;
}

static inline void free_sha512(struct cifsd_tcp_conn *conn)
{
	crypto_free_shash(conn->secmech.sha512);
	conn->secmech.sha512 = NULL;
	kfree(conn->secmech.sdescsha512);
	conn->secmech.sdescsha512 = NULL;
}

static inline void free_sdescmd5(struct cifsd_tcp_conn *conn)
{
	kfree(conn->secmech.md5);
	conn->secmech.md5 = NULL;
	kfree(conn->secmech.sdescmd5);
	conn->secmech.sdescmd5 = NULL;
}

static inline void free_ccmaes(struct cifsd_tcp_conn *conn)
{
	crypto_free_aead(conn->secmech.ccmaesencrypt);
	conn->secmech.ccmaesencrypt = NULL;
	crypto_free_aead(conn->secmech.ccmaesdecrypt);
	conn->secmech.ccmaesencrypt = NULL;
}

void cifsd_free_conn_secmech(struct cifsd_tcp_conn *conn)
{
	free_hmacmd5(conn);
	free_hmacsha256(conn);
	free_cmacaes(conn);
	free_sha512(conn);
	free_sdescmd5(conn);
	free_ccmaes(conn);
}

static int crypto_hmacmd5_alloc(struct cifsd_tcp_conn *conn)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (conn->secmech.sdeschmacmd5)
		return 0;

	conn->secmech.hmacmd5 = crypto_alloc_shash("hmac(md5)", 0, 0);
	if (IS_ERR(conn->secmech.hmacmd5)) {
		cifsd_debug("could not allocate crypto hmacmd5\n");
		rc = PTR_ERR(conn->secmech.hmacmd5);
		conn->secmech.hmacmd5 = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(conn->secmech.hmacmd5);
	conn->secmech.sdeschmacmd5 = kmalloc(size, GFP_KERNEL);
	if (!conn->secmech.sdeschmacmd5) {
		free_hmacmd5(conn);
		return -ENOMEM;
	}
	conn->secmech.sdeschmacmd5->shash.tfm = conn->secmech.hmacmd5;
	return 0;
}

/**
 * cifsd_gen_sess_key() - function to generate session key
 * @sess:	session of connection
 * @hash:	source hash value to be used for find session key
 * @hmac:	source hmac value to be used for finding session key
 *
 */
static int cifsd_gen_sess_key(struct cifsd_session *sess,
			      char *hash,
			      char *hmac)
{
	int rc;

	rc = crypto_hmacmd5_alloc(sess->conn);
	if (rc) {
		cifsd_debug("could not crypto alloc hmacmd5 rc %d\n", rc);
		goto out;
	}

	rc = crypto_shash_setkey(sess->conn->secmech.hmacmd5, hash,
			CIFS_HMAC_MD5_HASH_SIZE);
	if (rc) {
		cifsd_debug("hmacmd5 set key fail error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_init(&sess->conn->secmech.sdeschmacmd5->shash);
	if (rc) {
		cifsd_debug("could not init hmacmd5 error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacmd5->shash,
		hmac, SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifsd_debug("Could not update with response error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_final(&sess->conn->secmech.sdeschmacmd5->shash,
			sess->sess_key);
	if (rc) {
		cifsd_debug("Could not generate hmacmd5 hash error %d\n", rc);
		goto out;
	}

out:
	return rc;
}

static int calc_ntlmv2_hash(struct cifsd_session *sess, char *ntlmv2_hash,
	char *dname)
{
	int ret, len;
	wchar_t *domain = NULL;
	__le16 *uniname = NULL;

	if (!sess->conn->secmech.sdeschmacmd5) {
		cifsd_debug("can't generate ntlmv2 hash\n");
		return -1;
	}

	ret = crypto_shash_setkey(sess->conn->secmech.hmacmd5,
		user_passkey(sess->user), CIFS_ENCPWD_SIZE);
	if (ret) {
		cifsd_debug("Could not set NT Hash as a key\n");
		return ret;
	}

	ret = crypto_shash_init(&sess->conn->secmech.sdeschmacmd5->shash);
	if (ret) {
		cifsd_debug("could not init hmacmd5\n");
		return ret;
	}

	/* convert user_name to unicode */
	len = strlen(user_name(sess->user));
	uniname = kzalloc(2 + UNICODE_LEN(len), GFP_KERNEL);
	if (!uniname) {
		ret = -ENOMEM;
		goto out;
	}

	if (len) {
		len = smb_strtoUTF16(uniname, user_name(sess->user), len,
			sess->conn->local_nls);
		UniStrupr(uniname);
	}

	ret = crypto_shash_update(&sess->conn->secmech.sdeschmacmd5->shash,
			(char *)uniname, UNICODE_LEN(len));
	if (ret) {
		cifsd_debug("Could not update with user\n");
		goto out;
	}

	/* Convert domain name or conn name to unicode and uppercase */
	len = strlen(dname);
	domain = kzalloc(2 + UNICODE_LEN(len), GFP_KERNEL);
	if (!domain) {
		cifsd_debug("memory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	len = smb_strtoUTF16((__le16 *)domain, dname, len,
		sess->conn->local_nls);

	ret = crypto_shash_update(&sess->conn->secmech.sdeschmacmd5->shash,
					(char *)domain, UNICODE_LEN(len));
	if (ret) {
		cifsd_debug("Could not update with domain\n");
		goto out;
	}

	ret = crypto_shash_final(&sess->conn->secmech.sdeschmacmd5->shash,
			ntlmv2_hash);
out:
	if (ret)
		cifsd_debug("Could not generate md5 hash\n");
	kfree(uniname);
	kfree(domain);
	return ret;
}

/**
 * cifsd_auth_ntlm() - NTLM authentication handler
 * @sess:	session of connection
 * @pw_buf:	NTLM challenge response
 * @passkey:	user password
 *
 * Return:	0 on success, error number on error
 */
int cifsd_auth_ntlm(struct cifsd_session *sess, char *pw_buf)
{
	int rc;
	unsigned char p21[21];
	char key[CIFS_AUTH_RESP_SIZE];

	memset(p21, '\0', 21);
	memcpy(p21, user_passkey(sess->user), CIFS_NTHASH_SIZE);
	rc = cifsd_enc_p24(p21, sess->ntlmssp.cryptkey, key);
	if (rc) {
		cifsd_err("password processing failed\n");
		return rc;
	}

	cifsd_enc_md4(sess->sess_key,
			user_passkey(sess->user),
			CIFS_SMB1_SESSKEY_SIZE);
	memcpy(sess->sess_key + CIFS_SMB1_SESSKEY_SIZE, key,
		CIFS_AUTH_RESP_SIZE);
	sess->sequence_number = 1;

	if (strncmp(pw_buf, key, CIFS_AUTH_RESP_SIZE) != 0) {
		cifsd_debug("ntlmv1 authentication failed\n");
		rc = -EINVAL;
	} else
		cifsd_debug("ntlmv1 authentication pass\n");

	return rc;
}

/**
 * cifsd_auth_ntlmv2() - NTLMv2 authentication handler
 * @sess:	session of connection
 * @ntlmv2:		NTLMv2 challenge response
 * @blen:		NTLMv2 blob length
 * @domain_name:	domain name
 *
 * Return:	0 on success, error number on error
 */
int cifsd_auth_ntlmv2(struct cifsd_session *sess,
		      struct ntlmv2_resp *ntlmv2,
		      int blen,
		      char *domain_name)
{
	char ntlmv2_hash[CIFS_ENCPWD_SIZE];
	char ntlmv2_rsp[CIFS_HMAC_MD5_HASH_SIZE];
	char *construct = NULL;
	int rc, len;

	rc = crypto_hmacmd5_alloc(sess->conn);
	if (rc) {
		cifsd_debug("could not crypto alloc hmacmd5 rc %d\n", rc);
		goto out;
	}

	rc = calc_ntlmv2_hash(sess, ntlmv2_hash, domain_name);
	if (rc) {
		cifsd_debug("could not get v2 hash rc %d\n", rc);
		goto out;
	}

	rc = crypto_shash_setkey(sess->conn->secmech.hmacmd5, ntlmv2_hash,
						CIFS_HMAC_MD5_HASH_SIZE);
	if (rc) {
		cifsd_debug("Could not set NTLMV2 Hash as a key\n");
		goto out;
	}

	rc = crypto_shash_init(&sess->conn->secmech.sdeschmacmd5->shash);
	if (rc) {
		cifsd_debug("Could not init hmacmd5\n");
		goto out;
	}

	len = CIFS_CRYPTO_KEY_SIZE + blen;
	construct = kzalloc(len, GFP_KERNEL);
	if (!construct) {
		cifsd_debug("Memory allocation failed\n");
		rc = -ENOMEM;
		goto out;
	}

	memcpy(construct, sess->ntlmssp.cryptkey, CIFS_CRYPTO_KEY_SIZE);
	memcpy(construct + CIFS_CRYPTO_KEY_SIZE,
		(char *)(&ntlmv2->blob_signature), blen);

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacmd5->shash,
			construct, len);
	if (rc) {
		cifsd_debug("Could not update with response\n");
		goto out;
	}

	rc = crypto_shash_final(&sess->conn->secmech.sdeschmacmd5->shash,
			ntlmv2_rsp);
	if (rc) {
		cifsd_debug("Could not generate md5 hash\n");
		goto out;
	}

	rc = cifsd_gen_sess_key(sess, ntlmv2_hash, ntlmv2_rsp);
	if (rc) {
		cifsd_debug("Could not generate sess key\n");
		goto out;
	}

	rc = memcmp(ntlmv2->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE);
out:
	kfree(construct);
	return rc;
}

/**
 * __cifsd_auth_ntlmv2() - NTLM2(extended security) authentication handler
 * @sess:	session of connection
 * @client_nonce:	client nonce from LM response.
 * @ntlm_resp:		ntlm response data from client.
 *
 * Return:	0 on success, error number on error
 */
static int __cifsd_auth_ntlmv2(struct cifsd_session *sess,
			       char *client_nonce,
			       char *ntlm_resp)
{
	char sess_key[CIFS_SMB1_SESSKEY_SIZE] = {0};
	int rc;
	unsigned char p21[21];
	char key[CIFS_AUTH_RESP_SIZE];

	rc = cifsd_enc_update_sess_key(sess_key,
				       client_nonce,
				       (char *)sess->ntlmssp.cryptkey, 8);
	if (rc) {
		cifsd_err("password processing failed\n");
		goto out;
	}

	memset(p21, '\0', 21);
	memcpy(p21, user_passkey(sess->user), CIFS_NTHASH_SIZE);
	rc = cifsd_enc_p24(p21, sess_key, key);
	if (rc) {
		cifsd_err("password processing failed\n");
		goto out;
	}

	rc = memcmp(ntlm_resp, key, CIFS_AUTH_RESP_SIZE);
out:
	return rc;
}

/**
 * cifsd_decode_ntlmssp_auth_blob() - helper function to construct
 * authenticate blob
 * @authblob:	authenticate blob source pointer
 * @usr:	user details
 * @sess:	session of connection
 *
 * Return:	0 on success, error number on error
 */
int cifsd_decode_ntlmssp_auth_blob(AUTHENTICATE_MESSAGE *authblob,
				   int blob_len,
				   struct cifsd_session *sess)
{
	char *domain_name;
	unsigned int lm_off, nt_off;
	unsigned short nt_len;
	int ret;

	if (blob_len < sizeof(AUTHENTICATE_MESSAGE)) {
		cifsd_debug("negotiate blob len %d too small\n", blob_len);
		return -EINVAL;
	}

	if (memcmp(authblob->Signature, "NTLMSSP", 8)) {
		cifsd_debug("blob signature incorrect %s\n",
				authblob->Signature);
		return -EINVAL;
	}

	lm_off = le32_to_cpu(authblob->LmChallengeResponse.BufferOffset);
	nt_off = le32_to_cpu(authblob->NtChallengeResponse.BufferOffset);
	nt_len = le16_to_cpu(authblob->NtChallengeResponse.Length);

	/* process NTLM authentication */
	if (nt_len == CIFS_AUTH_RESP_SIZE) {
		if (le32_to_cpu(authblob->NegotiateFlags)
			& NTLMSSP_NEGOTIATE_EXTENDED_SEC)
			return __cifsd_auth_ntlmv2(sess, (char *)authblob +
				lm_off, (char *)authblob + nt_off);
		else
			return cifsd_auth_ntlm(sess, (char *)authblob +
				nt_off);
	}

	/* TODO : use domain name that imported from configuration file */
	domain_name = smb_strndup_from_utf16(
			(const char *)authblob +
			le32_to_cpu(authblob->DomainName.BufferOffset),
			le16_to_cpu(authblob->DomainName.Length), true,
			sess->conn->local_nls);
	if (IS_ERR(domain_name))
		return PTR_ERR(domain_name);

	/* process NTLMv2 authentication */
	cifsd_debug("decode_ntlmssp_authenticate_blob dname%s\n",
			domain_name);
	ret = cifsd_auth_ntlmv2(sess,
			(struct ntlmv2_resp *)((char *)authblob + nt_off),
			nt_len - CIFS_ENCPWD_SIZE,
			domain_name);
	kfree(domain_name);
	return ret;
}

/**
 * cifsd_decode_ntlmssp_neg_blob() - helper function to construct
 * negotiate blob
 * @negblob: negotiate blob source pointer
 * @rsp:     response header pointer to be updated
 * @sess:    session of connection
 *
 */
int cifsd_decode_ntlmssp_neg_blob(NEGOTIATE_MESSAGE *negblob,
				  int blob_len,
				  struct cifsd_session *sess)
{
	if (blob_len < sizeof(NEGOTIATE_MESSAGE)) {
		cifsd_debug("negotiate blob len %d too small\n", blob_len);
		return -EINVAL;
	}

	if (memcmp(negblob->Signature, "NTLMSSP", 8)) {
		cifsd_debug("blob signature incorrect %s\n",
				negblob->Signature);
		return -EINVAL;
	}

	sess->ntlmssp.client_flags = le32_to_cpu(negblob->NegotiateFlags);
	return 0;
}

/**
 * cifsd_build_ntlmssp_challenge_blob() - helper function to construct
 * challenge blob
 * @chgblob: challenge blob source pointer to initialize
 * @rsp:     response header pointer to be updated
 * @sess:    session of connection
 *
 */
unsigned int cifsd_build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
						struct cifsd_session *sess)
{
	TargetInfo *tinfo;
	wchar_t *name;
	__u8 *target_name;
	unsigned int len, flags, blob_off, blob_len, type, target_info_len = 0;
	int cflags = sess->ntlmssp.client_flags;

	memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);
	chgblob->MessageType = NtLmChallenge;

	flags = NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_VERSION;

	if (cflags & NTLMSSP_NEGOTIATE_SIGN) {
		flags |= NTLMSSP_NEGOTIATE_SIGN;
		flags |= cflags & (NTLMSSP_NEGOTIATE_128 |
			NTLMSSP_NEGOTIATE_56);
	}

	if (cflags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
		flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;

	if (cflags & NTLMSSP_REQUEST_TARGET)
		flags |= NTLMSSP_REQUEST_TARGET;

	if (sess->conn->use_spnego &&
		(cflags & NTLMSSP_NEGOTIATE_EXTENDED_SEC))
		flags |= NTLMSSP_NEGOTIATE_EXTENDED_SEC;

	chgblob->NegotiateFlags = cpu_to_le32(flags);
	len = strlen(cifsd_netbios_name());
	name = kmalloc(2 + (len * 2), GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	len = smb_strtoUTF16((__le16 *)name, cifsd_netbios_name(), len,
			sess->conn->local_nls);
	len = UNICODE_LEN(len);

	blob_off = sizeof(CHALLENGE_MESSAGE);
	blob_len = blob_off + len;

	chgblob->TargetName.Length = cpu_to_le16(len);
	chgblob->TargetName.MaximumLength = cpu_to_le16(len);
	chgblob->TargetName.BufferOffset = cpu_to_le32(blob_off);

	/* Initialize random conn challenge */
	get_random_bytes(sess->ntlmssp.cryptkey, sizeof(__u64));
	memcpy(chgblob->Challenge, sess->ntlmssp.cryptkey,
		CIFS_CRYPTO_KEY_SIZE);

	/* Add Target Information to security buffer */
	chgblob->TargetInfoArray.BufferOffset = cpu_to_le32(blob_len);

	target_name = (__u8 *)chgblob + blob_off;
	memcpy(target_name, name, len);
	tinfo = (TargetInfo *)(target_name + len);

	chgblob->TargetInfoArray.Length = 0;
	/* Add target info list for NetBIOS/DNS settings */
	for (type = NTLMSSP_AV_NB_COMPUTER_NAME;
		type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {
		tinfo->Type = cpu_to_le16(type);
		tinfo->Length = cpu_to_le16(len);
		memcpy(tinfo->Content, name, len);
		tinfo = (TargetInfo *)((char *)tinfo + 4 + len);
		target_info_len += 4 + len;
	}

	/* Add terminator subblock */
	tinfo->Type = 0;
	tinfo->Length = 0;
	target_info_len += 4;

	chgblob->TargetInfoArray.Length = chgblob->TargetInfoArray.MaximumLength =
			cpu_to_le16(target_info_len);
	blob_len += target_info_len;
	kfree(name);
	cifsd_debug("NTLMSSP SecurityBufferLength %d\n", blob_len);
	return blob_len;
}

#ifdef CONFIG_CIFS_INSECURE_SERVER
static int crypto_md5_alloc(struct cifsd_tcp_conn *conn)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (conn->secmech.md5)
		return 0;

	conn->secmech.md5 = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(conn->secmech.md5)) {
		cifsd_debug("could not allocate crypto md5\n");
		rc = PTR_ERR(conn->secmech.md5);
		conn->secmech.md5 = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(conn->secmech.md5);
	conn->secmech.sdescmd5 = kmalloc(size, GFP_KERNEL);
	if (!conn->secmech.sdescmd5) {
		free_sdescmd5(conn);
		return -ENOMEM;
	}
	conn->secmech.sdescmd5->shash.tfm = conn->secmech.md5;
	return 0;
}

/**
 * cifsd_sign_smb1_pdu() - function to generate SMB1 packet signing
 * @sess:	session of connection
 * @iov:        buffer iov array
 * @n_vec:	number of iovecs
 * @sig:        signature value generated for client request packet
 *
 */
int cifsd_sign_smb1_pdu(struct cifsd_session *sess,
			struct kvec *iov,
			int n_vec,
			char *sig)
{
	int rc;
	int i;

	rc = crypto_md5_alloc(sess->conn);
	if (rc) {
		cifsd_debug("could not crypto alloc md5 rc %d\n", rc);
		goto out;
	}

	rc = crypto_shash_init(&sess->conn->secmech.sdescmd5->shash);
	if (rc) {
		cifsd_debug("md5 init error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdescmd5->shash,
			sess->sess_key, 40);
	if (rc) {
		cifsd_debug("md5 update error %d\n", rc);
		goto out;
	}

	for (i = 0; i < n_vec; i++) {
		rc = crypto_shash_update(
				&sess->conn->secmech.sdescmd5->shash,
				iov[i].iov_base, iov[i].iov_len);
		if (rc) {
			cifsd_debug("md5 update error %d\n", rc);
			goto out;
		}
	}

	rc = crypto_shash_final(&sess->conn->secmech.sdescmd5->shash, sig);
	if (rc)
		cifsd_debug("md5 generation error %d\n", rc);

out:
	return rc;
}
#else
int cifsd_sign_smb1_pdu(struct cifsd_session *sess,
			struct kvec *iov,
			int n_vec,
			char *sig)
{
	return -ENOTSUPP;
}
#endif

static int crypto_hmacsha256_alloc(struct cifsd_tcp_conn *conn)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (conn->secmech.hmacsha256)
		return 0;

	conn->secmech.hmacsha256 = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(conn->secmech.hmacsha256)) {
		cifsd_debug("could not allocate crypto hmacsha256\n");
		rc = PTR_ERR(conn->secmech.hmacsha256);
		conn->secmech.hmacsha256 = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(conn->secmech.hmacsha256);
	conn->secmech.sdeschmacsha256 = kmalloc(size, GFP_KERNEL);
	if (!conn->secmech.sdeschmacsha256) {
		free_hmacsha256(conn);
		return -ENOMEM;
	}
	conn->secmech.sdeschmacsha256->shash.tfm = conn->secmech.hmacsha256;
	return 0;
}

static int crypto_cmac_alloc(struct cifsd_tcp_conn *conn)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (conn->secmech.sdesccmacaes)
		return 0;

	conn->secmech.cmacaes = crypto_alloc_shash("cmac(aes)", 0, 0);
	if (IS_ERR(conn->secmech.cmacaes)) {
		cifsd_debug("could not allocate crypto cmac-aes\n");
		rc = PTR_ERR(conn->secmech.cmacaes);
		conn->secmech.cmacaes = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(conn->secmech.cmacaes);
	conn->secmech.sdesccmacaes = kmalloc(size, GFP_KERNEL);
	if (!conn->secmech.sdesccmacaes) {
		free_cmacaes(conn);
		return -ENOMEM;
	}
	conn->secmech.sdesccmacaes->shash.tfm = conn->secmech.cmacaes;
	return 0;
}

static int crypto_sha512_alloc(struct cifsd_tcp_conn *conn)
{
	int rc;
	unsigned int size;

	/* check if already allocated */
	if (conn->secmech.sdescsha512)
		return 0;

	cifsd_debug("Inside crypto_sha512_alloc\n");
	conn->secmech.sha512 = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(conn->secmech.sha512)) {
		cifsd_debug("could not allocate crypto sha512\n");
		rc = PTR_ERR(conn->secmech.sha512);
		conn->secmech.sha512 = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) +
		crypto_shash_descsize(conn->secmech.sha512);
	conn->secmech.sdescsha512 = kmalloc(size, GFP_KERNEL);
	if (!conn->secmech.sdescsha512) {
		free_sha512(conn);
		return -ENOMEM;
	}
	conn->secmech.sdescsha512->shash.tfm = conn->secmech.sha512;
	return 0;
}

/**
 * cifsd_sign_smb2_pdu() - function to generate packet signing
 * @conn:	connection
 * @key:	signing key
 * @iov:        buffer iov array
 * @n_vec:	number of iovecs
 * @sig:	signature value generated for client request packet
 *
 */
int cifsd_sign_smb2_pdu(struct cifsd_tcp_conn *conn,
			char *key,
			struct kvec *iov,
			int n_vec,
			char *sig)
{
	int rc;
	int i;

	rc = crypto_hmacsha256_alloc(conn);
	if (rc) {
		cifsd_debug("could not crypto alloc hmacmd5 rc %d\n", rc);
		goto out;
	}

	rc = crypto_shash_setkey(conn->secmech.hmacsha256, key,
		SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifsd_debug("hmacsha256 update error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_init(&conn->secmech.sdeschmacsha256->shash);
	if (rc) {
		cifsd_debug("hmacsha256 init error %d\n", rc);
		goto out;
	}

	for (i = 0; i < n_vec; i++) {
		rc = crypto_shash_update(
				&conn->secmech.sdeschmacsha256->shash,
				iov[i].iov_base, iov[i].iov_len);
		if (rc) {
			cifsd_debug("hmacsha256 update error %d\n", rc);
			goto out;
		}
	}

	rc = crypto_shash_final(&conn->secmech.sdeschmacsha256->shash,
		sig);
	if (rc)
		cifsd_debug("hmacsha256 generation error %d\n", rc);

out:
	return rc;
}

/**
 * cifsd_sign_smb3_pdu() - function to generate packet signing
 * @conn:	connection
 * @key:	signing key
 * @iov:        buffer iov array
 * @n_vec:	number of iovecs
 * @sig:	signature value generated for client request packet
 *
 */
int cifsd_sign_smb3_pdu(struct cifsd_tcp_conn *conn,
			char *key,
			struct kvec *iov,
			int n_vec,
			char *sig)
{
	int rc;
	int i;

	rc = crypto_shash_setkey(conn->secmech.cmacaes, key,
		SMB2_CMACAES_SIZE);
	if (rc) {
		cifsd_debug("cmaces update error %d\n", rc);
		goto out;
	}

	rc = crypto_shash_init(&conn->secmech.sdesccmacaes->shash);
	if (rc) {
		cifsd_debug("cmaces init error %d\n", rc);
		goto out;
	}

	for (i = 0; i < n_vec; i++) {
		rc = crypto_shash_update(
				&conn->secmech.sdesccmacaes->shash,
				iov[i].iov_base, iov[i].iov_len);
		if (rc) {
			cifsd_debug("cmaces update error %d\n", rc);
			goto out;
		}
	}

	rc = crypto_shash_final(&conn->secmech.sdesccmacaes->shash,
		sig);
	if (rc)
		cifsd_debug("cmaces generation error %d\n", rc);

out:
	return rc;
}

struct derivation {
	struct kvec label;
	struct kvec context;
	bool binding;
};

static int generate_key(struct cifsd_session *sess, struct kvec label,
	struct kvec context, __u8 *key, unsigned int key_size)
{
	unsigned char zero = 0x0;
	__u8 i[4] = {0, 0, 0, 1};
	__u8 L[4] = {0, 0, 0, 128};
	int rc = 0;
	unsigned char prfhash[SMB2_HMACSHA256_SIZE];
	unsigned char *hashptr = prfhash;

	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	rc = crypto_hmacsha256_alloc(sess->conn);
	if (rc) {
		cifsd_debug("could not crypto alloc hmacmd5 rc %d\n", rc);
		goto smb3signkey_ret;
	}

	rc = crypto_cmac_alloc(sess->conn);
	if (rc) {
		cifsd_debug("could not crypto alloc cmac rc %d\n", rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_setkey(sess->conn->secmech.hmacsha256,
			sess->sess_key, SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifsd_debug("could not set with session key\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_init(&sess->conn->secmech.sdeschmacsha256->shash);
	if (rc) {
		cifsd_debug("could not init sign hmac\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacsha256->shash,
			i, 4);
	if (rc) {
		cifsd_debug("could not update with n\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacsha256->shash,
			label.iov_base, label.iov_len);
	if (rc) {
		cifsd_debug("could not update with label\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacsha256->shash,
			&zero, 1);
	if (rc) {
		cifsd_debug("could not update with zero\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacsha256->shash,
			context.iov_base, context.iov_len);
	if (rc) {
		cifsd_debug("could not update with context\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&sess->conn->secmech.sdeschmacsha256->shash,
			L, 4);
	if (rc) {
		cifsd_debug("could not update with L\n");
		goto smb3signkey_ret;
	}

	rc = crypto_shash_final(&sess->conn->secmech.sdeschmacsha256->shash,
			hashptr);
	if (rc) {
		cifsd_debug("Could not generate hmacmd5 hash error %d\n", rc);
		goto smb3signkey_ret;
	}

	memcpy(key, hashptr, key_size);

smb3signkey_ret:
	return rc;
}

static int generate_smb3signingkey(struct cifsd_session *sess,
	const struct derivation *signing)
{
	int rc;
	struct channel *chann;
	char *key;

	chann = lookup_chann_list(sess);
	if (!chann)
		return 0;

	if (sess->conn->dialect >= SMB30_PROT_ID && signing->binding)
		key = chann->smb3signingkey;
	else
		key = sess->smb3signingkey;

	rc = generate_key(sess, signing->label, signing->context, key,
		SMB3_SIGN_KEY_SIZE);
	if (rc)
		return rc;

	if (!(sess->conn->dialect >= SMB30_PROT_ID && signing->binding))
		memcpy(chann->smb3signingkey, key, SMB3_SIGN_KEY_SIZE);

	cifsd_debug("dumping generated AES signing keys\n");
	cifsd_debug("Session Id    %llu\n", sess->id);
	cifsd_debug("Session Key   %*ph\n",
			SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
	cifsd_debug("Signing Key   %*ph\n",
			SMB3_SIGN_KEY_SIZE, key);
	return rc;
}

int cifsd_gen_smb30_signingkey(struct cifsd_session *sess,
			       bool binding,
			       char *hash_value)
{
	struct derivation d;

	d.label.iov_base = "SMB2AESCMAC";
	d.label.iov_len = 12;
	d.context.iov_base = "SmbSign";
	d.context.iov_len = 8;
	d.binding = binding;

	return generate_smb3signingkey(sess, &d);
}

int cifsd_gen_smb311_signingkey(struct cifsd_session *sess,
				bool binding,
				char *hash_value)
{
	struct derivation d;

	d.label.iov_base = "SMBSigningKey";
	d.label.iov_len = 14;
	if (binding)
		d.context.iov_base = hash_value;
	else
		d.context.iov_base = sess->Preauth_HashValue;
	d.context.iov_len = 64;
	d.binding = binding;

	return generate_smb3signingkey(sess, &d);
}

struct derivation_twin {
	struct derivation encryption;
	struct derivation decryption;
};

static int generate_smb3encryptionkey(struct cifsd_session *sess,
	const struct derivation_twin *ptwin)
{
	int rc;

	rc = generate_key(sess, ptwin->encryption.label,
			ptwin->encryption.context, sess->smb3encryptionkey,
			SMB3_SIGN_KEY_SIZE);
	if (rc)
		return rc;

	rc = generate_key(sess, ptwin->decryption.label,
			ptwin->decryption.context,
			sess->smb3decryptionkey, SMB3_SIGN_KEY_SIZE);
	if (rc)
		return rc;

	cifsd_debug("dumping generated AES encryption keys\n");
	cifsd_debug("Session Id    %llu\n", sess->id);
	cifsd_debug("Session Key   %*ph\n",
			SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
	cifsd_debug("ServerIn Key  %*ph\n",
			SMB3_SIGN_KEY_SIZE, sess->smb3encryptionkey);
	cifsd_debug("ServerOut Key %*ph\n",
			SMB3_SIGN_KEY_SIZE, sess->smb3decryptionkey);
	return rc;
}

int cifsd_gen_smb30_encryptionkey(struct cifsd_session *sess)
{
	struct derivation_twin twin;
	struct derivation *d;

	d = &twin.encryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerOut";
	d->context.iov_len = 10;

	d = &twin.decryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerIn ";
	d->context.iov_len = 10;

	return generate_smb3encryptionkey(sess, &twin);
}

int cifsd_gen_smb311_encryptionkey(struct cifsd_session *sess)
{
	struct derivation_twin twin;
	struct derivation *d;

	d = &twin.encryption;
	d->label.iov_base = "SMBS2CCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = sess->Preauth_HashValue;
	d->context.iov_len = 64;

	d = &twin.decryption;
	d->label.iov_base = "SMBC2SCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = sess->Preauth_HashValue;
	d->context.iov_len = 64;

	return generate_smb3encryptionkey(sess, &twin);
}

int cifsd_gen_preauth_integrity_hash(struct cifsd_tcp_conn *conn,
				     char *buf,
				     __u8 *pi_hash)
{
	int rc = -1;
	struct crypto_shash *c_shash;
	struct sdesc *c_sdesc;
	struct smb2_hdr *rcv_hdr = (struct smb2_hdr *)buf;
	char *all_bytes_msg = (char *)&rcv_hdr->ProtocolId;
	int msg_size = be32_to_cpu(rcv_hdr->smb2_buf_length);

	if (conn->preauth_info->Preauth_HashId ==
		SMB2_PREAUTH_INTEGRITY_SHA512) {
		rc = crypto_sha512_alloc(conn);
		if (rc) {
			cifsd_debug("could not alloc sha512 rc %d\n", rc);
			goto out;
		}

		c_shash = conn->secmech.sha512;
		c_sdesc = conn->secmech.sdescsha512;
	} else
		goto out;

	rc = crypto_shash_init(&c_sdesc->shash);
	if (rc) {
		cifsd_debug("could not init shashn");
		goto out;
	}

	rc = crypto_shash_update(&c_sdesc->shash,
				pi_hash, 64);
	if (rc) {
		cifsd_debug("could not update with n\n");
		goto out;
	}

	rc = crypto_shash_update(&c_sdesc->shash, all_bytes_msg, msg_size);
	if (rc) {
		cifsd_debug("could not update with n\n");
		goto out;
	}

	rc = crypto_shash_final(&c_sdesc->shash, pi_hash);
	if (rc) {
		cifsd_debug("Could not generate hash err : %d\n", rc);
		goto out;
	}
out:
	return rc;
}

static int cifsd_alloc_aead(struct cifsd_tcp_conn *conn)
{
	struct crypto_aead *tfm;

	if (!conn->secmech.ccmaesencrypt) {
		tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			cifsd_err("Failed to alloc encrypt aead\n");
			return PTR_ERR(tfm);
		}
		conn->secmech.ccmaesencrypt = tfm;
	}

	if (!conn->secmech.ccmaesdecrypt) {
		tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			cifsd_err("Failed to alloc decrypt aead\n");
			free_ccmaes(conn);
			return PTR_ERR(tfm);
		}
		conn->secmech.ccmaesdecrypt = tfm;
	}

	return 0;
}

static int cifsd_get_encryption_key(struct cifsd_tcp_conn *conn,
				    __u64 ses_id,
				    int enc,
				    u8 *key)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static struct scatterlist *cifsd_init_sg(struct kvec *iov,
					 unsigned int nvec,
					 u8 *sign)
{
	struct scatterlist *sg;
	unsigned int i = 0;

	sg = kmalloc_array(nvec, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg)
		return NULL;

	sg_init_table(sg, nvec);
	for (i = 0; i < nvec - 1; i++)
		sg_set_buf(&sg[i], iov[i + 1].iov_base, iov[i + 1].iov_len);
	sg_set_buf(&sg[nvec - 1], sign, SMB2_SIGNATURE_SIZE);
	return sg;
}
#else
static struct scatterlist *cifsd_init_sg(struct kvec *iov,
					 unsigned int nvec,
					 u8 *sign)
{
	struct scatterlist *sg;
	unsigned int i = 0;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 24;

	sg = kmalloc_array(nvec + 1, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg)
		return NULL;

	sg_init_table(sg, nvec + 1);
	sg_set_buf(&sg[0], iov[0].iov_base + 24, assoc_data_len);
	for (i = 1; i < nvec; i++)
		sg_set_buf(&sg[i], iov[i].iov_base, iov[i].iov_len);
	sg_set_buf(&sg[nvec], sign, SMB2_SIGNATURE_SIZE);
	return sg;
}
#endif

int cifsd_crypt_message(struct cifsd_tcp_conn *conn,
			struct kvec *iov,
			unsigned int nvec,
			int enc)
{
	struct smb2_transform_hdr *tr_hdr =
		(struct smb2_transform_hdr *)iov[0].iov_base;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 24;
	int rc = 0;
	struct scatterlist *sg;
	u8 sign[SMB2_SIGNATURE_SIZE] = {};
	u8 key[SMB3_SIGN_KEY_SIZE];
	struct aead_request *req;
	char *iv;
	unsigned int iv_len;
	struct crypto_aead *tfm;
	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	struct scatterlist assoc;
#endif

	rc = cifsd_get_encryption_key(conn,
				      le64_to_cpu(tr_hdr->SessionId),
				      enc,
				      key);
	if (rc) {
		cifsd_err("Could not get %scryption key\n", enc ? "en" : "de");
		return 0;
	}

	rc = cifsd_alloc_aead(conn);
	if (rc) {
		cifsd_err("crypto alloc failed\n");
		return rc;
	}

	tfm = enc ? conn->secmech.ccmaesencrypt :
		conn->secmech.ccmaesdecrypt;
	rc = crypto_aead_setkey(tfm, key, SMB3_SIGN_KEY_SIZE);
	if (rc) {
		cifsd_err("Failed to set aead key %d\n", rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifsd_err("Failed to set authsize %d\n", rc);
		return rc;
	}

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		cifsd_err("Failed to alloc aead request\n");
		return -ENOMEM;
	}

	if (!enc) {
		memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);
		crypt_len += SMB2_SIGNATURE_SIZE;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	sg_init_one(&assoc, iov[0].iov_base + 24, assoc_data_len);
#endif

	sg = cifsd_init_sg(iov, nvec, sign);
	if (!sg) {
		cifsd_err("Failed to init sg\n");
		rc = -ENOMEM;
		goto free_req;
	}

	iv_len = crypto_aead_ivsize(tfm);
	iv = kzalloc(iv_len, GFP_KERNEL);
	if (!iv) {
		cifsd_err("Failed to alloc IV\n");
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
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);

	if (enc)
		rc = crypto_aead_encrypt(req);
	else
		rc = crypto_aead_decrypt(req);
	if (!rc && enc)
		memcpy(&tr_hdr->Signature, sign, SMB2_SIGNATURE_SIZE);

	kfree(iv);
free_sg:
	kfree(sg);
free_req:
	kfree(req);
	return rc;
}
