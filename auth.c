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
#include "ntlmssp.h"

/**
 * int proc_v2() - NTLMv2 authentication handler
 * @server:	TCP server instance of connection
 * @pv2:	NTLMv2 challenge response
 * @usr:	user details
 * @dname:	domain name
 * @blen:	NTLMv2 blob length
 * @local_nls:	nls table to convert char to unicode
 *
 * Return:	0 on success, error number on error
 */
int proc_v2(struct tcp_server_info *server, char *pv2, struct cifssrv_usr *usr,
		char *dname, int blen, struct nls_table *local_nls)
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
