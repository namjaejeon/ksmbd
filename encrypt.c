// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  SMB parameters and setup
 *  Copyright (C) Andrew Tridgell 1992-2000
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000
 *  Modified by Jeremy Allison 1995.
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
 *  Modified by Steve French (sfrench@us.ibm.com) 2002-2003
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include "glob.h" /* FIXME */
#include "unicode.h"
#include "encrypt.h"

#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

/* following came from the other byteorder.h to avoid include conflicts */
#define CVAL(buf, pos) (((unsigned char *)(buf))[(pos)])
#define SSVALX(buf, pos, val)	\
	(CVAL((buf), (pos)) = (val) & 0xFF, CVAL((buf), (pos)+1) = (val) >> 8)
#define SSVAL(buf, pos, val) SSVALX((buf), (pos), ((__u16)(val)))

static void
str_to_key(unsigned char *str, unsigned char *key)
{
	int i;

	key[0] = str[0] >> 1;
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
	key[7] = str[6] & 0x7F;
	for (i = 0; i < 8; i++)
		key[i] = (key[i] << 1);
}

static int
smbhash(unsigned char *out, const unsigned char *in, unsigned char *key)
{
	int rc;
	unsigned char key2[8];
	struct crypto_blkcipher *tfm_des;
	struct scatterlist sgin, sgout;
	struct blkcipher_desc desc;

	str_to_key(key, key2);

	tfm_des = crypto_alloc_blkcipher("ecb(des)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm_des)) {
		rc = PTR_ERR(tfm_des);
		cifsd_debug("could not allocate des crypto API\n");
		goto smbhash_err;
	}

	desc.tfm = tfm_des;

	crypto_blkcipher_setkey(tfm_des, key2, 8);

	sg_init_one(&sgin, in, 8);
	sg_init_one(&sgout, out, 8);

	rc = crypto_blkcipher_encrypt(&desc, &sgout, &sgin, 8);
	if (rc)
		cifsd_debug("could not encrypt crypt key rc: %d\n", rc);

	crypto_free_blkcipher(tfm_des);
smbhash_err:
	return rc;
}

int cifsd_enc_p24(unsigned char *p21,
		  const unsigned char *c8,
		  unsigned char *p24)
{
	int rc;

	rc = smbhash(p24, c8, p21);
	if (rc)
		return rc;
	rc = smbhash(p24 + 8, c8, p21 + 7);
	if (rc)
		return rc;
	rc = smbhash(p24 + 16, c8, p21 + 14);
	return rc;
}

/* produce a md4 message digest from data of length n bytes */
int cifsd_enc_md4(unsigned char *md4_hash,
		  unsigned char *link_str,
		  int link_len)
{
	int rc;
	unsigned int size;
	struct crypto_shash *md4;
	struct sdesc *sdescmd4;

	md4 = crypto_alloc_shash("md4", 0, 0);
	if (IS_ERR(md4)) {
		rc = PTR_ERR(md4);
		cifsd_debug("%s: Crypto md4 allocation error %d\n",
				__func__, rc);
		return rc;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(md4);
	sdescmd4 = kmalloc(size, GFP_KERNEL);
	if (!sdescmd4) {
		rc = -ENOMEM;
		goto smb_mdfour_err;
	}
	sdescmd4->shash.tfm = md4;
	sdescmd4->shash.flags = 0x0;

	rc = crypto_shash_init(&sdescmd4->shash);
	if (rc) {
		cifsd_debug("%s: Could not init md4 shash\n", __func__);
		goto smb_mdfour_err;
	}
	rc = crypto_shash_update(&sdescmd4->shash, link_str, link_len);
	if (rc) {
		cifsd_debug("%s: Could not update with link_str\n", __func__);
		goto smb_mdfour_err;
	}
	rc = crypto_shash_final(&sdescmd4->shash, md4_hash);
	if (rc)
		cifsd_debug("%s: Could not generate md4 hash\n", __func__);

smb_mdfour_err:
	crypto_free_shash(md4);
	kfree(sdescmd4);

	return rc;
}

/* produce sess key using md5 with client nonce and server chanllenge */
int cifsd_enc_update_sess_key(unsigned char *md5_hash,
			      char *nonce,
			      char *server_challenge,
			      int len)
{
	int rc;
	unsigned int size;
	struct crypto_shash *md5;
	struct sdesc *sdescmd5;

	md5 = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(md5)) {
		rc = PTR_ERR(md5);
		cifsd_debug("%s: Crypto md5 allocation error %d\n",
				__func__, rc);
		return rc;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
	sdescmd5 = kmalloc(size, GFP_KERNEL);
	if (!sdescmd5) {
		rc = -ENOMEM;
		goto err_out;
	}
	sdescmd5->shash.tfm = md5;
	sdescmd5->shash.flags = 0x0;

	rc = crypto_shash_init(&sdescmd5->shash);
	if (rc) {
		cifsd_debug("%s: Could not init md5 shash\n", __func__);
		goto err_out;
	}

	rc = crypto_shash_update(&sdescmd5->shash, server_challenge, len);
	if (rc) {
		cifsd_debug("%s: Could not update with challenge\n", __func__);
		goto err_out;
	}

	rc = crypto_shash_update(&sdescmd5->shash, nonce, len);
	if (rc) {
		cifsd_debug("%s: Could not update with nonce\n", __func__);
		goto err_out;
	}

	rc = crypto_shash_final(&sdescmd5->shash, md5_hash);
	if (rc)
		cifsd_debug("%s: Could not generate md5 hash\n", __func__);

err_out:
	crypto_free_shash(md5);
	kfree(sdescmd5);

	return rc;
}

/*
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
int cifsd_enc_md4hash(const unsigned char *passwd,
		  unsigned char *p16,
		  const struct nls_table *codepage)
{
	int rc;
	int len;
	__le16 wpwd[129];

	/* Password cannot be longer than 128 characters */
	if (passwd) /* Password must be converted to NT unicode */
		len = smb_strtoUTF16(wpwd, passwd, 128, codepage);
	else {
		len = 0;
		*wpwd = 0; /* Ensure string is null terminated */
	}

	rc = cifsd_enc_md4(p16, (unsigned char *) wpwd, len * sizeof(__le16));
	memset(wpwd, 0, 129 * sizeof(__le16));
	return rc;
}
