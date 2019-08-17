// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#ifndef __CRYPTO_CTX_H__
#define __CRYPTO_CTX_H__

#include <crypto/hash.h>
#include <crypto/aead.h>

enum {
	CRYPTO_SHASH_HMACMD5,
	CRYPTO_SHASH_HMACSHA256,
	CRYPTO_SHASH_CMACAES,
	CRYPTO_SHASH_SHA512,
#ifdef CONFIG_CIFS_INSECURE_SERVER
	CRYPTO_SHASH_MD5,
#endif
	CRYPTO_SHASH_MAX,
};

enum {
	CRYPTO_AEAD_AES128_GCM,
	CRYPTO_AEAD_AES128_CCM,
	CRYPTO_AEAD_MAX,
};

struct cifsd_crypto_ctx {
	struct list_head		list;

	struct shash_desc		*desc[CRYPTO_SHASH_MAX];
	struct crypto_aead		*ccmaes[CRYPTO_AEAD_MAX];
};

#define CRYPTO_HMACMD5(c)	((c)->desc[CRYPTO_SHASH_HMACMD5])
#define CRYPTO_HMACSHA256(c)	((c)->desc[CRYPTO_SHASH_HMACSHA256])
#define CRYPTO_CMACAES(c)	((c)->desc[CRYPTO_SHASH_CMACAES])
#define CRYPTO_SHA512(c)	((c)->desc[CRYPTO_SHASH_SHA512])
#ifdef CONFIG_CIFS_INSECURE_SERVER
#define CRYPTO_MD5(c)		((c)->desc[CRYPTO_SHASH_MD5])
#else
#define CRYPTO_MD5(c)		((c)->desc[CRYPTO_SHASH_MD5])
#endif

#define CRYPTO_HMACMD5_TFM(c)	\
				((c)->desc[CRYPTO_SHASH_HMACMD5]->tfm)
#define CRYPTO_HMACSHA256_TFM(c)\
				((c)->desc[CRYPTO_SHASH_HMACSHA256]->tfm)
#define CRYPTO_CMACAES_TFM(c)	\
				((c)->desc[CRYPTO_SHASH_CMACAES]->tfm)
#define CRYPTO_SHA512_TFM(c)	\
				((c)->desc[CRYPTO_SHASH_SHA512]->tfm)
#ifdef CONFIG_CIFS_INSECURE_SERVER
#define CRYPTO_MD5_TFM(c)	\
				((c)->desc[CRYPTO_SHASH_MD5]->tfm)
#else
#define CRYPTO_MD5_TFM(c)	\
				((c)->desc[CRYPTO_SHASH_MD5]->tfm)
#endif

#define CRYPTO_GCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES128_GCM])
#define CRYPTO_CCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES128_CCM])

void cifsd_release_crypto_ctx(struct cifsd_crypto_ctx *ctx);

struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_hmacmd5(void);
struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_hmacsha256(void);
struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_cmacaes(void);
struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_sha512(void);
struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_md5(void);

struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_gcm(void);
struct cifsd_crypto_ctx *cifsd_crypto_ctx_find_ccm(void);

void cifsd_crypto_destroy(void);
int cifsd_crypto_create(void);

#endif /* __CRYPTO_CTX_H__ */
