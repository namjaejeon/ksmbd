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
 *
 *  Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __ENCRYPT_H__
#define __ENCRYPT_H__

struct shash_desc;

/* crypto security descriptor definition */
struct sdesc {
	struct shash_desc	shash;
	char			ctx[];
};

int cifsd_enc_ntmd4(unsigned char *,
		    unsigned char *,
		    unsigned char *,
		    const struct nls_table *);

int cifsd_enc_md4hash(const unsigned char *passwd,
		      unsigned char *p16,
		      const struct nls_table *codepage);

int cifsd_enc_p24(unsigned char *p21,
		  const unsigned char *c8,
		  unsigned char *p24);

int cifsd_enc_md4(unsigned char *md4_hash,
		  unsigned char *link_str,
		  int link_len);

int cifsd_enc_update_sess_key(unsigned char *md5_hash,
			      char *nonce,
			      char *server_challenge,
			      int len);
#endif /* __ENCRYPT_H__ */
