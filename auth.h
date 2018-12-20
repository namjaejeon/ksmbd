// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __AUTH_H__
#define __AUTH_H__

#include "ntlmssp.h"

#define AUTH_GSS_LENGTH		74
#define AUTH_GSS_PADDING	6

#define CIFS_HMAC_MD5_HASH_SIZE	(16)

struct cifsd_session;
struct cifsd_tcp_conn;
struct kvec;

int cifsd_crypt_message(struct cifsd_tcp_conn *conn,
			struct kvec *iov,
			unsigned int nvec,
			int enc);

void cifsd_copy_gss_neg_header(void *buf);

void cifsd_free_conn_secmech(struct cifsd_tcp_conn *conn);

int cifsd_auth_ntlm(struct cifsd_session *sess,
		    char *pw_buf);

int cifsd_auth_ntlmv2(struct cifsd_session *sess,
		      struct ntlmv2_resp *ntlmv2,
		      int blen,
		      char *domain_name);

int cifsd_decode_ntlmssp_auth_blob(AUTHENTICATE_MESSAGE *authblob,
				   int blob_len,
				   struct cifsd_session *sess);

int cifsd_decode_ntlmssp_neg_blob(NEGOTIATE_MESSAGE *negblob,
				  int blob_len,
				  struct cifsd_session *sess);

unsigned int cifsd_build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
						struct cifsd_session *sess);

int cifsd_sign_smb1_pdu(struct cifsd_session *sess,
			struct kvec *iov,
			int n_vec,
			char *sig);
int cifsd_sign_smb2_pdu(struct cifsd_tcp_conn *conn,
			char *key,
			struct kvec *iov,
			int n_vec,
			char *sig);
int cifsd_sign_smb3_pdu(struct cifsd_tcp_conn *conn,
			char *key,
			struct kvec *iov,
			int n_vec,
			char *sig);

int cifsd_gen_smb30_signingkey(struct cifsd_session *sess,
			       bool binding,
			       char *hash_value);
int cifsd_gen_smb311_signingkey(struct cifsd_session *sess,
				bool binding,
				char *hash_value);
int cifsd_gen_smb30_encryptionkey(struct cifsd_session *sess);
int cifsd_gen_smb311_encryptionkey(struct cifsd_session *sess);

int cifsd_gen_preauth_integrity_hash(struct cifsd_tcp_conn *conn,
				     char *buf,
				     __u8 *pi_hash);
#endif
