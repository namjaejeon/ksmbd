// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __AUTH_H__
#define __AUTH_H__

#include "ntlmssp.h"

#define AUTH_GSS_LENGTH		74
#define AUTH_GSS_PADDING	6

struct cifsd_session;
struct cifsd_tcp_conn;

void cifsd_copy_gss_neg_header(void *buf);

int compute_sess_key(struct cifsd_session *sess, char *hash, char *hmac);

int process_ntlm(struct cifsd_session *sess, char *pw_buf);
int process_ntlmv2(struct cifsd_session *sess,
		   struct ntlmv2_resp *ntlmv2,
		   int blen, char *domain_name);

int decode_ntlmssp_authenticate_blob(AUTHENTICATE_MESSAGE *authblob,
				     int blob_len,
				     struct cifsd_session *sess);

int decode_ntlmssp_negotiate_blob(NEGOTIATE_MESSAGE *negblob,
				  int blob_len,
				  struct cifsd_session *sess);

unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
					  struct cifsd_session *sess);

int smb1_sign_smbpdu(struct cifsd_session *sess,
		     struct kvec *iov,
		     int n_vec,
		     char *sig);
int smb2_sign_smbpdu(struct cifsd_tcp_conn *conn,
		     char *key,
		     struct kvec *iov,
		     int n_vec,
		     char *sig);
int smb3_sign_smbpdu(struct cifsd_tcp_conn *conn,
		     char *key,
		     struct kvec *iov,
		     int n_vec,
		     char *sig);

int generate_smb30signingkey(struct cifsd_session *sess,
			     bool binding,
			     char *hash_value);
int generate_smb311signingkey(struct cifsd_session *sess,
			      bool binding,
			      char *hash_value);
int generate_smb30encryptionkey(struct cifsd_session *sess);
int generate_smb311encryptionkey(struct cifsd_session *sess);

int calc_preauth_integrity_hash(struct cifsd_tcp_conn *conn,
				char *buf,
				__u8 *pi_hash);
#endif
