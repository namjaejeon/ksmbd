/*
 *   fs/cifsd/export.h
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

#ifndef __CIFSD_EXPORT_H
#define __CIFSD_EXPORT_H

#include "smb1pdu.h"
#include "ntlmssp.h"

#include "mgmt/user_config.h"

#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif

extern int cifsd_debug_enable;

/* Global defines for server */
#define SERVER_MAX_MPX_COUNT 10
#define SERVER_MAX_VCS 1

#define CIFS_MAX_MSGSIZE 65536
#define MAX_CIFS_LOOKUP_BUFFER_SIZE (16*1024)

#define CIFS_DEFAULT_NON_POSIX_RSIZE (60 * 1024)
#define CIFS_DEFAULT_NON_POSIX_WSIZE (65536)
#define CIFS_DEFAULT_IOSIZE (1024 * 1024)
#define SERVER_MAX_RAW_SIZE 65536

#define SERVER_CAPS  (CAP_RAW_MODE | CAP_UNICODE | CAP_LARGE_FILES | \
			CAP_NT_SMBS | CAP_STATUS32 | CAP_LOCK_AND_READ | \
			CAP_NT_FIND | CAP_UNIX | CAP_LARGE_READ_X | \
			CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS | \
			CAP_EXTENDED_SECURITY)
#define SERVER_SECU  (SECMODE_USER | SECMODE_PW_ENCRYPT)

#define CIFSD_MAJOR_VERSION 1
#define CIFSD_MINOR_VERSION 0
#define STR_IPC	"IPC$"
#define STR_SRV_NAME	"CIFSD SERVER"
#define STR_WRKGRP	"WORKGROUP"

#define O_SERVER 1
#define O_CLIENT 2

extern unsigned int SMBMaxBufSize;

extern int cifsd_max_protocol(void);
extern int cifsd_min_protocol(void);
extern int get_protocol_idx(char *str);
extern int cifsd_init_registry(void);
extern void cifsd_free_registry(void);
extern struct cifsd_share *find_matching_share(__u16 tid);
int process_ntlm(struct cifsd_session *sess, char *pw_buf);
int process_ntlmv2(struct cifsd_session *sess, struct ntlmv2_resp *ntlmv2,
                int blen, char *domain_name);
int decode_ntlmssp_negotiate_blob(NEGOTIATE_MESSAGE *negblob,
                int blob_len, struct cifsd_session *sess);
unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
                struct cifsd_session *sess);
int decode_ntlmssp_authenticate_blob(AUTHENTICATE_MESSAGE *authblob,
                int blob_len, struct cifsd_session *sess);
int smb1_sign_smbpdu(struct cifsd_session *sess, struct kvec *iov, int n_vec,
                char *sig);
int smb2_sign_smbpdu(struct cifsd_tcp_conn *conn, char *key, struct kvec *iov,
        int n_vec, char *sig);
int smb3_sign_smbpdu(struct cifsd_tcp_conn *conn, char *key, struct kvec *iov,
        int n_vec, char *sig);
int compute_sess_key(struct cifsd_session *sess, char *hash, char *hmac);
int generate_smb30signingkey(struct cifsd_session *sess, bool binding,
        char *hash_value);
int generate_smb311signingkey(struct cifsd_session *sess, bool binding,
        char *hash_value);
int generate_smb30encryptionkey(struct cifsd_session *sess);
int generate_smb311encryptionkey(struct cifsd_session *sess);
extern struct cifsd_user *cifsd_is_user_present(char *name);
struct cifsd_share *get_cifsd_share(struct cifsd_tcp_conn *conn,
                struct cifsd_session *sess, char *sharename, bool *can_write);
extern struct cifsd_tcon *get_cifsd_tcon(struct cifsd_session *sess,
                        unsigned int tid);
struct cifsd_user *get_smb_session_user(struct cifsd_session *sess);

#endif /* __CIFSD_EXPORT_H */
