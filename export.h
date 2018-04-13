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

#include "management/user.h"

#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif

extern int cifsd_debug_enable;

/* Global list containing exported points */
extern struct list_head cifsd_share_list;
extern struct list_head cifsd_connection_list;
extern struct list_head cifsd_session_list;

/* Spinlock to protect global list */
extern spinlock_t export_list_lock;
extern spinlock_t connect_list_lock;

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
			CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS)
#define SERVER_SECU  (SECMODE_USER | SECMODE_PW_ENCRYPT)

#define CIFSD_MAJOR_VERSION 1
#define CIFSD_MINOR_VERSION 0
#define STR_IPC	"IPC$"
#define STR_SRV_NAME	"CIFSD SERVER"
#define STR_WRKGRP	"WORKGROUP"

#define O_SERVER 1
#define O_CLIENT 2

extern int cifsd_num_shares;
extern int server_signing;
extern char *guestAccountName;
extern int maptoguest;
extern int server_max_pr;
extern int server_min_pr;

extern unsigned int SMBMaxBufSize;

enum {
	DISABLE = 0,
	ENABLE,
	AUTO,
	MANDATORY
};

/* cifsd_sess coupled with cifsd_user */
struct cifsd_sess {
	struct cifsd_user *user;
	struct cifsd_tcp_conn *conn;
	struct list_head cifsd_ses_list;
	struct list_head cifsd_ses_global_list;
	struct list_head tcon_list;
	struct hlist_head notify_table[64];
	int tcon_count;
	int valid;
	unsigned int sequence_number;
	uint64_t sess_id;
	struct ntlmssp_auth ntlmssp;
	char sess_key[CIFS_KEY_SIZE];
	bool sign;
	struct list_head cifsd_chann_list;
	bool is_anonymous;
	bool is_guest;
	struct fidtable_desc fidtable;
	int state;
	__u8 Preauth_HashValue[64];
	struct cifsd_pipe *pipe_desc[MAX_PIPE];
	struct smb2_inotify_res_info *inotify_res;
	wait_queue_head_t pipe_q;
	wait_queue_head_t notify_q;
	int ev_state;
};

enum share_attrs {
	SH_AVAILABLE = 0,
	SH_BROWSABLE,
	SH_GUESTOK,
	SH_GUESTONLY,
	SH_OPLOCKS,
	SH_WRITEABLE,
	SH_READONLY,
	SH_WRITEOK,
	SH_STORE_DOS
};

#define SHARE_ATTR(bit, name)					\
static inline void set_attr_##name(unsigned long *val)		\
{								\
	set_bit(bit, val);					\
}								\
static inline void clear_attr_##name(unsigned long *val)	\
{								\
	clear_bit(bit, val);					\
}								\
static inline unsigned int get_attr_##name(unsigned long *val)	\
{								\
	return test_bit(bit, val);				\
}

SHARE_ATTR(SH_AVAILABLE, available)	/* default: enabled */
SHARE_ATTR(SH_BROWSABLE, browsable)	/* default: enabled */
SHARE_ATTR(SH_GUESTOK, guestok)		/* default: disabled */
SHARE_ATTR(SH_GUESTONLY, guestonly)	/* default: disabled */
SHARE_ATTR(SH_OPLOCKS, oplocks)		/* default: enabled */
SHARE_ATTR(SH_READONLY, readonly)	/* default: enabled */
SHARE_ATTR(SH_WRITEOK, writeok)		/* default: enabled */
SHARE_ATTR(SH_STORE_DOS, store_dos)	/* default: disable */

struct share_config {
	char *comment;
	char *allow_hosts;
	char *deny_hosts;
	char *invalid_users;
	char *read_list;
	char *write_list;
	char *valid_users;
	unsigned long attr;
	unsigned int max_connections;
};

struct cifsd_share {
	char *path;
	__u64 tid;
	bool is_pipe;
	int tcount;
	char *sharename;
	struct share_config config;
	/* global list of shares */
	struct list_head list;
	int writeable;
	unsigned int type;
};

/* cifsd_tcon is coupled with cifsd_share */
struct cifsd_tcon {
	struct cifsd_share *share;
	struct cifsd_sess *sess;
	struct path share_path;
	struct list_head tcon_list;
	int writeable;
	int maximal_access;
};

/*
 * Relation between tcp session, cifsd session and cifsd tree conn:
 * 1 TCP session per client. Each TCP session is represented by 1
 * connection object.
 * If there are multiple useres per client, than 1 session per user
 * per tcp sess.
 * These sessions are linked via cifsd_ses_list headed at conn->cifsd_sess.
 * Currently we have limited 1 cifsd session per tcp session.
 * However, multiple tree connect possible per session.
 * Each tree connect is associated with a share.
 * Tree cons are linked via tcon_list headed at cifsd_sess->tcon_list.
 */

/* functions */
extern int cifsd_max_protocol(void);
extern int cifsd_min_protocol(void);
extern int get_protocol_idx(char *str);
extern int cifsd_init_registry(void);
extern void cifsd_free_registry(void);
extern struct cifsd_share *find_matching_share(__u16 tid);
int process_ntlm(struct cifsd_sess *sess, char *pw_buf);
int process_ntlmv2(struct cifsd_sess *sess, struct ntlmv2_resp *ntlmv2,
		int blen, char *domain_name);
int decode_ntlmssp_negotiate_blob(NEGOTIATE_MESSAGE *negblob,
		int blob_len, struct cifsd_sess *sess);
unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
		struct cifsd_sess *sess);
int decode_ntlmssp_authenticate_blob(AUTHENTICATE_MESSAGE *authblob,
		int blob_len, struct cifsd_sess *sess);
int smb1_sign_smbpdu(struct cifsd_sess *sess, struct kvec *iov, int n_vec,
		char *sig);
int smb2_sign_smbpdu(struct cifsd_sess *sess, struct kvec *iov, int n_vec,
		char *sig);
int smb3_sign_smbpdu(struct channel *chann, struct kvec *iov, int n_vec,
		char *sig);
int compute_sess_key(struct cifsd_sess *sess, char *hash, char *hmac);
int compute_smb3xsigningkey(struct cifsd_sess *sess,  __u8 *key,
	unsigned int key_size);
extern struct cifsd_user *cifsd_is_user_present(char *name);
struct cifsd_share *get_cifsd_share(struct cifsd_tcp_conn *conn,
		struct cifsd_sess *sess, char *sharename, bool *can_write);
extern struct cifsd_tcon *construct_cifsd_tcon(struct cifsd_share *share,
		struct cifsd_sess *sess);
extern struct cifsd_tcon *get_cifsd_tcon(struct cifsd_sess *sess,
			unsigned int tid);
struct cifsd_user *get_smb_session_user(struct cifsd_sess *sess);
struct cifsd_pipe *get_pipe_desc(struct cifsd_sess *sess,
		unsigned int id);
int get_pipe_id(struct cifsd_sess *sess, unsigned int pipe_type);
int close_pipe_id(struct cifsd_sess *sess, int pipe_type);
int cifsstat_show(char *buf, char *ip, int flag);
int cifsadmin_user_query(char *username);
int cifsadmin_user_del(char *username);
int cifsd_user_store(const char *buf, size_t len);
int cifsd_config_store(const char *buf, size_t len);
int cifsd_user_show(char *buf);
int cifsd_debug_store(const char *buf);
int cifsd_caseless_search_store(const char *buf);
#endif /* __CIFSD_EXPORT_H */
