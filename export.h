/*
 *   fs/cifssrv/export.h
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

#ifndef __CIFSSRV_EXPORT_H
#define __CIFSSRV_EXPORT_H

#include "smb1pdu.h"
#include "ntlmssp.h"

#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif

#define SMB_PORT		445
#define MAX_CONNECTIONS		64

extern int cifssrv_debug_enable;

/* Global list containing exported points */
extern struct list_head cifssrv_usr_list;
extern struct list_head cifssrv_share_list;
extern struct list_head cifssrv_connection_list;
extern struct list_head cifssrv_session_list;

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

#define CIFSSRV_MAJOR_VERSION 1
#define CIFSSRV_MINOR_VERSION 0
#define STR_IPC	"IPC$"
#define STR_SRV_NAME	"CIFSSRV SERVER"
#define STR_WRKGRP	"WORKGROUP"

extern int cifssrv_num_shares;
extern char *guestAccountName;

extern unsigned int SMBMaxBufSize;

struct cifssrv_usr {
	char	*name;
	char	passkey[CIFS_NTHASH_SIZE];
	kuid_t	uid;
	kgid_t	gid;
	__le32	sess_uid;
	bool	guest;
	/* global list of cifssrv users */
	struct	list_head list;
	__u16	vuid;
	/* how many server have this user */
	int	ucount;
	/* unsigned int capabilities; what for */
};

/* cifssrv_sess coupled with cifssrv_usr */
struct cifssrv_sess {
	struct cifssrv_usr *usr;
	struct tcp_server_info *server;
	struct list_head cifssrv_ses_list;
	struct list_head cifssrv_ses_global_list;
	struct list_head tcon_list;
	int	tcon_count;
	int valid;
	uint64_t sess_id;
};

enum share_attrs {
	SH_AVAILABLE = 0,
	SH_BROWSABLE,
	SH_GUESTOK,
	SH_GUESTONLY,
	SH_OPLOCKS,
	SH_WRITEABLE
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

/*
 * There could be 2 ways to add path to an export list.
 * One is static, via a conf file. Other is dynamic, via sysfs entry.
 */
SHARE_ATTR(SH_AVAILABLE, available)	/* default: enabled */
SHARE_ATTR(SH_BROWSABLE, browsable)	/* default: enabled */
SHARE_ATTR(SH_GUESTOK, guestok)		/* default: disabled */
SHARE_ATTR(SH_GUESTONLY, guestonly)	/* default: disabled */
SHARE_ATTR(SH_OPLOCKS, oplocks)		/* default: enabled */
SHARE_ATTR(SH_WRITEABLE, writeable)	/* default: disabled */


struct share_config {
	char *comment;
	char *allow_hosts;
	char *deny_hosts;
	char *invalid_users;
	char *read_list;
	char *valid_users;
	unsigned long attr;
	unsigned int max_connections;
};

struct cifssrv_share {
	char	*path;
	__u16	tid;
	int	tcount;
	char    *sharename;
	struct share_config config;
	/* global list of shares */
	struct list_head list;

};

/* cifssrv_tcon is coupled with cifssrv_share */
struct cifssrv_tcon {
	struct cifssrv_share *share;
	struct cifssrv_sess *sess;
	struct path share_path;
	struct list_head tcon_list;
};

/*
 * Relation between tcp session, cifssrv session and cifssrv tree conn:
 * 1 TCP session per client. Each TCP session is represented by 1
 * tcp_server_info object.
 * If there are multiple useres per client, than 1 session per user
 * per tcp sess.
 * These sessions are linked via cifssrv_ses_list headed at
 * server_info->cifssrv_sess.
 * Currently we have limited 1 cifssrv session per tcp session.
 * However, multiple tree connect possible per session.
 * Each tree connect is associated with a share.
 * Tree cons are linked via tcon_list headed at cifssrv_sess->tcon_list.
 */

/* functions */

extern int cifssrv_init_registry(void);
extern void cifssrv_free_registry(void);
extern struct cifssrv_share *find_matching_share(__u16 tid);
int validate_usr(char *usr, struct cifssrv_share *share);
int validate_host(char *cip, struct cifssrv_share *share);
int process_ntlm(struct tcp_server_info *server, char *pw_buf, char *passkey);
int process_ntlmv2(struct tcp_server_info *server, struct ntlmv2_resp *ntlmv2,
		int blen, char *domain_name, struct cifssrv_usr *usr);
int decode_ntlmssp_negotiate_blob(NEGOTIATE_MESSAGE *negblob,
		int blob_len, struct tcp_server_info *server);
unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob,
		struct tcp_server_info *server);
int decode_ntlmssp_authenticate_blob(AUTHENTICATE_MESSAGE *authblob,
		int blob_len, struct cifssrv_usr *usr,
		struct tcp_server_info *server);
int sign_smbpdu(struct tcp_server_info *server, char *buf, int sz, char *sig);
int compute_sess_key(struct tcp_server_info *server, char *hash, char *hmac);
extern struct cifssrv_usr *cifssrv_is_user_present(char *name);
struct cifssrv_share *get_cifssrv_share(struct tcp_server_info *server,
		struct cifssrv_sess *sess,
		char *sharename);

#endif /* __CIFSSRV_EXPORT_H */
