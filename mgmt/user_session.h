// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __USER_SESSION_MANAGEMENT_H__
#define __USER_SESSION_MANAGEMENT_H__

#include <linux/hashtable.h>

#include "../glob.h"  /* FIXME */
#include "../ntlmssp.h"

#define CIFDS_SESSION_FLAG_SMB1		(1 << 0)
#define CIFDS_SESSION_FLAG_SMB2		(1 << 1)

#define PREAUTH_HASHVALUE_SIZE		64

struct cifsd_ida;

struct channel {
	__u8			smb3signingkey[SMB3_SIGN_KEY_SIZE];
	struct cifsd_tcp_conn	*conn;
	struct list_head	chann_list;
};

struct preauth_session {
	__u8			Preauth_HashValue[PREAUTH_HASHVALUE_SIZE];
	uint64_t		sess_id;
	struct list_head	list_entry;
};

struct cifsd_session {
	uint64_t			id;

	struct cifsd_user		*user;
	struct cifsd_tcp_conn		*conn;
	unsigned int			sequence_number;
	unsigned int			flags;

	int				valid;
	bool				sign;
	bool				enc;
	bool				is_anonymous;
	bool				is_guest;

	int				state;
	__u8				*Preauth_HashValue;

	struct ntlmssp_auth		ntlmssp;
	char				sess_key[CIFS_KEY_SIZE];

	struct hlist_node		hlist;
	struct list_head		cifsd_chann_list;
	struct list_head		tree_conn_list;
	struct cifsd_ida		*tree_conn_ida;
	struct list_head		rpc_handle_list;

	struct fidtable_desc		fidtable;
	__u8				smb3encryptionkey[SMB3_SIGN_KEY_SIZE];
	__u8				smb3decryptionkey[SMB3_SIGN_KEY_SIZE];
	__u8				smb3signingkey[SMB3_SIGN_KEY_SIZE];

	struct list_head		sessions_entry;
};

static inline int test_session_flag(struct cifsd_session *sess, int bit)
{
	return sess->flags & bit;
}

static inline void set_session_flag(struct cifsd_session *sess, int bit)
{
	sess->flags |= bit;
}

static inline void clear_session_flag(struct cifsd_session *sess, int bit)
{
	sess->flags &= ~bit;
}

struct cifsd_session *cifsd_smb1_session_create(void);
struct cifsd_session *cifsd_smb2_session_create(void);

void cifsd_session_destroy(struct cifsd_session *sess);

bool cifsd_session_id_match(struct cifsd_session *sess, unsigned long long id);
struct cifsd_session *cifsd_session_lookup_slowpath(unsigned long long id);
struct cifsd_session *cifsd_session_lookup(struct cifsd_tcp_conn *conn,
					   unsigned long long id);
void cifsd_session_register(struct cifsd_tcp_conn *conn,
			    struct cifsd_session *sess);
void cifsd_sessions_deregister(struct cifsd_tcp_conn *conn);

int cifsd_acquire_tree_conn_id(struct cifsd_session *sess);
void cifsd_release_tree_conn_id(struct cifsd_session *sess, int id);

int cifsd_session_rpc_open(struct cifsd_session *sess, char *rpc_name);
void cifsd_session_rpc_close(struct cifsd_session *sess, int id);
int cifsd_session_rpc_method(struct cifsd_session *sess, int id);

int cifsd_init_session_table(void);
void cifsd_free_session_table(void);

#endif /* __USER_SESSION_MANAGEMENT_H__ */
