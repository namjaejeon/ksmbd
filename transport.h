/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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

#ifndef __CIFSD_TRANSPORT_H__
#define __CIFSD_TRANSPORT_H__

#include <linux/list.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/kthread.h>
#include <linux/nls.h>

#define IS_SMB2(x) ((x)->vals->protocol_id != SMB10_PROT_ID)

/* crypto hashing related structure/fields, not specific to a sec mech */
struct cifsd_secmech {
	struct crypto_shash *hmacmd5; /* hmac-md5 hash function */
	struct crypto_shash *md5; /* md5 hash function */
	struct crypto_shash *hmacsha256; /* hmac-sha256 hash function */
	struct crypto_shash *cmacaes; /* block-cipher based MAC function */
	struct crypto_shash *sha512; /* sha512 hash function */
	struct sdesc *sdeschmacmd5;  /* ctxt to generate ntlmv2 hash, CR1 */
	struct sdesc *sdescmd5; /* ctxt to generate cifs/smb signature */
	struct sdesc *sdeschmacsha256;  /* ctxt to generate smb2 signature */
	struct sdesc *sdesccmacaes;  /* ctxt to generate smb3 signature */
	struct sdesc *sdescsha512;  /* ctxt to generate preauth integrity */
};

struct cifsd_tcp_conn {
	struct socket			*sock;
	unsigned short			family;
	/* Reference counter */
	int				srv_count;
	/* The number of sessions attached with this connection */
	int				sess_count;
	struct smb_version_values	*vals;
	struct smb_version_ops		*ops;
	struct smb_version_cmds		*cmds;
	unsigned int			max_cmds;
	char				*hostname;
	struct mutex			srv_mutex;
	enum statusEnum			tcp_status;
	unsigned int			maxReq;
	unsigned int			cli_cap;
	unsigned int			srv_cap;
	struct kvec			*iov;
	unsigned int			nr_iov;
	void 				*request_buf;
	struct nls_table		*local_nls;
	unsigned int			total_read;
	/* This session will become part of global tcp session list */
	struct list_head		tcp_sess;
	/* smb session 1 per user */
	struct list_head		cifsd_sess;
	struct task_struct		*handler;
	int				th_id;
	int				num_files_open;
	unsigned long			last_active;
	struct timespec			create_time;
	/* pending trans request table */
	struct trans_state		*recent_trans;
	struct list_head		trans_list;
	/* How many request are running currently */
	atomic_t			req_running;
	/* References which are made for this Server object*/
	atomic_t			r_count;
	wait_queue_head_t		req_running_q;
	/* Lock to protect requests list*/
	spinlock_t			request_lock;
	struct list_head		requests;
	struct list_head		async_requests;
	int				max_credits;
	int				credits_granted;
	char				peeraddr[MAX_ADDRBUFLEN];
	int				connection_type;
	struct cifsd_stats		stats;
	struct list_head		list;
#ifdef CONFIG_CIFS_SMB2_SERVER
	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];
#endif
	struct cifsd_secmech		secmech;
	/* Used by ntlmssp */
	char				ntlmssp_cryptkey[CIFS_CRYPTO_KEY_SIZE];

	/* PreAuth integrity Hash ID */
	int				Preauth_HashId;
	/* PreAuth integrity Hash Value */
	__u8				Preauth_HashValue[64];
	int				CipherId;

	/* PreAuthSession Table */
	struct list_head		p_sess_table;
	/* Supports NTLMSSP */
	bool				sec_ntlmssp;
	/* Supports U2U Kerberos */
	bool				sec_kerberosu2u;
	/* Supports plain Kerberos */
	bool				sec_kerberos;
	/* Supports legacy MS Kerberos */
	bool				sec_mskerberos;
	bool				sign;
	bool				need_neg;
	bool				oplocks:1;
	bool				use_spnego:1;
	__le16				vuid;
	__u16				cli_sec_mode;
	__u16				srv_sec_mode;
	/* dialect index that server chose */
	__u16				dialect;

	char				*mechToken;
};

bool cifsd_tcp_conn_alive(struct cifsd_tcp_conn *conn);

int cifsd_tcp_readv(struct cifsd_tcp_conn *conn,
		    struct kvec *iov_orig, unsigned int nr_segs,
		    unsigned int to_read);

int cifsd_tcp_read(struct cifsd_tcp_conn *conn,
		   char *buf,
		   unsigned int to_read);

void cifsd_tcp_stop_kthread(void);

void cifsd_tcp_destroy(void);
int cifsd_tcp_init(__u32 cifsd_pid);
#endif /* __CIFSD_TRANSPORT_H__ */
