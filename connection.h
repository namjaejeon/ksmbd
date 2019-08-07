// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_CONNECTION_H__
#define __CIFSD_CONNECTION_H__

#include <linux/list.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/kthread.h>
#include <linux/nls.h>

#include "smb_common.h"
#include "cifsd_work.h"

#define CIFSD_SOCKET_BACKLOG		16

/*
 * WARNING
 *
 * This is nothing but a HACK. Session status should move to channel
 * or to session. As of now we have 1 tcp_conn : 1 cifsd_session, but
 * we need to change it to 1 tcp_conn : N cifsd_sessions.
 */
enum {
	CIFSD_SESS_NEW = 0,
	CIFSD_SESS_GOOD,
	CIFSD_SESS_EXITING,
	CIFSD_SESS_NEED_RECONNECT,
	CIFSD_SESS_NEED_NEGOTIATE
};

struct cifsd_stats {
	atomic_t			open_files_count;
	atomic64_t			request_served;
};

struct cifsd_transport;

struct cifsd_conn {
	struct smb_version_values	*vals;
	struct smb_version_ops		*ops;
	struct smb_version_cmds		*cmds;
	unsigned int			max_cmds;
	struct mutex			srv_mutex;
	int				status;
	unsigned int			cli_cap;
	char				*request_buf;
	struct cifsd_transport		*transport;
	struct nls_table		*local_nls;
	struct list_head		conns_list;
	/* smb session 1 per user */
	struct list_head		sessions;
	unsigned long			last_active;
	/* How many request are running currently */
	atomic_t			req_running;
	/* References which are made for this Server object*/
	atomic_t			r_count;
	unsigned short			total_credits;
	unsigned short			max_credits;
	spinlock_t			credits_lock;
	wait_queue_head_t		req_running_q;
	/* Lock to protect requests list*/
	spinlock_t			request_lock;
	struct list_head		requests;
	struct list_head		async_requests;
	int				connection_type;
	struct cifsd_stats		stats;
	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];
	union {
		/* pending trans request table */
		struct trans_state	*recent_trans;
		/* Used by ntlmssp */
		char			*ntlmssp_cryptkey;
	};

	struct preauth_integrity_info	*preauth_info;

	bool				need_neg;
	/* Supports NTLMSSP */
	bool				sec_ntlmssp;
	/* Supports U2U Kerberos */
	bool				sec_kerberosu2u;
	/* Supports plain Kerberos */
	bool				sec_kerberos;
	/* Supports legacy MS Kerberos */
	bool				sec_mskerberos;
	bool				sign;
	bool				use_spnego:1;
	__u16				cli_sec_mode;
	__u16				srv_sec_mode;
	/* dialect index that server chose */
	__u16				dialect;

	char				*mechToken;

	struct cifsd_conn_ops	*conn_ops;

	/* Preauth Session Table */
	struct list_head		preauth_sess_table;

	struct sockaddr_storage		peer_addr;

	/* Identifier for async message */
	struct cifsd_ida		*async_ida;

	__le16				cipher_type;
	__le16				compress_algorithm;
	bool				posix_ext_supported;
};

struct cifsd_conn_ops {
	int	(*process_fn)(struct cifsd_conn *conn);
	int	(*terminate_fn)(struct cifsd_conn *conn);
};

struct cifsd_transport_ops {
	int (*prepare)(struct cifsd_transport *t);
	int (*read)(struct cifsd_transport *t, char *buf, unsigned int size);
	int (*writev)(struct cifsd_transport *t, struct kvec *iovs, int nvecs,
			int size);
	void (*disconnect)(struct cifsd_transport *t);
};

struct cifsd_transport {
	struct cifsd_conn		*conn;
	struct cifsd_transport_ops	*ops;
	struct task_struct		*handler;
};

#define CIFSD_TCP_RECV_TIMEOUT	(7 * HZ)
#define CIFSD_TCP_SEND_TIMEOUT	(5 * HZ)
#define CIFSD_TCP_PEER_SOCKADDR(c)	((struct sockaddr *)&((c)->peer_addr))

bool cifsd_conn_alive(struct cifsd_conn *conn);
void cifsd_conn_wait_idle(struct cifsd_conn *conn);

struct cifsd_conn *cifsd_conn_alloc(void);
void cifsd_conn_free(struct cifsd_conn *conn);
int cifsd_tcp_for_each_conn(int (*match)(struct cifsd_conn *, void *),
	void *arg);
int cifsd_conn_write(struct cifsd_work *work);

void cifsd_conn_enqueue_request(struct cifsd_work *work);
int cifsd_conn_try_dequeue_request(struct cifsd_work *work);
void cifsd_conn_init_server_callbacks(struct cifsd_conn_ops *ops);

int cifsd_conn_handler_loop(void *p);

int cifsd_conn_transport_init(void);
void cifsd_conn_transport_destroy(void);

/*
 * WARNING
 *
 * This is a hack. We will move status to a proper place once we land
 * a multi-sessions support.
 */
static inline bool cifsd_conn_good(struct cifsd_work *work)
{
	return work->conn->status == CIFSD_SESS_GOOD;
}

static inline bool cifsd_conn_need_negotiate(struct cifsd_work *work)
{
	return work->conn->status == CIFSD_SESS_NEED_NEGOTIATE;
}

static inline bool cifsd_conn_need_reconnect(struct cifsd_work *work)
{
	return work->conn->status == CIFSD_SESS_NEED_RECONNECT;
}

static inline bool cifsd_conn_exiting(struct cifsd_work *work)
{
	return work->conn->status == CIFSD_SESS_EXITING;
}

static inline void cifsd_conn_set_good(struct cifsd_work *work)
{
	work->conn->status = CIFSD_SESS_GOOD;
}

static inline void cifsd_conn_set_need_negotiate(struct cifsd_work *work)
{
	work->conn->status = CIFSD_SESS_NEED_NEGOTIATE;
}

static inline void cifsd_conn_set_need_reconnect(struct cifsd_work *work)
{
	work->conn->status = CIFSD_SESS_NEED_RECONNECT;
}

static inline void cifsd_conn_set_exiting(struct cifsd_work *work)
{
	work->conn->status = CIFSD_SESS_EXITING;
}
#endif /* __CIFSD_CONNECTION_H__ */
