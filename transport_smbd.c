// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 *
 *   Author(s): Long Li <longli@microsoft.com>,
 *   		Hyunchul Lee <hyc.lee@gmail.com>
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 */

#include <linux/kthread.h>
#include <linux/rwlock.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/scatterlist.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rw.h>

#include "glob.h"
#include "connection.h"
#include "smb_common.h"
#include "buffer_pool.h"

#define SMBD_PORT	5445

#define SMBD_VERSION_LE		__constant_cpu_to_le16(0x0100)

#define SMBD_MAX_RW_SIZE		(1 << 20)

/* SMBD negotiation timeout in seconds */
#define SMBD_NEGOTIATE_TIMEOUT		120

#define SMBDIRECT_MAX_SGE		4

/*
 * Default maximum number of RDMA read/write outstanding on this connection
 * This value is possibly decreased during QP creation on hardware limit
 */
#define SMBD_CM_RESPONDER_RESOURCES	32

/* Maximum number of retries on data transfer operations */
#define SMBD_CM_RETRY			6
/* No need to retry on Receiver Not Ready since SMBD manages credits */
#define SMBD_CM_RNR_RETRY		0

/*
 * User configurable initial values per SMBD transport connection
 * as defined in [MS-SMBD] 3.1.1.1
 * Those may change after a SMBD negotiation
 */
/* The local peer's maximum number of credits to grant to the peer */
int smbd_receive_credit_max = 255;

/* The remote peer's credit request of local peer */
int smbd_send_credit_target = 255;

/* The maximum single message size can be sent to remote peer */
int smbd_max_send_size = 1364;

/*  The maximum fragmented upper-layer payload receive size supported */
int smbd_max_fragmented_recv_size = 1024 * 1024;

/*  The maximum single-message size which can be received */
int smbd_max_receive_size = 8192;

/*
 * User configurable initial values for RDMA transport
 * The actual values used may be lower and are limited to hardware capabilities
 */
/* Default maximum number of SGEs in a RDMA write/read */
int smbd_max_frmr_depth = 2048;

struct smbd_listener {
	struct rdma_cm_id	*cm_id;
} smbd_listener;

enum smbd_status {
	SMBD_CS_NEW = 0,
	SMBD_CS_CLIENT_ACCEPTED,
	SMBD_CS_NEGOTIATED,
	SMBD_CS_CONNECTED,
	SMBD_CS_DISCONNECTING,
	SMBD_CS_DISCONNECTED,
};

struct smbd_transport {
	struct cifsd_transport	transport;

	enum smbd_status	status;
	bool			full_packet_received;
	wait_queue_head_t	wait_status;

	struct rdma_cm_id	*cm_id;
	struct ib_cq		*send_cq;
	struct ib_cq		*recv_cq;
	struct ib_pd		*pd;
	struct ib_qp		*qp;
	int			max_send_size;
	int			max_recv_size;
	int			max_fragmented_send_size;
	int			max_fragmented_recv_size;

	int			recv_credit_max;
	int			recv_credit_target;
	atomic_t		recv_credits;
	int			send_credit_target;
	atomic_t		send_credits;
	spinlock_t		lock_new_recv_credits;
	int			new_recv_credits;

	wait_queue_head_t	wait_send_queue;

	mempool_t		*sendmsg_mempool;
	struct kmem_cache	*sendmsg_cache;
	mempool_t		*recvmsg_mempool;
	struct kmem_cache	*recvmsg_cache;

	spinlock_t		recvmsg_queue_lock;
	struct list_head	recvmsg_queue;
	int			count_recvmsg_queue;

	spinlock_t		reassembly_queue_lock;
	struct list_head	reassembly_queue;
	int			reassembly_data_length;
	int			reassembly_queue_length;
	int			first_entry_offset;
	wait_queue_head_t	wait_reassembly_queue;

	spinlock_t		empty_recvmsg_queue_lock;
	struct list_head	empty_recvmsg_queue;
	int			count_empty_recvmsg_queue;

	wait_queue_head_t	wait_smbd_send_pending;
	int			smbd_send_pending;
	wait_queue_head_t	wait_send_payload_pending;
	atomic_t		send_payload_pending;
	wait_queue_head_t	wait_send_pending;
	atomic_t		send_pending;

	struct workqueue_struct	*workqueue;
	struct work_struct	post_recv_credits_work;
	struct work_struct	disconnect_work;
	struct work_struct	send_immediate_work;
};

#define CIFSD_TRANS(t)	((struct cifsd_transport *)&((t)->transport))
#define SMBD_TRANS(t)	((struct smbd_transport *)container_of(t, \
				struct smbd_transport, transport))

enum {
	SMBD_MSG_NEGOTIATE_REQ = 0,
	SMBD_MSG_DATA_TRANSFER
};

extern struct cifsd_transport_ops cifsd_smbd_transport_ops;

static struct smbd_transport *alloc_transport(struct rdma_cm_id *cm_id)
{
	struct smbd_transport *t;
	struct cifsd_conn *conn;
	char name[80];

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;

	t->cm_id = cm_id;
	cm_id->context = t;

	init_waitqueue_head(&t->wait_status);

	spin_lock_init(&t->recvmsg_queue_lock);
	INIT_LIST_HEAD(&t->recvmsg_queue);
	t->count_recvmsg_queue = 0;

	spin_lock_init(&t->reassembly_queue_lock);
	INIT_LIST_HEAD(&t->reassembly_queue);
	t->reassembly_data_length = 0;
	t->reassembly_queue_length = 0;
	init_waitqueue_head(&t->wait_reassembly_queue);
	init_waitqueue_head(&t->wait_send_queue);

	spin_lock_init(&t->empty_recvmsg_queue_lock);
	INIT_LIST_HEAD(&t->empty_recvmsg_queue);
	t->count_empty_recvmsg_queue = 0;

	init_waitqueue_head(&t->wait_smbd_send_pending);
	t->smbd_send_pending = 0;

	init_waitqueue_head(&t->wait_send_payload_pending);
	atomic_set(&t->send_payload_pending, 0);
	init_waitqueue_head(&t->wait_send_pending);
	atomic_set(&t->send_pending, 0);

	spin_lock_init(&t->lock_new_recv_credits);

	snprintf(name, sizeof(name), "smbd_%p", t);
	t->workqueue = create_workqueue(name);
	if (!t->workqueue)
		goto err;

	conn = cifsd_conn_alloc();
	if (!conn)
		goto err;
	conn->transport = CIFSD_TRANS(t);
	CIFSD_TRANS(t)->conn = conn;
	CIFSD_TRANS(t)->ops = &cifsd_smbd_transport_ops;
	return t;
err:
	if (t->workqueue)
		destroy_workqueue(t->workqueue);
	kfree(t);
	return NULL;
}

static void free_transport(struct smbd_transport *t)
{
	if (t->qp) {
		ib_drain_qp(t->qp);
		ib_destroy_qp(t->qp);
	}

	wake_up_interruptible(&t->wait_send_queue);

	cifsd_debug("wait for all send to finish\n");
	wait_event(t->wait_smbd_send_pending, t->smbd_send_pending == 0);

	cifsd_debug("wait for all send posted to IB to finish\n");
	wait_event(t->wait_send_payload_pending,
		atomic_read(&t->send_payload_pending) == 0);
	wait_event(t->wait_send_pending,
		atomic_read(&t->send_pending) == 0);

	t->reassembly_data_length = 0;

	if (t->send_cq)
		ib_free_cq(t->send_cq);
	if (t->recv_cq)
		ib_free_cq(t->recv_cq);
	if (t->pd)
		ib_dealloc_pd(t->pd);
	if (t->cm_id)
		rdma_destroy_id(t->cm_id);

	destroy_workqueue(t->workqueue);
	cifsd_conn_free(CIFSD_TRANS(t)->conn);
	kfree(t);
}

static bool rdma_frwr_is_supported(struct ib_device_attr *attrs)
{
	if (!(attrs->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS))
		return false;
	if (attrs->max_fast_reg_page_list_len == 0)
		return false;
	return true;
}

static int smbd_handle_connect_request(struct rdma_cm_id *new_cm_id)
{
	struct smbd_transport *t;

	if (!rdma_frwr_is_supported(&new_cm_id->device->attrs)) {
		cifsd_err("Fast Registration Work Requests is not "
			"supported. device capabilities=%llx",
			new_cm_id->device->attrs.device_cap_flags);
		return -EPROTONOSUPPORT;
	}

	t = alloc_transport(new_cm_id);
	if (!t)
		return -ENOMEM;

	CIFSD_TRANS(t)->handler = kthread_run(cifsd_conn_handler_loop,
				CIFSD_TRANS(t)->conn, "kcifsd:r%u", SMBD_PORT);
	if (IS_ERR(CIFSD_TRANS(t)->handler)) {
		int ret = PTR_ERR(CIFSD_TRANS(t)->handler);
		cifsd_err("Can't start thread\n");
		free_transport(t);
		return ret;
	}

	return 0;
}

static int smbd_listen_handler(struct rdma_cm_id *cm_id,
				struct rdma_cm_event *event)
{
	switch(event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST: {
		int ret = smbd_handle_connect_request(cm_id);
		if (ret) {
			cifsd_err("Can't create transport: %d\n", ret);
			return ret;
		}

		cifsd_debug("Received connection request. cm_id=%p\n", cm_id);
		break;
	}
	default:
		cifsd_err("Unexpected listen event. cm_id=%p, event=%s (%d)\n",
				cm_id,
				rdma_event_msg(event->event), event->event);
		break;
	}
	return 0;
}

static int smbd_listen(int port)
{
	int ret;
	struct rdma_cm_id *cm_id;
	struct sockaddr_in sin = {
		.sin_family		= AF_INET,
		.sin_addr.s_addr	= htonl(INADDR_ANY),
		.sin_port		= htons(port),
	};

	cm_id = rdma_create_id(&init_net, smbd_listen_handler, &smbd_listener,
				RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id)) {
		cifsd_err("Can't create cm id: %ld\n",
				PTR_ERR(cm_id));
		return PTR_ERR(cm_id);
	}

	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);
	if (ret) {
		cifsd_err("Can't bind: %d\n", ret);
		goto err;
	}

	smbd_listener.cm_id = cm_id;

	ret = rdma_listen(cm_id, 10);
	if (ret) {
		cifsd_err("Can't listen: %d\n", ret);
		goto err;
	}
	return 0;
err:
	smbd_listener.cm_id = NULL;
	rdma_destroy_id(cm_id);
	return ret;
}

int cifsd_smbd_init(void)
{
	int ret;

	smbd_listener.cm_id = NULL;
	ret = smbd_listen(SMBD_PORT);
	if (ret) {
		cifsd_err("Can't listen: %d\n", ret);
		return ret;
	}

	cifsd_debug("init RDMA listener. cm_id=%p\n", smbd_listener.cm_id);
	return 0;
}

int cifsd_smbd_destroy(void)
{
	if (smbd_listener.cm_id)
		rdma_destroy_id(smbd_listener.cm_id);
	return 0;
}

struct cifsd_transport_ops cifsd_smbd_transport_ops;
