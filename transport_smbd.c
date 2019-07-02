// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 *
 *   Author(s): Long Li <longli@microsoft.com>,
 *		Hyunchul Lee <hyc.lee@gmail.com>
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
#include "transport_smbd.h"

#define SMBD_PORT	5445

#define SMBD_VERSION_LE		cpu_to_le16(0x0100)

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
static int smbd_receive_credit_max = 255;

/* The remote peer's credit request of local peer */
static int smbd_send_credit_target = 255;

/* The maximum single message size can be sent to remote peer */
static int smbd_max_send_size = 1364;

/*  The maximum fragmented upper-layer payload receive size supported */
static int smbd_max_fragmented_recv_size = 1024 * 1024;

/*  The maximum single-message size which can be received */
static int smbd_max_receive_size = 8192;

/*
 * User configurable initial values for RDMA transport
 * The actual values used may be lower and are limited to hardware capabilities
 */
/* Default maximum number of SGEs in a RDMA write/read */
static int smbd_max_frmr_depth = 2048;

static struct smbd_listener {
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
	struct work_struct	send_immediate_work;
	struct work_struct	disconnect_work;
};

#define CIFSD_TRANS(t)	((struct cifsd_transport *)&((t)->transport))
#define SMBD_TRANS(t)	((struct smbd_transport *)container_of(t, \
				struct smbd_transport, transport))

enum {
	SMBD_MSG_NEGOTIATE_REQ = 0,
	SMBD_MSG_DATA_TRANSFER
};

static struct cifsd_transport_ops cifsd_smbd_transport_ops;

struct smbd_sendmsg {
	struct smbd_transport	*transport;
	int			num_sge;
	struct ib_sge		sge[SMBDIRECT_MAX_SGE];
	struct ib_cqe		cqe;
	u8			packet[];
};

struct smbd_recvmsg {
	struct smbd_transport	*transport;
	struct list_head	list;
	int			type;
	struct ib_sge		sge;
	struct ib_cqe		cqe;
	bool			first_segment;
	u8			packet[];
};

static void smbd_destroy_pools(struct smbd_transport *transport);
static void smbd_post_recv_credits(struct work_struct *work);
static int smbd_post_send_data(struct smbd_transport *t, struct kvec *iov,
			int nvecs, int remaining_data_length);

static inline void *smbd_recvmsg_payload(struct smbd_recvmsg *recvmsg)
{
	return (void *)recvmsg->packet;
}

static struct smbd_recvmsg *get_free_recvmsg(struct smbd_transport *t)
{
	struct smbd_recvmsg *recvmsg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&t->recvmsg_queue_lock, flags);
	if (!list_empty(&t->recvmsg_queue)) {
		recvmsg = list_first_entry(&t->recvmsg_queue,
				struct smbd_recvmsg, list);
		list_del(&recvmsg->list);
		t->count_recvmsg_queue--;
		spin_unlock_irqrestore(&t->recvmsg_queue_lock, flags);
		return recvmsg;
	} else {
		spin_unlock_irqrestore(&t->recvmsg_queue_lock, flags);
		return NULL;
	}
}

static void put_recvmsg(struct smbd_transport *t,
				struct smbd_recvmsg *recvmsg)
{
	unsigned long flags;

	ib_dma_unmap_single(t->cm_id->device, recvmsg->sge.addr,
			recvmsg->sge.length, DMA_FROM_DEVICE);

	spin_lock_irqsave(&t->recvmsg_queue_lock, flags);
	list_add(&recvmsg->list, &t->recvmsg_queue);
	t->count_recvmsg_queue++;
	spin_unlock_irqrestore(&t->recvmsg_queue_lock, flags);

	if (t->status == SMBD_CS_CONNECTED)
		queue_work(t->workqueue, &t->post_recv_credits_work);
}

static struct smbd_recvmsg *get_empty_recvmsg(struct smbd_transport *t)
{
	struct smbd_recvmsg *recvmsg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&t->empty_recvmsg_queue_lock, flags);
	if (!list_empty(&t->empty_recvmsg_queue)) {
		recvmsg = list_first_entry(
			&t->empty_recvmsg_queue,
			struct smbd_recvmsg, list);
		list_del(&recvmsg->list);
		t->count_empty_recvmsg_queue--;
	}
	spin_unlock_irqrestore(&t->empty_recvmsg_queue_lock, flags);

	return recvmsg;
}

static void __put_empty_recvmsg(struct smbd_transport *t,
			struct smbd_recvmsg *recvmsg)
{
	ib_dma_unmap_single(t->cm_id->device, recvmsg->sge.addr,
			recvmsg->sge.length, DMA_FROM_DEVICE);

	spin_lock(&t->empty_recvmsg_queue_lock);
	list_add_tail(&recvmsg->list, &t->empty_recvmsg_queue);
	t->count_empty_recvmsg_queue++;
	spin_unlock(&t->empty_recvmsg_queue_lock);
}

static void put_empty_recvmsg(struct smbd_transport *t,
			struct smbd_recvmsg *recvmsg)
{
	__put_empty_recvmsg(t, recvmsg);
	if (t->status == SMBD_CS_CONNECTED)
		queue_work(t->workqueue, &t->post_recv_credits_work);
}

static void enqueue_reassembly(struct smbd_transport *t,
					struct smbd_recvmsg *recvmsg,
					int data_length)
{
	spin_lock(&t->reassembly_queue_lock);
	list_add_tail(&recvmsg->list, &t->reassembly_queue);
	t->reassembly_queue_length++;
	/*
	 * Make sure reassembly_data_length is updated after list and
	 * reassembly_queue_length are updated. On the dequeue side
	 * reassembly_data_length is checked without a lock to determine
	 * if reassembly_queue_length and list is up to date
	 */
	virt_wmb();
	t->reassembly_data_length += data_length;
	spin_unlock(&t->reassembly_queue_lock);

}

static struct smbd_recvmsg *get_first_reassembly(
				struct smbd_transport *t)
{
	if (!list_empty(&t->reassembly_queue))
		return list_first_entry(&t->reassembly_queue,
				struct smbd_recvmsg, list);
	else
		return NULL;
}

static void smbd_disconnect_rdma_work(struct work_struct *work)
{
	struct smbd_transport *t =
		container_of(work, struct smbd_transport, disconnect_work);

	if (t->status >= SMBD_CS_CLIENT_ACCEPTED
			&& t->status <= SMBD_CS_CONNECTED) {
		t->status = SMBD_CS_DISCONNECTING;
		rdma_disconnect(t->cm_id);
	}
}

static void smbd_disconnect_rdma_connection(struct smbd_transport *t)
{
	queue_work(t->workqueue, &t->disconnect_work);
}

static void smbd_send_immediate_work(struct work_struct *work)
{
	struct smbd_transport *t = container_of(work, struct smbd_transport,
					send_immediate_work);

	if (t->status != SMBD_CS_CONNECTED)
		return;

	cifsd_debug("send an empty message\n");
	smbd_post_send_data(t, NULL, 0, 0);
}

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

	INIT_WORK(&t->post_recv_credits_work, smbd_post_recv_credits);
	INIT_WORK(&t->send_immediate_work, smbd_send_immediate_work);
	INIT_WORK(&t->disconnect_work, smbd_disconnect_rdma_work);

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
	struct smbd_recvmsg *recvmsg;
	unsigned long flags;

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

	cifsd_debug("drain the reassembly queue\n");
	do {
		spin_lock_irqsave(&t->reassembly_queue_lock, flags);
		recvmsg = get_first_reassembly(t);
		if (recvmsg) {
			list_del(&recvmsg->list);
			spin_unlock_irqrestore(
				&t->reassembly_queue_lock, flags);
			put_recvmsg(t, recvmsg);
		} else
			spin_unlock_irqrestore(&t->reassembly_queue_lock,
					flags);
	} while (recvmsg);
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
	smbd_destroy_pools(t);
	cifsd_conn_free(CIFSD_TRANS(t)->conn);
	kfree(t);
}

static struct smbd_sendmsg *smbd_alloc_sendmsg(struct smbd_transport *t)
{
	struct smbd_sendmsg *sendmsg;

	sendmsg = mempool_alloc(t->sendmsg_mempool, GFP_KERNEL);
	if (!sendmsg)
		return ERR_PTR(-ENOMEM);
	sendmsg->transport = t;
	return sendmsg;
}

static void smbd_free_sendmsg(struct smbd_transport *t,
			struct smbd_sendmsg *sendmsg)
{
	mempool_free(sendmsg, t->sendmsg_mempool);
}

static int smbd_check_recvmsg(struct smbd_recvmsg *recvmsg)
{
	switch (recvmsg->type) {
	case SMBD_MSG_DATA_TRANSFER: {
		struct smbd_data_transfer *req =
				(struct smbd_data_transfer *) recvmsg->packet;
		struct smb2_hdr *hdr = (struct smb2_hdr *) (recvmsg->packet
				+ le16_to_cpu(req->data_offset) - 4);
		cifsd_debug("CreditGranted: %u, CreditRequested: %u, "
				"DataLength: %u, RemaingDataLength: %u, "
				"SMB: %x, Command: %u\n",
				le16_to_cpu(req->credits_granted),
				le16_to_cpu(req->credits_requested),
				req->data_length, req->remaining_data_length,
				hdr->ProtocolId, hdr->Command);
		break;
	}
	case SMBD_MSG_NEGOTIATE_REQ: {
		struct smbd_negotiate_req *req =
				(struct smbd_negotiate_req *)recvmsg->packet;
		cifsd_debug("MinVersion: %u, MaxVersion: %u, "
			"CreditRequested: %u, MaxSendSize: %u, "
			"MaxRecvSize: %u, MaxFragmentedSize: %u\n",
			le16_to_cpu(req->min_version),
			le16_to_cpu(req->max_version),
			le16_to_cpu(req->credits_requested),
			le32_to_cpu(req->preferred_send_size),
			le32_to_cpu(req->max_receive_size),
			le32_to_cpu(req->max_fragmented_size));
		if (le16_to_cpu(req->min_version) > 0x0100 ||
				le16_to_cpu(req->max_version < 0x0100))
			return -ENOTSUPP;
		if (le16_to_cpu(req->credits_requested) <= 0 ||
				le32_to_cpu(req->max_receive_size) <= 128 ||
				le32_to_cpu(req->max_fragmented_size) <=
					128*1024)
			return -ECONNABORTED;

		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static void recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct smbd_recvmsg *recvmsg;
	struct smbd_transport *t;

	recvmsg = container_of(wc->wr_cqe, struct smbd_recvmsg, cqe);
	t = recvmsg->transport;

	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_RECV) {
		cifsd_err("Recv error. status='%s (%d)' opcode=%d\n",
			ib_wc_status_msg(wc->status), wc->status,
			wc->opcode);
		smbd_disconnect_rdma_connection(t);
		__put_empty_recvmsg(t, recvmsg);
		return;
	}

	cifsd_debug("Recv completed. status='%s (%d)', opcode=%d\n",
			ib_wc_status_msg(wc->status), wc->status,
			wc->opcode);

	ib_dma_sync_single_for_cpu(wc->qp->device, recvmsg->sge.addr,
			recvmsg->sge.length, DMA_FROM_DEVICE);

	switch (recvmsg->type) {
	case SMBD_MSG_NEGOTIATE_REQ:
		t->status = SMBD_CS_NEGOTIATED;
		t->full_packet_received = true;
		wake_up_interruptible(&t->wait_status);
		break;
	case SMBD_MSG_DATA_TRANSFER: {
		struct smbd_data_transfer *data_transfer =
			(struct smbd_data_transfer *)recvmsg->packet;
		int data_length = le32_to_cpu(data_transfer->data_length);

		if (data_length) {
			if (t->full_packet_received)
				recvmsg->first_segment = true;

			if (le32_to_cpu(data_transfer->remaining_data_length))
				t->full_packet_received = false;
			else
				t->full_packet_received = true;

			enqueue_reassembly(t, recvmsg, data_length);
			wake_up_interruptible(&t->wait_reassembly_queue);
		} else
			put_empty_recvmsg(t, recvmsg);

		atomic_dec(&t->recv_credits);
		t->recv_credit_target =
				le16_to_cpu(data_transfer->credits_requested);
		atomic_add(le16_to_cpu(data_transfer->credits_granted),
				&t->send_credits);

		if (le16_to_cpu(data_transfer->flags) &
				SMB_DIRECT_RESPONSE_REQUESTED)
			queue_work(t->workqueue, &t->send_immediate_work);

		if (atomic_read(&t->send_credits) > 0)
			wake_up_interruptible(&t->wait_send_queue);
		break;
	}
	default:
		break;
	}
}

static int smbd_post_recv(struct smbd_transport *t,
			struct smbd_recvmsg *recvmsg)
{
	struct ib_recv_wr wr;
	int ret;

	recvmsg->sge.addr = ib_dma_map_single(t->cm_id->device,
			recvmsg->packet, t->max_recv_size,
			DMA_FROM_DEVICE);
	if (ib_dma_mapping_error(t->cm_id->device, recvmsg->sge.addr))
		return -EIO;
	recvmsg->sge.length = t->max_recv_size;
	recvmsg->sge.lkey = t->pd->local_dma_lkey;
	recvmsg->cqe.done = recv_done;

	wr.wr_cqe = &recvmsg->cqe;
	wr.next = NULL;
	wr.sg_list = &recvmsg->sge;
	wr.num_sge = 1;

	ret = ib_post_recv(t->qp, &wr, NULL);
	if (ret) {
		cifsd_err("Can't post recv: %d\n", ret);
		ib_dma_unmap_single(t->cm_id->device,
			recvmsg->sge.addr, recvmsg->sge.length,
			DMA_FROM_DEVICE);
		smbd_disconnect_rdma_connection(t);
		return ret;
	}
	return ret;
}

static int smbd_read(struct cifsd_transport *t, char *buf, unsigned int size)
{
	struct smbd_recvmsg *recvmsg;
	struct smbd_data_transfer *data_transfer;
	int to_copy, to_read, data_read, offset;
	u32 data_length, remaining_data_length, data_offset;
	int rc;
	struct smbd_transport *st = SMBD_TRANS(t);

again:
	if (st->status != SMBD_CS_CONNECTED) {
		cifsd_err("disconnected\n");
		return -ENOTCONN;
	}

	/*
	 * No need to hold the reassembly queue lock all the time as we are
	 * the only one reading from the front of the queue. The transport
	 * may add more entries to the back of the queue at the same time
	 */
	cifsd_debug("size=%d st->reassembly_data_length=%d\n", size,
		st->reassembly_data_length);
	if (st->reassembly_data_length >= size) {
		int queue_length;
		int queue_removed = 0;

		/*
		 * Need to make sure reassembly_data_length is read before
		 * reading reassembly_queue_length and calling
		 * get_first_reassembly. This call is lock free
		 * as we never read at the end of the queue which are being
		 * updated in SOFTIRQ as more data is received
		 */
		virt_rmb();
		queue_length = st->reassembly_queue_length;
		data_read = 0;
		to_read = size;
		offset = st->first_entry_offset;
		while (data_read < size) {
			recvmsg = get_first_reassembly(st);
			data_transfer = smbd_recvmsg_payload(recvmsg);
			data_length = le32_to_cpu(data_transfer->data_length);
			remaining_data_length =
				le32_to_cpu(
					data_transfer->remaining_data_length);
			data_offset = le32_to_cpu(data_transfer->data_offset);

			/*
			 * The upper layer expects RFC1002 length at the
			 * beginning of the payload. Return it to indicate
			 * the total length of the packet. This minimize the
			 * change to upper layer packet processing logic. This
			 * will be eventually remove when an intermediate
			 * transport layer is added
			 */
			if (recvmsg->first_segment && size == 4) {
				unsigned int rfc1002_len =
					data_length + remaining_data_length;
				*((__be32 *)buf) = cpu_to_be32(rfc1002_len);
				data_read = 4;
				recvmsg->first_segment = false;
				cifsd_debug("returning rfc1002 length %d\n",
					rfc1002_len);
				goto read_rfc1002_done;
			}

			to_copy = min_t(int, data_length - offset, to_read);
			memcpy(
				buf + data_read,
				(char *)data_transfer + data_offset + offset,
				to_copy);

			/* move on to the next buffer? */
			if (to_copy == data_length - offset) {
				queue_length--;
				/*
				 * No need to lock if we are not at the
				 * end of the queue
				 */
				if (queue_length)
					list_del(&recvmsg->list);
				else {
					spin_lock_irq(
						&st->reassembly_queue_lock);
					list_del(&recvmsg->list);
					spin_unlock_irq(
						&st->reassembly_queue_lock);
				}
				queue_removed++;
				put_recvmsg(st, recvmsg);
				offset = 0;
			} else
				offset += to_copy;

			to_read -= to_copy;
			data_read += to_copy;

			cifsd_debug("_get_first_reassembly memcpy %d bytes "
				"data_transfer_length-offset=%d after that "
				"to_read=%d data_read=%d offset=%d\n",
				to_copy, data_length - offset,
				to_read, data_read, offset);
		}

		spin_lock_irq(&st->reassembly_queue_lock);
		st->reassembly_data_length -= data_read;
		st->reassembly_queue_length -= queue_removed;
		spin_unlock_irq(&st->reassembly_queue_lock);

		st->first_entry_offset = offset;
		cifsd_debug("returning to thread data_read=%d "
			"reassembly_data_length=%d first_entry_offset=%d\n",
			data_read, st->reassembly_data_length,
			st->first_entry_offset);
read_rfc1002_done:
		return data_read;
	}

	cifsd_debug("wait_event on more data\n");
	rc = wait_event_interruptible(
		st->wait_reassembly_queue,
		st->reassembly_data_length >= size ||
		st->status != SMBD_CS_CONNECTED);
	if (rc)
		return -EINTR;

	goto again;
}

static void smbd_post_recv_credits(struct work_struct *work)
{
	struct smbd_transport *t = container_of(work, struct smbd_transport,
					post_recv_credits_work);
	struct smbd_recvmsg *recvmsg;
	int credits;
	int ret;
	int use_free = 1;

	credits = 0;
	if (t->recv_credit_target > atomic_read(&t->recv_credits)) {
		while (true) {
			if (use_free)
				recvmsg = get_free_recvmsg(t);
			else
				recvmsg = get_empty_recvmsg(t);
			if (!recvmsg) {
				if (use_free) {
					use_free = 0;
					continue;
				} else
					break;
			}

			recvmsg->type = SMBD_MSG_DATA_TRANSFER;
			recvmsg->first_segment = false;

			ret = smbd_post_recv(t, recvmsg);
			if (ret) {
				cifsd_err("Can't post recv: %d\n", ret);
				put_recvmsg(t, recvmsg);
				break;
			}
			credits++;
		}
	}

	spin_lock(&t->lock_new_recv_credits);
	t->new_recv_credits += credits;
	spin_unlock(&t->lock_new_recv_credits);

	atomic_add(credits, &t->recv_credits);

	if (credits)
		queue_work(t->workqueue, &t->send_immediate_work);
}

static void send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct smbd_sendmsg *sendmsg;
	struct smbd_transport *t;
	int i;

	sendmsg = container_of(wc->wr_cqe, struct smbd_sendmsg, cqe);
	t = sendmsg->transport;

	cifsd_debug("Send completed. status='%s (%d)', opcode=%d\n",
			ib_wc_status_msg(wc->status), wc->status,
			wc->opcode);

	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_SEND) {
		cifsd_err("Send error. status='%s (%d)', opcode=%d\n",
			ib_wc_status_msg(wc->status), wc->status,
			wc->opcode);
		smbd_disconnect_rdma_connection(t);
	}

	for (i = 0; i < sendmsg->num_sge; i++)
		ib_dma_unmap_single(t->cm_id->device,
				sendmsg->sge[0].addr, sendmsg->sge[0].length,
				DMA_TO_DEVICE);

	if (sendmsg->num_sge > 1) {
		if (atomic_dec_and_test(&t->send_payload_pending))
			wake_up(&t->wait_send_payload_pending);
	} else {
		if (atomic_dec_and_test(&t->send_pending))
			wake_up(&t->wait_send_pending);
	}
	smbd_free_sendmsg(t, sendmsg);
}

static int manage_credits_prior_sending(struct smbd_transport *t)
{
	int new_credits;

	spin_lock(&t->lock_new_recv_credits);
	new_credits = t->new_recv_credits;
	t->new_recv_credits = 0;
	spin_unlock(&t->lock_new_recv_credits);

	return new_credits;
}

static int smbd_create_header(struct smbd_transport *t,
		int size, int remaining_data_length,
		struct smbd_sendmsg **sendmsg_out)
{
	struct smbd_sendmsg *sendmsg;
	struct smbd_data_transfer *packet;
	int header_length;
	int rc;

	/* Wait for send credits. A SMBD packet needs one credit */
	rc = wait_event_interruptible(t->wait_send_queue,
		atomic_read(&t->send_credits) > 0 ||
		t->status != SMBD_CS_CONNECTED);
	if (rc)
		return rc;

	if (t->status != SMBD_CS_CONNECTED) {
		cifsd_err("disconnected not sending\n");
		return -ENOENT;
	}
	atomic_dec(&t->send_credits);

	sendmsg = smbd_alloc_sendmsg(t);
	if (!sendmsg) {
		rc = -ENOMEM;
		goto err;
	}

	/* Fill in the packet header */
	packet = (struct smbd_data_transfer *)sendmsg->packet;
	packet->credits_requested = cpu_to_le16(t->send_credit_target);
	packet->credits_granted = cpu_to_le16(manage_credits_prior_sending(t));

	packet->flags = 0;
	packet->reserved = 0;
	if (!size)
		packet->data_offset = 0;
	else
		packet->data_offset = cpu_to_le32(24);
	packet->data_length = cpu_to_le32(size);
	packet->remaining_data_length = cpu_to_le32(remaining_data_length);
	packet->padding = 0;

	cifsd_debug("credits_requested=%d credits_granted=%d "
		"data_offset=%d data_length=%d remaining_data_length=%d\n",
		le16_to_cpu(packet->credits_requested),
		le16_to_cpu(packet->credits_granted),
		le32_to_cpu(packet->data_offset),
		le32_to_cpu(packet->data_length),
		le32_to_cpu(packet->remaining_data_length));

	/* Map the packet to DMA */
	header_length = sizeof(struct smbd_data_transfer);
	/* If this is a packet without payload, don't send padding */
	if (!size)
		header_length = offsetof(struct smbd_data_transfer, padding);

	sendmsg->num_sge = 1;
	sendmsg->sge[0].addr = ib_dma_map_single(t->cm_id->device,
						 (void *)packet,
						 header_length,
						 DMA_BIDIRECTIONAL);
	if (ib_dma_mapping_error(t->cm_id->device, sendmsg->sge[0].addr)) {
		smbd_free_sendmsg(t, sendmsg);
		rc = -EIO;
		goto err;
	}

	sendmsg->sge[0].length = header_length;
	sendmsg->sge[0].lkey = t->pd->local_dma_lkey;

	*sendmsg_out = sendmsg;
	return 0;

err:
	atomic_inc(&t->send_credits);
	return rc;
}

static int smbd_post_send(struct smbd_transport *t,
			struct smbd_sendmsg *sendmsg, int data_length)
{
	int ret;
	struct ib_send_wr wr;
	int i;

	for (i = 0; i < sendmsg->num_sge; i++)
		ib_dma_sync_single_for_device(t->cm_id->device,
				sendmsg->sge[i].addr, sendmsg->sge[i].length,
				DMA_TO_DEVICE);
	sendmsg->cqe.done = send_done;

	wr.next = NULL;
	wr.wr_cqe = &sendmsg->cqe;
	wr.sg_list = &sendmsg->sge[0];
	wr.num_sge = sendmsg->num_sge;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	if (data_length)
		atomic_inc(&t->send_payload_pending);
	else
		atomic_inc(&t->send_pending);

	ret = ib_post_send(t->qp, &wr, NULL);
	if (ret) {
		cifsd_err("Can't post send: %d\n", ret);
		if (data_length) {
			if (atomic_dec_and_test(&t->send_payload_pending))
				wake_up(&t->wait_send_payload_pending);
		} else {
			if (atomic_dec_and_test(&t->send_pending))
				wake_up(&t->wait_send_pending);
		}
		smbd_disconnect_rdma_connection(t);
	}
	return ret;
}

static int smbd_post_send_data(struct smbd_transport *t, struct kvec *iov,
			int nvecs, int remaining_data_length)
{
	int i, rc;
	struct smbd_sendmsg *sendmsg;
	int data_length;

	if (nvecs > SMBDIRECT_MAX_SGE-1)
		return -ENOMEM;

	data_length = 0;
	for (i = 0; i < nvecs; i++)
		data_length += iov[i].iov_len;

	rc = smbd_create_header(
		t, data_length, remaining_data_length, &sendmsg);
	if (rc)
		return rc;

	for (i = 0; i < nvecs; i++) {
		sendmsg->sge[i+1].addr =
			ib_dma_map_single(t->cm_id->device, iov[i].iov_base,
			       iov[i].iov_len, DMA_BIDIRECTIONAL);
		if (ib_dma_mapping_error(
				t->cm_id->device, sendmsg->sge[i+1].addr)) {
			rc = -EIO;
			sendmsg->sge[i+1].addr = 0;
			goto dma_mapping_failure;
		}
		sendmsg->sge[i+1].length = iov[i].iov_len;
		sendmsg->sge[i+1].lkey = t->pd->local_dma_lkey;
		sendmsg->num_sge++;
	}

	rc = smbd_post_send(t, sendmsg, data_length);
	if (!rc)
		return 0;

dma_mapping_failure:
	for (i = 1; i < sendmsg->num_sge; i++)
		if (sendmsg->sge[i].addr)
			ib_dma_unmap_single(t->cm_id->device,
					    sendmsg->sge[i].addr,
					    sendmsg->sge[i].length,
					    DMA_TO_DEVICE);
	ib_dma_unmap_single(t->cm_id->device,
			    sendmsg->sge[0].addr,
			    sendmsg->sge[0].length,
			    DMA_TO_DEVICE);
	smbd_free_sendmsg(t, sendmsg);
	atomic_inc(&t->send_credits);
	return rc;
}

static int smbd_writev(struct cifsd_transport *t, struct kvec *iov,
			int niovs, int buflen)
{
	struct smbd_transport *st = SMBD_TRANS(t);
	int remaining_data_length;
	int start, i, j;
	int max_iov_size = st->max_send_size -
			sizeof(struct smbd_data_transfer);
	int rc;
	struct kvec vec;
	int nvecs;

	st->smbd_send_pending++;
	if (st->status != SMBD_CS_CONNECTED) {
		rc = -ENODEV;
		goto done;
	}

	// FIXME: SMBD headers are appended per max_iov_size.
	if (buflen + sizeof(struct smbd_data_transfer) >
		st->max_fragmented_send_size) {
		cifsd_err("payload size %d > max size %d\n",
			buflen, st->max_fragmented_send_size);
		rc = -EINVAL;
		goto done;
	}

	//FIXME: skip RFC1002 header..
	buflen -= 4;
	iov[0].iov_base += 4;
	iov[0].iov_len -= 4;

	remaining_data_length = buflen;
	cifsd_debug("Sending smb (RDMA): smb_len=%u\n", buflen);

	start = i = 0;
	buflen = 0;
	while (true) {
		buflen += iov[i].iov_len;
		if (buflen > max_iov_size) {
			if (i > start) {
				remaining_data_length -=
					(buflen-iov[i].iov_len);
				cifsd_debug("sending iov[] from start=%d "
					"i=%d nvecs=%d "
					"remaining_data_length=%d\n",
					start, i, i-start,
					remaining_data_length);
				rc = smbd_post_send_data(
					st, &iov[start], i-start,
					remaining_data_length);
				if (rc)
					goto done;
			} else {
				/* iov[start] is too big, break it */
				nvecs = (buflen+max_iov_size-1)/max_iov_size;
				cifsd_debug("iov[%d] iov_base=%p size=%d"
					" break to %d vectors\n",
					start, iov[start].iov_base,
					buflen, nvecs);
				for (j = 0; j < nvecs; j++) {
					vec.iov_base =
						(char *)iov[start].iov_base +
						j*max_iov_size;
					vec.iov_len = max_iov_size;
					if (j == nvecs-1)
						vec.iov_len =
							buflen -
							max_iov_size*(nvecs-1);
					remaining_data_length -= vec.iov_len;
					cifsd_debug(
						"sending vec j=%d iov_base=%p"
						" iov_len=%zu "
						"remaining_data_length=%d\n",
						j, vec.iov_base, vec.iov_len,
						remaining_data_length);
					rc = smbd_post_send_data(
						st, &vec, 1,
						remaining_data_length);
					if (rc)
						goto done;
				}
				i++;
				if (i == niovs)
					break;
			}
			start = i;
			buflen = 0;
		} else {
			i++;
			if (i == niovs) {
				/* send out all remaining vecs */
				remaining_data_length -= buflen;
				cifsd_debug(
					"sending iov[] from start=%d i=%d "
					"nvecs=%d remaining_data_length=%d\n",
					start, i, i-start,
					remaining_data_length);
				rc = smbd_post_send_data(st, &iov[start],
					i-start, remaining_data_length);
				if (rc)
					goto done;
				break;
			}
		}
		cifsd_debug("looping i=%d buflen=%d\n", i, buflen);
	}

done:
	/*
	 * As an optimization, we don't wait for individual I/O to finish
	 * before sending the next one.
	 * Send them all and wait for pending send count to get to 0
	 * that means all the I/Os have been out and we are good to return
	 */

	wait_event(st->wait_send_payload_pending,
		atomic_read(&st->send_payload_pending) == 0);

	st->smbd_send_pending--;
	wake_up(&st->wait_smbd_send_pending);
	return rc;

}

static void smbd_disconnect(struct cifsd_transport *t)
{
	struct smbd_transport *st = SMBD_TRANS(t);

	cifsd_debug("Disconnecting cm_id=%p\n", st->cm_id);

	smbd_disconnect_rdma_connection(st);
	wait_event_interruptible(st->wait_status,
			st->status == SMBD_CS_DISCONNECTED);
	free_transport(st);
}

static int smbd_cm_handler(struct rdma_cm_id *cm_id,
				struct rdma_cm_event *event)
{
	struct smbd_transport *t = cm_id->context;

	cifsd_debug("RDMA CM event. cm_id=%p event=%s (%d)\n",
			cm_id, rdma_event_msg(event->event), event->event);

	switch (event->event) {
	case RDMA_CM_EVENT_ESTABLISHED: {
		t->status = SMBD_CS_CLIENT_ACCEPTED;
		wake_up_interruptible(&t->wait_status);
		break;
	}
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_DISCONNECTED: {
		t->status = SMBD_CS_DISCONNECTED;
		wake_up_interruptible(&t->wait_status);
		wake_up_interruptible(&t->wait_reassembly_queue);
		wake_up(&t->wait_send_queue);
		break;
	}
	default:
		cifsd_debug("Unexpected RDMA CM event. cm_id=%p, "
				"event=%s (%d)\n", cm_id,
				rdma_event_msg(event->event), event->event);
		break;
	}
	return 0;
}

static void smbd_qpair_handler(struct ib_event *event, void *context)
{
	struct smbd_transport *t = context;

	cifsd_debug("Received QP event. cm_id=%p, event=%s (%d)\n",
			t->cm_id, ib_event_msg(event->event), event->event);

	switch (event->event) {
	case IB_EVENT_CQ_ERR:
	case IB_EVENT_QP_FATAL:
		smbd_disconnect_rdma_connection(t);
		break;
	default:
		break;
	}
}

static int smbd_send_negotiate_response(struct smbd_transport *t, int failed)
{
	struct smbd_sendmsg *sendmsg;
	struct smbd_negotiate_resp *resp;
	int ret;

	sendmsg = smbd_alloc_sendmsg(t);
	if (IS_ERR(sendmsg))
		return -ENOMEM;

	resp = (struct smbd_negotiate_resp *)sendmsg->packet;
	if (failed) {
		memset(resp, 0, sizeof(*resp));
		resp->min_version = cpu_to_le16(0x0100);
		resp->max_version = cpu_to_le16(0x0100);
		resp->status = STATUS_NOT_SUPPORTED;
	} else {
		resp->status = STATUS_SUCCESS;
		resp->min_version = SMBD_VERSION_LE;
		resp->max_version = SMBD_VERSION_LE;
		resp->negotiated_version = SMBD_VERSION_LE;
		resp->reserved = 0;
		resp->credits_requested =
				cpu_to_le16(t->send_credit_target);
		resp->credits_granted = cpu_to_le16(
				manage_credits_prior_sending(t));
		resp->max_readwrite_size = cpu_to_le32(SMBD_MAX_RW_SIZE);
		resp->preferred_send_size = cpu_to_le32(t->max_send_size);
		resp->max_receive_size = cpu_to_le32(t->max_recv_size);
		resp->max_fragmented_size =
				cpu_to_le32(t->max_fragmented_recv_size);
	}

	sendmsg->num_sge = 1;
	sendmsg->sge[0].addr = ib_dma_map_single(t->cm_id->device,
				(void *)resp, sizeof(*resp), DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(t->cm_id->device,
				sendmsg->sge[0].addr);
	if (ret) {
		smbd_free_sendmsg(t, sendmsg);
		return ret;
	}

	sendmsg->sge[0].length = sizeof(*resp);
	sendmsg->sge[0].lkey = t->pd->local_dma_lkey;

	ret = smbd_post_send(t, sendmsg, 0);
	if (ret) {
		ib_dma_unmap_single(t->cm_id->device,
				sendmsg->sge[0].addr, sendmsg->sge[0].length,
				DMA_TO_DEVICE);
		smbd_free_sendmsg(t, sendmsg);
		return ret;
	}

	wait_event(t->wait_send_pending,
			atomic_read(&t->send_pending) == 0);
	return 0;
}

static int smbd_accept_client(struct smbd_transport *t)
{
	struct rdma_conn_param conn_param;
	struct ib_port_immutable port_immutable;
	u32 ird_ord_hdr[2];
	int ret;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.initiator_depth = 0;
	conn_param.responder_resources =
		t->cm_id->device->attrs.max_qp_rd_atom
			< SMBD_CM_RESPONDER_RESOURCES ?
		t->cm_id->device->attrs.max_qp_rd_atom :
		SMBD_CM_RESPONDER_RESOURCES;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	t->cm_id->device->ops.get_port_immutable(t->cm_id->device,
			t->cm_id->port_num, &port_immutable);
#else
	t->cm_id->device->get_port_immutable(t->cm_id->device,
			t->cm_id->port_num, &port_immutable);
#endif
	if (port_immutable.core_cap_flags & RDMA_CORE_PORT_IWARP) {
		ird_ord_hdr[0] = conn_param.responder_resources;
		ird_ord_hdr[1] = 1;
		conn_param.private_data = ird_ord_hdr;
		conn_param.private_data_len = sizeof(ird_ord_hdr);
	} else {
		conn_param.private_data = NULL;
		conn_param.private_data_len = 0;
	}
	conn_param.retry_count = SMBD_CM_RETRY;
	conn_param.rnr_retry_count = SMBD_CM_RNR_RETRY;
	conn_param.flow_control = 0;

	ret = rdma_accept(t->cm_id, &conn_param);
	if (ret)
		return ret;

	wait_event_interruptible(t->wait_status,
				t->status == SMBD_CS_CLIENT_ACCEPTED);
	return 0;
}
static int smbd_negotiate(struct smbd_transport *t)
{
	int ret;
	struct smbd_recvmsg *recvmsg;
	struct smbd_negotiate_req *req;

	recvmsg = get_free_recvmsg(t);
	if (!recvmsg)
		return -ENOMEM;
	recvmsg->type = SMBD_MSG_NEGOTIATE_REQ;

	ret = smbd_post_recv(t, recvmsg);
	if (ret) {
		cifsd_err("Can't post recv: %d\n", ret);
		goto out;
	}

	cifsd_debug("Accept client\n");
	ret = smbd_accept_client(t);
	if (ret) {
		cifsd_err("Can't accept client\n");
		goto out;
	}

	smbd_post_recv_credits(&t->post_recv_credits_work);

	cifsd_debug("Waiting for SMBD negotiate request\n");
	ret = wait_event_interruptible_timeout(t->wait_status,
			t->status == SMBD_CS_NEGOTIATED ||
			t->status == SMBD_CS_DISCONNECTED,
			SMBD_NEGOTIATE_TIMEOUT * HZ);
	if (ret <= 0) {
		ret = ret ?: -ETIMEDOUT;
		goto out;
	}

	ret = smbd_check_recvmsg(recvmsg);
	if (ret == -ECONNABORTED)
		goto out;

	req = (struct smbd_negotiate_req *)recvmsg->packet;
	t->max_recv_size = min_t(int, t->max_recv_size,
			le32_to_cpu(req->preferred_send_size));
	t->max_send_size = min_t(int, t->max_send_size,
			le32_to_cpu(req->max_receive_size));
	t->max_fragmented_send_size =
			le32_to_cpu(req->max_fragmented_size);

	ret = smbd_send_negotiate_response(t, ret);
out:
	if (recvmsg)
		put_recvmsg(t, recvmsg);
	return ret;
}

static int smbd_init_params(struct smbd_transport *t)
{
	struct ib_device *device = t->cm_id->device;

	if (smbd_send_credit_target > device->attrs.max_cqe ||
			smbd_send_credit_target > device->attrs.max_qp_wr) {
		cifsd_err(
			"consider lowering send_credit_target = %d. "
			"Possible CQE overrun, device "
			"reporting max_cpe %d max_qp_wr %d\n",
			smbd_send_credit_target,
			device->attrs.max_cqe,
			device->attrs.max_qp_wr);
		return -EINVAL;
	}

	if (smbd_receive_credit_max > device->attrs.max_cqe ||
	    smbd_receive_credit_max > device->attrs.max_qp_wr) {
		cifsd_err(
			"consider lowering receive_credit_max = %d. "
			"Possible CQE overrun, device "
			"reporting max_cpe %d max_qp_wr %d\n",
			smbd_receive_credit_max,
			device->attrs.max_cqe,
			device->attrs.max_qp_wr);
		return -EINVAL;
	}

	t->recv_credit_max = smbd_receive_credit_max;
	t->recv_credit_target = 10;
	t->new_recv_credits = 0;
	atomic_set(&t->recv_credits, 0);

	t->send_credit_target = smbd_send_credit_target;
	atomic_set(&t->send_credits, 0);

	t->max_send_size = smbd_max_send_size;
	t->max_fragmented_recv_size = smbd_max_fragmented_recv_size;
	t->max_recv_size = smbd_max_receive_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	if (device->attrs.max_send_sge < SMBDIRECT_MAX_SGE) {
		cifsd_err(
			"warning: device max_send_sge = %d too small\n",
			device->attrs.max_send_sge);
		return -EINVAL;
	}
	if (device->attrs.max_recv_sge < SMBDIRECT_MAX_SGE) {
		cifsd_err(
			"warning: device max_recv_sge = %d too small\n",
			device->attrs.max_recv_sge);
		return -EINVAL;
	}
#else
	if (device->attrs.max_sge < SMBDIRECT_MAX_SGE) {
		cifsd_err(
			"warning: device max_sge = %d too small\n",
			device->attrs.max_sge);
		return -EINVAL;
	}
#endif
	return 0;
}

static void smbd_destroy_pools(struct smbd_transport *t)
{
	struct smbd_recvmsg *recvmsg;

	while ((recvmsg = get_free_recvmsg(t)))
		mempool_free(recvmsg, t->recvmsg_mempool);
	while ((recvmsg = get_empty_recvmsg(t)))
		mempool_free(recvmsg, t->recvmsg_mempool);

	mempool_destroy(t->recvmsg_mempool);
	t->recvmsg_mempool = NULL;

	kmem_cache_destroy(t->recvmsg_cache);
	t->recvmsg_cache = NULL;

	mempool_destroy(t->sendmsg_mempool);
	t->sendmsg_mempool = NULL;

	kmem_cache_destroy(t->sendmsg_cache);
	t->sendmsg_cache = NULL;
}

static int smbd_create_pools(struct smbd_transport *t)
{
	char name[80];
	int i;
	struct smbd_recvmsg *recvmsg;

	snprintf(name, sizeof(name), "smbd_rqst_pool_%p", t);
	t->sendmsg_cache = kmem_cache_create(name,
			sizeof(struct smbd_sendmsg) +
			sizeof(struct smbd_negotiate_resp),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (!t->sendmsg_cache)
		return -ENOMEM;

	t->sendmsg_mempool = mempool_create(t->send_credit_target,
			mempool_alloc_slab, mempool_free_slab,
			t->sendmsg_cache);
	if (!t->sendmsg_mempool)
		goto err;

	snprintf(name, sizeof(name), "smbd_resp_%p", t);
	t->recvmsg_cache = kmem_cache_create(name,
			sizeof(struct smbd_recvmsg) +
			t->max_recv_size,
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (!t->recvmsg_cache)
		goto err;

	t->recvmsg_mempool =
		mempool_create(t->recv_credit_max, mempool_alloc_slab,
		       mempool_free_slab, t->recvmsg_cache);
	if (!t->recvmsg_mempool)
		goto err;

	INIT_LIST_HEAD(&t->recvmsg_queue);

	for (i = 0; i < t->recv_credit_max; i++) {
		recvmsg = mempool_alloc(t->recvmsg_mempool, GFP_KERNEL);
		if (!recvmsg)
			goto err;
		recvmsg->transport = t;
		list_add(&recvmsg->list, &t->recvmsg_queue);
		t->count_recvmsg_queue++;
	}

	return 0;
err:
	smbd_destroy_pools(t);
	return -ENOMEM;
}

static int smbd_create_qpair(struct smbd_transport *t)
{
	int ret;
	struct ib_qp_init_attr qp_attr = {
		.cap.max_send_wr	= t->send_credit_target,
		.cap.max_recv_wr	= t->recv_credit_max,
		.cap.max_send_sge	= SMBDIRECT_MAX_SGE,
		.cap.max_recv_sge	= 1,
		.qp_type		= IB_QPT_RC,
		.sq_sig_type		= IB_SIGNAL_REQ_WR,
	};

	t->pd = ib_alloc_pd(t->cm_id->device, 0);
	if (IS_ERR(t->pd)) {
		cifsd_err("Can't create RDMA PD\n");
		ret = PTR_ERR(t->pd);
		t->pd = NULL;
		return ret;
	}

	t->send_cq = ib_alloc_cq(t->cm_id->device, t,
			t->send_credit_target, 0, IB_POLL_SOFTIRQ);
	if (IS_ERR(t->send_cq)) {
		cifsd_err("Can't create RDMA send CQ\n");
		ret = PTR_ERR(t->send_cq);
		t->send_cq = NULL;
		goto err;
	}

	t->recv_cq = ib_alloc_cq(t->cm_id->device, t,
			t->recv_credit_max, 0, IB_POLL_SOFTIRQ);
	if (IS_ERR(t->recv_cq)) {
		cifsd_err("Can't create RDMA recv CQ\n");
		ret = PTR_ERR(t->recv_cq);
		t->recv_cq = NULL;
		goto err;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.event_handler = smbd_qpair_handler;
	qp_attr.qp_context = t;
	qp_attr.cap.max_send_wr = t->send_credit_target;
	qp_attr.cap.max_recv_wr = t->recv_credit_max;
	qp_attr.cap.max_send_sge = SMBDIRECT_MAX_SGE;
	qp_attr.cap.max_recv_sge = SMBDIRECT_MAX_SGE;
	qp_attr.cap.max_inline_data = 0;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = t->send_cq;
	qp_attr.recv_cq = t->recv_cq;
	qp_attr.port_num = ~0;

	ret = rdma_create_qp(t->cm_id, t->pd, &qp_attr);
	if (ret) {
		cifsd_err("Can't create RDMA QP: %d\n", ret);
		goto err;
	}

	t->qp = t->cm_id->qp;
	t->cm_id->event_handler = smbd_cm_handler;

	return 0;
err:
	if (t->qp) {
		ib_destroy_qp(t->qp);
		t->qp = NULL;
	}
	if (t->recv_cq) {
		ib_destroy_cq(t->recv_cq);
		t->recv_cq = NULL;
	}
	if (t->send_cq) {
		ib_destroy_cq(t->send_cq);
		t->send_cq = NULL;
	}
	if (t->pd) {
		ib_dealloc_pd(t->pd);
		t->pd = NULL;
	}
	return ret;
}

static int smbd_prepare(struct cifsd_transport *t)
{
	struct smbd_transport *st = SMBD_TRANS(t);
	int ret;

	ret = smbd_init_params(st);
	if (ret) {
		cifsd_err("Can't configure RDMA parameters\n");
		return ret;
	}

	ret = smbd_create_pools(st);
	if (ret) {
		cifsd_err("Can't init RDMA pool: %d\n", ret);
		return ret;
	}

	ret = smbd_create_qpair(st);
	if (ret) {
		cifsd_err("Can't accept RDMA client: %d\n", ret);
		return ret;
	}

	ret = smbd_negotiate(st);
	if (ret) {
		cifsd_err("Can't negotiate: %d\n", ret);
		return ret;
	}

	st->status = SMBD_CS_CONNECTED;
	return 0;
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
	switch (event->event) {
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

static struct cifsd_transport_ops cifsd_smbd_transport_ops = {
	.prepare	= smbd_prepare,
	.writev		= smbd_writev,
	.read		= smbd_read,
	.disconnect	= smbd_disconnect,
};
