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

static int smbd_listen(int port)
{
	int ret;
	struct rdma_cm_id *cm_id;
	struct sockaddr_in sin = {
		.sin_family		= AF_INET,
		.sin_addr.s_addr	= htonl(INADDR_ANY),
		.sin_port		= htons(port),
	};

	cm_id = rdma_create_id(&init_net, NULL, &smbd_listener,
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
