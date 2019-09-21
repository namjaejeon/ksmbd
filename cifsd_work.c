// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "server.h"
#include "connection.h"
#include "cifsd_work.h"
#include "buffer_pool.h"
#include "mgmt/cifsd_ida.h"

/* @FIXME */
#include "cifsd_server.h"

static struct kmem_cache *work_cache;
static struct workqueue_struct *cifsd_wq;

struct cifsd_work *cifsd_alloc_work_struct(void)
{
	struct cifsd_work *work = kmem_cache_zalloc(work_cache, GFP_KERNEL);

	if (work) {
		INIT_LIST_HEAD(&work->request_entry);
		INIT_LIST_HEAD(&work->async_request_entry);
		INIT_LIST_HEAD(&work->fp_entry);
		INIT_LIST_HEAD(&work->interim_entry);
	}
	return work;
}

void cifsd_free_work_struct(struct cifsd_work *work)
{
	if (server_conf.flags & CIFSD_GLOBAL_FLAG_CACHE_TBUF)
		cifsd_release_buffer(RESPONSE_BUF(work));
	else
		cifsd_free_response(RESPONSE_BUF(work));

	if (server_conf.flags & CIFSD_GLOBAL_FLAG_CACHE_RBUF)
		cifsd_release_buffer(AUX_PAYLOAD(work));
	else
		cifsd_free_response(AUX_PAYLOAD(work));

	cifsd_free_response(TRANSFORM_BUF(work));
	cifsd_free_request(REQUEST_BUF(work));
	if (work->async_id)
		cifds_release_id(work->conn->async_ida, work->async_id);
	kmem_cache_free(work_cache, work);
}

void cifsd_work_pool_destroy(void)
{
	kmem_cache_destroy(work_cache);
}

int cifsd_work_pool_init(void)
{
	work_cache = kmem_cache_create("cifsd_work_cache",
					sizeof(struct cifsd_work), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (!work_cache)
		return -EINVAL;
	return 0;
}

int cifsd_workqueue_init(void)
{
	cifsd_wq = alloc_workqueue("kcifsd-io", 0, 0);
	if (!cifsd_wq)
		return -EINVAL;
	return 0;
}

void cifsd_workqueue_destroy(void)
{
	flush_workqueue(cifsd_wq);
	destroy_workqueue(cifsd_wq);
	cifsd_wq = NULL;
}

bool cifsd_queue_work(struct cifsd_work *work)
{
	return queue_work(cifsd_wq, &work->work);
}
