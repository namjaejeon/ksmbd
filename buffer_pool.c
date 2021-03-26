// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rwlock.h>

#include "glob.h"
#include "buffer_pool.h"
#include "connection.h"
#include "mgmt/ksmbd_ida.h"

static struct kmem_cache *filp_cache;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
/*
 * A simple kvmalloc()/kvfree() implementation.
 */
static inline void *__alloc(size_t size, gfp_t flags)
{
	gfp_t kmalloc_flags = flags;
	void *ret;

	/*
	 * We want to attempt a large physically contiguous block first because
	 * it is less likely to fragment multiple larger blocks and therefore
	 * contribute to a long term fragmentation less than vmalloc fallback.
	 * However make sure that larger requests are not too disruptive - no
	 * OOM killer and no allocation failure warnings as we have a fallback.
	 */
	if (size > PAGE_SIZE)
		kmalloc_flags |= __GFP_NOWARN | __GFP_NORETRY;

	ret = kmalloc(size, kmalloc_flags);

	/*
	 * It doesn't really make sense to fallback to vmalloc for sub page
	 * requests
	 */
	if (ret || size <= PAGE_SIZE)
		return ret;

	return __vmalloc(size, flags, PAGE_KERNEL);
}

static inline void __free(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

void *ksmbd_alloc(size_t size)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	return __alloc(size, GFP_KERNEL | __GFP_ZERO);
#else
	return kvmalloc(size, GFP_KERNEL | __GFP_ZERO);
#endif
}

void ksmbd_free(void *ptr)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	__free(ptr);
#else
	kvfree(ptr);
#endif
}

void ksmbd_free_request(void *addr)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	__free(addr);
#else
	kvfree(addr);
#endif
}

void *ksmbd_alloc_request(size_t size)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	return __alloc(size, GFP_KERNEL);
#else
	return kvmalloc(size, GFP_KERNEL);
#endif
}

void ksmbd_free_response(void *buffer)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	__free(buffer);
#else
	kvfree(buffer);
#endif
}

void *ksmbd_alloc_response(size_t size)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	return __alloc(size, GFP_KERNEL | __GFP_ZERO);
#else
	return kvmalloc(size, GFP_KERNEL | __GFP_ZERO);
#endif
}

void *ksmbd_realloc_response(void *ptr, size_t old_sz, size_t new_sz)
{
	size_t sz = min(old_sz, new_sz);
	void *nptr;

	nptr = ksmbd_alloc_response(new_sz);
	if (!nptr)
		return ptr;
	memcpy(nptr, ptr, sz);
	ksmbd_free_response(ptr);
	return nptr;
}

void ksmbd_free_file_struct(void *filp)
{
	kmem_cache_free(filp_cache, filp);
}

void *ksmbd_alloc_file_struct(void)
{
	return kmem_cache_zalloc(filp_cache, GFP_KERNEL);
}

void ksmbd_destroy_buffer_pools(void)
{
	ksmbd_work_pool_destroy();
	kmem_cache_destroy(filp_cache);
}

int ksmbd_init_buffer_pools(void)
{
	if (ksmbd_work_pool_init())
		goto out;

	filp_cache = kmem_cache_create("ksmbd_file_cache",
					sizeof(struct ksmbd_file), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (!filp_cache)
		goto out;

	return 0;

out:
	ksmbd_err("failed to allocate memory\n");
	ksmbd_destroy_buffer_pools();
	return -ENOMEM;
}
