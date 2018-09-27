// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "cifsd_ida.h"

struct cifsd_ida *cifsd_ida_alloc(void)
{
	struct cifsd_ida *ida;

	ida = kmalloc(sizeof(struct cifsd_ida), GFP_KERNEL);
	if (!ida)
		return NULL;

	ida_init(&ida->map);
	return ida;
}

void cifsd_ida_free(struct cifsd_ida *ida)
{
	ida_destroy(&ida->map);
	kfree(ida);
}

static inline int __acquire_id(struct cifsd_ida *ida, int from, int to)
{
	return ida_simple_get(&ida->map, from, to, GFP_KERNEL);
}

int cifds_acquire_smb1_tid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0, 0xFFFF);
}

int cifds_acquire_smb2_tid(struct cifsd_ida *ida)
{
	int id;

	do {
		id = __acquire_id(ida, 0, 0);
	} while (id == 0xFFFF);

	return id;
}

int cifds_acquire_smb1_uid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 1, 0xFFFE);
}

int cifds_acquire_smb2_uid(struct cifsd_ida *ida)
{
	int id;

	do {
		id = __acquire_id(ida, 1, 0);
	} while (id == 0xFFFE);

	return id;
}

int cifds_acquire_async_msg_id(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 1, 0);
}

int cifds_acquire_id(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0, 0);
}

void cifds_release_id(struct cifsd_ida *ida, int id)
{
	ida_simple_remove(&ida->map, id);
}
