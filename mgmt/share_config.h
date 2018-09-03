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

#ifndef __SHARE_CONFIG_MANAGEMENT_H__
#define __SHARE_CONFIG_MANAGEMENT_H__

#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <linux/path.h>

#include "../glob.h"  /* FIXME */

struct cifsd_share_config {
	char			*name;
	char			*path;

	unsigned int		flags;
	struct list_head	veto_list;

	struct path		vfs_path;

	atomic_t		refcount;
	struct hlist_node	hlist;
	struct work_struct	free_work;
};

static inline int test_share_config_flag(struct cifsd_share_config *share,
					 int flag)
{
	return share->flags & flag;
}

extern void __cifsd_share_config_put(struct cifsd_share_config *share);

static inline void cifsd_share_config_put(struct cifsd_share_config *share)
{
	if (!atomic_dec_and_test(&share->refcount))
		return;
	__cifsd_share_config_put(share);
}

struct cifsd_share_config *cifsd_share_config_get(char *name);
bool cifsd_share_veto_filename(struct cifsd_share_config *share,
			       const char *filename);
void cifsd_share_configs_cleanup(void);

#endif /* __SHARE_CONFIG_MANAGEMENT_H__ */
