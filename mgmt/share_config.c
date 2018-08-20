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

#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/parser.h>

#include "share_config.h"
#include "../buffer_pool.h"
#include "../transport_ipc.h"
#include "../cifsd_server.h" /* FIXME */

#define SHARE_HASH_BITS		3
static DEFINE_HASHTABLE(shares_table, SHARE_HASH_BITS);
static DECLARE_RWSEM(shares_table_lock);

struct cifsd_veto_pattern {
	char			*pattern;
	struct list_head	list;
};

static unsigned int share_name_hash(char *name)
{
	return jhash(name, strlen(name), 0);
}

static void kill_share(struct cifsd_share_config *share)
{
	while (!list_empty(&share->veto_list)) {
		struct cifsd_veto_pattern *p;

		p = list_entry(share->veto_list.next,
			       struct cifsd_veto_pattern,
			       list);
		list_del(&p->list);
		kfree(p->pattern);
		kfree(p);
	}

	if (share->path)
		path_put(&share->vfs_path);
	kfree(share->name);
	kfree(share->path);
	kfree(share);
}

static void deferred_share_free(struct work_struct *work)
{
	struct cifsd_share_config *share = container_of(work,
					       struct cifsd_share_config,
					       free_work);

	kill_share(share);
}

void __cifsd_share_config_put(struct cifsd_share_config *share)
{
	down_write(&shares_table_lock);
	hash_del(&share->hlist);
	up_write(&shares_table_lock);

	schedule_work(&share->free_work);
}

static struct cifsd_share_config *
__get_share_config(struct cifsd_share_config *share)
{
	if (!atomic_inc_not_zero(&share->refcount))
		return NULL;
	return share;
}

static struct cifsd_share_config *__share_lookup(char *name)
{
	struct cifsd_share_config *share;
	unsigned int key = share_name_hash(name);

	hash_for_each_possible(shares_table, share, hlist, key) {
		if (!strcmp(name, share->name))
			return share;
	}
	return NULL;
}

static int parse_veto_list(struct cifsd_share_config *share,
			   char *veto_list,
			   int veto_list_sz)
{
	int sz = 0;

	if (!veto_list_sz)
		return 0;

	while (veto_list_sz > 0) {
		struct cifsd_veto_pattern *p;

		p = cifsd_alloc(sizeof(struct cifsd_veto_pattern));
		if (!p)
			return -ENOMEM;

		sz = strlen(veto_list);
		if (!sz)
			break;

		p->pattern = kstrdup(veto_list, GFP_KERNEL);
		if (!p->pattern) {
			cifsd_free(p);
			return -ENOMEM;
		}

		list_add(&p->list, &share->veto_list);

		veto_list += sz + 1;
		veto_list_sz -= (sz + 1);
	}

	return 0;
}

static struct cifsd_share_config *share_config_request(char *name)
{
	struct cifsd_share_config_response *resp;
	struct cifsd_share_config *share = NULL;
	struct cifsd_share_config *lookup;
	int ret;

	resp = cifsd_ipc_share_config_request(name);
	if (!resp)
		return NULL;

	if (resp->flags == CIFSD_SHARE_FLAG_INVALID)
		goto out;

	share = cifsd_alloc(sizeof(struct cifsd_share_config));
	if (!share)
		goto out;

	share->flags = resp->flags;
	atomic_set(&share->refcount, 1);
	INIT_WORK(&share->free_work, deferred_share_free);
	INIT_LIST_HEAD(&share->veto_list);
	share->name = kstrdup(name, GFP_KERNEL);

	if (!test_share_config_flag(share, CIFSD_SHARE_FLAG_PIPE)) {
		share->path = kstrdup(CIFSD_SHARE_CONFIG_PATH(resp),
				      GFP_KERNEL);
		ret = parse_veto_list(share,
				      CIFSD_SHARE_CONFIG_VETO_LIST(resp),
				      resp->veto_list_sz);
		if (!ret && share->path) {
			ret = kern_path(share->path, 0, &share->vfs_path);
			if (ret) {
				/* Avoid put_path() */
				kfree(share->path);
				share->path = NULL;
			}
		}
		if (ret || !share->name) {
			kill_share(share);
			share = NULL;
			goto out;
		}
	}

	down_write(&shares_table_lock);
	lookup = __share_lookup(name);
	if (lookup)
		lookup = __get_share_config(lookup);
	if (!lookup) {
		hash_add(shares_table, &share->hlist, share_name_hash(name));
	} else {
		kill_share(share);
		share = lookup;
	}
	up_write(&shares_table_lock);

out:
	cifsd_free(resp);
	return share;
}

struct cifsd_share_config *cifsd_share_config_get(char *name)
{
	struct cifsd_share_config *share;

	down_read(&shares_table_lock);
	share = __share_lookup(name);
	if (share)
		share = __get_share_config(share);
	up_read(&shares_table_lock);

	if (share)
		return share;
	return share_config_request(name);
}

bool cifsd_share_veto_filename(struct cifsd_share_config *share,
			       const char *filename)
{
	struct cifsd_veto_pattern *p;

	list_for_each_entry(p, &share->veto_list, list) {
		if (match_wildcard(p->pattern, filename))
			return true;
	}
	return false;
}

void cifsd_share_configs_cleanup(void)
{
	struct cifsd_share_config *share;
	struct hlist_node *tmp;
	int i;

	down_write(&shares_table_lock);
	hash_for_each_safe(shares_table, i, tmp, share, hlist) {
		hash_del(&share->hlist);
		kill_share(share);
	}
	up_write(&shares_table_lock);
}
