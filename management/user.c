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

#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/rwsem.h>

#include "user.h"

static unsigned short global_smb1_vuids;
static DEFINE_SPINLOCK(global_vuids_lock);

#define USERS_HASH_BITS		3
static DEFINE_HASHTABLE(users_table, USERS_HASH_BITS);
static DECLARE_RWSEM(users_table_lock);

static unsigned short get_next_vuid(void)
{
	unsigned short v;

	spin_lock(&global_vuids_lock);
	v = global_smb1_vuids++;
	spin_unlock(&global_vuids_lock);
	return v;
}

static unsigned int um_hash(char *name)
{
	return jhash(name, strlen(name), 0);
}

static void um_kill_user(struct cifsd_user *user)
{
	kfree(user);
}

static void deferred_user_free(struct work_struct *work)
{
	struct cifsd_user *user = container_of(work,
					       struct cifsd_user,
					       free_work);

	down_write(&users_table_lock);
	hash_del(&user->hlist);
	up_write(&users_table_lock);
	um_kill_user(user);
}

void __put_cifsd_user(struct cifsd_user *user)
{
	schedule_work(&user->free_work);
}

static struct cifsd_user *__um_user_search(char *name)
{
	struct cifsd_user *user;
	unsigned int key = um_hash(name);

	hash_for_each_possible(users_table, user, hlist, key) {
		if (!strcmp(name, user->name))
			return user;
	}
	return NULL;
}

struct cifsd_user *um_user_search(char *name)
{
	struct cifsd_user *user, *ret = NULL;

	down_read(&users_table_lock);
	user = __um_user_search(name);
	/*
	 * Check that we can get user struct. get_cifsd_user()
	 * will return NULL if cifsd_user is going to be freed
	 * soon.
	 */
	if (user)
		ret = get_cifsd_user(user);
	up_read(&users_table_lock);
	return ret;
}

struct cifsd_user *um_user_search_guest(void)
{
	struct cifsd_user *user, *ret = NULL;
	int i;

	down_read(&users_table_lock);
	hash_for_each(users_table, i, user, hlist) {
		if (user_guest(user)) {
			ret = get_cifsd_user(user);
			if (ret)
				break;
		}
	}
	up_read(&users_table_lock);
	return ret;
}

static void __um_add_new_user(struct cifsd_user *user,
			      char *name,
			      char *pass,
			      kuid_t uid,
			      kgid_t gid)
{
	user->name = name;
	user->passkey = pass;
	user->uid.val = uid.val;
	user->gid.val = gid.val;

	user->smb1_vuid = get_next_vuid();
	refcount_set(&user->refcount, 1);

	INIT_WORK(&user->free_work, deferred_user_free);
	hash_add(users_table, &user->hlist, um_hash(name));
}

int um_add_new_user(char *name, char *pass, kuid_t uid, kgid_t gid)
{
	struct cifsd_user *user;

	/* GFP_KERNEL allocation, pre-allocate user out of users_table_lock */
	user = kzalloc(sizeof(struct cifsd_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	down_write(&users_table_lock);
	if (__um_user_search(name)) {
		up_write(&users_table_lock);
		um_kill_user(user);
		return -EEXIST;
	}

	__um_add_new_user(user, name, pass, uid, gid);
	up_write(&users_table_lock);
	return 0;
}

int um_delete_user(char *name)
{
	struct cifsd_user *user;
	int ret = -EINVAL;

	down_write(&users_table_lock);
	user = __um_user_search(name);
	if (user && !(user->flags & UF_PENDING_REMOVAL)) {
		user->flags |= UF_PENDING_REMOVAL;
		put_cifsd_user(user);
		ret = 0;
	}
	up_write(&users_table_lock);
	return ret;
}

void um_cleanup_users(void)
{
	struct cifsd_user *user;
	struct hlist_node *tmp;
	int i;

	down_write(&users_table_lock);
	hash_for_each_safe(users_table, i, tmp, user, hlist) {
		hash_del(&user->hlist);
		kfree(user);
	}
	up_write(&users_table_lock);
}

size_t um_users_show(char *buf, size_t sz)
{
	/* Not supported */
	return 0;
}
