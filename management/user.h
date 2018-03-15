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

#ifndef __USER_MANAGEMENT_H__
#define __USER_MANAGEMENT_H__

#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>

#define UF_GUEST_ACCOUNT	(1 << 0)
#define UF_PENDING_REMOVAL	(1 << 1)

struct cifsd_user {
	char			*name;
	/* Max size CIFS_NTHASH_SIZE */
	char			*passkey;

	kuid_t			uid;
	kgid_t			gid;

	refcount_t		refcount;
	struct hlist_node	hlist;
	struct work_struct	free_work;

	unsigned short		smb1_vuid;
	unsigned short		flags;
};

extern void __put_cifsd_user(struct cifsd_user *user);

static inline void put_cifsd_user(struct cifsd_user *user)
{
	if (!refcount_dec_and_test(&user->refcount))
		return;
	__put_cifsd_user(user);
}

static inline struct cifsd_user *get_cifsd_user(struct cifsd_user *user)
{
	if (!refcount_inc_not_zero(&user->refcount))
		return NULL;
	return user;
}

static inline bool user_guest(struct cifsd_user *user)
{
	return user->flags & UF_GUEST_ACCOUNT;
}

static inline void set_user_guest(struct cifsd_user *user)
{
	user->flags |= UF_GUEST_ACCOUNT;
	user->smb1_vuid = 0;
}

static inline unsigned short user_smb1_vuid(struct cifsd_user *user)
{
	return user->smb1_vuid;
}

static inline char *user_passkey(struct cifsd_user *user)
{
	return user->passkey;
}

static inline char *user_name(struct cifsd_user *user)
{
	return user->name;
}

static inline kuid_t user_uid(struct cifsd_user *user)
{
	return user->uid;
}

static inline kgid_t user_gid(struct cifsd_user *user)
{
	return user->gid;
}

struct cifsd_user *um_user_search(char *name);
struct cifsd_user *um_user_search_guest(void);
int um_add_new_user(char *name, char *pass, kuid_t uid, kgid_t gid);
int um_delete_user(char *name);
void um_cleanup_users(void);
size_t um_users_show(char *buf, size_t sz);

#endif /* __USER_MANAGEMENT_H__ */
