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

#include "user_config.h"
#include "../buffer_pool.h"
#include "../transport_ipc.h"
#include "../cifsd_server.h" /* FIXME */

struct cifsd_user *cifsd_alloc_user(const char *account)
{
	struct cifsd_login_response *resp;
	struct cifsd_user *user = NULL;

	resp = cifsd_ipc_login_request(account);
	if (!resp)
		return NULL;

	if (!(resp->status & CIFSD_USER_FLAG_OK))
		goto out;

	user = cifsd_alloc(sizeof(struct cifsd_user));
	if (!user)
		goto out;

	user->name = kstrdup(resp->account, GFP_KERNEL);
	user->flags = resp->status;
	user->gid = resp->gid;
	user->uid = resp->uid;
	user->passkey_sz = resp->hash_sz;
	user->passkey = cifsd_alloc(resp->hash_sz);
	if (user->passkey)
		memcpy(user->passkey, resp->hash, resp->hash_sz);

	if (!user->name || !user->passkey) {
		kfree(user->name);
		cifsd_free(user->passkey);
		cifsd_free(user);
		user = NULL;
	}
out:
	cifsd_free(resp);
	return user;
}

void cifsd_free_user(struct cifsd_user *user)
{
	cifsd_ipc_logout_request(user->name);
	kfree(user->name);
	cifsd_free(user->passkey);
	cifsd_free(user);
}
