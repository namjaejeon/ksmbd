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

#ifndef __TREE_CONNECT_MANAGEMENT_H__
#define __TREE_CONNECT_MANAGEMENT_H__

#include <linux/hashtable.h>

#include "../cifsd_server.h" /* FIXME */

struct cifsd_share_config;
struct cifsd_user;

struct cifsd_tree_connect {
	int				id;

	unsigned int			flags;
	struct cifsd_share_config	*share_conf;
	struct cifsd_user		*user;

	struct list_head		list;

	int				maximal_access;
};

struct cifsd_tree_conn_status {
	unsigned int			ret;
	struct cifsd_tree_connect	*tree_conn;
};

static inline int test_tree_conn_flag(struct cifsd_tree_connect *tree_conn,
				      int flag)
{
	return tree_conn->flags & flag;
}

struct cifsd_session;

struct cifsd_tree_conn_status
cifsd_tree_conn_connect(struct cifsd_session *sess, char *share_name);

int cifsd_tree_conn_disconnect(struct cifsd_session *sess,
			       struct cifsd_tree_connect *tree_conn);

struct cifsd_tree_connect *cifsd_tree_conn_lookup(struct cifsd_session *sess,
						  unsigned int id);

struct cifsd_share_config *cifsd_tree_conn_share(struct cifsd_session *sess,
						 unsigned int id);

int cifsd_tree_conn_session_logoff(struct cifsd_session *sess);

#endif /* __TREE_CONNECT_MANAGEMENT_H__ */
