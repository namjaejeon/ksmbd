// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/list.h>
#include <linux/slab.h>

#include "../cifsd_server.h" /* FIXME */
#include "../buffer_pool.h"
#include "../transport_ipc.h"
#include "../transport_tcp.h"

#include "tree_connect.h"
#include "user_config.h"
#include "share_config.h"
#include "user_session.h"

struct cifsd_tree_conn_status
cifsd_tree_conn_connect(struct cifsd_session *sess, char *share_name)
{
	struct cifsd_tree_conn_status status = {-EINVAL, NULL};
	struct cifsd_tree_connect_response *resp = NULL;
	struct cifsd_share_config *sc = NULL;
	struct cifsd_tree_connect *tree_conn = NULL;
	struct sockaddr *peer_addr;

	sc = cifsd_share_config_get(share_name);
	if (!sc)
		return status;

	tree_conn = cifsd_alloc(sizeof(struct cifsd_tree_connect));
	if (!tree_conn) {
		status.ret = -ENOMEM;
		goto out_error;
	}

	tree_conn->id = cifsd_acquire_tree_conn_id(sess);
	if (tree_conn->id < 0) {
		status.ret = -EINVAL;
		goto out_error;
	}

	peer_addr = CIFSD_TCP_PEER_SOCKADDR(sess->conn);
	resp = cifsd_ipc_tree_connect_request(sess,
					      sc,
					      tree_conn,
					      peer_addr);
	if (!resp) {
		status.ret = -EINVAL;
		goto out_error;
	}

	status.ret = resp->status;
	if (status.ret != CIFSD_TREE_CONN_STATUS_OK)
		goto out_error;

	tree_conn->flags = resp->connection_flags;
	tree_conn->user = sess->user;
	tree_conn->share_conf = sc;
	status.tree_conn = tree_conn;

	list_add(&tree_conn->list, &sess->tree_conn_list);

	cifsd_free(resp);
	return status;

out_error:
	if (tree_conn && tree_conn->id >= 0)
		cifsd_release_tree_conn_id(sess, tree_conn->id);
	cifsd_share_config_put(sc);
	cifsd_free(tree_conn);
	cifsd_free(resp);
	return status;
}

int cifsd_tree_conn_disconnect(struct cifsd_session *sess,
			       struct cifsd_tree_connect *tree_conn)
{
	int ret;

	ret = cifsd_ipc_tree_disconnect_request(sess->id, tree_conn->id);
	cifsd_release_tree_conn_id(sess, tree_conn->id);
	list_del(&tree_conn->list);
	cifsd_share_config_put(tree_conn->share_conf);
	cifsd_free(tree_conn);
	return ret;
}

struct cifsd_tree_connect *cifsd_tree_conn_lookup(struct cifsd_session *sess,
						  unsigned int id)
{
	struct cifsd_tree_connect *tree_conn;
	struct list_head *tmp;

	list_for_each(tmp, &sess->tree_conn_list) {
		tree_conn = list_entry(tmp, struct cifsd_tree_connect, list);
		if (tree_conn->id == id)
			return tree_conn;
	}
	return NULL;
}

struct cifsd_share_config *cifsd_tree_conn_share(struct cifsd_session *sess,
						 unsigned int id)
{
	struct cifsd_tree_connect *tc;

	tc = cifsd_tree_conn_lookup(sess, id);
	if (tc)
		return tc->share_conf;
	return NULL;
}

int cifsd_tree_conn_session_logoff(struct cifsd_session *sess)
{
	int ret = 0;

	while (!list_empty(&sess->tree_conn_list)) {
		struct cifsd_tree_connect *tc;

		tc = list_entry(sess->tree_conn_list.next,
				struct cifsd_tree_connect,
				list);
		ret |= cifsd_tree_conn_disconnect(sess, tc);
	}

	return ret;
}
