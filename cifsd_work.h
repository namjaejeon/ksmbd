// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_WORK_H__
#define __CIFSD_WORK_H__

#include <linux/ctype.h>
#include <linux/workqueue.h>

#define	WORK_STATE_CANCELLED	0x2
#define WORK_STATE_CLOSED	0x3

struct cifsd_conn;
struct cifsd_session;
struct cifsd_tree_connect;

/* one of these for every pending CIFS request at the connection */
struct cifsd_work {
	/* Server corresponding to this mid */
	struct cifsd_conn		*conn;
	struct cifsd_session		*sess;
	struct cifsd_tree_connect	*tcon;

	/* Pointer to received SMB header */
	char				*request_buf;
	/* Response buffer */
	char				*response_buf;
	unsigned int			response_sz;

	/* Read data buffer */
	char				*aux_payload_buf;
	/* Read data count */
	unsigned int			aux_payload_sz;
	/* response smb header size */
	unsigned int			resp_hdr_sz;

	/* Next cmd hdr in compound req buf*/
	int				next_smb2_rcv_hdr_off;
	/* Next cmd hdr in compound rsp buf*/
	int				next_smb2_rsp_hdr_off;

	/* Transform header buffer */
	void				*tr_buf;

	/*
	 * Current Local FID assigned compound response if SMB2 CREATE
	 * command is present in compound request
	 */
	unsigned int			compound_fid;
	unsigned int			compound_pfid;
	unsigned int			compound_sid;

	int				state;

	/* Multiple responses for one request e.g. SMB ECHO */
	bool				multiRsp:1;
	/* No response for cancelled request */
	bool				send_no_response:1;
	/* Request is encrypted */
	bool				encrypted:1;
	/* Is this SYNC or ASYNC cifsd_work */
	bool				syncronous:1;
	/* List head at conn->requests */
	struct list_head		request_entry;
	/* List head at conn->async_requests */
	struct list_head		async_request_entry;
	struct work_struct		work;

	/* cancel works */
	int				async_id;
	void				**cancel_argv;
	void				(*cancel_fn)(void **argv);
	struct list_head		fp_entry;
	struct list_head		interim_entry;
};

#define RESPONSE_BUF(w)		(void *)((w)->response_buf)
#define RESPONSE_SZ(w)		((w)->response_sz)

#define REQUEST_BUF(w)		(void *)((w)->request_buf)

#define INIT_AUX_PAYLOAD(w)	((w)->aux_payload_buf = NULL)
#define HAS_AUX_PAYLOAD(w)	((w)->aux_payload_sz != 0)
#define AUX_PAYLOAD(w)		(void *)((w)->aux_payload_buf)
#define AUX_PAYLOAD_SIZE(w)	((w)->aux_payload_sz)
#define RESP_HDR_SIZE(w)	((w)->resp_hdr_sz)

#define HAS_TRANSFORM_BUF(w)	((w)->tr_buf != NULL)
#define TRANSFORM_BUF(w)	(void *)((w)->tr_buf)

struct cifsd_work *cifsd_alloc_work_struct(void);
void cifsd_free_work_struct(struct cifsd_work *work);

void cifsd_work_pool_destroy(void);
int cifsd_work_pool_init(void);

#endif /* __CIFSD_WORK_H__ */
