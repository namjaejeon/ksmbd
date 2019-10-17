/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 */

#ifndef __CIFSD_TRANSPORT_SMBD_H__
#define __CIFSD_TRANSPORT_SMBD_H__

#define SMBD_PORT	5445

/* SMBD negotiation request packet [MS-SMBD] 2.2.1 */
struct smbd_negotiate_req {
	__le16 min_version;
	__le16 max_version;
	__le16 reserved;
	__le16 credits_requested;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

/* SMBD negotiation response packet [MS-SMBD] 2.2.2 */
struct smbd_negotiate_resp {
	__le16 min_version;
	__le16 max_version;
	__le16 negotiated_version;
	__le16 reserved;
	__le16 credits_requested;
	__le16 credits_granted;
	__le32 status;
	__le32 max_readwrite_size;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

#define SMB_DIRECT_RESPONSE_REQUESTED 0x0001

/* SMBD data transfer packet with payload [MS-SMBD] 2.2.3 */
struct smbd_data_transfer {
	__le16 credits_requested;
	__le16 credits_granted;
	__le16 flags;
	__le16 reserved;
	__le32 remaining_data_length;
	__le32 data_offset;
	__le32 data_length;
	__le32 padding;
	__u8 buffer[];
} __packed;

#ifdef CONFIG_CIFS_SERVER_SMBDIRECT
int cifsd_smbd_init(void);
int cifsd_smbd_destroy(void);
#else
static inline int cifsd_smbd_init(void) { return 0; }
static inline int cifsd_smbd_destroy(void) { return 0; }
#endif

#endif /* __CIFSD_TRANSPORT_SMBD_H__ */
