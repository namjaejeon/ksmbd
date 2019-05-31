// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 */

#ifndef __CIFSD_TRANSPORT_SMBD_H__
#define __CIFSD_TRANSPORT_SMBD_H__

#define SMBD_PORT	5445

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

#ifdef CONFIG_CIFSD_SMBDIRECT
extern int cifsd_smbd_init(void);
extern int cifsd_smbd_destroy(void);
#else
int cifsd_smbd_init(void) { return 0; }
int cifsd_smbd_destroy(void) { return 0; }
#endif

#endif /* __CIFSD_TRANSPORT_SMBD_H__ */
