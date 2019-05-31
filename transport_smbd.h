#ifndef __CIFSD_TRANSPORT_RDMA_H_
#define __CIFSD_TRANSPORT_RDMA_H_

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

#endif
