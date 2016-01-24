/*
 *   fs/cifssrv/dcerpc.h
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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

#ifndef __CIFSSRV_DCERPC_H
#define __CIFSSRV_DCERPC_H

#include"glob.h"
#include"ntlmssp.h"
/* these are win32 error codes. There are only a few places where
 *    these matter for Samba, primarily in the NT printing code */
#define WERR_OK			0x00000000
#define WERR_BAD_FILE		0x00000002
#define WERR_ACCESS_DENIED	0x00000005
#define WERR_INVALID_NAME	0x0000007B

/* DCE/RPC packet types */

enum RPC_PKT_TYPE {
	RPC_REQUEST	= 0x00,    /* Ordinary request. */
	RPC_PING	= 0x01,
	RPC_RESPONSE	= 0x02,    /* Ordinary reply. */
	RPC_FAULT	= 0x03,
	RPC_WORKING	= 0x04,
	RPC_NOCALL	= 0x05,
	RPC_REJECT	= 0x06,
	RPC_ACK		= 0x07,
	RPC_CL_CANCEL	= 0x08,
	RPC_FACK	= 0x09,
	RPC_CANCEL_ACK	= 0x0A,
	RPC_BIND	= 0x0B,    /* Bind to interface. */
	RPC_BINDACK	= 0x0C,    /* Server ack of bind. */
	RPC_BINDNACK	= 0x0D,
	RPC_ALTCONT	= 0x0E,
	RPC_ALTCONTRESP	= 0x0F,
	RPC_AUTH3	= 0x10,
	RPC_SHUTDOWN	= 0x11,
	RPC_CO_CANCEL	= 0x12,
	RPC_ORPHANED	= 0x13
};

/* SRVSVC pipe packet types*/

#define SRV_NET_SHARE_ENUM_ALL     0x0f
#define SRV_NET_SHARE_GETINFO     0x10

/* WKSSVC pipe packet type */
#define WKSSVC_NET_SHARE_GETINFO	0x00
/* LANMAN pipe packet types*/

#define RAP_NetshareEnum	0
#define RAP_WkstaGetInfo       63

/* Shares type */
#define STYPE_DISKTREE 0
#define STYPE_PRINTQ 1
#define STYPE_DEVICE 2
#define STYPE_IPC 3
#define STYPE_HIDDEN    (0x80000000)
#define STYPE_IPC_HIDDEN (STYPE_IPC|STYPE_HIDDEN)

/* Info Level Values*/

#define INFO_1		1
#define INFO_10		10
#define INFO_100	100

/* RPC_HDR - dce rpc header */
typedef struct rpc_hdr_info {
	__u8  major; /* 5 - RPC major version */
	__u8  minor; /* 0 - RPC minor version */
	__u8  pkt_type; /* RPC_PKT_TYPE - RPC response packet */
	__u8  flags; /* DCE/RPC flags */
	__u8  pack_type[4]; /* 0x1000 0000 - little-endian packed data */
	__u16 frag_len; /* frag len - data size (bytes) inc header and tail. */
	__u16 auth_len; /* 0 - authentication length  */
	__u32 call_id; /* call identifier */
} __attribute__((packed)) RPC_HDR;

struct GUID {
	__u32 time_low;
	__u16 time_mid;
	__u16 time_hi_and_version;
	__u8  clock_seq[2];
	__u8  node[6];
};

/* RPC interface */
typedef struct rpc_iface_info {
	struct GUID uuid;  /* 16 bytes of rpc interface identification */
	__u16 version_maj;    /* the interface version number */
	__u16 version_min;
} __attribute__((packed)) RPC_IFACE;

typedef struct rpc_context {
	__u16		context_id;
	__u8		num_transfer_syntaxes;
	__u8		reserved;
	RPC_IFACE	abstract;
} __attribute__((packed))  RPC_CONTEXT;

typedef struct rpc_bind_req {
	RPC_HDR hdr;
	__u16  max_tsize;
	__u16  max_rsize;
	__u32  assoc_gid;
	__u8   num_contexts;
	__u8   reserved1;
	__u16  reserved2;
} __attribute__((packed)) RPC_BIND_REQ;

typedef struct auth_info {
	__u8   auth_type;
	__u8   auth_level;
	__u8   auth_pad_len;
	__u8   auth_reserved;
	__u32  auth_ctx_id;
} __attribute__((packed)) RPC_AUTH_INFO;

/* Request RPC  */
typedef struct rpc_request_req {
	RPC_HDR hdr;
	__u32 alloc_hint;   /* allocation hint */
	__u16 context_id;   /* presentation context identifier */
	__u16  opnum;       /* opnum */
} __attribute__((packed)) RPC_REQUEST_REQ;

/* Request RPC response */
typedef struct rpc_request_rsp {
	RPC_HDR hdr;
	__u32 alloc_hint;
	__u16 context_id;
	__u8 cancel_count;
	__u8 reserved;
} __attribute__((packed)) RPC_REQUEST_RSP;

typedef struct rpc_addr_info {
	__u16	sec_addr_len;
	char	*sec_addr;
} RPC_ADDR_INFO;

typedef struct rpc_results_info {
	__u8 num_results; /* the number of results (0x01) */
	__u8 reserved1;
	__u16 reserved2;
	__u16 result; /* result (0x00 = accept) */
	__u16 reason; /* reason (0x00 = no reason specified) */
} __attribute__((packed)) RPC_RESULTS;

typedef struct bind_ack_info {
	__u16  max_tsize;
	__u16  max_rsize;
	__u32  assoc_gid;
} __attribute__((packed)) BIND_ACK_INFO;

typedef struct rpc_bind_rsp {
	RPC_HDR hdr;
	BIND_ACK_INFO bind_info;
	RPC_ADDR_INFO addr;
	RPC_RESULTS results;
	RPC_IFACE *transfer;
	RPC_AUTH_INFO auth;
	__u32 BufferLength;
	__u8 *Buffer;
} RPC_BIND_RSP;

/* SRVSVC structures */

typedef struct unistr_info {
	__u32 max_count;
	__u32 offset;
	__u32 actual_count;
} __attribute__((packed)) UNISTR_INFO;

typedef struct server_handle {
	__u32 ref_id;
	UNISTR_INFO handle_info;
} __attribute__((packed)) SERVER_HANDLE;

typedef struct srvsvc_req {
	SERVER_HANDLE server_unc_handle;
	char  *server_unc; /* unicode */
	__u32 info_level;
} SRVSVC_REQ;

typedef struct srvsvc_share_ptr_info1 {
	__u32 ptr_netname; /* pointer to net name. */
	__u32 type; /* ipc, print, disk ... */
	__u32 ptr_remark; /* pointer to comment. */
} __attribute__((packed)) PTR_INFO1;

typedef struct srvsvc_share_info1 {
	UNISTR_INFO str_info1;
	char sharename[256];
	UNISTR_INFO str_info2;
	char comment[256];
} SRVSVC_SHARE_INFO1;

typedef struct srvsvc_share_common_info {
	__u32 info_level;
	__u32 switch_value;
	__u32 ptr_share_info;

	__u32 num_entries;
	__u32 ptr_entries;
	__u32 num_entries2;
} __attribute__((packed)) SRVSVC_SHARE_COMMON_INFO;

typedef struct srvsvc_share_info_ctr {
	RPC_REQUEST_RSP rpc_request_rsp;
	SRVSVC_SHARE_COMMON_INFO info;

	PTR_INFO1 *ptrs;
	SRVSVC_SHARE_INFO1 *shares;
	__u32 total_entries;
	__u32 resume_handle;
	__u32 status;
} SRVSVC_SHARE_INFO_CTR;

typedef struct srvsvc_share_getinfo {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32 info_level;
	__u32 switch_value;
	__u32 ptr_share_info;

	PTR_INFO1 *ptrs;

	SRVSVC_SHARE_INFO1 *shares;
	__u32 status;
} SRVSVC_SHARE_GETINFO;

typedef struct wkssvc_share_info1 {
	UNISTR_INFO str_info1;
	char server_name[256];
	UNISTR_INFO str_info2;
	char domain_name[256];
} WKSSVC_SHARE_INFO1;


typedef struct wkssvc_share_getinfo {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32 info_level;
	__u32 refid;
	__u32 platform_id;
	__u32 ref_id1;
	__u32 ref_id2;
	__u32 maj;
	__u32 min;
	WKSSVC_SHARE_INFO1 *shares;
	__u32 status;
} WKSSVC_SHARE_GETINFO;

/* LANMAN PIPE STRUCTURES */

typedef struct lanman_params {
	__u16 InfoLevel;
	__u16 ReceiveBufferSize;
} __attribute__((packed)) LANMAN_PARAMS;

typedef struct lanman_req {
	__u16 RAPOpcode;
	__u8  ParamDesc[1];
} __attribute__((packed)) LANMAN_REQ;

typedef struct lanman_netshareenum_resp {
	__u16 Win32ErrorCode;
	__u16 Converter;
	__u16 EntriesReturned;
	__u16 EntriesAvailable;
	char  RAPOutData[1];
} __attribute__((packed)) LANMAN_NETSHAREENUM_RESP;

typedef struct netshareinfo1 {
	__u8 NetworkName[13];
	__u8 Pad;
	__u16 Type;
	__u16 RemarkOffsetLow;
	__u16 RemarkOffsetHigh;
} __attribute__((packed)) NETSHAREINFO1;

typedef struct lanman_wkstageinfo_resp {
	__u16 Win32ErrorCode;
	__u16 Converter;
	__u16 TotalBytesAvailable;
	char  RAPOutData[1];
} __attribute__((packed)) LANMAN_WKSTAGEINFO_RESP;

typedef struct netwkstageinfo10 {
	__u32 ComputerName;
	__u32 UserName;
	__u32 LanGroup;
	__u8  VerMajor;
	__u8  VerMinor;
	__u32 LogonDomain;
	__u32 OtherDomain;
} __attribute__((packed)) NETWKSTAGEINFO10;

/* DCERPC Functions */

int process_rpc(struct tcp_server_info *server, char *data);
int process_rpc_rsp(struct tcp_server_info *server, char *data_buf, int size);

int rpc_bind(struct tcp_server_info *server, char *data);
int rpc_request(struct tcp_server_info *server, char *data);
int rpc_read_bind_data(struct tcp_server_info *server, char *data);
int rpc_read_winreg_data(struct tcp_server_info *server, char *outdata,
							int buf_len);

int winreg_rpc_request(struct tcp_server_info *server, char *in_data);
/* SRVSVC pipe function */

int rpc_read_srvsvc_data(struct tcp_server_info *server,
					char *data, int buf_len);

/* LANMAN pipe function */

int handle_lanman_pipe(struct tcp_server_info *server,
			char *in_data, char *out_data, int *param_len);
int handle_wkstagetinfo(struct tcp_server_info *server,
			LANMAN_REQ *req, char *out_data);

extern char *server_string;
extern char *workgroup;

#endif /* __CIFSSRV_DCERPC_H  */
