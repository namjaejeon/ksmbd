/*
 *   fs/cifssrv/winreg.h
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  021111307 USA
 */

#ifndef __CIFSSRV_WINREG_H
#define __CIFSSRV_WINREG_H

#include "dcerpc.h"

#define WINREG_OPENHKCR		0x00
#define WINREG_OPENHKCU		0x01
#define WINREG_OPENHKLM		0x02
#define WINREG_OPENHKPD		0x03
#define WINREG_OPENHKU		0x04
#define WINREG_CLOSEKEY		0x05
#define WINREG_CREATEKEY	0x06
#define WINREG_DELETEKEY	0x07
#define WINREG_FLUSHKEY		0x0b
#define WINREG_OPENKEY		0x0f
#define WINREG_GETVERSION	0x1a

union registry_datatype {
	__u32   reg_dword;
	__le32  reg_dword_le;
	__be32  reg_dword_be;
	__u64   reg_qword;
	__le64  reg_qword_le;
	bool    reg_binary;
};

struct registry_value {
	char registry_value_name[40];
	union registry_datatype key_value;
};

struct registry_node {
	char key_name[256];
	struct registry_value *value_list;
	struct registry_node *child;
	struct registry_node *neighbour;
	int access;
};

/* Winreg open root key request structure */
typedef struct handle_to_key {
	__u32 addr;
	__u32 time_hi;
	__u32 time_mi;
	__u32 time_lo;
	__u32 reserved;
} __attribute__((packed)) KEY_HANDLE;

typedef struct key_class {
	__u16 name_len;
	__u16 name_size;
	__u32 keyclass;
} __attribute__((packed)) KEY_CLASS;

typedef struct key_info {
	__u16 key_packet_len;
	__u16 key_packet_size;
	__u32 ref_id;
	UNISTR_INFO str_info;
	__u8  Buffer[0];
} __attribute__((packed)) KEY_INFO;

typedef struct openhkcu_req {
	__le64 access_mask;
	__u16 ptr_sys_name;
} __attribute__((packed)) OPENHKCU_REQ;

typedef struct openhkcr_req {
	__le64 access_mask;
	__u16 ptr_sys_name;
} __attribute__((packed)) OPENHKCR_REQ;

typedef	struct openhklm_req {
	__le64 access_mask;
	__u16 ptr_sys_name;
} __attribute__((packed)) OPENHKLM_REQ;

typedef struct openhku_req {
	__le64 access_mask;
	__u16 ptr_sys_name;
} __attribute__((packed)) OPENHKU_REQ;

/* Winreg open root key response structure */
typedef struct getversion_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32 version;
	__u32 werror;
} __attribute__((packed)) GET_VERSION_RSP;

typedef struct openhkcu_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32 werror;
} __attribute__((packed)) OPENHKCU_RSP;

typedef struct openhkcr_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32 werror;
} __attribute__((packed)) OPENHKCR_RSP;

typedef	struct openhklm_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32 werror;
} __attribute__((packed)) OPENHKLM_RSP;

typedef	struct openhku_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32 werror;
} __attribute__((packed)) OPENHKU_RSP;

typedef struct open_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32	werror;
} __attribute__((packed)) OPEN_KEY_RSP;

typedef struct delete_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32	werror;
} __attribute__((packed)) DELETE_KEY_RSP;

typedef struct flush_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32   werror;
} __attribute__((packed)) FLUSH_KEY_RSP;

typedef struct close_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32   werror;
} __attribute__((packed)) CLOSE_KEY_RSP;

typedef struct create_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32	ref_id;
	__u32	action_taken;
	__u32   werror;
} __attribute__((packed)) CREATE_KEY_RSP;


#define REG_ACTION_NONE			0x00000000
#define REG_CREATED_NEW_KEY		0x00000001
#define REG_OPENED_EXISTING_KEY		0x00000002


#define WINREG_KEY_WOW64_32KEY		0x00000200
#define WINREG_KEY_WOW64_64KEY		0x00000100
#define WINREG_KEY_CREATE_LINK		0x00000020
#define WINREG_KEY_NOTIFY		0x00000010
#define WINREG_KEY_ENUMERATE_SUB_KEY	0x00000008
#define WINREG_KEY_CREATE_SUB_KEY	0x00000004
#define WINREG_KEY_SET_VALUE		0x00000002
#define WINREG_KEY_QUERY_VALUE		0x00000001

int winreg_open_HKCR(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_open_HKCU(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_open_HKLM(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_open_HKU(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_open_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_get_version(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_delete_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_create_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_close_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_open_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_flush_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);

int dcerpc_packet_setup(RPC_REQUEST_RSP *rpc_request_rsp,
					RPC_REQUEST_REQ *rpc_request_req);

#endif /* __CIFSSRV_WINREG_H  */
