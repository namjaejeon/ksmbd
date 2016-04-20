/*
 *   fs/cifssrv/winreg.h
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

/* WINREG opnum values */
#define WINREG_OPENHKCR			0x00
#define WINREG_OPENHKCU			0x01
#define WINREG_OPENHKLM			0x02
#define WINREG_OPENHKPD			0x03
#define WINREG_OPENHKU			0x04
#define WINREG_CLOSEKEY			0x05
#define WINREG_CREATEKEY		0x06
#define WINREG_DELETEKEY		0x07
#define WINREG_DELETEVALUE		0x08
#define WINREG_ENUMKEY			0x09
#define WINREG_ENUMVALUE		0x0a
#define WINREG_FLUSHKEY			0x0b
#define WINREG_NOTIFYCHANGEKEYVALUE	0x0e
#define WINREG_OPENKEY			0x0f
#define WINREG_QUERYINFOKEY		0x10
#define WINREG_QUERYVALUE		0x11
#define WINREG_SETVALUE			0x16
#define WINREG_GETVERSION		0x1a

/* Registry structure*/
struct registry_value {
	char value_name[40];
	__u32 value_type;
	__u32 value_size;
	char *value_buffer;
	struct registry_value *neighbour;
};

struct registry_node {
	char key_name[40];
	struct registry_value *value_list;
	struct registry_node *child;
	struct registry_node *neighbour;
	__u8 open_status;
	__u8 access_status;
};

typedef struct handle_to_key {
	__u32 addr;
	__u32 time_hi;
	__u32 time_mi;
	__u32 time_lo;
	__u32 reserved;
} __attribute__((packed)) KEY_HANDLE;

typedef struct name_info {
	__u16 key_packet_len;
	__u16 key_packet_size;
	__u32 ref_id;
	UNISTR_INFO str_info;
	__u8  Buffer[0];
} __attribute__((packed)) NAME_INFO;

typedef struct data_info {
	__u32 ref_id;
	__u32 info;
} __attribute__((packed)) DATA_INFO;

typedef struct buffer_info {
	__u32 ref_id;
	UNISTR_INFO data_info;
} __attribute__((packed)) BUFFER_INFO;

typedef struct class_name {
	__u16 len;
	__u16 size;
	__u32 name;
} __attribute__((packed)) CLASSNAME_INFO;

typedef struct key_info {
	__u32 ptr_num_subkeys;
	__u32 ptr_max_subkeylen;
	__u32 ptr_max_classlen;
	__u32 ptr_num_values;
	__u32 ptr_num_valnamelen;
	__u32 ptr_max_valbufsize;
	__u32 ptr_secdescsize;
	__u64 last_changed_time;
} __attribute__((packed)) KEY_INFO;

typedef struct query_info {
	DATA_INFO type_info;
	__u32 data_ref_id;
	UNISTR_INFO data_info;
	__u8 *Buffer;
	DATA_INFO size_info;
	DATA_INFO length_info;
} __attribute__((packed)) QUERY_INFO;

typedef struct value_buffer {
	__u32 value_type;
	__u32 buffer_count;
	__u8 Buffer[0];
} __attribute__((packed)) VALUE_BUFFER;

/* Winreg response structure */
typedef struct enum_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	CLASSNAME_INFO key_name;
	__u32 key_class_ref_id;
	NAME_INFO key_class;
	__u32 last_changed_time_ref_id;
	__u64 last_changed_time;
	__u32 werror;
} __attribute__((packed)) ENUM_KEY_RSP;

typedef struct enum_value_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u16 name_len;
	__u16 name_size;
	__u32 name_ref_id;
	UNISTR_INFO name_str_info;
	__u16 *Buffer;
	DATA_INFO type_info;
	__u32 value_ptr;
	DATA_INFO size_info;
	DATA_INFO length_info;
	__u32 werror;
} __attribute__((packed)) ENUM_VALUE_RSP;

typedef struct query_value_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	QUERY_INFO *query_val_info;
	__u32 werror;
} __attribute__((packed)) QUERY_VALUE_RSP;

typedef struct query_info_key_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	CLASSNAME_INFO class_info;
	KEY_INFO key_info;
	__u32 werror;
} __attribute__((packed)) QUERY_INFO_KEY_RSP;

typedef struct getversion_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32 version;
	__u32 werror;
} __attribute__((packed)) GET_VERSION_RSP;

typedef struct openhkey_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	KEY_HANDLE key_handle;
	__u32 werror;
} __attribute__((packed)) OPENHKEY_RSP;

typedef struct winreg_common_rsp {
	RPC_REQUEST_RSP rpc_request_rsp;
	__u32	werror;
} __attribute__((packed)) WINREG_COMMON_RSP;

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

int winreg_open_root_key(struct tcp_server_info *server, int opnum,
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
int winreg_set_value(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_delete_value(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_query_value(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_query_info_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_notify_change_key_value(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_enum_key(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);
int winreg_enum_value(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *in_data);

struct registry_node *init_root_key(char *name);
int init_predefined_registry(void);
void free_registry(struct registry_node *key_addr);
struct registry_node *search_registry(char *name,
						struct registry_node *key_addr);
struct registry_node *create_key(char *name, struct registry_node *key_addr);
struct registry_value *search_value(char *name, struct registry_node *key_addr);
struct registry_value *set_value(char *name, VALUE_BUFFER *buffer_info,
					struct registry_node *key_addr);
#endif /* __CIFSSRV_WINREG_H  */
