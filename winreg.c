/*
 *   fs/cifssrv/winreg.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include "winreg.h"
#include "dcerpc.h"

struct registry_node *reg_openhkcr;
struct registry_node *reg_openhkcu;
struct registry_node *reg_openhklm;
struct registry_node *reg_openhku;

/* Predefined registry*/
unsigned int npre_def_keys = 14;

char *pre_def_key[] = {
	"SYSTEM\\CurrentControlSet\\Services",
	"SYSTEM\\CurrentControlSet\\Services\\Eventlog",
	"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares",
	"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
	"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
	"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
	"SYSTEM\\CurrentControlSet\\Control\\Print",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Group Policy",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
};

int cifssrv_init_registry(void)
{
	int ret = 0;

	cifssrv_debug("Initializing winreg support\n");
	reg_openhkcr = init_root_key("HKEY_CLASSES_ROOT");
	if (IS_ERR(reg_openhkcr))
		return -ENOMEM;

	reg_openhkcu = init_root_key("HKEY_CURRENT_USER");
	if (IS_ERR(reg_openhkcu))
		return -ENOMEM;

	reg_openhklm = init_root_key("HKEY_LOCAL_MACHINE");
	if (IS_ERR(reg_openhklm))
		return -ENOMEM;

	reg_openhku = init_root_key("HKEY_USERS");
	if (IS_ERR(reg_openhku))
		return -ENOMEM;

	ret = init_predefined_registry();
	if (ret == -ENOMEM)
		return -ENOMEM;
	return 0;
}

struct registry_node *init_root_key(char *name)
{
	struct registry_node *root_key = kzalloc(sizeof(struct registry_node),
								GFP_KERNEL);
	if (!root_key)
		return ERR_PTR(-ENOMEM);
	strcpy(root_key->key_name, name);
	root_key->value_list = NULL;
	root_key->child = NULL;
	root_key->neighbour = NULL;
	root_key->access_status = 1;
	root_key->open_status = 0;
	return root_key;
}

void cifssrv_free_registry(void)
{
	free_registry(reg_openhkcr);
	free_registry(reg_openhkcu);
	free_registry(reg_openhklm);
	free_registry(reg_openhku);
}

int init_predefined_registry(void)
{
	struct registry_node *ret;
	int i;

	char *(*ptr)[npre_def_keys] = &pre_def_key;

	for (i = 0; i < npre_def_keys; i++) {
		ret = create_key((*ptr)[i], reg_openhklm);
		if (IS_ERR(ret))
			return -ENOMEM;
	}

	return 0;
}

int winreg_open_root_key(struct cifssrv_sess *sess, int opnum,
				RPC_REQUEST_REQ *rpc_request_req,
				char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKEY_RSP *winreg_rsp = kzalloc(sizeof(OPENHKEY_RSP), GFP_KERNEL);

	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	switch (opnum) {
	case WINREG_OPENHKCR:
		winreg_rsp->key_handle.addr = (__u32)reg_openhkcr;
		reg_openhkcr->open_status = 1;
		break;
	case WINREG_OPENHKCU:
		winreg_rsp->key_handle.addr = (__u32)reg_openhkcu;
		reg_openhkcu->open_status = 1;
		break;
	case WINREG_OPENHKLM:
		winreg_rsp->key_handle.addr = (__u32)reg_openhklm;
		reg_openhklm->open_status = 1;
		break;
	case WINREG_OPENHKU:
		winreg_rsp->key_handle.addr = (__u32)reg_openhku;
		reg_openhku->open_status = 1;
		break;
	default:
		cifssrv_debug("opnum :%d is not supported\n", opnum);
		return -EINVAL;
	}
	reg_openhkcr->open_status = 1;
	winreg_rsp->key_handle.addr = (__u32)reg_openhkcr;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("open_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_get_version(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	GET_VERSION_RSP *winreg_rsp =
				kzalloc(sizeof(GET_VERSION_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->version = cpu_to_le32(5);
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("get_version version = %d\n",
					winreg_rsp->version);
	return 0;
}

int winreg_delete_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	WINREG_COMMON_RSP *winreg_rsp;
	struct registry_node *ret;
	int key_addr;
	char *relative_name;
	struct registry_node *base_key;
	struct registry_node *key;
	struct registry_node *prev_key;
	char *token;
	char *name;
	KEY_HANDLE *key_handle = (KEY_HANDLE *)in_data;
	NAME_INFO *name_info = (NAME_INFO *)(((char *)in_data) +
							sizeof(KEY_HANDLE));

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;
	relative_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(relative_name))
		return PTR_ERR(relative_name);
	name = kzalloc(sizeof(strlen(relative_name)), GFP_KERNEL);
	strcpy(name, relative_name);
	ret = search_registry(relative_name, (struct registry_node *)key_addr);
	cifssrv_debug("ret %x\n", (__u32)ret);

	winreg_rsp = kzalloc(sizeof(WINREG_COMMON_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	if (base_key == NULL || base_key->open_status == 0 ||
				relative_name == NULL) {
		winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
	} else if (IS_ERR(ret)) {
		winreg_rsp->werror = cpu_to_le32(WERR_BAD_FILE);
	} else {
		key = base_key;
		token = strsep(&name, "\\");
		while (token) {
			if (key->child == ret) {
				key->child = key->child->neighbour;
			} else {
				prev_key = NULL;
				key = key->child;
				while ((key != NULL) &&
					(strcmp(key->key_name, token) != 0)) {
					prev_key = key;
					key = key->neighbour;
				}
				if (key == ret) {
					prev_key->neighbour = key->neighbour;
					break;
				}
			}
			token = strsep(&name, "\\");
		}
		free_registry(ret);
		winreg_rsp->werror = cpu_to_le32(WERR_OK);
	}
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	kfree(relative_name);
	cifssrv_debug("delete_key\n");
	return 0;
}

int winreg_flush_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	WINREG_COMMON_RSP *winreg_rsp =
				kzalloc(sizeof(WINREG_COMMON_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("flush_key\n");
	return 0;

}

int winreg_create_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	CREATE_KEY_RSP *winreg_rsp;
	struct registry_node *ret;
	int key_addr;
	char *relative_name;

	KEY_HANDLE *key_handle = (KEY_HANDLE *)in_data;
	NAME_INFO *name_info = (NAME_INFO *)(((char *)in_data) +
						sizeof(KEY_HANDLE));

	key_addr = key_handle->addr;
	relative_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(relative_name))
		return PTR_ERR(relative_name);
	ret = create_key(relative_name, (struct registry_node *)key_addr);

	winreg_rsp = kzalloc(sizeof(CREATE_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	winreg_rsp->key_handle.addr = (__u32)ret;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->ref_id = cpu_to_le32(0x00020008);
	winreg_rsp->action_taken = cpu_to_le32(REG_CREATED_NEW_KEY);
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	kfree(relative_name);
	cifssrv_debug("create_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}


int winreg_open_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKEY_RSP *winreg_rsp;
	struct registry_node *ret;
	int key_addr;
	char *relative_name;
	struct registry_node *base_key;

	KEY_HANDLE *key_handle = (KEY_HANDLE *)in_data;
	NAME_INFO *name_info = (NAME_INFO *)(((char *)in_data) +
						sizeof(KEY_HANDLE));

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;
	relative_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(relative_name))
		return PTR_ERR(relative_name);
	ret = search_registry(relative_name, (struct registry_node *)key_addr);

	winreg_rsp = kzalloc(sizeof(OPENHKEY_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;

	if (base_key == NULL || base_key->open_status == 0
				|| relative_name == NULL) {
		winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
		winreg_rsp->key_handle.addr = 0;
	} else if (IS_ERR(ret)) {
		winreg_rsp->werror = cpu_to_le32(WERR_BAD_FILE);
		winreg_rsp->key_handle.addr = 0;
	} else {
		ret->open_status = 1;
		winreg_rsp->key_handle.addr = (__u32)ret;
		winreg_rsp->werror = cpu_to_le32(WERR_OK);
	}
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	kfree(relative_name);
	cifssrv_debug("open_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);

	return 0;
}

int winreg_close_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKEY_RSP *winreg_rsp;
	int key_addr;
	struct registry_node *base_key;
	KEY_HANDLE *key_handle = (KEY_HANDLE *)in_data;

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;

	winreg_rsp = kzalloc(sizeof(OPENHKEY_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	if (base_key == NULL || base_key->open_status == 0) {
		winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
		winreg_rsp->key_handle.addr = key_handle->addr;
	} else {
		base_key->open_status = 0;
		winreg_rsp->key_handle.addr = 0;
		winreg_rsp->werror = cpu_to_le32(WERR_OK);
	}
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	cifssrv_debug("close_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_enum_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	ENUM_KEY_RSP *winreg_rsp = kzalloc(sizeof(ENUM_KEY_RSP), GFP_KERNEL);

	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	winreg_rsp->key_name.size = 1024;
	winreg_rsp->key_class_ref_id = 0X0002000c;
	winreg_rsp->key_class.key_packet_size = 1024;
	winreg_rsp->key_class.ref_id = 0x00020010;
	winreg_rsp->last_changed_time_ref_id = 0x00020014;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->werror = cpu_to_le32(WERR_NO_MORE_DATA);
	cifssrv_debug("enum_key\n");
	return 0;
}

int winreg_query_info_key(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	QUERY_INFO_KEY_RSP *winreg_rsp =
				kzalloc(sizeof(QUERY_INFO_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("flush_key\n");
	return 0;
}

int winreg_notify_change_key_value(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	WINREG_COMMON_RSP *winreg_rsp =
				kzalloc(sizeof(WINREG_COMMON_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->werror = cpu_to_le32(WERR_NOT_SUPPORTED);
	cifssrv_debug("flush_key\n");
	return 0;
}
int winreg_set_value(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	struct registry_value *ret;
	int offset = 0;
	int value_len = 0;
	int key_addr;
	struct registry_node *base_key;
	char *value_name;
	KEY_HANDLE *key_handle;
	NAME_INFO *name_info;
	VALUE_BUFFER *value_buffer;
	WINREG_COMMON_RSP *winreg_rsp;

	key_handle = (KEY_HANDLE *)in_data;
	offset += sizeof(KEY_HANDLE);
	name_info = (NAME_INFO *)(((char *)in_data) + offset);

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;

	value_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(value_name))
		return PTR_ERR(value_name);
	value_len = name_info->key_packet_len;
	value_len = ((value_len + 3) & ~3);
	offset += (sizeof(NAME_INFO) + value_len);

	value_buffer =  (VALUE_BUFFER *)(((char *)in_data) + offset);
	winreg_rsp = kzalloc(sizeof(WINREG_COMMON_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	if (base_key == NULL || base_key->open_status == 0) {
		winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
	} else {
		ret = set_value(value_name, value_buffer,
			(struct registry_node *)key_handle->addr);
		if (IS_ERR(ret))
			return -ENOMEM;
		winreg_rsp->werror = cpu_to_le32(WERR_OK);
	}
	kfree(value_name);
	return 0;
}

int winreg_delete_value(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	struct registry_value *ret;
	int offset = 0;
	int key_addr;
	struct registry_node *base_key;
	struct registry_value *value;
	struct registry_value *prev_value;
	char *value_name;
	KEY_HANDLE *key_handle;
	NAME_INFO *name_info;
	WINREG_COMMON_RSP *winreg_rsp;

	key_handle = (KEY_HANDLE *)in_data;
	offset += sizeof(KEY_HANDLE);
	name_info = (NAME_INFO *)(((char *)in_data) + offset);

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;

	value_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(value_name))
		return PTR_ERR(value_name);
	winreg_rsp = kzalloc(sizeof(WINREG_COMMON_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	if (base_key == NULL || base_key->open_status == 0) {
		winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
	} else {
		ret = search_value(value_name,
					(struct registry_node *)key_addr);
		if (IS_ERR(ret))
			winreg_rsp->werror = cpu_to_le32(WERR_OK);
		else {
			value = base_key->value_list;
			prev_value = NULL;
			while ((strcmp(value->value_name, value_name) != 0)) {
				prev_value = value;
				value = value->neighbour;
			}
			if (prev_value == NULL) {
				value = base_key->value_list->neighbour;
				kfree(base_key->value_list->value_buffer);
				kfree(base_key->value_list);
				base_key->value_list = value;
			} else {
				prev_value->neighbour = value->neighbour;
				kfree(value->value_buffer);
				kfree(value);
			}
			winreg_rsp->werror = cpu_to_le32(WERR_OK);
		}
	}
	kfree(value_name);
	cifssrv_debug("delete_value\n");
	return 0;
}

int winreg_query_value(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	struct registry_value *ret;
	int offset = 0;
	int value_len = 0;
	int key_addr;
	struct registry_node *base_key;
	struct registry_value *value;
	char *value_name;
	QUERY_VALUE_RSP *winreg_rsp;
	KEY_HANDLE *key_handle;
	NAME_INFO *name_info;
	BUFFER_INFO *buffer_info;
	__u32 *ptr_check;
	QUERY_INFO *query_info;

	winreg_rsp = kzalloc(sizeof(QUERY_VALUE_RSP), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	key_handle = (KEY_HANDLE *)in_data;
	offset += sizeof(KEY_HANDLE);
	name_info = (NAME_INFO *)(((char *)in_data) + offset);

	key_addr = key_handle->addr;
	base_key = (struct registry_node *)key_addr;

	value_name = smb_strndup_from_utf16(name_info->Buffer,
			name_info->key_packet_len, 1, sess->server->local_nls);
	if (IS_ERR(value_name))
		return PTR_ERR(value_name);
	cifssrv_debug("base key addr %x, value name %s\n", key_addr,
								value_name);

	ret = search_value(value_name, (struct registry_node *)key_addr);
	if (IS_ERR(ret)) {
		if ((strcmp(value_name, "") == 0) ||
			(strcmp(value_name, "Default") == 0))
			goto err_invalid_param;
		else
			goto err_bad_file;
	}
	value = (struct registry_value *)ret;

	value_len = name_info->key_packet_len;
	value_len = ((value_len + 3) & ~3);
	offset += (sizeof(NAME_INFO) + value_len);

	ptr_check = (__u32 *)((in_data) + offset);
	if (*ptr_check == 0)
		goto err_invalid_param;

	offset += (sizeof(DATA_INFO));

	buffer_info = (BUFFER_INFO *)(in_data + offset);

	if (buffer_info->ref_id != 0)
		offset += (sizeof(__u32)*4);
	else
		offset += (sizeof(__u32));

	ptr_check = (__u32 *)((in_data) + offset);
	if (*ptr_check == 0)
		goto err_invalid_param;

	offset += (sizeof(DATA_INFO));

	ptr_check = (__u32 *)((in_data) + offset);
	if (*ptr_check == 0)
		goto err_invalid_param;

	offset += (sizeof(DATA_INFO));
	query_info = kzalloc(sizeof(QUERY_INFO), GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	winreg_rsp->query_val_info = query_info;
	query_info->type_info.info = value->value_type;
	query_info->type_info.ref_id = cpu_to_le32(0x00020010);
	query_info->size_info.info = value->value_size;
	query_info->size_info.ref_id = cpu_to_le32(0x00020018);
	query_info->length_info.info = value->value_size;
	query_info->length_info.ref_id = cpu_to_le32(0x0002001c);
	query_info->data_info.max_count = value->value_size;
	query_info->data_info.actual_count = value->value_size;
	query_info->data_info.offset = 0;
	query_info->data_ref_id = cpu_to_le32(0x00020014);

	if (query_info->size_info.info < sizeof(__u32))
		query_info->Buffer = kzalloc(sizeof(__u32), GFP_KERNEL);
	else
		query_info->Buffer = kzalloc(value->value_size + 1, GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	memcpy(query_info->Buffer, value->value_buffer, value->value_size);
	if (buffer_info->ref_id != 0) {
		cifssrv_debug("client buffer size %d value buffer size %d\n",
			buffer_info->data_info.max_count, value->value_size);
		if (buffer_info->data_info.max_count >= value->value_size)
			winreg_rsp->werror = cpu_to_le32(WERR_OK);
		else
			winreg_rsp->werror = cpu_to_le32(WERR_MORE_DATA);
	} else {
		winreg_rsp->werror = cpu_to_le32(WERR_OK);
	}
	kfree(value_name);
	return 0;

err_invalid_param:
	kfree(value_name);
	winreg_rsp->werror = cpu_to_le32(WERR_INVALID_PARAMETER);
	return 0;

err_bad_file:
	kfree(value_name);
	winreg_rsp->werror = cpu_to_le32(WERR_BAD_FILE);
	return 0;

}

int winreg_enum_value(struct cifssrv_sess *sess,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	ENUM_VALUE_RSP *winreg_rsp = kzalloc(sizeof(ENUM_VALUE_RSP),
								GFP_KERNEL);
	if (!winreg_rsp)
		return -ENOMEM;

	sess->pipe_desc[WINREG]->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	winreg_rsp->name_ref_id = 0x00020014;
	winreg_rsp->type_info.ref_id = 0x00020018;
	winreg_rsp->length_info.ref_id = 0x00020020;
	winreg_rsp->size_info.ref_id = 0x00020024;
	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;
	winreg_rsp->werror = cpu_to_le32(WERR_NO_MORE_DATA);
	cifssrv_debug("enum_value\n");
	return 0;
}

struct registry_value *search_value(char *name, struct registry_node *key_addr)
{
	struct registry_node *base_key_addr =  (struct registry_node *)key_addr;
	struct registry_value *value;

	cifssrv_debug("value name %s\n", name);
	if (strcmp(name, "") == 0)
		strcpy(name, "Default");
	if (base_key_addr->value_list == NULL)
		return ERR_PTR(-EINVAL);

	value = base_key_addr->value_list;
	while ((value != NULL) && (strcmp(value->value_name, name) != 0))
			value = value->neighbour;
	if (value == NULL)
		return ERR_PTR(-EINVAL);
	else
		return value;

}

struct registry_value *set_value(char *name, VALUE_BUFFER *buffer_info,
					struct registry_node *key_addr)
{
	struct registry_node *base_key_addr = (struct registry_node *)key_addr;
	struct registry_value *value;
	struct registry_value *ret = NULL;

	if (strcmp(name, "") == 0)
		strcpy(name, "Default");
	if (base_key_addr->value_list == NULL) {
		value = kzalloc(sizeof(struct registry_value), GFP_KERNEL);
		if (!value)
			return ERR_PTR(-ENOMEM);

		strcpy(value->value_name, name);
		value->value_type = buffer_info->value_type;
		value->value_size = buffer_info->buffer_count;
		cifssrv_debug("type %d, size %d, name %s\n",
			value->value_type, value->value_size,
				value->value_name);
		value->value_buffer = kzalloc(value->value_size, GFP_KERNEL);
		if (!value->value_buffer)
			return ERR_PTR(-ENOMEM);

		memcpy(value->value_buffer, buffer_info->Buffer,
							value->value_size);
		value->neighbour = NULL;
		base_key_addr->value_list = value;
	} else {
		ret = search_value(name, key_addr);
		if (IS_ERR(ret)) {
			value = kzalloc(sizeof(struct registry_value),
								GFP_KERNEL);
			if (!value)
				return ERR_PTR(-ENOMEM);

			strcpy(value->value_name, name);
			value->value_type = buffer_info->value_type;
			value->value_size = buffer_info->buffer_count;
			value->value_buffer = kzalloc(value->value_size,
								GFP_KERNEL);
			if (!value->value_buffer)
				return ERR_PTR(-ENOMEM);

			memcpy(value->value_buffer, buffer_info->Buffer,
							value->value_size);
			value->neighbour = base_key_addr->value_list;
			base_key_addr->value_list = value;
		} else {
			value = (struct registry_value *)ret;
			value->value_size = buffer_info->buffer_count;
			value->value_type = buffer_info->value_type;
			memcpy(value->value_buffer, buffer_info->Buffer,
							value->value_size);
		}
	}
	return ret;
}

void free_registry(struct registry_node *key_addr)
{
	struct registry_node *base_key_addr = (struct registry_node *)key_addr;
	struct registry_node *key;
	struct registry_node *prev_key;
	struct registry_value *value;
	struct registry_value *prev_value;

	if (base_key_addr->child == NULL) {
		cifssrv_debug("free address %x key name %s\n",
			(__u32)base_key_addr, base_key_addr->key_name);
		if (base_key_addr->value_list != NULL) {
			value = base_key_addr->value_list;
			while (value != NULL) {
				prev_value = value;
				value = value->neighbour;
				kfree(prev_value->value_buffer);
				cifssrv_debug("free address %x value name %s\n",
					(__u32)prev_value,
					prev_value->value_name);
				kfree(prev_value);
			}
		}
		kfree(base_key_addr);
	} else {
		key = base_key_addr->child;
		while (key != NULL) {
			prev_key = key;
			key = key->neighbour;
			free_registry(prev_key);
		}
		cifssrv_debug("free address %x key name%s\n",
				(__u32)base_key_addr, base_key_addr->key_name);
		if (base_key_addr->value_list != NULL) {
			value = base_key_addr->value_list;
			while (value != NULL) {
				prev_value = value;
				value = value->neighbour;
				cifssrv_debug("free address %x value name %s\n",
					(__u32)prev_value,
					prev_value->value_name);
				kfree(prev_value->value_buffer);
				kfree(prev_value);
			}
		}
		kfree(base_key_addr);
	}
}

struct registry_node *search_registry(char *name,
					struct registry_node *key_addr)
{
	struct registry_node *base_key_addr = key_addr;
	struct registry_node *key = base_key_addr;
	struct registry_node *prev_key;
	char *token = strsep(&name, "\\");

	while (token) {
		if (key->child == NULL) {
			return ERR_PTR(-EINVAL);
		} else {
			prev_key = key;
			key = key->child;
			while ((key != NULL) &&
				(strcmp(key->key_name, token) != 0))
				key = key->neighbour;
			if (key == NULL)
				return ERR_PTR(-EINVAL);

		}
		token = strsep(&name, "\\");
	}
	return key;
}

struct registry_node *create_key(char *key_name, struct registry_node *key_addr)
{
	struct registry_node *base_key_addr = key_addr;
	struct registry_node *key = base_key_addr;
	struct registry_node *child;
	struct registry_node *prev_key;
	char *token;
	char *name, *kname;

	cifssrv_debug("key name %s\n", key_name);
	name = kname = kstrdup(key_name, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);

	token = strsep(&name, "\\");
	while (token) {
		if (key->child == NULL) {
			child = kzalloc(sizeof(struct registry_node),
								GFP_KERNEL);
			if (!child) {
				kfree(kname);
				return ERR_PTR(-ENOMEM);
			}
			strcpy(child->key_name, token);
			child->value_list = NULL;
			child->child = NULL;
			child->neighbour = NULL;
			child->open_status = 1;
			key->child = child;
			key = key->child;
		} else {
			prev_key = key;
			key = key->child;
			while ((key != NULL) &&
				(strcmp(key->key_name, token) != 0))
				key = key->neighbour;
			if (key == NULL) {
				child = kzalloc(sizeof(struct registry_node),
								GFP_KERNEL);
				if (!child) {
					kfree(kname);
					return ERR_PTR(-ENOMEM);
				}
				strcpy(child->key_name, token);
				child->value_list = NULL;
				child->child = NULL;
				child->open_status = 1;
				key = prev_key;
				child->neighbour = key->child;
				key->child = child;
				key = key->child;
			} else {
				key->open_status = 1;
			}
		}
		token = strsep(&name, "\\");
	}
	kfree(kname);
	return key;
}
