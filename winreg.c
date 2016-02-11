/*
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

#include "winreg.h"
#include "dcerpc.h"

struct registry_node *reg_openhkcr;
struct registry_node *reg_openhkcu;
struct registry_node *reg_openhklm;
struct registry_node *reg_openhku;

int winreg_open_HKCR(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKCR_RSP *winreg_rsp = kzalloc(sizeof(OPENHKCR_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhkcr;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT open_HKCR ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}


int winreg_open_HKCU(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKCU_RSP *winreg_rsp = kzalloc(sizeof(OPENHKCU_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhkcu;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT open_HKCU ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_open_HKLM(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKLM_RSP *winreg_rsp = kzalloc(sizeof(OPENHKLM_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhklm;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT open_HKLM ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_open_HKU(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPENHKU_RSP *winreg_rsp = kzalloc(sizeof(OPENHKU_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhku;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT open_HKU ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_get_version(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	GET_VERSION_RSP *winreg_rsp =
				kzalloc(sizeof(GET_VERSION_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->version = cpu_to_le32(5);
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT get_version version = %d\n",
					winreg_rsp->version);
	return 0;
}

int winreg_delete_key(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	DELETE_KEY_RSP *winreg_rsp =
				kzalloc(sizeof(DELETE_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->werror = cpu_to_le32(WERR_BAD_FILE);
	cifssrv_debug("GOT delete_key\n");
	return 0;
}

int winreg_flush_key(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	FLUSH_KEY_RSP *winreg_rsp =
				kzalloc(sizeof(FLUSH_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT flush_key\n");
	return 0;

}

int winreg_create_key(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	CREATE_KEY_RSP *winreg_rsp;

	winreg_rsp = kzalloc(sizeof(CREATE_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;
	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhku;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->ref_id = cpu_to_le32(0x00020008);
	winreg_rsp->action_taken = cpu_to_le32(REG_ACTION_NONE);
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT create_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}


int winreg_open_key(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	OPEN_KEY_RSP *winreg_rsp =
				kzalloc(sizeof(OPEN_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhku;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT open_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}

int winreg_close_key(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req, char *in_data)
{
	RPC_REQUEST_RSP *rpc_request_rsp;
	CLOSE_KEY_RSP *winreg_rsp = kzalloc(sizeof(CLOSE_KEY_RSP), GFP_KERNEL);
	if (!winreg_rsp) {
		cifssrv_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)winreg_rsp;
	rpc_request_rsp = &winreg_rsp->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	winreg_rsp->key_handle.addr = (__u32)(unsigned long)&reg_openhku;
	winreg_rsp->werror = cpu_to_le32(WERR_OK);
	cifssrv_debug("GOT close_key ptr to handle = %x\n",
					winreg_rsp->key_handle.addr);
	return 0;
}
