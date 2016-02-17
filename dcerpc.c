/*
 *   fs/cifssrv/dcerpc.c
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

#include"dcerpc.h"
#include"export.h"
#include"winreg.h"

struct cifssrv_pipe_table cifssrv_pipes[] = {
	{"\\srvsvc", SRVSVC},
	{"srvsvc", SRVSVC},
	{"\\wkssvc", SRVSVC},
	{"wkssvc", SRVSVC},
	{"\\winreg", WINREG},
	{"winreg", WINREG},
};
unsigned int npipes = sizeof(cifssrv_pipes)/sizeof(cifssrv_pipes[0]);

/**
 * get_pipe_type() - get the type of the pipe from the string name
 * @name:      string name for representation of pipe, need to be searched
 *             in the supported table
 * Return:     the pipe type number if found in the table,
 *             else invalid pipe type
 */
unsigned int get_pipe_type(char *pipename)
{
	int i;
	unsigned int pipetype = INVALID_PIPE;

	for (i = 0; i < npipes; i++) {
		if (!strcmp(cifssrv_pipes[i].pipename, pipename)) {
			pipetype = cifssrv_pipes[i].pipetype;
			break;
		}
	}
	return pipetype;
}

/**
 * process_rpc() - process a RPC request
 * @server:     TCP server instance of connection
 * @data:	RPC request packet - data
 *
 * Return:      0 on success, error number on error
 */
int process_rpc(struct tcp_server_info *server, char *data)
{
	RPC_HDR *rpc_hdr;
	int ret = 0;

	rpc_hdr = (RPC_HDR *)data;

	cifssrv_debug("DCERPC pktype = %u\n", rpc_hdr->pkt_type);

	switch (rpc_hdr->pkt_type) {
	case RPC_REQUEST:
		cifssrv_debug("GOT RPC_REQUEST\n");
		ret = rpc_request(server, data);
		break;
	case RPC_BIND:
		cifssrv_debug("GOT RPC_BIND\n");
		ret = rpc_bind(server, data);
		break;
	default:
		cifssrv_debug("rpc type = %d Not Implemented\n",
				rpc_hdr->pkt_type);
		ret = -EOPNOTSUPP;
	}

	if (!ret)
		server->pipe_desc->pkt_type = rpc_hdr->pkt_type;

	return ret;
}

/**
 * process_rpc_rsp() - create RPC response buffer
 * @server:     TCP server instance of connection
 * @data_buf:	RPC response out buffer
 * @size:	response buffer size
 *
 * Return:      response length on success, otherwise error number
 */
int process_rpc_rsp(struct tcp_server_info *server, char *data_buf, int size)
{
	int nbytes = 0;

	if (server->pipe_desc == NULL) {
		cifssrv_debug("Pipe Not opened\n");
		return -EINVAL;
	}
	switch (server->pipe_desc->pkt_type) {
	case RPC_REQUEST:
		switch (server->pipe_desc->pipe_type) {
		case SRVSVC:
			nbytes = rpc_read_srvsvc_data(server,
				data_buf, size);
			break;
		case WINREG:
			nbytes = rpc_read_winreg_data(server,
				data_buf, size);
			break;
		default:
			cifssrv_debug("rpc pipe = %d Not Implemented\n",
				server->pipe_desc->pipe_type);
			return -EINVAL;
		}
		break;
	case RPC_BIND:
		nbytes = rpc_read_bind_data(server, data_buf);
		break;
	default:
		cifssrv_debug("rpc type = %d Not Implemented\n",
				server->pipe_desc->pkt_type);
		return -EINVAL;
	}

	return nbytes;
}



int rpc_read_winreg_data(struct tcp_server_info *server, char *outdata,
								int buf_len)
{
	RPC_REQUEST_RSP *rpc_request_rsp = (RPC_REQUEST_RSP *)outdata;
	int offset = 0;

	if (server->pipe_desc->opnum == WINREG_OPENHKCR ||
			server->pipe_desc->opnum == WINREG_OPENHKCU ||
			server->pipe_desc->opnum == WINREG_OPENHKLM ||
			server->pipe_desc->opnum == WINREG_OPENHKU ||
			server->pipe_desc->opnum == WINREG_OPENKEY ||
			server->pipe_desc->opnum == WINREG_CLOSEKEY) {

		OPENHKEY_RSP *winreg_rsp;

		winreg_rsp = (OPENHKEY_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->key_handle,
						sizeof(KEY_HANDLE));
		offset += sizeof(KEY_HANDLE);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_GETVERSION) {
		GET_VERSION_RSP *winreg_rsp;

		winreg_rsp = (GET_VERSION_RSP *)server->pipe_desc->data;

		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);

		memcpy(outdata + offset, &winreg_rsp->version, sizeof(__u32));
		offset += sizeof(__u32);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_DELETEKEY ||
			server->pipe_desc->opnum == WINREG_FLUSHKEY ||
			server->pipe_desc->opnum == WINREG_SETVALUE ||
			server->pipe_desc->opnum ==
					WINREG_NOTIFYCHANGEKEYVALUE ||
			server->pipe_desc->opnum == WINREG_DELETEVALUE) {
		WINREG_COMMON_RSP *winreg_rsp;

		winreg_rsp = (WINREG_COMMON_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_CREATEKEY) {
		CREATE_KEY_RSP *winreg_rsp;

		winreg_rsp = (CREATE_KEY_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->key_handle,
						sizeof(KEY_HANDLE));
		offset += sizeof(KEY_HANDLE);
		memcpy(outdata + offset, &winreg_rsp->ref_id, sizeof(__u32));
		offset += sizeof(__u32);
		memcpy(outdata + offset, &winreg_rsp->action_taken,
								sizeof(__u32));
		offset += sizeof(__u32);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);

		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_FLUSHKEY) {
		FLUSH_KEY_RSP *winreg_rsp;

		winreg_rsp = (FLUSH_KEY_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_OPENKEY) {
		OPEN_KEY_RSP *winreg_rsp;

		winreg_rsp = (OPEN_KEY_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->key_handle,
				sizeof(KEY_HANDLE));
		offset += sizeof(KEY_HANDLE);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	if (server->pipe_desc->opnum == WINREG_CLOSEKEY) {
		CLOSE_KEY_RSP *winreg_rsp;

		winreg_rsp = (CLOSE_KEY_RSP *)server->pipe_desc->data;
		memcpy(outdata + offset, &winreg_rsp->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);
		memcpy(outdata + offset, &winreg_rsp->key_handle,
				sizeof(KEY_HANDLE));
		offset += sizeof(KEY_HANDLE);
		memcpy(outdata + offset, &winreg_rsp->werror, sizeof(__u32));
		offset += sizeof(__u32);
		kfree(winreg_rsp);
	}

	rpc_request_rsp->hdr.frag_len = offset;
	rpc_request_rsp->alloc_hint = offset - sizeof(RPC_REQUEST_RSP);

	cifssrv_debug("offset = %d size of RPC_REQUEST_RSP = %d\n",
	offset, sizeof(RPC_REQUEST_RSP));
	cifssrv_debug("frag len = %d alloc_hint = %d\n",
	rpc_request_rsp->hdr.frag_len, rpc_request_rsp->alloc_hint);

	return offset;
}

/**
 * rpc_read_bind_data() - create RPC response buffer for RPC_BIND request
 * @server:     TCP server instance of connection
 * @out_data:	RPC response out buffer
 *
 * Return:      response length on success, otherwise error number
 */
int rpc_read_bind_data(struct tcp_server_info *server, char *out_data)
{
	RPC_HDR *hdr = (RPC_HDR *)out_data;
	int offset = 0;
	int pipe_type = server->pipe_desc->pipe_type;
	RPC_BIND_RSP *rpc_bind_rsp;

	rpc_bind_rsp = (RPC_BIND_RSP *)server->pipe_desc->data;

	memcpy(out_data, &rpc_bind_rsp->hdr, sizeof(RPC_HDR));
	offset += sizeof(RPC_HDR);

	memcpy(out_data + offset, &rpc_bind_rsp->bind_info,
	       sizeof(BIND_ACK_INFO));
	offset += sizeof(BIND_ACK_INFO);

	memcpy(out_data + offset, &rpc_bind_rsp->addr.sec_addr_len,
	       sizeof(__u16));
	offset += sizeof(__u16);

	memcpy(out_data + offset, rpc_bind_rsp->addr.sec_addr,
		rpc_bind_rsp->addr.sec_addr_len);
	offset += rpc_bind_rsp->addr.sec_addr_len;
	offset += (((offset + 3) & ~3) - offset);

	memcpy(out_data + offset, &rpc_bind_rsp->results, sizeof(RPC_RESULTS));
	offset += sizeof(RPC_RESULTS);

	memcpy(out_data + offset, rpc_bind_rsp->transfer, sizeof(RPC_IFACE));
	offset += sizeof(RPC_IFACE);

	if (pipe_type == WINREG) {
		memcpy(out_data + offset, &rpc_bind_rsp->auth,
							sizeof(RPC_AUTH_INFO));
		offset += sizeof(RPC_AUTH_INFO);

		memcpy(out_data + offset, rpc_bind_rsp->Buffer,
						rpc_bind_rsp->BufferLength);
		offset += rpc_bind_rsp->BufferLength;

		kfree(rpc_bind_rsp->Buffer);
	}

	hdr->frag_len = offset;
	hdr->auth_len = rpc_bind_rsp->BufferLength;
	kfree(rpc_bind_rsp->addr.sec_addr);
	kfree(rpc_bind_rsp->transfer);
	kfree(rpc_bind_rsp);

	return offset;
}

/**
 * rpc_read_srvsvc_data() - create RPC response buffer for RPC_REQUEST
 * @server:     TCP server instance of connection
 * @out_data:	RPC response out buffer
 * @buf_len:	RPC response buffer length
 *
 * Return:      response length on success, otherwise error number
 */
int rpc_read_srvsvc_data(struct tcp_server_info *server, char *outdata,
								int buf_len)
{
	RPC_REQUEST_RSP *rpc_request_rsp = (RPC_REQUEST_RSP *)outdata;
	int offset = 0, num_shares, string_len = 0;
	int i = 0, resume_handle = 0, data_sent = 0, datasize = 0;
	SRVSVC_SHARE_INFO_CTR *sharectr;
	SRVSVC_SHARE_GETINFO *shareinfo;
	WKSSVC_SHARE_GETINFO *wkssvc_info;
	char *buf = NULL;


	sharectr = (SRVSVC_SHARE_INFO_CTR *)server->pipe_desc->data;
	memcpy(outdata, &sharectr->rpc_request_rsp, sizeof(RPC_REQUEST_RSP));
	offset += sizeof(RPC_REQUEST_RSP);


	if (server->pipe_desc->opnum == SRV_NET_SHARE_GETINFO) {
		shareinfo = (SRVSVC_SHARE_GETINFO *)server->pipe_desc->data;

		memcpy(outdata + offset, &shareinfo->info_level,
				sizeof(shareinfo->info_level));
		offset += sizeof(shareinfo->info_level);
		memcpy(outdata + offset, &shareinfo->switch_value,
				sizeof(shareinfo->switch_value));
		offset += sizeof(shareinfo->switch_value);
		if (shareinfo->status == WERR_INVALID_NAME)
			goto out;
		memcpy(outdata + offset, shareinfo->ptrs,
				sizeof(PTR_INFO1));
		offset += sizeof(PTR_INFO1);

		for (i = 0; i < 1; i++) {
			memcpy(outdata + offset,
			&shareinfo->shares[i].str_info1, sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			string_len =
				shareinfo->shares[i].str_info1.actual_count * 2;

			memcpy(outdata + offset, shareinfo->shares[i].sharename,
					string_len);
			offset += ((string_len + 3) & ~3);

			memcpy(outdata + offset,
			       &shareinfo->shares[i].str_info2,
			       sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			string_len =
				shareinfo->shares[i].str_info2.actual_count * 2;

			memcpy(outdata + offset, shareinfo->shares[i].comment,
					string_len);
			offset += ((string_len + 3) & ~3);
		}
out:
		memcpy(outdata + offset, &shareinfo->status,
				sizeof(shareinfo->status));
		offset += sizeof(shareinfo->status);

		rpc_request_rsp->hdr.frag_len = offset;
		rpc_request_rsp->alloc_hint = offset - sizeof(RPC_REQUEST_RSP);

		cifssrv_debug("frag len = %d alloc_hint = %d\n",
			       rpc_request_rsp->hdr.frag_len,
			       rpc_request_rsp->alloc_hint);

		kfree(shareinfo->shares);
		kfree(shareinfo->ptrs);
		kfree(shareinfo);
	}

	if (server->pipe_desc->opnum == SRV_NET_SHARE_ENUM_ALL) {
		sharectr = (SRVSVC_SHARE_INFO_CTR *)server->pipe_desc->data;
		buf = server->pipe_desc->buf;
		data_sent = server->pipe_desc->sent;
		datasize = server->pipe_desc->datasize;
		num_shares = sharectr->info.num_entries;
		resume_handle = sharectr->resume_handle;

		cifssrv_debug("num entries = %d\n", sharectr->info.num_entries);
		if (resume_handle) {
			memcpy(outdata, server->pipe_desc->buf + data_sent,
								resume_handle);
			datasize = resume_handle;
			goto finish;
		}

		if (datasize > buf_len) {
			memcpy(outdata, buf, buf_len);
			resume_handle = datasize - buf_len;
			server->pipe_desc->sent = buf_len;
			sharectr->resume_handle = resume_handle;
		} else {
			memcpy(outdata, buf, datasize);
		}

		rpc_request_rsp->hdr.frag_len = datasize;
		rpc_request_rsp->alloc_hint = datasize -
					sizeof(RPC_REQUEST_RSP);
		cifssrv_debug("frag len = %d alloc_hint = %d\n",
				       rpc_request_rsp->hdr.frag_len,
				       rpc_request_rsp->alloc_hint);
		if (resume_handle) {
			server->pipe_desc->sent = buf_len;
			cifssrv_debug("Pipe data is outstanding, "
			"sent %d, remaining %d\n", buf_len, datasize - buf_len);
			return datasize;
		}
finish:
		kfree(sharectr->shares);
		kfree(sharectr->ptrs);
		kfree(sharectr);
		kfree(server->pipe_desc->buf);
		server->pipe_desc->buf = NULL;
		server->pipe_desc->sent = 0;
		server->pipe_desc->datasize = 0;
		return datasize;
	}

	if (server->pipe_desc->opnum == 0) {
		wkssvc_info = (WKSSVC_SHARE_GETINFO *)server->pipe_desc->data;

		memcpy(outdata + offset, &wkssvc_info->info_level,
				sizeof(wkssvc_info->info_level));
		offset += sizeof(wkssvc_info->info_level);

		memcpy(outdata + offset, &wkssvc_info->platform_id,
					sizeof(wkssvc_info->platform_id));
		offset += sizeof(wkssvc_info->platform_id);

		memcpy(outdata + offset, &wkssvc_info->refid,
						sizeof(wkssvc_info->refid));
		offset += sizeof(wkssvc_info->refid);

		memcpy(outdata + offset, &wkssvc_info->ref_id1,
						sizeof(wkssvc_info->ref_id1));
		offset += sizeof(wkssvc_info->ref_id1);

		memcpy(outdata + offset, &wkssvc_info->ref_id2,
						sizeof(wkssvc_info->ref_id2));
		offset += sizeof(wkssvc_info->ref_id2);

		memcpy(outdata + offset, &wkssvc_info->maj,
						sizeof(wkssvc_info->maj));
		offset += sizeof(wkssvc_info->maj);

		memcpy(outdata + offset, &wkssvc_info->min,
						sizeof(wkssvc_info->min));
		offset += sizeof(wkssvc_info->min);

		for (i = 0; i < 1; i++) {
			memcpy(outdata + offset,
			&wkssvc_info->shares[i].str_info1, sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			string_len =
			wkssvc_info->shares[i].str_info1.actual_count * 2;

			memcpy(outdata + offset,
				wkssvc_info->shares[i].server_name, string_len);
			offset += ((string_len + 3) & ~3);

			memcpy(outdata + offset,
			&wkssvc_info->shares[i].str_info2, sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			string_len =
			wkssvc_info->shares[i].str_info2.actual_count * 2;

			memcpy(outdata + offset,
			wkssvc_info->shares[i].domain_name, string_len);
			offset += ((string_len + 3) & ~3);
		}

		memcpy(outdata + offset, &wkssvc_info->status,
				sizeof(wkssvc_info->status));
		offset += sizeof(wkssvc_info->status);

		rpc_request_rsp->hdr.frag_len = offset;
		rpc_request_rsp->alloc_hint = offset - sizeof(RPC_REQUEST_RSP);

		cifssrv_debug("frag len = %d alloc_hint = %d\n",
		rpc_request_rsp->hdr.frag_len, rpc_request_rsp->alloc_hint);

		kfree(wkssvc_info->shares);
		kfree(wkssvc_info);

	}
	return offset;
}

/**
 * pipe_data_size() - determine data size on pipe for share list enumeration
 * @server:     TCP server instance of connection
 * @data:	share control specific data
 * @num_shares:	number of shares points on given share control
 *
 * Return:      data size used for share enumeration so far
 */
int pipe_data_size(struct tcp_server_info *server, void *data, int num_shares)
{
	int size = 0, i, string_len;
	SRVSVC_SHARE_INFO_CTR *sharectr;

	if (server->pipe_desc->opnum == SRV_NET_SHARE_ENUM_ALL) {
		sharectr = (SRVSVC_SHARE_INFO_CTR *)data;

		size += sizeof(RPC_REQUEST_RSP);
		size += sizeof(SRVSVC_SHARE_COMMON_INFO);
		size += num_shares * sizeof(PTR_INFO1);

		/* determine the size of share info */
		for (i = 0; i < num_shares; i++) {
			size += sizeof(UNISTR_INFO);
			string_len =
				sharectr->shares[i].str_info1.actual_count * 2;
			size += ((string_len + 3) & ~3);
			size += sizeof(UNISTR_INFO);
			string_len =
				sharectr->shares[i].str_info2.actual_count * 2;

			size += ((string_len + 3) & ~3);
		}

		size += sizeof(sharectr->total_entries);
		size += sizeof(sharectr->resume_handle);
		size += sizeof(sharectr->status);
	}
	cifssrv_debug("Total data length in pipe %d\n", size);
	return size;
}

/**
 * pipe_data_copy() - copy share info data on rpc pipe
 * @server:     TCP server instance of connection
 * @buf:	buffer to copy share data
 *
 * Return:      data size copied on buffer
 */
int pipe_data_copy(struct tcp_server_info *server, char *buf)
{
	int offset = 0, i, str_len, num_shares;
	SRVSVC_SHARE_INFO_CTR *sharectr;

	if (server->pipe_desc->opnum == SRV_NET_SHARE_ENUM_ALL) {
		sharectr = (SRVSVC_SHARE_INFO_CTR *)server->pipe_desc->data;
		num_shares = sharectr->info.num_entries;

		cifssrv_debug("num entries = %d\n", sharectr->info.num_entries);
		memcpy(buf, &sharectr->rpc_request_rsp,
						sizeof(RPC_REQUEST_RSP));
		offset += sizeof(RPC_REQUEST_RSP);

		memcpy(buf + offset, &sharectr->info,
				sizeof(SRVSVC_SHARE_COMMON_INFO));
		offset += sizeof(SRVSVC_SHARE_COMMON_INFO);

		memcpy(buf + offset, sharectr->ptrs,
				num_shares * sizeof(PTR_INFO1));
		offset += num_shares * sizeof(PTR_INFO1);

		for (i = 0; i < num_shares; i++) {

			memcpy(buf + offset, &sharectr->shares[i].str_info1,
					sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			str_len =
				sharectr->shares[i].str_info1.actual_count * 2;

			memcpy(buf + offset, sharectr->shares[i].sharename,
					str_len);
			offset += ((str_len + 3) & ~3);

			memcpy(buf + offset, &sharectr->shares[i].str_info2,
					sizeof(UNISTR_INFO));
			offset += sizeof(UNISTR_INFO);

			str_len =
				sharectr->shares[i].str_info2.actual_count * 2;

			memcpy(buf + offset, sharectr->shares[i].comment,
					str_len);
			offset += ((str_len + 3) & ~3);

		}
		memcpy(buf + offset, &sharectr->total_entries,
				sizeof(sharectr->total_entries));
		offset += sizeof(sharectr->total_entries);
		memcpy(buf + offset, &sharectr->resume_handle,
				sizeof(sharectr->resume_handle));
		offset += sizeof(sharectr->resume_handle);
		memcpy(buf + offset, &sharectr->status,
				sizeof(sharectr->status));
		offset += sizeof(sharectr->status);
	}

	return offset;
}

/**
 * dcerpc_header_init() - initialize the header for rpc response
 * @header: pointer to header in response packet
 * @packet_type : DCE/RPC Packet type
 * @flags : DCE/RPC flags
 * @call_id: call_id from RPC request
 *
 */
void dcerpc_header_init(RPC_HDR *header, int packet_type,
				int flags, int call_id)
{
	header->major = RPC_MAJOR_VER;
	header->minor = RPC_MINOR_VER;
	header->pkt_type = packet_type;
	header->flags = flags;
	header->pack_type[0] = 0x10;
	header->pack_type[1] = 0;
	header->pack_type[2] = 0;
	header->pack_type[3] = 0;
	header->auth_len = 0;
	header->call_id  = call_id;
}

/**
 * init_srvsvc_share_info1() - initialize srvsvc pipe share information
 * @server:		TCP server instance of connection
 * @rpc_request_req:	rpc request
 *
 * Return:      0 on success or error number
 */
static int init_srvsvc_share_info1(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req)
{
	int num_shares = 0, cnt = 0, len = 0;
	int total_pipe_data = 0, data_copied = 0;
	struct list_head *tmp;
	struct cifssrv_share *share;
	SRVSVC_SHARE_INFO1 *share_info;
	PTR_INFO1 *ptr_info;
	int share_name_len, comment_len = 0;
	RPC_REQUEST_RSP *rpc_request_rsp;
	SRVSVC_SHARE_INFO_CTR *sharectr;
	char *buf = NULL;

	num_shares = cifssrv_num_shares;
	sharectr = (SRVSVC_SHARE_INFO_CTR *)
			kzalloc(sizeof(SRVSVC_SHARE_INFO_CTR), GFP_KERNEL);
	if (!sharectr) {
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)sharectr;

	sharectr->ptrs = kzalloc((num_shares *
				sizeof(PTR_INFO1)), GFP_KERNEL);

	if (!sharectr->ptrs) {
		kfree(sharectr);
		return -ENOMEM;
	}
	sharectr->shares = kzalloc((num_shares * sizeof(SRVSVC_SHARE_INFO1)),
					GFP_KERNEL);

	if (!sharectr->shares) {
		kfree(sharectr->ptrs);
		kfree(sharectr);
		return -ENOMEM;
	}

	rpc_request_rsp = &sharectr->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	sharectr->info.info_level = cpu_to_le32(1);
	sharectr->info.switch_value = cpu_to_le32(1);
	sharectr->info.ptr_share_info = cpu_to_le32(1);
	sharectr->info.num_entries = cpu_to_le32(num_shares);
	sharectr->info.ptr_entries = cpu_to_le32(1);
	sharectr->info.num_entries2 = cpu_to_le32(num_shares);

	list_for_each(tmp, &cifssrv_share_list) {
		share_info = &sharectr->shares[cnt];
		ptr_info = &sharectr->ptrs[cnt];
		share = list_entry(tmp, struct cifssrv_share, list);
		share_name_len = strlen(share->sharename) + 1;

		if (share_name_len > 13) {
			cifssrv_debug("Not displaying share = %s",
					share->sharename);
			continue;
		}

		if (strcmp(share->sharename, "IPC$") == 0) {
			ptr_info->type = STYPE_IPC_HIDDEN;
			len = smbConvertToUTF16((__le16 *)share_info->comment,
					"IPC SHARE", 256, server->local_nls, 0);
			comment_len = strlen("IPC SHARE") + 1;
			cifssrv_debug("IPC share %s added len = %d\n",
				       share->sharename, len);
		} else {
			ptr_info->type = STYPE_DISKTREE;
			if (share->config.comment) {
				len =
				smbConvertToUTF16((__le16 *)share_info->comment,
				share->config.comment,
						256, server->local_nls, 0);
				comment_len = strlen(share->config.comment) + 1;
			} else {
				/* Windows expect comment to be non-null
				   In case comment is not given in conf file,
				   using sharename as comment */
				len =
				smbConvertToUTF16((__le16 *)share_info->comment,
				share->sharename,
						256, server->local_nls, 0);
				comment_len = strlen(share->sharename) + 1;
			}
			cifssrv_debug("share %s added\n", share->sharename);
		}

		cifssrv_debug("comment len = %d share len = %d uni len = %d\n",
				comment_len, share_name_len, len);

		/* Since sharename and comment are non-null*/
		ptr_info->ptr_netname = 1;
		ptr_info->ptr_remark = 1;

		smbConvertToUTF16((__le16 *)share_info->sharename,
				share->sharename, 256, server->local_nls, 0);
		share_info->str_info1.max_count = share_name_len;
		share_info->str_info1.offset = 0;
		share_info->str_info1.actual_count = share_name_len;

		share_info->str_info2.max_count = comment_len;
		share_info->str_info2.offset = 0;
		share_info->str_info2.actual_count = comment_len;
		cnt++;
	}

	sharectr->total_entries = cpu_to_le32(num_shares);
	sharectr->resume_handle = 0;
	sharectr->status = 0;

	total_pipe_data = pipe_data_size(server, (void *)sharectr, num_shares);
	if (total_pipe_data == 0)
		return 0;
	buf =  kzalloc(total_pipe_data, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;
	server->pipe_desc->buf = buf;

	data_copied = pipe_data_copy(server, buf);
	cifssrv_debug("data_copied %d, total_pipe_data %d\n", data_copied,
							total_pipe_data);
	server->pipe_desc->datasize = data_copied;
	return 0;
}

/**
 * srvsvc_net_share_enum_all() - srvsvc pipe for share list enumeration
 * @server:     TCP server instance of connection
 * @data:	SRVSVC_REQ data
 * @rpc_request_req:	rpc request
 *
 * Return:      0 on success or error number
 */
static int srvsvc_net_share_enum_all(struct tcp_server_info *server, char *data,
				RPC_REQUEST_REQ *rpc_request_req)
{
	SRVSVC_REQ *req = (SRVSVC_REQ *)data;
	SERVER_HANDLE handle;
	char *server_unc_ptr, *server_unc;
	int server_unc_len = 0;
	int ret = 0;

	handle = req->server_unc_handle;
	server_unc_ptr = (char *)(data + sizeof(SERVER_HANDLE));
	server_unc = smb_strndup_from_utf16(server_unc_ptr, 256, 1,
			server->local_nls);
	if (IS_ERR(server_unc))
		return PTR_ERR(server_unc);

	cifssrv_debug("server_unc = %s unc size = %d\n", server_unc,
			handle.handle_info.actual_count);

	server_unc_len = 2 * handle.handle_info.actual_count;
	server_unc_len = ((server_unc_len + 3) & ~3);
	/* Add 2 for Pad */
	req->info_level = le32_to_cpu(*(server_unc_ptr + server_unc_len));

	switch (req->info_level) {

	case INFO_1:
		cifssrv_debug("GOT SRVSVC pipe info level %u\n",
			       req->info_level);

		ret = init_srvsvc_share_info1(server, rpc_request_req);
		break;

	default:
		cifssrv_debug("SRVSVC pipe info level %u  not supported\n",
				req->info_level);
		return -EOPNOTSUPP;
	}

	return ret;
}

/**
 * init_srvsvc_share_info2() - get a share information on srvsvc pipe
 * @server:		TCP server instance of connection
 * @rpc_request_req:	rpc request
 * @share_name:		share_name for which information is requested
 *
 * Return:      0 on success or error number
 */
int init_srvsvc_share_info2(struct tcp_server_info *server,
			RPC_REQUEST_REQ *rpc_request_req, char *share_name)
{
	int num_shares = 1, cnt = 0, len = 0;
	struct list_head *tmp;
	struct cifssrv_share *share;
	SRVSVC_SHARE_INFO1 *share_info;
	SRVSVC_SHARE_GETINFO *shareinfo;
	PTR_INFO1 *ptr_info;
	int share_name_len, comment_len = 0;
	RPC_REQUEST_RSP *rpc_request_rsp;

	shareinfo = (SRVSVC_SHARE_GETINFO *)
			kzalloc(sizeof(SRVSVC_SHARE_GETINFO), GFP_KERNEL);
	if (!shareinfo) {
		return -ENOMEM;
	}

	server->pipe_desc->data = (char *)shareinfo;
	shareinfo->ptrs = kzalloc((num_shares *
				sizeof(PTR_INFO1)), GFP_KERNEL);
	if (!shareinfo->ptrs) {
		kfree(shareinfo);
		return -ENOMEM;
	}

	shareinfo->shares = kzalloc((num_shares * sizeof(SRVSVC_SHARE_INFO1)),
				   GFP_KERNEL);
	if (!shareinfo->shares) {
		kfree(shareinfo->ptrs);
		kfree(shareinfo);
		return -ENOMEM;
	}

	rpc_request_rsp = &shareinfo->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	shareinfo->status = cpu_to_le32(WERR_INVALID_NAME);
	shareinfo->info_level = cpu_to_le32(1);
	shareinfo->switch_value = cpu_to_le32(0);

	list_for_each(tmp, &cifssrv_share_list) {
		share_info = &shareinfo->shares[cnt];
		ptr_info = &shareinfo->ptrs[cnt];
		share = list_entry(tmp, struct cifssrv_share, list);
		share_name_len = strlen(share->sharename) + 1;

		if (share_name_len > 13) {
			cifssrv_err("Not displaying share = %s",
					share->sharename);
			continue;
		}

		if (strcmp(share->sharename, share_name) == 0) {
			ptr_info->type = STYPE_DISKTREE;
			if (share->config.comment) {
				len =
				smbConvertToUTF16((__le16 *)share_info->comment,
				share->config.comment,
						256, server->local_nls, 0);
				comment_len = strlen(share->config.comment) + 1;
			} else {
				len =
				smbConvertToUTF16((__le16 *)share_info->comment,
				share->sharename,
						256, server->local_nls, 0);
				comment_len = strlen(share->sharename) + 1;
			}
			cifssrv_debug("share %s added\n", share->sharename);

			shareinfo->switch_value = cpu_to_le32(1);
			cifssrv_debug("comment len = %d share len = %d uni len = %d\n",
				      comment_len, share_name_len, len);

			/* Since sharename and comment are non-null*/
			ptr_info->ptr_netname = 1;
			ptr_info->ptr_remark = 1;

			smbConvertToUTF16((__le16 *)share_info->sharename,
					  share->sharename, 256,
					  server->local_nls, 0);
			share_info->str_info1.max_count = share_name_len;
			share_info->str_info1.offset = 0;
			share_info->str_info1.actual_count = share_name_len;

			share_info->str_info2.max_count = comment_len;
			share_info->str_info2.offset = 0;
			share_info->str_info2.actual_count = comment_len;
			shareinfo->status = cpu_to_le32(WERR_OK);
		}
	}

	return 0;
}

/**
 * srvsvc_net_share_info() - get share information on srvsvc pipe
 * @server:		TCP server instance of connection
 * @data:		SRVSVC_REQ data
 * @rpc_request_req:	rpc request
 *
 * parse srvspc packet for share_name. Get share information on requested
 * share_name
 *
 * Return:      0 on success or error number
 */
int srvsvc_net_share_info(struct tcp_server_info *server, char *data,
				RPC_REQUEST_REQ *rpc_request_req)
{
	SRVSVC_REQ *req = (SRVSVC_REQ *)data;
	SERVER_HANDLE handle;
	char *server_unc_ptr, *server_unc;
	int server_unc_len = 0;
	int ret = 0;
	int infolevel_len;
	UNISTR_INFO *istr_info;
	char *ptr, *share_name_ptr, *share_name;

	handle = req->server_unc_handle;
	server_unc_ptr = (char *)(data + sizeof(SERVER_HANDLE));
	server_unc = smb_strndup_from_utf16(server_unc_ptr, 256, 1,
			server->local_nls);
	if (IS_ERR(server_unc))
		return PTR_ERR(server_unc);

	cifssrv_debug("server_unc = %s unc size = %d\n", server_unc,
			handle.handle_info.actual_count);

	server_unc_len = 2 * handle.handle_info.actual_count;
	server_unc_len = ((server_unc_len + 3) & ~3);
	/* Add 2 for Pad */
	istr_info = (UNISTR_INFO *)((char *)(server_unc_ptr + server_unc_len));

	infolevel_len = 2 * istr_info->actual_count;
	infolevel_len = ((infolevel_len + 3) & ~3);

	cifssrv_debug("istr_info->max_count %u, offset %u, actual count %u\n",
	istr_info->max_count, istr_info->offset, istr_info->actual_count);
	share_name_ptr = (char *)((char *)istr_info + sizeof(UNISTR_INFO));
	share_name = smb_strndup_from_utf16(share_name_ptr, 256, 1,
				server->local_nls);
	if (IS_ERR(share_name))
		return PTR_ERR(share_name);

	ptr = (char *)((char *)istr_info + infolevel_len + sizeof(UNISTR_INFO));
	cifssrv_debug("Share name is %s\n", share_name);
	switch (le32_to_cpu(*(ptr))) {
	case INFO_1:
		cifssrv_debug("GOT SRVSVC pipe info level %u\n",
			       req->info_level);
		ret = init_srvsvc_share_info2(server, rpc_request_req,
								share_name);
		break;

	default:
		cifssrv_debug("SRVSVC pipe info level %u  not supported\n",
				req->info_level);
		return -EOPNOTSUPP;
	}

	return ret;
}

/**
 * init_wkssvc_share_info2() - helper function to initialize share info
 *			response on wkssvc pipe
 * @server:		TCP server instance of connection
 * @rpc_request_req:	rpc request
 *
 * Return:      0 on success or error number
 */
int init_wkssvc_share_info2(struct tcp_server_info *server,
				RPC_REQUEST_REQ *rpc_request_req)
{
	int len = 0;
	WKSSVC_SHARE_INFO1 *share_info;
	WKSSVC_SHARE_GETINFO *shareinfo;
	int share_name_len, comment_len;
	RPC_REQUEST_RSP *rpc_request_rsp;

	shareinfo = (WKSSVC_SHARE_GETINFO *)
			kzalloc(sizeof(WKSSVC_SHARE_GETINFO), GFP_KERNEL);
	if (!shareinfo) {
		return -ENOMEM;
	}
	server->pipe_desc->data = (char *)shareinfo;
	shareinfo->shares = kzalloc(sizeof(WKSSVC_SHARE_INFO1),
				   GFP_KERNEL);

	if (!shareinfo->shares) {
		kfree(shareinfo);
		return -ENOMEM;
	}

	rpc_request_rsp = &shareinfo->rpc_request_rsp;

	dcerpc_header_init(&rpc_request_rsp->hdr, RPC_RESPONSE,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_request_req->hdr.call_id);
	rpc_request_rsp->context_id = rpc_request_req->context_id;

	shareinfo->info_level = cpu_to_le32(100);
	shareinfo->refid = cpu_to_le32(1);
	shareinfo->platform_id = cpu_to_le32(500);
	shareinfo->ref_id1 = cpu_to_le32(1);
	shareinfo->ref_id2 = cpu_to_le32(1);
	shareinfo->maj =	cpu_to_le32(4);
	shareinfo->min = cpu_to_le32(9);
	share_info = &shareinfo->shares[0];


	len = smbConvertToUTF16((__le16 *)share_info->domain_name,
			workgroup, 256, server->local_nls, 0);
	comment_len = strlen(workgroup) + 1;


	share_name_len = strlen(server_string) + 1;
	cifssrv_debug("comment len = %d share len = %d uni len = %d\n",
			comment_len, share_name_len, len);

	smbConvertToUTF16((__le16 *)share_info->server_name,
			server_string, 256, server->local_nls, 0);

	share_info->str_info1.max_count = share_name_len;
	share_info->str_info1.offset = 0;
	share_info->str_info1.actual_count = share_name_len;

	share_info->str_info2.max_count = comment_len;
	share_info->str_info2.offset = 0;
	share_info->str_info2.actual_count = comment_len;

	shareinfo->status = cpu_to_le32(0);
	return 0;
}

/**
 * wkkssvc_net_share_info() - get share info on wkssvc pipe
 * @server:		TCP server instance of connection
 * @data:		wkssvc request data
 * @rpc_request_req:	rpc request
 *
 * Return:      0 on success or error number
 */
int wkkssvc_net_share_info(struct tcp_server_info *server, char *data,
				RPC_REQUEST_REQ *rpc_request_req)
{
	SRVSVC_REQ *req = (SRVSVC_REQ *)data;
	SERVER_HANDLE handle;
	char *server_unc_ptr, *server_unc;
	int server_unc_len = 0;
	int ret = 0;
	int *info_level;

	handle = req->server_unc_handle;
	server_unc_ptr = (char *)(data + sizeof(SERVER_HANDLE));
	server_unc = smb_strndup_from_utf16(server_unc_ptr, 256, 1,
			server->local_nls);
	if (IS_ERR(server_unc))
		return PTR_ERR(server_unc);

	cifssrv_debug("server_unc = %s unc size = %d\n", server_unc,
			handle.handle_info.actual_count);

	server_unc_len = 2 * handle.handle_info.actual_count;
	server_unc_len = ((server_unc_len + 3) & ~3);
	/* Add 2 for Pad */
	info_level = (int *)((char *)(server_unc_ptr + server_unc_len));

	switch (le32_to_cpu(*info_level)) {
	case INFO_100:
		cifssrv_debug("GOT WKSSVC pipe info level %u\n",
			       le32_to_cpu(*info_level));

		ret = init_wkssvc_share_info2(server, rpc_request_req);
		break;

	default:
		cifssrv_err("WKSSVC pipe info level %u  not supported\n",
				req->info_level);
		return -EOPNOTSUPP;
	}

	return ret;
}

/**
 * rpc_request() - rpc request dispatcher
 * @server:	TCP server instance of connection
 * @in_data:	wkssvc request data
 *
 * parse rpc request command number, and call corresponding
 * command handler
 *
 * Return:      0 on success or error number
 */
static int srvsvc_rpc_request(struct tcp_server_info *server, char *in_data)
{
	RPC_REQUEST_REQ *rpc_request_req = (RPC_REQUEST_REQ *)in_data;
	int opnum;
	char *data;
	int ret = 0;

	opnum = cpu_to_le16(rpc_request_req->opnum);
	server->pipe_desc->opnum = opnum;
	switch (opnum) {
	case SRV_NET_SHARE_ENUM_ALL:
		cifssrv_debug("Got SRV_NET_SHARE_ENUM_ALL\n");
		data = in_data + sizeof(RPC_REQUEST_REQ);
		ret = srvsvc_net_share_enum_all(server, data, rpc_request_req);
		break;
	case SRV_NET_SHARE_GETINFO:
		cifssrv_debug("Got SRV_NET_SHARE_GETINFO\n");
		data = in_data + sizeof(RPC_REQUEST_REQ);
		ret = srvsvc_net_share_info(server, data, rpc_request_req);
		break;
	case WKSSVC_NET_SHARE_GETINFO:
		cifssrv_debug("Got WKSSVC_SHARE_GETINFO\n");
		data = in_data + sizeof(RPC_REQUEST_REQ);
		ret = wkkssvc_net_share_info(server, data, rpc_request_req);
		break;
	default:
		cifssrv_debug("WKSSVC pipe opnum not supported = %d\n", opnum);
		return -EOPNOTSUPP;
	}
	return ret;
}

int winreg_rpc_request(struct tcp_server_info *server, char *in_data)
{
	RPC_REQUEST_REQ *rpc_request_req = (RPC_REQUEST_REQ *)in_data;
	int opnum;
	char *data;
	int ret = 0;

	opnum = cpu_to_le16(rpc_request_req->opnum);
	server->pipe_desc->opnum = opnum;
	data = in_data + sizeof(RPC_REQUEST_REQ);
	cifssrv_debug("Opnum %d\n", opnum);

	switch (opnum) {
	case WINREG_OPENHKCR:
		cifssrv_debug("Got WINREG_OPENHKCR\n");
		/* fall through */
	case WINREG_OPENHKCU:
		cifssrv_debug("Got WINREG_OPENHKCU\n");
		/* fall through */
	case WINREG_OPENHKLM:
		cifssrv_debug("Got WINREG_OPENHKLM\n");
		/* fall through */
	case WINREG_OPENHKU:
		cifssrv_debug("Got WINREG_OPENHKU\n");
		ret = winreg_open_root_key(server,
				opnum, rpc_request_req, data);
		break;
	case WINREG_GETVERSION:
		cifssrv_debug("Got WINREG_GETVERSION\n");
		ret = winreg_get_version(server, rpc_request_req, data);
		break;
	case WINREG_DELETEKEY:
		cifssrv_debug("Got WINREG_DELETEKEY\n");
		ret = winreg_delete_key(server, rpc_request_req, data);
		break;
	case WINREG_FLUSHKEY:
		cifssrv_debug("Got WINREG_FLUSHKEY\n");
		ret = winreg_flush_key(server, rpc_request_req, data);
		break;
	case WINREG_OPENKEY:
		cifssrv_debug("Got WINREG_OPENKEY\n");
		ret = winreg_open_key(server, rpc_request_req, data);
		break;
	case WINREG_CREATEKEY:
		cifssrv_debug("Got WINREG_CREATEKEY\n");
		ret = winreg_create_key(server, rpc_request_req, data);
		break;
	case WINREG_CLOSEKEY:
		cifssrv_debug("Got WINREG_CLOSEKEY\n");
		ret = winreg_close_key(server, rpc_request_req, data);
		break;
	default:
		cifssrv_debug("WINREG pipe opnum not supported = %d\n", opnum);
		return -EOPNOTSUPP;
	}
	return ret;
}

int rpc_request(struct tcp_server_info *server, char *in_data)
{
	int ret = 0;
	cifssrv_debug("server pipe request %d\n", server->pipe_desc->pipe_type);
	switch (server->pipe_desc->pipe_type) {
	case SRVSVC:
		cifssrv_debug("SRVSVC pipe\n");
		ret = srvsvc_rpc_request(server, in_data);
		break;
	case WINREG:
		cifssrv_debug("WINREG pipe\n");
		ret = winreg_rpc_request(server, in_data);
		break;
	default:
		cifssrv_debug("pipe not supported\n");
		return -EOPNOTSUPP;
	}
	return ret;
}

/**
 * rpc_bind() - rpc bind request handler
 * @server:	TCP server instance of connection
 * @in_data:	rpc bind request data
 *
 * Return:      0 on success or error number
 */
int rpc_bind(struct tcp_server_info *server, char *in_data)
{
	RPC_BIND_REQ *rpc_bind_req = (RPC_BIND_REQ *)in_data;
	char *pipe_name = NULL;
	int len;
	RPC_CONTEXT *rpc_context;
	RPC_IFACE *transfer;
	RPC_BIND_RSP *rpc_bind_rsp;
	int version_maj;
	int pipe_type;
	int num_ctx;
	int i = 0;
	int offset = 0;
	rpc_context = (RPC_CONTEXT *)(((char *)in_data) + sizeof(RPC_BIND_REQ));
	transfer = (RPC_IFACE *)(((char *)in_data) + sizeof(RPC_BIND_REQ) +
				   sizeof(RPC_CONTEXT));
	rpc_bind_rsp = kzalloc(sizeof(RPC_BIND_RSP), GFP_KERNEL);
	if (!rpc_bind_rsp)
		return -ENOMEM;

	version_maj = rpc_context->abstract.version_maj;
	pipe_type = server->pipe_desc->pipe_type;

	server->pipe_desc->data = (char *)rpc_bind_rsp;

	rpc_bind_rsp->addr.sec_addr = kmalloc(256, GFP_KERNEL);
	if (!rpc_bind_rsp->addr.sec_addr) {
		kfree(rpc_bind_rsp);
		return -ENOMEM;
	}

	/* Initialize header */
	dcerpc_header_init(&rpc_bind_rsp->hdr, RPC_BINDACK,
				RPC_FLAG_FIRST | RPC_FLAG_LAST,
				rpc_bind_req->hdr.call_id);
	cifssrv_debug("incoming call id = %u frag_len = %u\n",
		      rpc_bind_req->hdr.call_id, rpc_bind_req->hdr.frag_len);

	/* Update bind info */
	rpc_bind_rsp->bind_info.max_tsize = rpc_bind_req->max_tsize;
	rpc_bind_rsp->bind_info.max_rsize = rpc_bind_req->max_rsize;
	/* Using hard coded assoc_gid value, same as as used by Samba*/
	rpc_bind_rsp->bind_info.assoc_gid = 0x53f0;

	num_ctx = rpc_bind_req->num_contexts;

	cifssrv_debug("max_tsize = %u max_rsize = %u\n",
		       rpc_bind_req->max_tsize, rpc_bind_req->max_rsize);
	cifssrv_debug("RPC authentication length %d\n",
						rpc_bind_req->hdr.auth_len);
	/* Update pipe name*/
	if (pipe_type == SRVSVC) {
		if (version_maj == 3)
			pipe_name = "\\PIPE\\srvsvc";
		else if (version_maj == 1)
			pipe_name = "\\PIPE\\wkssvc";
	} else if (pipe_type == WINREG) {
		pipe_name = "\\PIPE\\winreg";
		rpc_bind_rsp->BufferLength = 0;
		if (rpc_bind_req->hdr.auth_len != 0) {
			NEGOTIATE_MESSAGE *negblob;
			CHALLENGE_MESSAGE *chgblob;
			__le16 name[8];
			while (i < num_ctx) {
				offset  = offset + sizeof(RPC_CONTEXT);
				i++;
			}
			rpc_bind_rsp->auth.auth_type = 10;
			rpc_bind_rsp->auth.auth_level = 6;
			rpc_bind_rsp->auth.auth_pad_len = 0;
			rpc_bind_rsp->auth.auth_reserved = 0;
			rpc_bind_rsp->auth.auth_ctx_id = 1;
			negblob = (NEGOTIATE_MESSAGE *)(((char *)in_data) +
						sizeof(RPC_BIND_REQ) +
						offset + sizeof(RPC_AUTH_INFO));
			if (*(__le64 *)negblob->Signature ==
							NTLMSSP_SIGNATURE_VAL)
				cifssrv_debug("%s NTLMSSP present\n", __func__);
			else
				cifssrv_debug("%s NTLMSSP not present\n",
								__func__);
			if (negblob->MessageType == NtLmNegotiate) {
				cifssrv_debug("%s negotiate phase\n", __func__);
				chgblob = kzalloc(sizeof(CHALLENGE_MESSAGE),
								GFP_KERNEL);
				len = smb_strtoUTF16(name, netbios_name,
							strlen(netbios_name),
					server->local_nls);
				rpc_bind_rsp->Buffer = kzalloc(
					sizeof(CHALLENGE_MESSAGE) +
					sizeof(TargetInfo)*5 +
					UNICODE_LEN(len)*4, GFP_KERNEL);
				rpc_bind_rsp->BufferLength =
				build_ntlmssp_challenge_blob(chgblob,
					rpc_bind_rsp->Buffer, 0, server);
				memcpy(rpc_bind_rsp->Buffer, chgblob,
						sizeof(CHALLENGE_MESSAGE));
				kfree(chgblob);
			}
		}

	} else {
		cifssrv_err("invalid version %d\n", version_maj);
		kfree(rpc_bind_rsp->addr.sec_addr);
		kfree(rpc_bind_rsp);
		return -EINVAL;
	}

	memcpy(rpc_bind_rsp->addr.sec_addr, pipe_name, strlen(pipe_name));
	len = strlen(pipe_name) + 1;
	rpc_bind_rsp->addr.sec_addr[len - 1] = '\0';
	rpc_bind_rsp->addr.sec_addr_len = len;
	cifssrv_debug("pipe_name len = %d\n", len);

	/* Results */
	rpc_bind_rsp->results.num_results = 1;
	rpc_bind_rsp->results.reserved1 = 0;
	rpc_bind_rsp->results.reserved2 = 0;
	rpc_bind_rsp->results.result = 0;
	rpc_bind_rsp->results.reason = 0;

	/* Interface */
	rpc_bind_rsp->transfer = kmalloc(sizeof(RPC_IFACE), GFP_KERNEL);

	if (!rpc_bind_rsp->transfer) {
		kfree(rpc_bind_rsp->addr.sec_addr);
		kfree(rpc_bind_rsp);
		return -ENOMEM;
	}

	cifssrv_debug("num syntaxes = %u\n",
		       rpc_context->num_transfer_syntaxes);

	memcpy(rpc_bind_rsp->transfer, transfer, sizeof(RPC_IFACE));
	return 0;
}

/**
 * handle_netshareenum_info1() - helper function for share info using LANMAN
 *		request
 * @server:	TCP server instance of connection
 * @in_params:	LANMAN request parameters
 * @out_data:	output response buffer
 *
 * Return:      response buffer size or error number
 */
static int handle_netshareenum_info1(struct tcp_server_info *server,
				     LANMAN_PARAMS *in_params, char *out_data)
{
	LANMAN_NETSHAREENUM_RESP *resp;
	NETSHAREINFO1 *info1;
	struct list_head *tmp;
	struct cifssrv_share *share;
	int out_buffersize, comment_len = 0, comment_offset;
	int num_shares = 0;
	char *data_buf, *comment_buf;

	resp = (LANMAN_NETSHAREENUM_RESP *)out_data;

	data_buf = resp->RAPOutData;

	info1 = (NETSHAREINFO1 *)resp->RAPOutData;

	num_shares = cifssrv_num_shares;
	comment_offset = num_shares * sizeof(NETSHAREINFO1);

	list_for_each(tmp, &cifssrv_share_list) {
		memset(info1, 0, sizeof(NETSHAREINFO1));
		share = list_entry(tmp, struct cifssrv_share, list);
		memcpy(info1->NetworkName, share->sharename,
			strlen(share->sharename));

		comment_buf = resp->RAPOutData + comment_offset;

		info1->RemarkOffsetLow = comment_offset;

		info1->RemarkOffsetHigh = 0;

		if (strcmp(share->sharename, "IPC$") == 0) {
			info1->Type = STYPE_IPC;
			comment_len = strlen("IPC share");
			memcpy(comment_buf, "IPC share", comment_len);
		} else {
			if (share->config.comment) {
				comment_len = strlen(share->config.comment);
				memcpy(comment_buf, share->config.comment,
				       comment_len);
			} else {
				comment_len = strlen(share->sharename);
				memcpy(comment_buf, share->config.comment,
				       comment_len);
			}
			info1->Type = STYPE_DISKTREE;
		}

		/* Increment for '\0' */
		comment_buf[comment_len] = '\0';
		comment_len++;
		comment_offset += comment_len;

		cifssrv_debug("share %s added comment_offset = %d\n",
				share->sharename, comment_offset);
		info1++;
	}

	out_buffersize = sizeof(LANMAN_NETSHAREENUM_RESP) - 1 + comment_offset;

	resp->Win32ErrorCode = 0;
	resp->Converter = 0;
	resp->EntriesReturned = num_shares;
	resp->EntriesAvailable = num_shares;

	cifssrv_debug("num_shares = %d out buffer size = %d\n",
			num_shares, out_buffersize);

	return out_buffersize;
}

/**
 * handle_netshareenum() - get share info using LANMAN request
 * @server:	TCP server instance of connection
 * @req:	LANMAN request
 * @out_data:	output response buffer
 *
 * Return:      response buffer size or error number
 */
static int handle_netshareenum(struct tcp_server_info *server, LANMAN_REQ *req,
				char *out_data)
{
	char *paramdesc, *datadesc;
	int paramdesc_len, datadesc_len;
	LANMAN_PARAMS *in_params;
	int info_level;
	int ret = 0;

	paramdesc = req->ParamDesc;

	paramdesc_len = strlen("WrLeh") + 1;
	cifssrv_debug("paramdesc = %s paramdesc_len = %d\n",
			paramdesc, paramdesc_len);

	if (strcmp(paramdesc, "WrLeh") != 0)
		return -EOPNOTSUPP;

	datadesc = (req->ParamDesc + paramdesc_len);

	datadesc_len = strlen(datadesc) + 1;

	cifssrv_debug("datadesc = %s datadesc_len = %d\n",
			datadesc, datadesc_len);

	in_params = (LANMAN_PARAMS *)(datadesc + datadesc_len);

	info_level = le16_to_cpu(in_params->InfoLevel);

	cifssrv_debug("info_level = %d\n", info_level);

	switch (info_level) {
	case INFO_1:
		cifssrv_debug("GOT RAP_NetshareEnum Info1\n");
		ret = handle_netshareenum_info1(server, in_params, out_data);
		break;
	default:
		cifssrv_debug("Info level = %d not supported\n", info_level);
		ret = -EOPNOTSUPP;
	}

	return ret;
}

/**
 * handle_wkstagetinfo_info10() - helper function to get target info command
 *		using LANMAN request
 * @server:	TCP server instance of connection
 * @in_params:	LANMAN request parameters
 * @out_data:	output response buffer
 *
 * Return:      response buffer size or error number
 */
int handle_wkstagetinfo_info10(struct tcp_server_info *server,
			       LANMAN_PARAMS *in_params, char *out_data)
{
	LANMAN_WKSTAGEINFO_RESP *resp;
	NETWKSTAGEINFO10 *info10;
	int out_buffersize;
	int offset, len;
	char *data;
	struct cifssrv_usr *usr, *tmp;
	int user_valid = false;

	resp = (LANMAN_WKSTAGEINFO_RESP *)out_data;

	offset = sizeof(NETWKSTAGEINFO10);

	info10 = (NETWKSTAGEINFO10 *)resp->RAPOutData;
	data = resp->RAPOutData;

	/* Add name of workstation */
	data += offset;
	info10->ComputerName = offset;
	len = strlen(server_string);
	memcpy(data, server_string, len);
	data[len] = '\0';
	offset += len + 1;
	data += len + 1;

	/* Add user name */
	info10->UserName = offset;
	list_for_each_entry_safe(usr, tmp, &cifssrv_usr_list, list) {
		if (server->vuid  == usr->vuid) {
			user_valid = true;
			break;
		}
	}

	/* If valid user is found provide logged in user
	   otherwise send default user "root" */
	if (user_valid == true) {
		len = strlen(usr->name);
		memcpy(data, usr->name, len);
	} else {
		return -EINVAL;
	}

	data[len] = '\0';
	offset += len + 1;
	data += len + 1;

	/* Add Domain name */
	info10->LanGroup = offset;
	len = strlen(workgroup);
	memcpy(data, workgroup, len);
	data[len] = '\0';
	offset += len + 1;
	data += len + 1;

	/* Add Major version*/
	info10->VerMajor = CIFSSRV_MAJOR_VERSION;

	/* Add Minor Version */
	info10->VerMinor = CIFSSRV_MINOR_VERSION;

	/* User logged domain */
	info10->LogonDomain = offset;
	len = strlen(workgroup);
	memcpy(data, workgroup, len);
	data[len] = '\0';
	offset += len + 1;
	data += len + 1;

	/* All domains */
	info10->OtherDomain = offset;
	len = strlen(workgroup);
	memcpy(data, workgroup, len);
	data[len] = '\0';
	offset += len + 1;

	resp->TotalBytesAvailable = offset;
	resp->Win32ErrorCode = 0;
	resp->Converter = 0;

	out_buffersize = offset + sizeof(LANMAN_WKSTAGEINFO_RESP) - 1;

	return out_buffersize;
}

/**
 * handle_wkstagetinfo() - handle target info command using
 *			LANMAN request
 * @server:	TCP server instance of connection
 * @in_params:	LANMAN request parameters
 * @out_data:	output response buffer
 *
 * Return:      response buffer size or error number
 */
int handle_wkstagetinfo(struct tcp_server_info *server,
			LANMAN_REQ *req, char *out_data)
{
	char *paramdesc, *datadesc;
	int paramdesc_len, datadesc_len;
	LANMAN_PARAMS *in_params;
	int info_level;
	int ret = 0;

	paramdesc = req->ParamDesc;

	paramdesc_len = strlen("WrLh") + 1;
	cifssrv_debug("paramdesc = %s paramdesc_len = %d\n",
			paramdesc, paramdesc_len);

	if (strcmp(paramdesc, "WrLh") != 0)
		return -EOPNOTSUPP;

	datadesc = (req->ParamDesc + paramdesc_len);

	datadesc_len = strlen(datadesc) + 1;

	cifssrv_debug("datadesc = %s datadesc_len = %d\n",
			datadesc, datadesc_len);

	in_params = (LANMAN_PARAMS *)(datadesc + datadesc_len);

	info_level = le16_to_cpu(in_params->InfoLevel);

	cifssrv_debug("info_level = %d\n", info_level);

	switch (info_level) {
	case INFO_10:
		cifssrv_debug("GOT RAP_WkstaGetInfo Info10\n");
		ret = handle_wkstagetinfo_info10(server, in_params, out_data);
		break;
	default:
		cifssrv_debug("Info level = %d not supported\n", info_level);
		ret = -EOPNOTSUPP;
	}

	return ret;
}

/**
 * handle_lanman_pipe() - dispatcher for LANMAN pipe requests
 * @server:	TCP server instance of connection
 * @in_data:	LANMAN request parameters
 * @out_data:	output response buffer
 * @param_len:	LANMAN request parameters length
 *
 * Return:      response buffer size or error number
 */
int handle_lanman_pipe(struct tcp_server_info *server, char *in_data,
		       char *out_data, int *param_len)
{
	LANMAN_REQ *req = (LANMAN_REQ *)in_data;
	int opcode;
	int ret = 0;

	opcode = le16_to_cpu(req->RAPOpcode);

	switch (opcode) {
	case RAP_NetshareEnum:
		cifssrv_debug("GOT RAP_NetshareEnum\n");
		ret = handle_netshareenum(server, req, out_data);
		if (ret < 0)
			ret = -EOPNOTSUPP;
		else
			*param_len = 8;
		break;
	case RAP_WkstaGetInfo:
		cifssrv_debug("GOT RAP_WkstaGetInfo\n");
		ret = handle_wkstagetinfo(server, req, out_data);
		if (ret < 0)
			ret = -EOPNOTSUPP;
		else
			*param_len = 6;
		break;
	default:
		cifssrv_debug("opcode = %d not supported\n", opcode);
		ret = -EOPNOTSUPP;
	}

	return ret;
}
