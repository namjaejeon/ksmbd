// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __SMB_COMMON_H__
#define __SMB_COMMON_H__

#include <linux/kernel.h>

#include "smb1pdu.h"
#include "smb2pdu.h"

#define SMB1_PROT		0
#define SMB2_PROT		1
#define SMB21_PROT		2
/* multi-protocol negotiate request */
#define SMB2X_PROT		3
#define SMB30_PROT		4
#define SMB302_PROT		5
#define SMB311_PROT		6
#define BAD_PROT		0xFFFF

#define SMB1_VERSION_STRING	"1.0"
#define SMB20_VERSION_STRING	"2.0"
#define SMB21_VERSION_STRING	"2.1"
#define SMB30_VERSION_STRING	"3.0"
#define SMB302_VERSION_STRING	"3.02"
#define SMB311_VERSION_STRING	"3.1.1"

/* Dialects */
#define SMB10_PROT_ID		0x00
#define SMB20_PROT_ID		0x0202
#define SMB21_PROT_ID		0x0210
/* multi-protocol negotiate request */
#define SMB2X_PROT_ID		0x02FF
#define SMB30_PROT_ID		0x0300
#define SMB302_PROT_ID		0x0302
#define SMB311_PROT_ID		0x0311
#define BAD_PROT_ID		0xFFFF

struct cifsd_work;
struct cifsd_tcp_conn;
struct cifsd_dir_info;
struct cifsd_file;
struct dir_context;

#define IS_SMB2(x)		((x)->vals->protocol_id != SMB10_PROT_ID)

#define HEADER_SIZE(conn)		((conn)->vals->header_size)
#define HEADER_SIZE_NO_BUF_LEN(conn)	((conn)->vals->header_size - 4)
#define MAX_HEADER_SIZE(conn)		((conn)->vals->max_header_size)

int cifsd_min_protocol(void);
int cifsd_max_protocol(void);

int cifsd_lookup_protocol_idx(char *str);

int cifsd_verify_smb_message(struct cifsd_work *work);
bool cifsd_smb_request(struct cifsd_tcp_conn *conn);

int cifsd_lookup_dialect_by_id(__le16 *cli_dialects, __le16 dialects_count);

int cifsd_negotiate_smb_dialect(void *buf);
int cifsd_init_smb_server(struct cifsd_work *work);

bool cifsd_pdu_size_has_room(unsigned int pdu);

struct cifsd_kstat;
int cifsd_populate_dot_dotdot_entries(struct cifsd_tcp_conn *conn,
				      int info_level,
				      struct cifsd_file *dir,
				      struct cifsd_dir_info *d_info,
				      char *search_pattern,
				      int (*fn)(struct cifsd_tcp_conn *,
						int,
						struct cifsd_dir_info *,
						struct cifsd_kstat *));

int cifsd_extract_shortname(struct cifsd_tcp_conn *conn,
			    char *longname,
			    char *shortname);

int cifsd_fill_dirent(struct dir_context *ctx,
		      const char *name,
		      int namlen,
		      loff_t offset,
		      u64 ino,
		      unsigned int d_type);

void cifsd_init_smb2_server_common(struct cifsd_tcp_conn *conn);
int cifsd_smb_negotiate_common(struct cifsd_work *work, unsigned int command);

unsigned int cifsd_max_msg_size(void);
unsigned int cifsd_default_io_size(void);
unsigned int cifsd_small_buffer_size(void);
#endif /* __SMB_COMMON_H__ */
