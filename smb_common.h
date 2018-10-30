// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __SMB_COMMON_H__
#define __SMB_COMMON_H__

#include <linux/kernel.h>

#define CIFSD_SMB1_PROT		0
#define CIFSD_SMB2_PROT		1
#define CIFSD_SMB21_PROT		2
/* multi-protocol negotiate request */
#define CIFSD_SMB2X_PROT		3
#define CIFSD_SMB30_PROT		4
#define CIFSD_SMB302_PROT		5
#define CIFSD_SMB311_PROT		6
#define CIFSD_BAD_PROT		0xFFFF

#define CIFSD_SMB1_VERSION_STRING	"1.0"
#define CIFSD_SMB20_VERSION_STRING	"2.0"
#define CIFSD_SMB21_VERSION_STRING	"2.1"
#define CIFSD_SMB30_VERSION_STRING	"3.0"
#define CIFSD_SMB302_VERSION_STRING	"3.02"
#define CIFSD_SMB311_VERSION_STRING	"3.1.1"

/* Dialects */
#define CIFSD_SMB10_PROT_ID		0x00
#define CIFSD_SMB20_PROT_ID		0x0202
#define CIFSD_SMB21_PROT_ID		0x0210
/* multi-protocol negotiate request */
#define CIFSD_SMB2X_PROT_ID		0x02FF
#define CIFSD_SMB30_PROT_ID		0x0300
#define CIFSD_SMB302_PROT_ID		0x0302
#define CIFSD_SMB311_PROT_ID		0x0311
#define CIFSD_BAD_PROT_ID		0xFFFF

#define IS_SMB2(x) ((x)->vals->protocol_id != CIFSD_SMB10_PROT_ID)

struct cifsd_work;
struct cifsd_tcp_conn;
struct cifsd_dir_info;
struct cifsd_file;
struct dir_context;

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
#endif /* __SMB_COMMON_H__ */
