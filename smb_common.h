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

#ifdef CONFIG_CIFS_SMB1_SERVER
#define CIFSD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb_hdr))
#else
#define CIFSD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb2_hdr))
#endif

struct cifsd_work;
struct cifsd_tcp_conn;
struct cifsd_tcp_conn;

int cifsd_min_protocol(void);
int cifsd_max_protocol(void);

int get_protocol_idx(char *str);

int check_message(struct cifsd_work *work);
bool is_smb_request(struct cifsd_tcp_conn *conn);

int cifsd_lookup_smb1_dialect(char *cli_dialects, __le16 byte_count);
int cifsd_lookup_smb2_dialect(__le16 *cli_dialects, __le16 dialects_count);

int cifsd_negotiate_smb_dialect(void *buf);
void cifsd_init_smb_server(struct cifsd_work *work);

#endif /* __SMB_COMMON_H__ */
