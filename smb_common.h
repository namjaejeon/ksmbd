// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __SMB_COMMON_H__
#define __SMB_COMMON_H__

#include <linux/kernel.h>

#include "smb1pdu.h"
#include "smb2pdu.h"

/* cifsd's Specific ERRNO */
#define ESHARE			50000

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

#define SMB_ECHO_INTERVAL	(60*HZ)

extern struct list_head global_lock_list;

struct cifsd_work;
struct cifsd_conn;
struct cifsd_dir_info;
struct cifsd_file;
struct dir_context;

#define IS_SMB2(x)		((x)->vals->protocol_id != SMB10_PROT_ID)

#define HEADER_SIZE(conn)		((conn)->vals->header_size)
#define HEADER_SIZE_NO_BUF_LEN(conn)	((conn)->vals->header_size - 4)
#define MAX_HEADER_SIZE(conn)		((conn)->vals->max_header_size)

struct smb_version_values {
	char		*version_string;
	__u16		protocol_id;
	__le16		lock_cmd;
	__u32		capabilities;
	__u32		max_io_size;
	__u32		large_lock_type;
	__u32		exclusive_lock_type;
	__u32		shared_lock_type;
	__u32		unlock_lock_type;
	size_t		header_size;
	size_t		max_header_size;
	size_t		read_rsp_size;
	unsigned int	cap_unix;
	unsigned int	cap_nt_find;
	unsigned int	cap_large_files;
	__u16		signing_enabled;
	__u16		signing_required;
	size_t		create_lease_size;
	size_t		create_durable_size;
	size_t		create_durable_v2_size;
	size_t		create_mxac_size;
	size_t		create_disk_id_size;
};

struct smb_version_ops {
	int (*get_cmd_val)(struct cifsd_work *swork);
	int (*init_rsp_hdr)(struct cifsd_work *swork);
	void (*set_rsp_status)(struct cifsd_work *swork, __le32 err);
	int (*allocate_rsp_buf)(struct cifsd_work *work);
	int (*check_user_session)(struct cifsd_work *work);
	int (*get_cifsd_tcon)(struct cifsd_work *work);
	int (*is_sign_req)(struct cifsd_work *work, unsigned int command);
	int (*check_sign_req)(struct cifsd_work *work);
	void (*set_sign_rsp)(struct cifsd_work *work);
	int (*generate_signingkey)(struct cifsd_session *sess, bool binding,
		char *hash_value);
	int (*generate_encryptionkey)(struct cifsd_session *sess);
	int (*is_transform_hdr)(void *buf);
	int (*decrypt_req)(struct cifsd_work *work);
	int (*encrypt_resp)(struct cifsd_work *work);
};

struct smb_version_cmds {
	int (*proc)(struct cifsd_work *swork);
};

int cifsd_min_protocol(void);
int cifsd_max_protocol(void);

int cifsd_lookup_protocol_idx(char *str);

int cifsd_verify_smb_message(struct cifsd_work *work);
bool cifsd_smb_request(struct cifsd_conn *conn);

int cifsd_lookup_dialect_by_id(__le16 *cli_dialects, __le16 dialects_count);

int cifsd_negotiate_smb_dialect(void *buf);
int cifsd_init_smb_server(struct cifsd_work *work);

bool cifsd_pdu_size_has_room(unsigned int pdu);

struct cifsd_kstat;
int cifsd_populate_dot_dotdot_entries(struct cifsd_conn *conn,
				      int info_level,
				      struct cifsd_file *dir,
				      struct cifsd_dir_info *d_info,
				      char *search_pattern,
				      int (*fn)(struct cifsd_conn *,
						int,
						struct cifsd_dir_info *,
						struct cifsd_kstat *));

int cifsd_extract_shortname(struct cifsd_conn *conn,
			    const char *longname,
			    char *shortname);

void cifsd_init_smb2_server_common(struct cifsd_conn *conn);
int cifsd_smb_negotiate_common(struct cifsd_work *work, unsigned int command);

int cifsd_smb_check_shared_mode(struct file *filp, struct cifsd_file *curr_fp);

unsigned int cifsd_small_buffer_size(void);
unsigned int cifsd_server_side_copy_max_chunk_count(void);
unsigned int cifsd_server_side_copy_max_chunk_size(void);
unsigned int cifsd_server_side_copy_max_total_size(void);
bool is_asterisk(char *p);

static inline unsigned int get_rfc1002_len(void *buf)
{
	return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

static inline void inc_rfc1001_len(void *buf, int count)
{
	be32_add_cpu((__be32 *)buf, count);
}
#endif /* __SMB_COMMON_H__ */
