// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_MISC_H__
#define __CIFSD_MISC_H__

struct cifsd_share_config;
struct nls_table;
struct kstat;
struct cifsd_file;

void dump_smb_msg(void *buf, int smb_buf_length);

int get_pos_strnstr(const char *s1, const char *s2, size_t len);

int smb_check_shared_mode(struct file *filp, struct cifsd_file *curr_fp);

int pattern_cmp(const char *string, const char *pattern);

bool is_matched(const char *fname, const char *exp);

int check_invalid_char(char *filename);
int check_invalid_char_stream(char *stream_name);

int parse_stream_name(char *filename, char **stream_name, int *s_type);

int construct_xattr_stream_name(char *stream_name, char **xattr_stream_name);

char *convert_to_nt_pathname(char *filename, char *sharepath);

int get_nlink(struct kstat *st);

void convert_delimiter(char *path, int flags);

char *extract_sharename(char *treename);

char *convert_to_unix_name(struct cifsd_share_config *share, char *name);

char *convname_updatenextoffset(char *namestr, int len, int size,
		const struct nls_table *local_nls, int *name_len,
		int *next_entry_offset, int *buf_len, int *data_count,
		int alignment, bool no_namelen_field);
#endif /* __CIFSD_MISC_H__ */
