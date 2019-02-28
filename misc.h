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

int match_pattern(const char *str, const char *pattern);

int check_invalid_char(char *filename);

int parse_stream_name(char *filename, char **stream_name, int *s_type);

char *convert_to_nt_pathname(char *filename, char *sharepath);

int get_nlink(struct kstat *st);

void cifsd_conv_path_to_unix(char *path);
void cifsd_conv_path_to_windows(char *path);

char *extract_sharename(char *treename);

char *convert_to_unix_name(struct cifsd_share_config *share, char *name);

char *convname_updatenextoffset(char *namestr, int len, int size,
		const struct nls_table *local_nls, int *name_len,
		int *next_entry_offset, int *buf_len, int *data_count,
		int alignment, bool no_namelen_field);
#endif /* __CIFSD_MISC_H__ */
