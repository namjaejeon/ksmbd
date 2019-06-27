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

int cifsd_validate_filename(char *filename);

int parse_stream_name(char *filename, char **stream_name, int *s_type);

char *convert_to_nt_pathname(char *filename, char *sharepath);

int get_nlink(struct kstat *st);

void cifsd_conv_path_to_unix(char *path);
void cifsd_conv_path_to_windows(char *path);

char *extract_sharename(char *treename);

char *convert_to_unix_name(struct cifsd_share_config *share, char *name);

#define CIFSD_DIR_INFO_ALIGNMENT	8

struct cifsd_dir_info;
char *cifsd_convert_dir_info_name(struct cifsd_dir_info *d_info,
				  const struct nls_table *local_nls,
				  int *conv_len);
#endif /* __CIFSD_MISC_H__ */
