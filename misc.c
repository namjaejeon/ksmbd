// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/xattr.h>

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#include "smb2pdu.h"
#include "transport_tcp.h"
#include "vfs.h"

#include "mgmt/share_config.h"

/* @FIXME rework this code */

/**
 * dump_smb_msg() - print smb packet for debugging
 * @buf:		smb packet
 * @smb_buf_length:	packet print length
 *
 */
void dump_smb_msg(void *buf, int smb_buf_length)
{
	int i, j;
	char debug_line[33];
	unsigned char *buffer = buf;

	if (likely(cifsd_debugging != 2))
		return;

	for (i = 0, j = 0; i < smb_buf_length; i++, j++) {
		if (i % 16 == 0) {
			/* have reached the beginning of line */
			pr_err("%04x ", i);
			pr_cont("| ");
			j = 0;
		}

		pr_cont("%02x ", buffer[i]);
		debug_line[2 * j] = ' ';
		if (isprint(buffer[i]))
			debug_line[1 + (2 * j)] = buffer[i];
		else
			debug_line[1 + (2 * j)] = '_';

		if (i % 16 == 15) {
			/* reached end of line, time to print ascii */
			debug_line[32] = 0;
			pr_cont(" | %s\n", debug_line);
		}
	}
	for (; j < 16; j++) {
		pr_cont("   ");
		debug_line[2 * j] = ' ';
		debug_line[1 + (2 * j)] = ' ';
	}
	pr_cont(" | %s\n", debug_line);
	return;
}

int get_pos_strnstr(const char *s1, const char *s2, size_t len)
{
	size_t l2;
	int index = 0;

	l2 = strlen(s2);
	if (!l2)
		return 0;

	while (len >= l2) {
		len--;
		if (!memcmp(s1, s2, l2))
			return index;
		s1++;
		index++;
	}
	return 0;
}

int smb_check_shared_mode(struct file *filp, struct cifsd_file *curr_fp)
{
	int rc = 0;
	struct cifsd_file *prev_fp;
	struct list_head *cur;

	/*
	 * Lookup fp in master fp list, and check desired access and
	 * shared mode between previous open and current open.
	 */
	spin_lock(&curr_fp->f_ci->m_lock);
	list_for_each(cur, &curr_fp->f_ci->m_fp_list) {
		prev_fp = list_entry(cur, struct cifsd_file, node);
		if (prev_fp->f_state == FP_FREEING)
			continue;
		if (file_inode(filp) == FP_INODE(prev_fp)) {
			if (prev_fp->is_stream && curr_fp->is_stream)
				if (strcmp(prev_fp->stream.name,
					curr_fp->stream.name))
					continue;

			if (prev_fp->is_durable) {
				prev_fp->is_durable = 0;
				continue;
			}

			if (prev_fp->attrib_only != curr_fp->attrib_only)
				continue;

			if (!(prev_fp->saccess & (FILE_SHARE_DELETE_LE)) &&
					curr_fp->daccess & (FILE_DELETE_LE |
				FILE_GENERIC_ALL_LE | FILE_MAXIMAL_ACCESS_LE)) {
				cifsd_err("previous filename don't have share delete\n");
				cifsd_err("previous file's share access : 0x%x, current file's desired access : 0x%x\n",
					prev_fp->saccess, curr_fp->daccess);
				rc = -EPERM;
				break;
			}

			/*
			 * Only check FILE_SHARE_DELETE if stream opened and
			 * normal file opened.
			 */
			if (prev_fp->is_stream && !curr_fp->is_stream)
				continue;

			if (!(prev_fp->saccess & (FILE_SHARE_READ_LE)) &&
				curr_fp->daccess & (FILE_READ_DATA_LE |
					FILE_GENERIC_READ_LE |
					FILE_GENERIC_ALL_LE |
					FILE_MAXIMAL_ACCESS_LE)) {
				cifsd_err("previous filename don't have share read\n");
				cifsd_err("previous file's share access : 0x%x, current file's desired access : 0x%x\n",
					prev_fp->saccess, curr_fp->daccess);
				rc = -EPERM;
				break;
			}

			if (!(prev_fp->saccess & (FILE_SHARE_WRITE_LE)) &&
				curr_fp->daccess & (FILE_WRITE_DATA_LE |
					FILE_GENERIC_WRITE_LE |
					FILE_GENERIC_ALL_LE |
					FILE_MAXIMAL_ACCESS_LE)) {
				cifsd_err("previous filename don't have share write\n");
				cifsd_err("previous file's share access : 0x%x, current file's desired access : 0x%x\n",
					prev_fp->saccess, curr_fp->daccess);
				rc = -EPERM;
				break;
			}

			if (prev_fp->daccess & (FILE_READ_DATA_LE |
					FILE_GENERIC_READ_LE |
					FILE_GENERIC_ALL_LE |
					FILE_MAXIMAL_ACCESS_LE) &&
				!(curr_fp->saccess & FILE_SHARE_READ_LE)) {
				cifsd_err("previous filename don't have desired read access\n");
				cifsd_err("previous file's desired access : 0x%x, current file's share access : 0x%x\n",
					prev_fp->daccess, curr_fp->saccess);
				rc = -EPERM;
				break;
			}

			if (prev_fp->daccess & (FILE_WRITE_DATA_LE |
					FILE_GENERIC_WRITE_LE |
					FILE_GENERIC_ALL_LE |
					FILE_MAXIMAL_ACCESS_LE) &&
				!(curr_fp->saccess & FILE_SHARE_WRITE_LE)) {
				cifsd_err("previous filename don't have desired write access\n");
				cifsd_err("previous file's desired access : 0x%x, current file's share access : 0x%x\n",
					prev_fp->daccess, curr_fp->saccess);
				rc = -EPERM;
				break;
			}

			if (prev_fp->daccess & (FILE_DELETE_LE |
					FILE_GENERIC_ALL_LE |
					FILE_MAXIMAL_ACCESS_LE) &&
				!(curr_fp->saccess & FILE_SHARE_DELETE_LE)) {
				cifsd_err("previous filename don't have desired delete access\n");
				cifsd_err("previous file's desired access : 0x%x, current file's share access : 0x%x\n",
					prev_fp->daccess, curr_fp->saccess);
				rc = -EPERM;
				break;
			}

		}
	}
	spin_unlock(&curr_fp->f_ci->m_lock);

	return rc;
}

/**
 * pattern_cmp() - compare a string with a pattern which might include
 * wildcard '*' and '?'
 * TODO : implement consideration about DOS_DOT, DOS_QM and DOS_STAR
 *
 * @string:	string to compare with a pattern
 * @pattern:	pattern string which might include wildcard '*' and '?'
 *
 * Return:	0 if pattern matched with the string, otherwise non zero value
 */
int pattern_cmp(const char *string, const char *pattern)
{
	const char *cp = NULL;
	const char *mp = NULL;
	int diff;

	/* handle plain characters and '?' */
	while ((*string) && (*pattern != '*')) {
		diff = strncasecmp(pattern, string, 1);
		if (diff && (*pattern != '?'))
			return diff;

		pattern++;
		string++;
	}

	/* handle '*' wildcard */
	while (*string) {
		if (*pattern == '*') {
			/*
			 * if the last char of a pattern is '*',
			 * any string matches with the pattern
			 */
			if (!*++pattern)
				return 0;

			mp = pattern;
			cp = string + 1;
		} else if (!strncasecmp(pattern, string, 1)
				|| (*pattern == '?')) {
			/* ? is matched with any "one" char */
			pattern++;
			string++;
		} else {
			pattern = mp;
			string = cp++;
		}
	}

	/* handle remaining '*' */
	while (*pattern == '*')
		pattern++;

	return *pattern;
}

/**
 * is_matched() - compare a file name with an expression which might
 * include wildcards
 *
 * @fname:	file name to compare with an expression
 * @exp:	an expression which might include wildcard '*' and '?'
 *
 * Return:	true if fname and exp are matched, otherwise false
 */
bool is_matched(const char *fname, const char *exp)
{
	/* optimization to avoid pattern compare */
	if (!*fname && *exp)
		return false;
	else if (*fname && !*exp)
		return false;
	else if (!*fname && !*exp)
		return true;
	else if (*exp == '*' && strlen(exp) == 1)
		return true;

	if (pattern_cmp(fname, exp))
		return false;
	else
		return true;
}

/*
 * is_char_allowed() - check for valid character
 * @ch:		input character to be checked
 *
 * Return:	1 if char is allowed, otherwise 0
 */
static inline int is_char_allowed(char *ch)
{
	/* check for control chars, wildcards etc. */
	if (!(*ch & 0x80) &&
		(*ch <= 0x1f ||
		 *ch == '?' || *ch == '"' || *ch == '<' ||
		 *ch == '>' || *ch == '|' || *ch == '*'))
		return 0;

	return 1;
}

int check_invalid_char(char *filename)
{
	int len, i, rc = 0;

	len = strlen(filename);

	/* Check invalid character in stream name */
	for (i = 0; i < len; i++) {
		if (!is_char_allowed(&filename[i])) {
			cifsd_err("found invalid character : 0x%x\n",
					filename[i]);
			rc = -ENOENT;
			break;
		}
	}

	return rc;
}

int check_invalid_char_stream(char *stream_name)
{
	int len, i, rc = 0;

	len = strlen(stream_name);
	/* Check invalid character in stream name */
	for (i = 0; i < len; i++) {
		if (stream_name[i] == '/' || stream_name[i] == ':' ||
				stream_name[i] == '\\') {
			cifsd_err("found invalid character : %c\n",
					stream_name[i]);
			rc = -ENOENT;
			break;
		}
	}

	return rc;
}

int parse_stream_name(char *filename, char **stream_name, int *s_type)
{
	char *stream_type;
	char *s_name;
	int rc = 0;

	s_name = filename;
	filename = strsep(&s_name, ":");
	cifsd_debug("filename : %s, streams : %s\n", filename, s_name);
	if (strchr(s_name, ':')) {
		stream_type = s_name;
		s_name = strsep(&stream_type, ":");

		rc = check_invalid_char_stream(s_name);
		if (rc < 0) {
			rc = -ENOENT;
			goto out;
		}

		cifsd_debug("stream name : %s, stream type : %s\n", s_name,
				stream_type);
		if (!strncasecmp("$data", stream_type, 5))
			*s_type = DATA_STREAM;
		else if (!strncasecmp("$index_allocation", stream_type, 17))
			*s_type = DIR_STREAM;
		else
			rc = -ENOENT;
	}

	*stream_name = s_name;
out:
	return rc;
}

int construct_xattr_stream_name(char *stream_name, char **xattr_stream_name)
{
	int stream_name_size;
	int xattr_stream_name_size;
	char *xattr_stream_name_buf;

	stream_name_size = strlen(stream_name);
	xattr_stream_name_size = stream_name_size + XATTR_NAME_STREAM_LEN + 1;
	xattr_stream_name_buf = kmalloc(xattr_stream_name_size, GFP_KERNEL);
	memcpy(xattr_stream_name_buf, XATTR_NAME_STREAM,
		XATTR_NAME_STREAM_LEN);

	if (stream_name_size)
		memcpy(&xattr_stream_name_buf[XATTR_NAME_STREAM_LEN],
			stream_name, stream_name_size);

	xattr_stream_name_buf[xattr_stream_name_size - 1] = '\0';
	*xattr_stream_name = xattr_stream_name_buf;

	return xattr_stream_name_size;
}

/**
 * convert_to_nt_pathname() - extract and return windows path string
 *      whose share directory prefix was removed from file path
 * @filename : unix filename
 * @sharepath: share path string
 *
 * Return : windows path string or error
 */

char *convert_to_nt_pathname(char *filename, char *sharepath)
{
	char *ab_pathname;
	int len;

	ab_pathname = kmalloc(strlen(filename), GFP_KERNEL);
	if (!ab_pathname)
		return NULL;

	ab_pathname[0] = '\\';
	ab_pathname[1] = '\0';

	len = strlen(sharepath);
	if (!strncmp(filename, sharepath, len) && strlen(filename) != len) {
		strcpy(ab_pathname, &filename[len]);
		convert_delimiter(ab_pathname, 1);
	}

	return ab_pathname;
}

int get_nlink(struct kstat *st)
{
	int nlink;

	nlink = st->nlink;
	if (S_ISDIR(st->mode))
		nlink--;

	return nlink;
}

/**
 * convert_delimiter() - convert windows path to unix format or unix format
 *			 to windos path
 * @path:	path to be converted
 * @flags:	1 is to convert windows, 2 is to convert unix
 *
 */
void convert_delimiter(char *path, int flags)
{
	char *pos = path;

	if (flags == 1)
		while ((pos = strchr(pos, '/')))
			*pos = '\\';
	else
		while ((pos = strchr(pos, '\\')))
			*pos = '/';
}

/**
 * extract_sharename() - get share name from tree connect request
 * @treename:	buffer containing tree name and share name
 *
 * Return:      share name on success, otherwise error
 */
char *extract_sharename(char *treename)
{
	int len;
	char *dst;

	/* skip double chars at the beginning */
	while (strchr(treename, '\\'))
		strsep(&treename, "\\");
	len = strlen(treename);

	/* caller has to free the memory */
	dst = kstrndup(treename, len, GFP_KERNEL);
	if (!dst)
		return ERR_PTR(-ENOMEM);

	return dst;
}

/**
 * convert_to_unix_name() - convert windows name to unix format
 * @path:	name to be converted
 * @tid:	tree id of mathing share
 *
 * Return:	converted name on success, otherwise NULL
 */
char *convert_to_unix_name(struct cifsd_share_config *share, char *name)
{
	int len;
	char *new_name;

	len = strlen(share->path);
	len += strlen(name);

	/* for '/' needed for smb2
	 * as '/' is not present in beginning of name*/
	if (name[0] != '/')
		len++;

	/* 1 extra for NULL byte */
	cifsd_debug("new_name len = %d\n", len);
	new_name = kmalloc(len + 1, GFP_KERNEL);

	if (new_name == NULL) {
		cifsd_debug("Failed to allocate memory\n");
		return new_name;
	}

	memcpy(new_name, share->path, strlen(share->path));

	if (name[0] != '/') {
		memset(new_name + strlen(share->path), '/', 1);
		memcpy(new_name + strlen(share->path) + 1, name, strlen(name));
	} else
		memcpy(new_name + strlen(share->path), name, strlen(name));

	*(new_name + len) = '\0';

	return new_name;
}

/**
 * convname_updatenextoffset() - convert name to UTF, update next_entry_offset
 * @namestr:            source filename buffer
 * @len:                source buffer length
 * @size:               used buffer size
 * @local_nls           code page table
 * @name_len:           file name length after conversion
 * @next_entry_offset:  offset of dentry
 * @buf_len:            response buffer length
 * @data_count:         used response buffer size
 * @no_namelen_field:	flag which shows if a namelen field flag exist
 *
 * Return:      return error if next entry could not fit in current response
 *              buffer, otherwise return encode buffer.
 */
char *convname_updatenextoffset(char *namestr, int len, int size,
		const struct nls_table *local_nls, int *name_len,
		int *next_entry_offset, int *buf_len, int *data_count,
		int alignment, bool no_namelen_field)
{
	char *enc_buf;

	enc_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!enc_buf)
		return NULL;

	*name_len = smbConvertToUTF16((__le16 *)enc_buf,
			namestr, len, local_nls, 0);
	*name_len *= 2;
	if (no_namelen_field) {
		enc_buf[*name_len] = '\0';
		enc_buf[*name_len+1] = '\0';
		*name_len += 2;
	}

	*next_entry_offset = (size - 1 + *name_len + alignment) & ~alignment;

	if (*next_entry_offset > *buf_len) {
		cifsd_debug("buf_len : %d next_entry_offset : %d"
				" data_count : %d\n", *buf_len,
				*next_entry_offset, *data_count);
		*buf_len = -1;
		kfree(enc_buf);
		return NULL;
	}
	return enc_buf;
}
