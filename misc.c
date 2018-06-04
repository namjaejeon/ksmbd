/*
 *   fs/cifsd/misc.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/textsearch.h>

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#include "smb2pdu.h"
#include "transport.h"

static struct {
	int index;
	char *name;
	char *prot;
	__u16 prot_id;
} protocols[] = {
	{CIFS_PROT, "\2NT LM 0.12", "NT1", 0},
#ifdef CONFIG_CIFS_SMB2_SERVER
	{SMB2_PROT, "\2SMB 2.002", "SMB2_02", SMB20_PROT_ID},
	{SMB21_PROT, "\2SMB 2.1", "SMB2_10", SMB21_PROT_ID},
	{SMB2X_PROT, "\2SMB 2.???", "SMB2_22", SMB2X_PROT_ID},
	{SMB30_PROT, "\2SMB 3.0", "SMB3_00", SMB30_PROT_ID},
	{SMB302_PROT, "\2SMB 3.02", "SMB3_02", SMB302_PROT_ID},
	{SMB311_PROT, "\2SMB 3.1.1", "SMB3_11", SMB311_PROT_ID},
#endif
};

inline int cifsd_min_protocol(void)
{
	return protocols[0].index;
}

inline int cifsd_max_protocol(void)
{
	return protocols[ARRAY_SIZE(protocols) - 1].index;
}

int get_protocol_idx(char *str)
{
	int res = -1, i;
	int protocol_index = protocols[ARRAY_SIZE(protocols) - 1].index;
	int len = strlen(str);

	for (i = 0; i <= protocol_index; i++) {
		if (!strncmp(str, protocols[i].prot, len)) {
			cifsd_debug("selected %s dialect i = %d\n",
				protocols[i].prot, i);
			res = protocols[i].index;
			break;
		}
	}
	return res;
}

/**
 * check_smb_hdr() - check for valid smb request header
 * @smb:	smb header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 * TODO: properly check client authetication and tree authentication
 *
 * Return:      0 on success, otherwise 1
 */
static int check_smb_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {
		cifsd_debug("Bad protocol string signature header 0x%x\n",
			*(unsigned int *)smb->Protocol);
		return 1;
	} else
		cifsd_debug("got SMB\n");

	/* if it's not a response then accept */
	/* TODO : check for oplock break */
	if (!(smb->Flags & SMBFLG_RESPONSE))
		return 0;

	cifsd_debug("Server sent request, not response\n");
	return 1;
}

/**
 * check_smb2_hdr() - helper function to check for valid smb2 request header
 * @smb:	smb2 header to be checked
 *
 * Return:      0 on success, otherwise 1
 */
static inline int check_smb2_hdr(struct smb2_hdr *smb)
{
	if (!(smb->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
		return 0;
	return 1;
}

/**
 * check_smb2_hdr() - check for valid smb2 request header
 * @buf:	smb2 header to be checked
 *
 * check for valid smb signature and packet direction(request/response)
 *
 * Return:      0 on success, otherwise 1
 */
int check_smb_message(char *buf)
{

	if (*(__le32 *)((struct smb2_hdr *)buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {

		cifsd_debug("got SMB2 command\n");
		return check_smb2_hdr((struct smb2_hdr *)buf);

	}

	return check_smb_hdr((struct smb_hdr *)buf);

}

/**
 * add_request_to_queue() - check a request for addition to pending smb work
 *				queue
 * @cifsd_work:	smb request work
 *
 * Return:      true if not add to queue, otherwise false
 */
void add_request_to_queue(struct cifsd_work *work)
{
	struct cifsd_tcp_conn *conn = work->conn;
	struct list_head *requests_queue = NULL;
	struct smb2_hdr *hdr = REQUEST_BUF(work);

	if (*(__le32 *)hdr->ProtocolId == SMB2_PROTO_NUMBER) {
		unsigned int command = conn->ops->get_cmd_val(work);

		if (command != SMB2_CANCEL) {
			requests_queue = &conn->requests;
			work->type = SYNC;
		}
	} else {
		if (conn->ops->get_cmd_val(work) != SMB_COM_NT_CANCEL)
			requests_queue = &conn->requests;
	}

	if (requests_queue) {
		spin_lock(&conn->request_lock);
		list_add_tail(&work->request_entry, requests_queue);
		work->added_in_request_list = 1;
		spin_unlock(&conn->request_lock);
	}
}

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

	if (likely(cifsd_debug_enable != 2))
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

/**
 * is_smb_request() - check for valid smb request type
 * @conn:     TCP server instance of connection
 * @type:	smb request type
 *
 * Return:      true on success, otherwise false
 */
bool is_smb_request(struct cifsd_tcp_conn *conn)
{
	int type = *(char *)conn->request_buf;

	switch (type) {
	case RFC1002_SESSION_MESSAGE:
		/* Regular SMB request */
		return true;
	case RFC1002_SESSION_KEEP_ALIVE:
		cifsd_debug("RFC 1002 session keep alive\n");
		break;
	default:
		cifsd_debug("RFC 1002 unknown request type 0x%x\n", type);
	}

	return false;
}

int find_matching_smb1_dialect(int start_index, char *cli_dialects,
		__le16 byte_count)
{
	int i, smb1_index, cli_count, bcount, dialect_id = BAD_PROT_ID;
	char *dialects = NULL;

	if (unlikely(start_index >= ARRAY_SIZE(protocols))) {
		cifsd_err("bad start_index %d\n", start_index);
		return dialect_id;
	}

	for (i = start_index; i >= CIFS_PROT; i--) {
		smb1_index = 0;
		bcount = le16_to_cpu(byte_count);
		dialects = cli_dialects;

		while (bcount) {
			cli_count = strlen(dialects);
			cifsd_debug("client requested dialect %s\n",
					dialects);
			if (!strncmp(dialects, protocols[i].name,
						cli_count)) {
				if (i >= server_min_pr && i <= server_max_pr) {
					cifsd_debug("selected %s dialect\n",
							protocols[i].name);
					if (i == CIFS_PROT)
						dialect_id = smb1_index;
					else
						dialect_id =
						protocols[i].prot_id;
				}
				goto out;
			}
			bcount -= (++cli_count);
			dialects += cli_count;
			smb1_index++;
		}
	}

out:
	return dialect_id;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * find_matching_smb2_dialect() - find the greatest dialect between dialects
 * client and server support.
 * @start_index:	start protocol id for lookup
 * @cli_dialects:	client dialects
 * @srv_dialects:	server dialects
 * @directs_count:	client dialect count
 *
 * Return:      0
 */
int find_matching_smb2_dialect(int start_index, __le16 *cli_dialects,
	__le16 dialects_count)
{
	int i, dialect_id = BAD_PROT_ID;
	int count;

	for (i = start_index; i >= SMB2_PROT; i--) {
		count = le16_to_cpu(dialects_count);
		while (--count >= 0) {
			cifsd_debug("client requested dialect 0x%x\n",
				le16_to_cpu(cli_dialects[count]));
			if (le16_to_cpu(cli_dialects[count]) ==
					protocols[i].prot_id) {
				if (i >= server_min_pr && i <= server_max_pr) {
					cifsd_debug("selected %s dialect\n",
							protocols[i].name);
					dialect_id = protocols[i].prot_id;
				}
				goto out;
			}
		}
	}

out:
	return dialect_id;
}
#endif

/**
 * negotiate_dialect() - negotiate smb dialect with smb client
 * @buf:	smb header
 *
 * Return:     protocol index on success, otherwise bad protocol id error
 */
int negotiate_dialect(void *buf)
{
	int start_index, ret = BAD_PROT_ID;

#ifdef CONFIG_CIFS_SMB2_SERVER
	start_index = SMB311_PROT;
#else
	start_index = CIFS_PROT;
#endif

	if (*(__le32 *)((struct smb_hdr *)buf)->Protocol ==
			SMB1_PROTO_NUMBER) {
		/* SMB1 neg protocol */
		NEGOTIATE_REQ *req = (NEGOTIATE_REQ *)buf;
		ret = find_matching_smb1_dialect(start_index,
			req->DialectsArray, le16_to_cpu(req->ByteCount));
	} else if (*(__le32 *)((struct smb2_hdr *)buf)->ProtocolId ==
			SMB2_PROTO_NUMBER) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		/* SMB2 neg protocol */
		struct smb2_negotiate_req *req;
		req = (struct smb2_negotiate_req *)buf;
		ret = find_matching_smb2_dialect(start_index, req->Dialects,
			le16_to_cpu(req->DialectCount));
#endif
	}

	return ret;
}

struct cifsd_sess *lookup_session_on_server(struct cifsd_tcp_conn *conn,
		uint64_t sess_id)
{
	struct cifsd_sess *sess;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &conn->cifsd_sess) {
		sess = list_entry(tmp, struct cifsd_sess, cifsd_ses_list);
		if (sess->sess_id == sess_id)
			return sess;
	}

	cifsd_err("User session(ID : %llu) not found\n", sess_id);
	return NULL;
}

/**
 * validate_sess_handle() - check for valid session handle
 * @sess:	handle to be validated
 *
 * Return:      matching session handle, otherwise NULL
 */
struct cifsd_sess *validate_sess_handle(struct cifsd_sess *session)
{
	struct cifsd_sess *sess;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifsd_session_list) {
		sess = list_entry(tmp, struct cifsd_sess,
				cifsd_ses_global_list);
		if (sess == session)
			return sess;
	}

	cifsd_err("session(%p) not found\n", session);
	return NULL;
}

#ifndef CONFIG_CIFS_SMB2_SERVER
void init_smb2_0_server(struct cifsd_tcp_conn *server) { }
void init_smb2_1_server(struct cifsd_tcp_conn *server) { }
void init_smb3_0_server(struct cifsd_tcp_conn *server) { }
void init_smb3_02_server(struct cifsd_tcp_conn *server) { }
void init_smb3_11_server(struct cifsd_tcp_conn *server) { }
int is_smb2_neg_cmd(struct cifsd_work *work)
{
	return 0;
}

bool is_chained_smb2_message(struct cifsd_work *work)
{
	return 0;
}

void init_smb2_neg_rsp(struct cifsd_work *work)
{
}
int is_smb2_rsp(struct cifsd_work *work)
{
	return 0;
};
#endif

int smb_store_cont_xattr(struct path *path, char *prefix, void *value,
	ssize_t v_len)
{
	int err;

	err = smb_vfs_setxattr(NULL, path, prefix, value, v_len, 0);
	if (err)
		cifsd_debug("setxattr failed, err %d\n", err);

	return err;
}

ssize_t smb_find_cont_xattr(struct path *path, char *prefix, int p_len,
	char **value, int flags)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = smb_vfs_listxattr(path->dentry, &xattr_list,
		XATTR_LIST_MAX);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		cifsd_debug("empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));
		if (strncasecmp(prefix, name, p_len))
			continue;

		value_len = smb_vfs_getxattr(path->dentry, name, value, flags);
		if (value_len < 0)
			cifsd_err("failed to get xattr in file\n");
		break;
	}

out:
	if (xattr_list)
		vfree(xattr_list);
	return value_len;
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
	int same_stream = 0;
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
			if (prev_fp->is_stream && curr_fp->is_stream) {
				if (strcmp(prev_fp->stream.name,
					curr_fp->stream.name)) {
					continue;
				}
				same_stream = 1;
			}

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
				rc = EPERM;
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

	if (!same_stream && !curr_fp->is_stream) {
		if (curr_fp->cdoption == FILE_SUPERSEDE_LE) {
			smb_vfs_truncate_stream_xattr(
				curr_fp->filp->f_path.dentry);
		}
	}

	return rc;
}

struct cifsd_file *find_fp_using_inode(struct inode *inode)
{
	struct cifsd_file *lfp;
	struct cifsd_inode *ci;
	struct list_head *cur;

	ci = cifsd_inode_lookup_by_vfsinode(inode);
	if (!ci)
		goto out;

	spin_lock(&ci->m_lock);
	list_for_each(cur, &ci->m_fp_list) {
		lfp = list_entry(cur, struct cifsd_file, node);
		if (inode == FP_INODE(lfp)) {
			atomic_dec(&ci->m_count);
			spin_unlock(&ci->m_lock);
			return lfp;
		}
	}
	atomic_dec(&ci->m_count);
	spin_unlock(&ci->m_lock);

out:
	return NULL;
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

bool cifsd_filter_filename_match(struct cifsd_share *share, char *filename)
{
	struct cifsd_filter *cf;
	char *source_string;
	struct ts_state state;
	int pos, len;

	list_for_each_entry(cf, &share->config.filter_list, entry) {
		if (cf->type == FILTER_FILE_EXTENSION) {
			source_string = strchr(filename, '.');
			if (!source_string)
				continue;
			len = strlen(source_string);
			pos = textsearch_find_continuous(cf->config, &state,
				source_string, len);
			if (!pos && state.offset == len)
				return true;
		} else if (cf->type == FILTER_WILDCARD) {
			source_string = filename;
			len = strlen(source_string);
			pos = textsearch_find_continuous(cf->config, &state,
				source_string, len);
			if (pos >= 0)
				return true;
		} else {
			source_string = filename;
			len = strlen(source_string);
			pos = textsearch_find_continuous(cf->config, &state,
				source_string, len);
			if (!pos && state.offset == len)
				return true;
		}
	}

	return false;
}

