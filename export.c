/*
 *   fs/cifssrv/export.c
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

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"

/* max string size for share and parameters */
#define SHARE_MAX_NAME_LEN	100
/* max string size data, ex- path, usernames, servernames etc */
#define SHARE_MAX_DATA_LEN	PATH_MAX
#define MAX_NT_PWD_LEN		128

/*
 * There could be 2 ways to add path to an export list.
 * One is static, via a conf file. Other is dynamic, via sysfs entry.
 */
struct cifssrv_sysfs_obj *sysobj;

LIST_HEAD(cifssrv_usr_list);
LIST_HEAD(cifssrv_share_list);
LIST_HEAD(cifssrv_connection_list);
LIST_HEAD(cifssrv_session_list);

__u16 vid = 1;
__u16 tid = 1;
int cifssrv_debug_enable;
int cifssrv_caseless_search;
static char key[CIFS_NTHASH_SIZE];
static char statIP[MAX_ADDRBUFLEN];
static inline void free_share(struct cifssrv_share *share);

/* Number of shares defined on server */
int cifssrv_num_shares;
char *guestAccountName;
char *server_string;
char *workgroup;

/**
 * __add_share() - helper function to add a share in global exported share list
 * @share:	share instance to be added to global share list
 * @sharename:	name of share
 * @pathname:	path of share point
 *
 * Return:      0 on success, error number on error
 */
static int __add_share(struct cifssrv_share *share, char *sharename,
		       char *pathname)
{
	struct kstat stat;
	int err;

	/* pathname will be NULL for IPC$ share */
	if (pathname != NULL) {
		err = kern_path(pathname, 0, &share->vfspath);
		if (err) {
			cifssrv_err("share add failed for %s\n", pathname);
			return err;
		} else {
			err = vfs_getattr(&share->vfspath, &stat);
			if (err) {
				path_put(&share->vfspath);
				cifssrv_err("share add failed for %s\n",
					    pathname);
				return err;
			}
		}
	}

	share->path = pathname;
	share->tcount = 0;
	share->tid = tid++;
	share->sharename = sharename;
	INIT_LIST_HEAD(&share->list);
	list_add(&share->list, &cifssrv_share_list);
	cifssrv_num_shares++;
	return 0;
}

/**
 * init_params() - initialize config parameters of a share
 * @share:	share instance to be initialized
 */
static void init_params(struct cifssrv_share *share)
{
	set_attr_available(&share->config.attr);
	set_attr_browsable(&share->config.attr);
	clr_attr_guestok(&share->config.attr);
	clr_attr_guestonly(&share->config.attr);
	set_attr_oplocks(&share->config.attr);
	clr_attr_writeable(&share->config.attr);
	share->config.max_connections = 0;
}

/**
 * add_share() - allocate and add a share in global exported share list
 * @sharename:	name of share
 * @pathname:	path of share point
 *
 * Return:      0 on success, error number on error
 */
static int add_share(char *sharename, char *pathname)
{
	struct cifssrv_share *share;
	int ret;

	share = kzalloc(sizeof(struct cifssrv_share), GFP_KERNEL);
	if (!share)
		return -ENOMEM;

	init_params(share);

	ret = __add_share(share, sharename, pathname);
	if (ret) {
		free_share(share);
		kfree(share);
	}

	return 0;
}

/**
 * free_share() - free a share point release associated memory
 * @share:	share instance to be freed
 */
static inline void free_share(struct cifssrv_share *share)
{
	kfree(share->sharename);

	if (share->path) {
		path_put(&share->vfspath);
		kfree(share->path);
	}

	kfree(share->config.comment);
	kfree(share->config.allow_hosts);
	kfree(share->config.deny_hosts);
	kfree(share->config.invalid_users);
	kfree(share->config.read_list);
	kfree(share->config.valid_users);
}

/**
 * cifssrv_share_free() - delete all shares from global exported share list
 */
static void cifssrv_share_free(void)
{
	struct cifssrv_share *share;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);
		list_del(&share->list);
		cifssrv_num_shares--;
		free_share(share);
		kfree(share);
	}
}

/**
 * add_user() - allocate and add an user in global user list
 * @name:	user name to be added
 * @pass:	password of user
 *
 * Return:      0 on success, error number on error
 */
static int add_user(char *name, char *pass)
{
	struct cifssrv_usr *usr;

	usr = kmalloc(sizeof(struct cifssrv_usr), GFP_KERNEL);
	if (!usr)
		return -ENOMEM;

	if (!strlen(pass)) {
		cifssrv_err("[%s] Err: no password supplied\n", __func__);
		kfree(usr);
		return -EINVAL;
	}
	if (guestAccountName != NULL) {
		if (strcmp(guestAccountName, name) == 0) {
			usr->vuid = 0;
			usr->guest = true;
		} else{
			usr->vuid = vid++;
			usr->guest = false;
		}
	} else{
		usr->vuid = vid++;
		usr->guest = false;
	}
	usr->name = name;
	memcpy(usr->passkey, pass, CIFS_NTHASH_SIZE);
	usr->gid = current_gid();
	usr->uid = current_uid();
	usr->sess_uid = 0;
	INIT_LIST_HEAD(&usr->list);
	list_add(&usr->list, &cifssrv_usr_list);
	usr->ucount = 0;
	return 0;
}

/**
 * cifssrv_user_free() - delete all users from global exported user list
 */
static void cifssrv_user_free(void)
{
	struct cifssrv_usr *usr;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifssrv_usr_list) {
		usr = list_entry(tmp, struct cifssrv_usr, list);
		list_del(&usr->list);
		kfree(usr->name);
		kfree(usr);
	}
}

/**
 * init_2_strings() - allocate and initialize two strings from src string
 * @src:	src string contains two stings delimated by ":"
 * @str1:	allocated and intialized by string prior to ":" in src
 * @str2:	allocated and intialized by string after ":" in src
 * @len:	length of src string
 *
 * Return:      0 on success, -ENOMEM on error
 */
static int init_2_strings(const char *src, char **str1, char **str2, int len)
{
	int idx;
	int idx2;
	char *pos;

	if (src[len - 1] == '\n')
		len--;

	pos = strnchr(src, len, ':');
	if (!pos)
		return -EINVAL;

	idx = (int)(pos - src);
	if (idx <= 0)
		return -EINVAL;

	idx2 = len - idx - 1;

	*str1 = kmalloc(idx + 1, GFP_NOFS);
	if (!*str1)
		return -ENOMEM;

	*str2 = kmalloc(idx2 + 1, GFP_NOFS);
	if (!*str2) {
		kfree(*str1);
		return -ENOMEM;
	}

	memcpy(*str1, src, idx);
	*(*str1 + idx) = '\0';

	src += (idx + 1);

	memcpy(*str2, src, idx2);
	*(*str2 + idx2) = '\0';

	return 0;
}

/**
 * chktkn() - utility function to validate user or host
 * @userslist:	list of allowed or denied user or host
 * @str2:	check if this user or host is present in userslist
 *
 * Return:      1 if str2 is present in userslist, otherwise 0
 */
static int chktkn(char *userslist, char *str2)
{
	char *token;
	char *dup, *dup_orig;

	if (userslist) {
		dup_orig = dup = kstrdup(userslist, GFP_KERNEL);
		if (!dup)
			return -ENOMEM;

		while ((token = strsep(&dup, "	, ")) != NULL) {
			if (!strcmp(token, str2)) {
				kfree(dup_orig);
				return 1;
			}
		}
		kfree(dup_orig);
	}
	return 0;
}

/**
 * validate_clip() - check if a client is allowed or denied access of a share
 * @cip:	client ip to be checked
 * @share:	share config containing allowed and denied list of client ip
 *
 * Return:      1 if cip is allowed access to share, otherwise 0
 */
int validate_clip(char *cip, struct cifssrv_share *share)
{
	char *alist = share->config.allow_hosts;
	char *dlist = share->config.deny_hosts;
	int allow, deny;
	int asz = 0;
	int dsz = 0;

	if (alist)
		asz = strlen(alist);
	if (dlist)
		dsz = strlen(dlist);

	if (!asz && !dsz)
		return 1;

	allow = chktkn(alist, cip);
	if (allow == -ENOMEM)
		return -ENOMEM;

	deny = chktkn(dlist, cip);
	if (deny == -ENOMEM)
		return -ENOMEM;

	/* "allow hosts" list takes precedence over "deny hosts" list */
	if (allow)
		return 1;
	else if (!asz && deny)
		return 0;
	else if (!asz && !deny)
		return 1;

	return 0;
}

/**
 * validate_usr() - check if an user is allowed or denied access of a share
 * @usr:	user to be checked
 * @share:	share config containing allowed and denied list of users
 *
 * Return:      1 if usr is allowed access to share, otherwise 0
 */
int validate_usr(char *usr, struct cifssrv_share *share)
{
	char *vlist = share->config.valid_users;
	char *ilist = share->config.invalid_users;
	int ret;

	/* name should not be present in "invalid users" */
	ret = chktkn(ilist, usr);
	if (ret == -ENOMEM)
		return -ENOMEM;

	if (!ret) {
		/* if "valid users" list is empty then any user can login */
		if (!vlist)
			return 1;

		/* user exists in "valid users" list? */
		return chktkn(vlist, usr);
	}
	return 0;
}

/**
 * find_matching_share() - get a share instance from tree id
 * @tid:	tree id for share instance lookup
 *
 * Return:      share if there is matching share tid, otherwise NULL
 */
struct cifssrv_share *find_matching_share(__u16 tid)
{
	struct cifssrv_share *share;
	struct list_head *tmp;

	list_for_each(tmp, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);
		if (share->tid == tid)
			return share;
	}

	return NULL;
}

/**
 * check_sharepath() - check if a share path is already exported
 * @path:	share path to check
 *
 * Return:      0 if share is already exported, otherwise 1
 */
static int check_sharepath(char *path)
{
	struct cifssrv_share *share;
	struct list_head *tmp;
	int srclen, targetlen = 0;

	srclen = strlen(path);

	list_for_each(tmp, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);
		if (share->path) {
			targetlen = strlen(share->path);
			if (srclen == targetlen) {
				if (!strncmp(path, share->path, srclen))
					return 0;
			}
		}
	}

	return 1;
}

/**
 * check_user() - check if a user name is already added
 * @name:	user name to be checked
 * @pass:	user password
 *
 * Return:      0 if user is already added, otherwise 1
 */
static int check_user(char *name, char *pass)
{
	struct cifssrv_usr *usr;
	struct list_head *tmp;
	int srclen, targetlen;

	srclen = strlen(name);

	list_for_each(tmp, &cifssrv_usr_list) {
		usr = list_entry(tmp, struct cifssrv_usr, list);
		targetlen = strlen(usr->name);
		if (srclen == targetlen) {
			if (!strncmp(name, usr->name, srclen)) {
				if (!strlen(pass)) {
					list_del(&usr->list);
					kfree(usr->name);
					kfree(usr);
					return 0;
				}
				memcpy(usr->passkey, pass,
					CIFS_NTHASH_SIZE);
				return 0;
			}
		}
	}

	return 1;
}

/**
 * check_share() - check if a share name is already exported
 * @share_buf:	buffer containing share name
 * @share_sz:	share name length
 *
 * Return:      share name if already exported, otherwise NULL
 */
static struct cifssrv_share *check_share(char *share_buf, int share_sz)
{
	struct cifssrv_share *share;
	struct list_head *tmp;
	int srclen;

	list_for_each(tmp, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);
		srclen = strlen(share->sharename);
		if (srclen == share_sz) {
			if (strncasecmp(share->sharename,
					share_buf, srclen) == 0)
				return share;
		}
	}

	return NULL;
}

/**
 * valstr() - get hash value from a string i.e. config parameter name
 * @str:	config parameter name e.g. ALLOWHOSTS
 *
 * calculate hash value from config parameter name and compare them with hash
 * value of known config param instead of string compare with each param.
 *
 * Return:      hash value of str
 */
static inline int valstr(char *str)
{
	int val = 0;

	while (*str) {
		if (*str >= 'A' && *str <= 'Z')
			val += *str + 32;
		else
			val += *str;

		str++;
	}

	return val;
}

/**
 * getval() - check if a config setting is enabled or disabled
 * @str:	may contain yes, true or 1 etc.
 *
 * Return:      1 if config is enabled, 0 if disabled, otherwise -1
 */
static int getval(char *str)
{
	if (!strcasecmp(str, "yes") ||
		!strcasecmp(str, "true") ||
		!strcmp(str, "1"))
		return 1;
	else if (!strcasecmp(str, "no") ||
		!strcasecmp(str, "false") ||
		!strcmp(str, "0"))
		return 0;
	else
		return -1;
}

/**
 * update_global() - update a global config setting
 * @param_buf:	config parameter name e.g. GUESTACCOUNT
 * @data_buf:	config parameter value
 * @param_sz:	config parameter name length
 * @data_sz:	config parameter value - data length
 *
 * Return:      0 on success, otherwise error
 */
static int update_global(char *param_buf,
				char *data_buf, int param_sz, int data_sz)
{
	switch (valstr(param_buf)) {
	case GUESTACCOUNT:
	{
		if (strcasecmp(param_buf, "guest account")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}
		guestAccountName = kzalloc(data_sz+1, GFP_KERNEL);
		if (!guestAccountName)
			return -ENOMEM;
		strncpy(guestAccountName, data_buf , data_sz);
		break;
	}
	case SERVERSTRING:
	{
		if (strcasecmp(param_buf, "server string")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}
		server_string = kzalloc(data_sz+1, GFP_KERNEL);
		if (!server_string)
			return -ENOMEM;
		strncpy(server_string, data_buf , data_sz);
		break;
	}
	case WORKGROUP:
	{
		if (strcasecmp(param_buf, "workgroup")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}
		workgroup = kzalloc(data_sz+1, GFP_KERNEL);
		if (!workgroup)
			return -ENOMEM;
		strncpy(workgroup, data_buf , data_sz);
		break;
	}
	default:
		cifssrv_err("[%s] not supported value = %d\n",
			     param_buf, valstr(param_buf));
	}
	return 0;
}

/**
 * update_share() - update a share config setting
 * @share:	share instance for updating config setting
 * @param_buf:	config parameter name e.g. ALLOWHOSTS
 * @data_buf:	config parameter value
 * @param_sz:	config parameter name length
 * @data_sz:	config parameter value - data length
 *
 * Return:      0 on success, otherwise error
 */
static int update_share(struct cifssrv_share *share, char *param_buf,
			char *data_buf, int param_sz, int data_sz)
{
	switch (valstr(param_buf)) {
	case ALLOWHOSTS:
	{
		if (strcasecmp(param_buf, "allow hosts")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.allow_hosts);
		share->config.allow_hosts = NULL;

		share->config.allow_hosts = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.allow_hosts)
			return -ENOMEM;

		strncpy(share->config.allow_hosts, data_buf, data_sz);
	}
	break;
	case AVAILABLE:
	{
		int val;

		if (strcasecmp(param_buf, "available")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 0)
			clr_attr_available(&share->config.attr);
		else	/* default is also enabled */
			set_attr_available(&share->config.attr);
	}
	break;
	case BROWSABLE:
	{
		int val;

		if (strcasecmp(param_buf, "browsable")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 0)
			clr_attr_browsable(&share->config.attr);
		else	/* default is also enabled */
			set_attr_browsable(&share->config.attr);
	}
	break;
	case COMMENT:
	{
		if (strcasecmp(param_buf, "comment")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.comment);
		share->config.comment = NULL;

		share->config.comment = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.comment)
			return -ENOMEM;

		strncpy(share->config.comment, data_buf, data_sz);
	}
	break;
	case DENYHOSTS:
	{
		if (strcasecmp(param_buf, "deny hosts")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.deny_hosts);
		share->config.deny_hosts = NULL;

		share->config.deny_hosts = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.deny_hosts)
			return -ENOMEM;

		strncpy(share->config.deny_hosts, data_buf, data_sz);
	}
	break;
	case GUESTOK:
	{
		int val;

		if (strcasecmp(param_buf, "guest ok")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 1)
			set_attr_guestok(&share->config.attr);
		else	/* default is also disabled */
			clr_attr_guestok(&share->config.attr);
	}
	break;
	case GUESTONLY:
	{
		int val;

		if (strcasecmp(param_buf, "guest only")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 1)
			set_attr_guestonly(&share->config.attr);
		else	/* default is also disabled */
			clr_attr_guestonly(&share->config.attr);
	}
	break;
	case INVALIDUSERS:
	{
		if (strcasecmp(param_buf, "invalid users")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.invalid_users);
		share->config.invalid_users = NULL;

		share->config.invalid_users = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.invalid_users)
			return -ENOMEM;

		strncpy(share->config.invalid_users, data_buf, data_sz);
	}
	break;
	case MAXCONNECTIONS:
	{
		int val;

		if (strcasecmp(param_buf, "max connections")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		if (data_sz) {
			if (!kstrtouint(data_buf, 10, &val)) {
				if (val >= 0)
					share->config.max_connections = val;
			}
		}
	}
	break;
	case OPLOCKS:
	{
		int val;

		if (strcasecmp(param_buf, "oplocks")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 0)
			clr_attr_oplocks(&share->config.attr);
		else	/* default is also enabled */
			set_attr_oplocks(&share->config.attr);
	}
	break;
	case PATH:
	{
		if (strcasecmp(param_buf, "path")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->path);
		share->path = NULL;

		share->path = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->path)
			return -ENOMEM;

		strncpy(share->path, data_buf, data_sz);
	}
	break;
	case READLIST:
	{
		if (strcasecmp(param_buf, "read list")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.read_list);
		share->config.read_list = NULL;

		share->config.read_list = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.read_list)
			return -ENOMEM;

		strncpy(share->config.read_list, data_buf, data_sz);
	}
	break;
	case VALIDUSERS:
	{
		if (strcasecmp(param_buf, "valid users")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		kfree(share->config.valid_users);
		share->config.valid_users = NULL;

		share->config.valid_users = kzalloc(data_sz+1, GFP_KERNEL);
		if (!share->config.valid_users)
			return -ENOMEM;

		strncpy(share->config.valid_users, data_buf, data_sz);
	}
	break;
	case WRITEABLE:
	{
		int val;

		if (strcasecmp(param_buf, "writeable")) {
			cifssrv_err("[%s] invalid parameter\n", param_buf);
			break;
		}

		val = getval(data_buf);
		if (val == 1)
			set_attr_writeable(&share->config.attr);
		else	/* default is also disabled */
			clr_attr_writeable(&share->config.attr);
	}
	break;
	default:
		cifssrv_err("[%s] not supported\n", param_buf);
	}

	return 0;
}

/* utility function for next share */
static void nxt_share(const char *src, int *pos, char *dst, int *dsz,
		int *eof)
{
	char c;
	*dsz = 0;

	while (src[*pos] != '<')
		(*pos)++;

	*pos += 1;

	if (src[(*pos)++] == '[') {
		while ((c = src[(*pos)++]) != ']')
			dst[(*dsz)++] = c;
	}

	if (src[(*pos)+1] == '#') {
		*dsz = 0;
		*eof = 1;
	}
}

/* utility function for next parameter */
static void nxt_param(const char *src, int *pos, char *param_buf,
		      char *data_buf, int *param_sz, int *data_sz,
		      int *share, int *eof)
{
	*param_sz = 0;
	*data_sz = 0;
	*eof = 0;

	while (src[*pos] != '<')
		(*pos)++;

	*pos += 1;

	if (src[*pos] != '[') {
		while (!((src[*pos] == ' ') && (src[(*pos)+1] == '=')) &&
				(src[*pos] != '>'))
			param_buf[(*param_sz)++] = src[(*pos)++];

		if (src[*pos] != '>')
			while (!(src[*pos] >= 'A' && src[*pos] <= 'Z') &&
				!(src[*pos] >= 'a' && src[*pos] <= 'z') &&
				!(src[*pos] >= '0' && src[*pos] <= '9') &&
				(src[*pos] != '/'))
				(*pos)++;

		while (src[*pos] != '>')
			data_buf[(*data_sz)++] = src[(*pos)++];

		if (src[(*pos)+1] == '#')
			*eof = 1;

		*share = 0;
	} else {
		*pos -= 1;
		*share = 1;
	}
}

/**
 * share_show() - show a list of exported shares
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing share list output
 *
 * Return:      output buffer length
 */
static ssize_t share_show(struct kobject *kobj,
			  struct kobj_attribute *kobj_attr,
			  char *buf)
{
	struct cifssrv_share *share;
	struct list_head *tmp;
	ssize_t len = 0, total = 0, limit = PAGE_SIZE;
	char *tbuf = buf;

	list_for_each(tmp, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);
		if (share->path) {
			len = snprintf(tbuf, limit, "%s:%s\n",
				 share->sharename, share->path);
			if (len < 0) {
				total = len;
				break;
			}
			tbuf += len;
			total += len;
			limit -= len;
		}
	}

	return total;
}

/**
 * share_store() - add a share path in exported share list
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing share path to be exported
 * @len:	share name buf length
 *
 * Return:      share name buf length on success, otherwise error
 */
static ssize_t share_store(struct kobject *kobj,
			   struct kobj_attribute *kobj_attr,
			   const char *buf, size_t len)
{
	char *str1[1], *str2[1];
	int rc;

	rc = init_2_strings(buf, str1, str2, len);
	if (rc)
		return rc;

	/* check if sharepath is already exported */
	rc = check_sharepath(*str2);
	if (!rc) {
		cifssrv_err("path %s is already exported\n", *str2);
		kfree(*str1);
		kfree(*str2);
		return -EEXIST;
	}

	rc = add_share(*str1, *str2);
	if (rc) {
		kfree(*str1);
		kfree(*str2);
		return rc;
	}

	return len;
}

/**
 * user_show() - show a list of added user
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing user list output
 *
 * Return:      output buffer length
 */
static ssize_t user_show(struct kobject *kobj,
			 struct kobj_attribute *kobj_attr,
			 char *buf)

{
	struct cifssrv_usr *usr;
	struct list_head *tmp;
	ssize_t len = 0, total = 0, limit = PAGE_SIZE;
	char *tbuf = buf;

	list_for_each(tmp, &cifssrv_usr_list) {
		usr = list_entry(tmp, struct cifssrv_usr, list);
		len = snprintf(tbuf, limit, "%s\n", usr->name);
		if (len < 0) {
			total = len;
			break;
		}
		tbuf += len;
		total += len;
		limit -= len;
	}

	return total;
}

/**
 * user_store() - add a user in valid user list
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing user name to be added
 * @len:	user name buf length
 *
 * Return:      user name buf length on success, otherwise error
 */
static ssize_t user_store(struct kobject *kobj,
			  struct kobj_attribute *kobj_attr,
			  const char *buf, size_t len)
{
	char *str1[1], *str2[1];
	int rc;

	rc = init_2_strings(buf, str1, str2, len);
	if (rc) {
		if (rc == -EINVAL) {
			cifssrv_err("[%s] <usr:pass> format err\n", __func__);
			return len;
		}
		return rc;
	}

	/* check if user is already present*/
	rc = check_user(*str1, *str2);
	if (!rc)
		goto EXIT2;

	rc = add_user(*str1, *str2);
	if (!rc)
		goto EXIT1;

EXIT2:
	kfree(*str1);
EXIT1:
	kfree(*str2);

	if (rc == -ENOMEM)
		return -ENOMEM;

	return len;
}

/**
 * debug_store() - enable debug prints
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing debug enable disable setting
 * @len:	buf length of debug enable disable setting
 *
 * Return:      debug setting buf length
 */
static ssize_t debug_store(struct kobject *kobj,
			   struct kobj_attribute *kobj_attr,
			   const char *buf, size_t len)
{
	long int value;

	if (kstrtol(buf, 10, &value))
		goto out;
	if (value > 0)
		cifssrv_debug_enable = value;
	else if (value == 0)
		cifssrv_debug_enable = 0;
out:
	return len;
}

/**
 * debug_show() - show debug print enable disable setting
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing debug print setting
 *
 * Return:      output buffer length
 */
static ssize_t debug_show(struct kobject *kobj,
			  struct kobj_attribute *kobj_attr,
			  char *buf)

{
	return snprintf(buf, PAGE_SIZE, "%d\n", cifssrv_debug_enable);
}

/**
 * caseless_search_store() - enable disable case insensitive search of files
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing case setting
 * @len:	buf length of case setting
 *
 * Return:      case setting buf length
 */
static ssize_t caseless_search_store(struct kobject *kobj,
				     struct kobj_attribute *kobj_attr,
				     const char *buf, size_t len)
{
	long int value;

	if (kstrtol(buf, 10, &value))
		goto out;
	if (value > 0)
		cifssrv_caseless_search = 1;
	else if (value == 0)
		cifssrv_caseless_search = 0;
out:
	return len;
}

/**
 * caseless_search_show() - show caseless search enable disable setting status
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing caseless search setting
 *
 * Return:      output buffer length
 */
static ssize_t caseless_search_show(struct kobject *kobj,
		struct kobj_attribute *kobj_attr,
		char *buf)

{
	return snprintf(buf, PAGE_SIZE, "%d\n", cifssrv_caseless_search);
}

/**
 * config_show() - show config setting
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing config setting
 *
 * Return:      output buffer length
 */
static ssize_t config_show(struct kobject *kobj,
			   struct kobj_attribute *kobj_attr,
			   char *buf)

{
	struct cifssrv_share *share;
	struct list_head *tmp;
	int cum = 0;
	int ret = 0;
	int limit = PAGE_SIZE;

	list_for_each(tmp, &cifssrv_share_list) {
		share = list_entry(tmp, struct cifssrv_share, list);

		if (cum < limit && share->sharename) {
			ret = snprintf(buf+cum, limit - cum, "[%s]\n",
					share->sharename);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.comment &&
			strlen(share->config.comment)) {
			ret = snprintf(buf+cum, limit - cum, "\tcomment = %s\n",
					share->config.comment);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->path) {
			ret = snprintf(buf+cum, limit - cum, "\tpath = %s\n",
					share->path);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.allow_hosts &&
			strlen(share->config.allow_hosts)) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tallow hosts = %s\n",
				       share->config.allow_hosts);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.deny_hosts &&
			strlen(share->config.deny_hosts)) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tdeny hosts = %s\n",
				       share->config.deny_hosts);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.invalid_users &&
			strlen(share->config.invalid_users)) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tinvalid users = %s\n",
				       share->config.invalid_users);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.read_list &&
			strlen(share->config.read_list)) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tread list = %s\n",
				       share->config.read_list);
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit && share->config.valid_users &&
			strlen(share->config.valid_users)) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tvalid users = %s\n",
				       share->config.valid_users);
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tavailable = %d\n",
				       get_attr_available(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tbrowsable = %d\n",
				       get_attr_browsable(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tguest ok = %d\n",
				       get_attr_guestok(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tguest only = %d\n",
				       get_attr_guestonly(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum, "\toplocks = %d\n",
					get_attr_oplocks(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\twriteable = %d\n",
				       get_attr_writeable(&share->config.attr));
			if (ret < 0)
				return cum;
			cum += ret;
		}
		if (cum < limit) {
			ret = snprintf(buf+cum, limit - cum,
				       "\tmax connections = %u\n",
				       share->config.max_connections);
			if (ret < 0)
				return cum;
			cum += ret;
		}
	}

	return cum;
}

/**
 * config_store() - update config settings
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing config setting
 * @len:	buf length of config setting
 *
 * Return:      config setting buf length
 */
static ssize_t config_store(struct kobject *kobj,
		struct kobj_attribute *kobj_attr,
		const char *buf, size_t len)
{
	struct cifssrv_share *share;
	int cum = 0;
	int is_share = 0;
	char *share_buf;
	char *param_buf;
	char *data_buf;
	int share_sz = 0;
	int param_sz = 0;
	int data_sz = 0;
	int end = 0;
	int new;
	int ret = len;

	share_buf = kmalloc(SHARE_MAX_NAME_LEN, GFP_KERNEL);
	if (!share_buf)
		return -ENOMEM;

	param_buf = kmalloc(SHARE_MAX_NAME_LEN, GFP_KERNEL);
	if (!param_buf) {
		ret = -ENOMEM;
		goto EXIT1;
	}

	data_buf = kmalloc(SHARE_MAX_DATA_LEN, GFP_KERNEL);
	if (!data_buf) {
		ret = -ENOMEM;
		goto EXIT2;
	}

	while (!end) {
		memset(share_buf, 0, SHARE_MAX_NAME_LEN);
		nxt_share(buf, &cum, share_buf, &share_sz, &end);

		if (share_sz && strcmp("global", share_buf)) {
			new = 0;
			share = check_share(share_buf, share_sz);

			if (!share) {
				share = kzalloc(sizeof(struct cifssrv_share),
						GFP_KERNEL);
				if (!share) {
					ret = -ENOMEM;
					goto EXIT3;
				}

				share->sharename = kzalloc(share_sz+1,
							GFP_KERNEL);
				if (!share->sharename) {
					ret = -ENOMEM;
					kfree(share);
					goto EXIT3;
				}
				strncpy(share->sharename, share_buf, share_sz);
				init_params(share);
				new = 1;
			}
			do {
				param_sz = 0;
				data_sz = 0;

				memset(param_buf, 0, SHARE_MAX_NAME_LEN);
				memset(data_buf, 0, SHARE_MAX_DATA_LEN);

				nxt_param(buf, &cum, param_buf, data_buf,
					&param_sz, &data_sz, &is_share, &end);

				if (param_sz)
					if (update_share(share, param_buf,
						data_buf, param_sz, data_sz) ==
							-ENOMEM) {
						ret = -ENOMEM;
						free_share(share);
						kfree(share);
						goto EXIT3;
					}
			} while (!is_share && !end);

			if (new) {
				/* By this time path configuration should be
				done for the [share] through config file;
				if not then handle this */
				if (!share->path) {
					cifssrv_err(
					"[share=%s] add failed; path missing\n",
					share->sharename);

					free_share(share);
					kfree(share);
				} else {
					ret = __add_share(share,
							share->sharename,
							share->path);
					if (ret) {
						free_share(share);
						kfree(share);
					}
				}
			}
		} else{
			/* global share*/
			do {
				param_sz = 0;
				data_sz = 0;

				memset(param_buf, 0, SHARE_MAX_NAME_LEN);
				memset(data_buf, 0, SHARE_MAX_DATA_LEN);

				nxt_param(buf, &cum, param_buf, data_buf,
					&param_sz, &data_sz, &is_share, &end);
				if (param_sz)
					if (update_global(param_buf,
						data_buf, param_sz, data_sz) ==
							-ENOMEM) {
						ret = -ENOMEM;
						goto EXIT3;
				}
			} while (!is_share && !end);
		}

	}

EXIT3:
	kfree(data_buf);
EXIT2:
	kfree(param_buf);
EXIT1:
	kfree(share_buf);

	return ret;
}

/**
 * util_show() - show util setting - password hash
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing password hash
 *
 * Return:      output buffer length
 */
static ssize_t util_show(struct kobject *kobj,
			 struct kobj_attribute *kobj_attr,
			 char *buf)
{
	if (!strlen(key))
		return 0;

	memcpy(buf, "<", 1);
	memcpy(buf+1, key, CIFS_NTHASH_SIZE);
	memcpy(buf+1+CIFS_NTHASH_SIZE, ">", 1);

	memset(key, 0, CIFS_NTHASH_SIZE);

	return CIFS_NTHASH_SIZE+2;
}

/**
 * util_store() - update util settings - password hash
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing util setting
 * @len:	buf length of util setting
 *
 * Return:      util setting buf length
 */
static ssize_t util_store(struct kobject *kobj,
			  struct kobj_attribute *kobj_attr,
			  const char *buf, size_t len)
{
	struct nls_table *local_nls;
	char genkey[CIFS_NTHASH_SIZE];
	char *str1[1], *str2[1];
	long int sz;
	int rc;

	local_nls = load_nls_default();

	rc = init_2_strings(buf, str1, str2, len);
	if (rc) {
		unload_nls(local_nls);
		return rc;
	}

	if (kstrtol(*str1, 10, &sz)) {
		unload_nls(local_nls);
		kfree(*str1);
		kfree(*str2);
		return 0;
	}

	if (strlen(*str2) != sz) {
		cifssrv_err("[%s:%d] pwd corrupted\n", __func__, __LINE__);
		goto EXIT;
	}

	if (sz > MAX_NT_PWD_LEN) {
		cifssrv_err(
			"[%s:%d] pwd len %ld bytes exceed NT limit %d bytes\n",
				__func__, __LINE__, sz, MAX_NT_PWD_LEN);
		goto EXIT;
	}

	memset(genkey, '\0', CIFS_NTHASH_SIZE);

	rc = smb_E_md4hash(*str2, genkey, local_nls);
	if (rc) {
		cifssrv_err("%s Can't generate NT hash, error: %d\n",
				__func__, rc);
		goto EXIT;
	}
	memcpy(key, genkey, CIFS_NTHASH_SIZE);

EXIT:
	unload_nls(local_nls);
	kfree(*str1);
	kfree(*str2);
	return len;
}

/**
 * stat_store() - update client stat IP
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing config setting
 * @len:	buf length of client stat IP setting
 *
 * Return:      client stat IP setting buf length
 */
static ssize_t stat_store(struct kobject *kobj,
		struct kobj_attribute *kobj_attr,
		const char *buf, size_t len)
{
	int i = 0;

	if (!strncmp("CLIENT_STAT", buf, strlen("CLIENT_STAT"))) {
		while (buf[i++] != ':')
			;
		strncpy(statIP, &buf[i], MAX_ADDRBUFLEN);
	}

	return len;
}

/**
 * stat_show() - show cifssrv stat
 * @kobj:	kobject of the modules
 * @kobj_attr:	kobject attribute of the modules
 * @buf:	buffer containing stat info
 *
 * Return:      output buffer length
 */
static ssize_t stat_show(struct kobject *kobj,
		struct kobj_attribute *kobj_attr,
		char *buf)
{
	struct cifssrv_share *share;
	struct list_head *tmp;
	struct tcp_server_info *server;
	int count = 0, cum = 0, ret = 0, limit = PAGE_SIZE;

	if (!strlen(statIP)) {
		ret = snprintf(buf+cum, limit - cum,
				"Server uptime secs = %ld\n",
				(jiffies - server_start_time)/HZ);
		if (ret < 0)
			return cum;
		cum += ret;

		list_for_each(tmp, &cifssrv_share_list) {
			share = list_entry(tmp, struct cifssrv_share, list);
			if (share->path)
				count++;
		}

		ret = snprintf(buf+cum, limit - cum,
				"Number of shares = %d\n", count);
		if (ret < 0)
			return cum;
		cum += ret;
	} else {
		list_for_each(tmp, &cifssrv_connection_list) {
			server = list_entry(tmp, struct tcp_server_info, list);

			if (!strncmp(statIP, server->peeraddr,
			    strlen(server->peeraddr))) {

				if (server->connection_type == 0) {
					ret = snprintf(buf+cum, limit - cum,
						"Connection type = SMB1\n");
					if (ret < 0)
						return cum;
					cum += ret;
				} else if (server->connection_type ==
						SMB20_PROT_ID) {
					ret = snprintf(buf+cum, limit - cum,
						"\t> Connection type = SMB2.0\n");
					if (ret < 0)
						return cum;
					cum += ret;
				} else if (server->connection_type ==
						SMB21_PROT_ID) {
					ret = snprintf(buf+cum, limit - cum,
						"Connection type = SMB2.1\n");
					if (ret < 0)
						return cum;
					cum += ret;
				} else if (server->connection_type ==
						SMB30_PROT_ID) {
					ret = snprintf(buf+cum, limit - cum,
						"Connection type = SMB3.0\n");
					if (ret < 0)
						return cum;
					cum += ret;
				}

				ret = snprintf(buf+cum, limit - cum,
					"Current open files count = %d\n",
					server->stats.open_files_count);
				if (ret < 0)
					return cum;
				cum += ret;

				ret = snprintf(buf+cum, limit - cum,
					"Outstanding Request = %d\n",
					atomic_read(&server->req_running));
				if (ret < 0)
					return cum;
				cum += ret;

				ret = snprintf(buf+cum, limit - cum,
					"Total Requests Served = %d\n",
					server->stats.request_served);
				if (ret < 0)
					return cum;
				cum += ret;

				if (cifssrv_debug_enable) {
					ret = snprintf(buf+cum, limit - cum,
					"Avg. duration per request = %ld\n",
					server->stats.avg_req_duration);
					if (ret < 0)
						return cum;
					cum += ret;

					ret = snprintf(buf+cum, limit - cum,
					      "Max. duration request = %ld\n",
					      server->stats.max_timed_request);
					if (ret < 0)
						return cum;
					cum += ret;
				}

				break;
			}
		}

		memset(statIP, 0, MAX_ADDRBUFLEN);
	}

	return cum;
}

/* cifssrv sysfs entries */
static ssize_t cifssrv_attr_show(struct kobject *kobj,
				 struct attribute *attr, char *buf)
{
	struct kobj_attribute *kobj_attr =
			container_of(attr, struct kobj_attribute, attr);
	return kobj_attr->show(kobj, kobj_attr, buf);
}


static ssize_t cifssrv_attr_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buf, size_t len)
{
	struct kobj_attribute *kobj_attr =
			container_of(attr, struct kobj_attribute, attr);
	return kobj_attr->store(kobj, kobj_attr, buf, len);
}

#define SMB_ATTR(_name) \
	static struct kobj_attribute _name##_attr = \
__ATTR(_name, 0755, _name##_show, _name##_store)

SMB_ATTR(share);
SMB_ATTR(user);
SMB_ATTR(debug);
SMB_ATTR(caseless_search);
SMB_ATTR(config);
SMB_ATTR(util);
SMB_ATTR(stat);

static struct attribute *cifssrv_sysfs_attrs[] = {
	&share_attr.attr,
	&user_attr.attr,
	&debug_attr.attr,
	&caseless_search_attr.attr,
	&config_attr.attr,
	&util_attr.attr,
	&stat_attr.attr,
	NULL,
};

struct cifssrv_sysfs_obj {
	struct kobject kobj;
	struct completion kobj_unregister;
};

static const struct sysfs_ops cifssrv_attr_ops = {
	.show   = cifssrv_attr_show,
	.store  = cifssrv_attr_store,
};

static void cifssrv_attr_release(struct kobject *kobj)
{
	complete(&sysobj->kobj_unregister);
}

struct kobj_type cifssrvfs_ktype  = {
	.default_attrs  = cifssrv_sysfs_attrs,
	.sysfs_ops      = &cifssrv_attr_ops,
	.release        = cifssrv_attr_release,
};

/**
 * cifssrv_init_sysfs_parser() - init cifssrv sysfs entries
 *
 * Return:      0 on success, otherwise error
 */
static int cifssrv_init_sysfs_parser(void)
{
	int ret;
	sysobj = kzalloc(sizeof(struct cifssrv_sysfs_obj), GFP_NOFS);
	if (!sysobj)
		return -ENOMEM;

	init_completion(&sysobj->kobj_unregister);
	ret = kobject_init_and_add(&sysobj->kobj, &cifssrvfs_ktype,
							fs_kobj, "cifssrv");
	if (ret)
		kfree(sysobj);

	return 0;
}

/**
 * cifssrv_init_sysfs_parser() - cleanup cifssrv sysfs entries at modules exit
 *
 * Return:      0 on success, otherwise error
 */
static void exit_sysfs_parser(void)
{
	kobject_put(&sysobj->kobj);
	wait_for_completion(&sysobj->kobj_unregister);
	kfree(sysobj);
}

/**
 * cifssrv_add_IPC_share() - add share entry for IPC$ pipe with tid = 1
 *
 * Return:      0 on success, otherwise error
 */
static int cifssrv_add_IPC_share(void)
{
	char *ipc;
	int len, rc;

	len = strlen("IPC$") + 1;

	ipc = kmalloc(len, GFP_KERNEL);
	if (!ipc)
		return -ENOMEM;

	memcpy(ipc, "IPC$", len - 1);
	ipc[len - 1] = '\0';

	rc = add_share(ipc, NULL);
	if (rc)
		kfree(ipc);

	return rc;
}

/**
 * cifssrv_init_global_params() - initialize default values of Server name
 *		Domain name
 *
 * Return:      0 on success, otherwise -ENOMEM
 */
int cifssrv_init_global_params(void)
{
	int len;
	/* Add default values of Server name & Domain name*/

	len = strlen("CIFSSRV SERVER");

	server_string = kmalloc(len + 1, GFP_KERNEL);
	if (!server_string)
		return -ENOMEM;

	memcpy(server_string, "CIFSSRV SERVER", len);
	server_string[len] = '\0';

	len = strlen("WORKGROUP");

	workgroup = kmalloc(len + 1, GFP_KERNEL);
	if (!workgroup) {
		kfree(server_string);
		return -ENOMEM;
	}

	memcpy(workgroup, "WORKGROUP", len);
	workgroup[len] = '\0';

	return 0;
}

/**
 * cifssrv_free_global_params() - free global parameters
 */
void cifssrv_free_global_params(void)
{
	kfree(server_string);
	kfree(workgroup);
	kfree(guestAccountName);
}

/**
 * cifssrv_export_init() - perform export related setup at module
 *			load time
 *
 * Return:      0 on success, otherwise error
 */
int cifssrv_export_init(void)
{
	int rc;

	/* IPC share */
	rc = cifssrv_add_IPC_share();
	if (rc)
		return rc;

	rc = cifssrv_init_sysfs_parser();
	if (rc) {
		cifssrv_share_free();
		return rc;
	}

	rc = cifssrv_init_global_params();
	if (rc) {
		exit_sysfs_parser();
		cifssrv_share_free();
		return rc;
	}

	return 0;
}

/**
 * cifssrv_export_exit() - perform export related cleanup at module
 *			exit time
 */
void cifssrv_export_exit(void)
{
	exit_sysfs_parser();
	cifssrv_free_global_params();
	cifssrv_user_free();
	cifssrv_share_free();
}
