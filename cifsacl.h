// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *   Copyright (c) International Business Machines  Corp., 2007
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Modified by Namjae Jeon (namjae.jeon@protocolfreedom.org)
 */

#ifndef _CIFSACL_H
#define _CIFSACL_H


#define NUM_AUTHS (6)	/* number of authority fields */
#define SID_MAX_SUB_AUTHORITIES (15) /* max number of sub authority fields */

#define READ_BIT        0x4
#define WRITE_BIT       0x2
#define EXEC_BIT        0x1

#define UBITSHIFT	6
#define GBITSHIFT	3

#define ACCESS_ALLOWED	0
#define ACCESS_DENIED	1

#define SIDOWNER 1
#define SIDGROUP 2

/* Revision for ACLs */
#define SD_REVISION	1

/* Control flags for Security Descriptor */
#define OWNER_DEFAULTED		0x0001
#define GROUP_DEFAULTED		0x0002
#define DACL_PRESENT		0x0004
#define DACL_DEFAULTED		0x0008
#define SACL_PRESENT		0x0010
#define SACL_DEFAULTED		0x0020
#define DACL_TRUSTED		0x0040
#define SERVER_SECURITY		0x0080
#define DACL_AUTO_INHERIT_REQ	0x0100
#define SACL_AUTO_INHERIT_REQ	0x0200
#define DACL_AUTO_INHERITED	0x0400
#define SACL_AUTO_INHERITED	0x0800
#define DACL_PROTECTED		0x1000
#define SACL_PROTECTED		0x2000
#define RM_CONTROL_VALID	0x4000
#define SELF_RELATIVE		0x8000

/*
 * Security Descriptor length containing DACL with 3 ACEs (one each for
 * owner, group and world).
 */
#define DEFAULT_SEC_DESC_LEN (sizeof(struct cifs_ntsd) + \
			      sizeof(struct cifs_acl) + \
			      (sizeof(struct cifs_ace) * 3))

/*
 * Maximum size of a string representation of a SID:
 *
 * The fields are unsigned values in decimal. So:
 *
 * u8:  max 3 bytes in decimal
 * u32: max 10 bytes in decimal
 *
 * "S-" + 3 bytes for version field + 15 for authority field + NULL terminator
 *
 * For authority field, max is when all 6 values are non-zero and it must be
 * represented in hex. So "-0x" + 12 hex digits.
 *
 * Add 11 bytes for each subauthority field (10 bytes each + 1 for '-')
 */
#define SID_STRING_BASE_SIZE (2 + 3 + 15 + 1)
#define SID_STRING_SUBAUTH_SIZE (11) /* size of a single subauth string */

struct cifs_ntsd {
	__le16 revision; /* revision level */
	__le16 type;
	__le32 osidoffset;
	__le32 gsidoffset;
	__le32 sacloffset;
	__le32 dacloffset;
} __attribute__((packed));

struct cifs_sid {
	__u8 revision; /* revision level */
	__u8 num_subauth;
	__u8 authority[NUM_AUTHS];
	__le32 sub_auth[SID_MAX_SUB_AUTHORITIES]; /* sub_auth[num_subauth] */
} __attribute__((packed));

/* size of a struct cifs_sid, sans sub_auth array */
#define CIFS_SID_BASE_SIZE (1 + 1 + NUM_AUTHS)

struct cifs_acl {
	__le16 revision; /* revision level */
	__le16 size;
	__le32 num_aces;
} __attribute__((packed));

struct cifs_ace {
	__u8 type;
	__u8 flags;
	__le16 size;
	__le32 access_req;
	struct cifs_sid sid; /* ie UUID of user or group who gets these perms */
} __attribute__((packed));

struct cifsd_fattr {
	kuid_t	cf_uid;
	kgid_t	cf_gid;
	umode_t	cf_mode;
};

#endif /* _CIFSACL_H */

int compare_sids(const struct cifs_sid *ctsid, const struct cifs_sid *cwsid);
int parse_sid(struct cifs_sid *psid, char *end_of_acl);
void dump_ace(struct cifs_ace *pace, char *end_of_acl);
int check_permission_dacl(struct cifs_acl *pdacl, char *end_of_acl,
	struct cifs_sid *pownersid, struct cifs_sid *pgrpsid, __le32 daccess);
int get_dacl_size(struct cifs_acl *pdacl, char *end_of_acl);
int sid_to_id(struct cifs_sid *psid, struct cifsd_fattr *fattr, uint sidtype);
int id_to_sid(unsigned int cid, uint sidtype, struct cifs_sid *ssid);
int parse_sec_desc(struct cifs_ntsd *pntsd, int acl_len,
	struct cifsd_fattr *fattr);
int build_sec_desc(struct cifs_ntsd *pntsd, int addition_info,
	struct inode *inode);
void cifsd_fattr_to_inode(struct inode *inode, struct cifsd_fattr *fattr);
int init_cifsd_idmap(void);
void exit_cifsd_idmap(void);
