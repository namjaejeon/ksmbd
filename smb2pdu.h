/*
 *   fs/cifsd/smb2pdu.h
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

#ifndef _SMB2PDU_SERVER_H
#define _SMB2PDU_SERVER_H

#include "ntlmssp.h"

/* SMB2's Specific ERRNO */
#define ESHARE 50000

/*
 * Note that, due to trying to use names similar to the protocol specifications,
 * there are many mixed case field names in the structures below.  Although
 * this does not match typical Linux kernel style, it is necessary to be
 * be able to match against the protocol specfication.
 *
 * SMB2 commands
 * Some commands have minimal (wct=0,bcc=0), or uninteresting, responses
 * (ie no useful data other than the SMB error code itself) and are marked such.
 * Knowing this helps avoid response buffer allocations and copy in some cases.
 */

/* List of commands in host endian */
#define SMB2_NEGOTIATE_HE	0x0000
#define SMB2_SESSION_SETUP_HE	0x0001
#define SMB2_LOGOFF_HE		0x0002 /* trivial request/resp */
#define SMB2_TREE_CONNECT_HE	0x0003
#define SMB2_TREE_DISCONNECT_HE	0x0004 /* trivial req/resp */
#define SMB2_CREATE_HE		0x0005
#define SMB2_CLOSE_HE		0x0006
#define SMB2_FLUSH_HE		0x0007 /* trivial resp */
#define SMB2_READ_HE		0x0008
#define SMB2_WRITE_HE		0x0009
#define SMB2_LOCK_HE		0x000A
#define SMB2_IOCTL_HE		0x000B
#define SMB2_CANCEL_HE		0x000C
#define SMB2_ECHO_HE		0x000D
#define SMB2_QUERY_DIRECTORY_HE	0x000E
#define SMB2_CHANGE_NOTIFY_HE	0x000F
#define SMB2_QUERY_INFO_HE	0x0010
#define SMB2_SET_INFO_HE	0x0011
#define SMB2_OPLOCK_BREAK_HE	0x0012

/* The same list in little endian */
#define SMB2_NEGOTIATE		cpu_to_le16(SMB2_NEGOTIATE_HE)
#define SMB2_SESSION_SETUP	cpu_to_le16(SMB2_SESSION_SETUP_HE)
#define SMB2_LOGOFF		cpu_to_le16(SMB2_LOGOFF_HE)
#define SMB2_TREE_CONNECT	cpu_to_le16(SMB2_TREE_CONNECT_HE)
#define SMB2_TREE_DISCONNECT	cpu_to_le16(SMB2_TREE_DISCONNECT_HE)
#define SMB2_CREATE		cpu_to_le16(SMB2_CREATE_HE)
#define SMB2_CLOSE		cpu_to_le16(SMB2_CLOSE_HE)
#define SMB2_FLUSH		cpu_to_le16(SMB2_FLUSH_HE)
#define SMB2_READ		cpu_to_le16(SMB2_READ_HE)
#define SMB2_WRITE		cpu_to_le16(SMB2_WRITE_HE)
#define SMB2_LOCK		cpu_to_le16(SMB2_LOCK_HE)
#define SMB2_IOCTL		cpu_to_le16(SMB2_IOCTL_HE)
#define SMB2_CANCEL		cpu_to_le16(SMB2_CANCEL_HE)
#define SMB2_ECHO		cpu_to_le16(SMB2_ECHO_HE)
#define SMB2_QUERY_DIRECTORY	cpu_to_le16(SMB2_QUERY_DIRECTORY_HE)
#define SMB2_CHANGE_NOTIFY	cpu_to_le16(SMB2_CHANGE_NOTIFY_HE)
#define SMB2_QUERY_INFO		cpu_to_le16(SMB2_QUERY_INFO_HE)
#define SMB2_SET_INFO		cpu_to_le16(SMB2_SET_INFO_HE)
#define SMB2_OPLOCK_BREAK	cpu_to_le16(SMB2_OPLOCK_BREAK_HE)

/*Create Action Flags*/
#define FILE_SUPERSEDED                0x00000000
#define FILE_OPENED            0x00000001
#define FILE_CREATED           0x00000002
#define FILE_OVERWRITTEN       0x00000003


#define NUMBER_OF_SMB2_COMMANDS	0x0013

/* BB FIXME - analyze following length BB */
#define MAX_SMB2_HDR_SIZE 0x78 /* 4 len + 64 hdr + (2*24 wct) + 2 bct + 2 pad */

#define SMB2_PROTO_NUMBER __constant_cpu_to_le32(0x424d53fe) /* 'B''M''S' */

#define STATUS_NO_MORE_FILES __constant_cpu_to_le32(0x80000006)
#define STATUS_OBJECT_NAME_NOT_FOUND __constant_cpu_to_le32(0xC0000034)
/*
 * SMB2 Header Definition
 *
 * "MBZ" :  Must be Zero
 * "BB"  :  BugBug, Something to check/review/analyze later
 * "PDU" :  "Protocol Data Unit" (ie a network "frame")
 *
 */

#define SMB2_HEADER_STRUCTURE_SIZE __constant_cpu_to_le16(64)

struct smb2_hdr {
	__be32 smb2_buf_length;	/* big endian on wire */
				/* length is only two or three bytes - with
				 one or two byte type preceding it that MBZ */
	__u8   ProtocolId[4];	/* 0xFE 'S' 'M' 'B' */
	__le16 StructureSize;	/* 64 */
	__le16 CreditCharge;	/* MBZ */
	__le32 Status;		/* Error from server */
	__le16 Command;
	__le16 CreditRequest;  /* CreditResponse */
	__le32 Flags;
	__le32 NextCommand;
	__u64  MessageId;	/* opaque - so can stay little endian */
	union {
		struct {
			__le32 ProcessId;
			__u32  TreeId;
		} __packed SyncId;
		__u64  AsyncId;
	} __packed Id;
	__u64  SessionId;	/* opaque - so do not make little endian */
	__u8   Signature[16];
} __packed;

struct smb2_pdu {
	struct smb2_hdr hdr;
	__le16 StructureSize2; /* size of wct area (varies, request specific) */
} __packed;

/*
 *	SMB2 flag definitions
 */
#define SMB2_FLAGS_SERVER_TO_REDIR	__constant_cpu_to_le32(0x00000001)
#define SMB2_FLAGS_ASYNC_COMMAND	__constant_cpu_to_le32(0x00000002)
#define SMB2_FLAGS_RELATED_OPERATIONS	__constant_cpu_to_le32(0x00000004)
#define SMB2_FLAGS_SIGNED		__constant_cpu_to_le32(0x00000008)
#define SMB2_FLAGS_DFS_OPERATIONS	__constant_cpu_to_le32(0x10000000)

/*
 *	Definitions for SMB2 Protocol Data Units (network frames)
 *
 *  See MS-SMB2.PDF specification for protocol details.
 *  The Naming convention is the lower case version of the SMB2
 *  command code name for the struct. Note that structures must be packed.
 *
 */

#define SMB2_ERROR_STRUCTURE_SIZE2 __constant_cpu_to_le16(9)

struct smb2_err_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;
	__le16 Reserved; /* MBZ */
	__le32 ByteCount;  /* even if zero, at least one byte follows */
	__u8   ErrorData[1];  /* variable length */
} __packed;

struct smb2_negotiate_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 36 */
	__le16 DialectCount;
	__le16 SecurityMode;
	__le16 Reserved;	/* MBZ */
	__le32 Capabilities;
	__u8   ClientGUID[SMB2_CLIENT_GUID_SIZE];
	/* In SMB3.02 and earlier next three were MBZ le64 ClientStartTime */
	__le32 NegotiateContextOffset; /* SMB3.1.1 only. MBZ earlier */
	__le16 NegotiateContextCount;  /* SMB3.1.1 only. MBZ earlier */
	__le16 Reserved2;
	__le16 Dialects[1]; /* One dialect (vers=) at a time for now */
} __packed;

/* SecurityMode flags */
#define	SMB2_NEGOTIATE_SIGNING_ENABLED	0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED	0x0002
/* Capabilities flags */
#define SMB2_GLOBAL_CAP_DFS		0x00000001
#define SMB2_GLOBAL_CAP_LEASING		0x00000002 /* Resp only New to SMB2.1 */
#define SMB2_GLOBAL_CAP_LARGE_MTU	0X00000004 /* Resp only New to SMB2.1 */
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL	0x00000008 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_ENCRYPTION	0x00000040 /* New to SMB3 */
/* Internal types */
#define SMB2_NT_FIND			0x00100000
#define SMB2_LARGE_FILES		0x00200000

#define SMB311_SALT_SIZE			32
/* Hash Algorithm Types */
#define SMB2_PREAUTH_INTEGRITY_SHA512	cpu_to_le16(0x0001)

struct smb2_preauth_neg_context {
	__le16	ContextType; /* 1 */
	__le16	DataLength;
	__le32	Reserved;
	__le16	HashAlgorithmCount; /* 1 */
	__le16	SaltLength;
	__le16	HashAlgorithms; /* HashAlgorithms[0] since only one defined */
	__u8	Salt[SMB311_SALT_SIZE];
} __packed;

/* Encryption Algorithms Ciphers */
#define SMB2_ENCRYPTION_AES128_CCM	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)

struct smb2_encryption_neg_context {
	__le16	ContextType; /* 2 */
	__le16	DataLength;
	__le32	Reserved;
	__le16	CipherCount; /* AES-128-GCM and AES-128-CCM */
	__le16	Ciphers[2]; /* Ciphers[0] since only one used now */
} __packed;

struct smb2_negotiate_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 65 */
	__le16 SecurityMode;
	__le16 DialectRevision;
	__le16 NegotiateContextCount;	/* Prior to SMB3.1.1 was Reserved & MBZ */
	__u8   ServerGUID[16];
	__le32 Capabilities;
	__le32 MaxTransactSize;
	__le32 MaxReadSize;
	__le32 MaxWriteSize;
	__le64 SystemTime;	/* MBZ */
	__le64 ServerStartTime;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__le32 NegotiateContextOffset;	/* Pre:SMB3.1.1 was reserved/ignored */
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;

/* Flags */
#define SMB2_SESSION_REQ_FLAG_BINDING		0x01
#define SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA	0x04

#define SMB2_SESSION_EXPIRED 0x1
#define SMB2_SESSION_IN_PROGRESS 0x2
#define SMB2_SESSION_VALID 0x3

/* Flags */
#define SMB2_SESSION_REQ_FLAG_BINDING		0x01
#define SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA	0x04

struct smb2_sess_setup_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 25 */
	__u8   Flags;
	__u8   SecurityMode;
	__le32 Capabilities;
	__le32 Channel;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__le64 PreviousSessionId;
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;

/* Flags/Reserved for SMB3.1.1 */
#define SMB2_SHAREFLAG_CLUSTER_RECONNECT	0x0001

/* Currently defined SessionFlags */
#define SMB2_SESSION_FLAG_IS_GUEST	0x0001
#define SMB2_SESSION_FLAG_IS_NULL	0x0002
#define SMB2_SESSION_FLAG_ENCRYPT_DATA	0x0004
struct smb2_sess_setup_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 9 */
	__le16 SessionFlags;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;

struct smb2_logoff_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_logoff_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_tree_connect_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 9 */
	__le16 Reserved;	/* Flags in SMB3.1.1 */
	__le16 PathOffset;
	__le16 PathLength;
	__u8   Buffer[1];	/* variable length */
} __packed;

struct smb2_tree_connect_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 16 */
	__u8   ShareType;  /* see below */
	__u8   Reserved;
	__le32 ShareFlags; /* see below */
	__le32 Capabilities; /* see below */
	__le32 MaximalAccess;
} __packed;

/* Possible ShareType values */
#define SMB2_SHARE_TYPE_DISK	0x01
#define SMB2_SHARE_TYPE_PIPE	0x02
#define	SMB2_SHARE_TYPE_PRINT	0x03

/*
 * Possible ShareFlags - exactly one and only one of the first 4 caching flags
 * must be set (any of the remaining, SHI1005, flags may be set individually
 * or in combination.
 */
#define SMB2_SHAREFLAG_MANUAL_CACHING			0x00000000
#define SMB2_SHAREFLAG_AUTO_CACHING			0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING			0x00000020
#define SMB2_SHAREFLAG_NO_CACHING			0x00000030
#define SHI1005_FLAGS_DFS				0x00000001
#define SHI1005_FLAGS_DFS_ROOT				0x00000002
#define SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS		0x00000100
#define SHI1005_FLAGS_FORCE_SHARED_DELETE		0x00000200
#define SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING		0x00000400
#define SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM	0x00000800
#define SHI1005_FLAGS_FORCE_LEVELII_OPLOCK		0x00001000
#define SHI1005_FLAGS_ENABLE_HASH			0x00002000

/* Possible share capabilities */
#define SMB2_SHARE_CAP_DFS	cpu_to_le32(0x00000008)

struct smb2_tree_disconnect_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_tree_disconnect_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

/* File Attrubutes */
#define FILE_ATTRIBUTE_READONLY_LE		cpu_to_le32(0x00000001)
#define FILE_ATTRIBUTE_HIDDEN_LE		cpu_to_le32(0x00000002)
#define FILE_ATTRIBUTE_SYSTEM_LE		cpu_to_le32(0x00000004)
#define FILE_ATTRIBUTE_DIRECTORY_LE		cpu_to_le32(0x00000010)
#define FILE_ATTRIBUTE_ARCHIVE_LE		cpu_to_le32(0x00000020)
#define FILE_ATTRIBUTE_NORMAL_LE		cpu_to_le32(0x00000080)
#define FILE_ATTRIBUTE_TEMPORARY_LE		cpu_to_le32(0x00000100)
#define FILE_ATTRIBUTE_SPARSE_FILE_LE		cpu_to_le32(0x00000200)
#define FILE_ATTRIBUTE_REPARSE_POINT_LE		cpu_to_le32(0x00000400)
#define FILE_ATTRIBUTE_COMPRESSED_LE		cpu_to_le32(0x00000800)
#define FILE_ATTRIBUTE_OFFLINE_LE		cpu_to_le32(0x00001000)
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED_LE	cpu_to_le32(0x00002000)
#define FILE_ATTRIBUTE_ENCRYPTED_LE		cpu_to_le32(0x00004000)
#define FILE_ATTRIBUTE_INTEGRITY_STREAML_LE	cpu_to_le32(0x00008000)
#define FILE_ATTRIBUTE_NO_SCRUB_DATA_LE		cpu_to_le32(0x00020000)
#define FILE_ATTRIBUTE_MASK			cpu_to_le32(0x00007FB7)

/* Oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE		0x00
#define SMB2_OPLOCK_LEVEL_II		0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08
#define SMB2_OPLOCK_LEVEL_BATCH		0x09
#define SMB2_OPLOCK_LEVEL_LEASE		0xFF
/* Non-spec internal type */
#define SMB2_OPLOCK_LEVEL_NOCHANGE	0x99

/* Desired Access Flags */
#define FILE_READ_DATA_LE		cpu_to_le32(0x00000001)
#define FILE_LIST_DIRECTORY_LE		cpu_to_le32(0x00000001)
#define FILE_WRITE_DATA_LE		cpu_to_le32(0x00000002)
#define FILE_ADD_FILE_LE		cpu_to_le32(0x00000002)
#define FILE_APPEND_DATA_LE		cpu_to_le32(0x00000004)
#define FILE_ADD_SUBDIRECTORY_LE	cpu_to_le32(0x00000004)
#define FILE_READ_EA_LE			cpu_to_le32(0x00000008)
#define FILE_WRITE_EA_LE		cpu_to_le32(0x00000010)
#define FILE_EXECUTE_LE			cpu_to_le32(0x00000020)
#define FILE_TRAVERSE_LE		cpu_to_le32(0x00000020)
#define FILE_DELETE_CHILD_LE		cpu_to_le32(0x00000040)
#define FILE_READ_ATTRIBUTES_LE		cpu_to_le32(0x00000080)
#define FILE_WRITE_ATTRIBUTES_LE	cpu_to_le32(0x00000100)
#define FILE_DELETE_LE			cpu_to_le32(0x00010000)
#define FILE_READ_CONTROL_LE		cpu_to_le32(0x00020000)
#define FILE_WRITE_DAC_LE		cpu_to_le32(0x00040000)
#define FILE_WRITE_OWNER_LE		cpu_to_le32(0x00080000)
#define FILE_SYNCHRONIZE_LE		cpu_to_le32(0x00100000)
#define FILE_ACCESS_SYSTEM_SECURITY_LE	cpu_to_le32(0x01000000)
#define FILE_MAXIMAL_ACCESS_LE		cpu_to_le32(0x02000000)
#define FILE_GENERIC_ALL_LE		cpu_to_le32(0x10000000)
#define FILE_GENERIC_EXECUTE_LE		cpu_to_le32(0x20000000)
#define FILE_GENERIC_WRITE_LE		cpu_to_le32(0x40000000)
#define FILE_GENERIC_READ_LE		cpu_to_le32(0x80000000)
#define DISIRED_ACCESS_MASK		cpu_to_le32(0xF20F01FF)

/* ShareAccess Flags */
#define FILE_SHARE_READ_LE		cpu_to_le32(0x00000001)
#define FILE_SHARE_WRITE_LE		cpu_to_le32(0x00000002)
#define FILE_SHARE_DELETE_LE		cpu_to_le32(0x00000004)
#define FILE_SHARE_ALL_LE		cpu_to_le32(0x00000007)

/* CreateDisposition Flags */
#define FILE_SUPERSEDE_LE		cpu_to_le32(0x00000000)
#define FILE_OPEN_LE			cpu_to_le32(0x00000001)
#define FILE_CREATE_LE			cpu_to_le32(0x00000002)
#define	FILE_OPEN_IF_LE			cpu_to_le32(0x00000003)
#define FILE_OVERWRITE_LE		cpu_to_le32(0x00000004)
#define FILE_OVERWRITE_IF_LE		cpu_to_le32(0x00000005)

#define FILE_READ_RIGHTS_LE (FILE_READ_DATA_LE | FILE_READ_EA_LE \
			| FILE_READ_ATTRIBUTES_LE)
#define FILE_WRITE_RIGHTS_LE (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE \
			| FILE_WRITE_EA_LE | FILE_WRITE_ATTRIBUTES_LE)
#define FILE_EXEC_RIGHTS_LE (FILE_EXECUTE_LE)

/* Impersonation Levels */
#define IL_ANONYMOUS		cpu_to_le32(0x00000000)
#define IL_IDENTIFICATION	cpu_to_le32(0x00000001)
#define IL_IMPERSONATION	cpu_to_le32(0x00000002)
#define IL_DELEGATE		cpu_to_le32(0x00000003)

/* Create Context Values */
#define SMB2_CREATE_EA_BUFFER			"ExtA" /* extended attributes */
#define SMB2_CREATE_SD_BUFFER			"SecD" /* security descriptor */
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST	"DHnQ"
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT	"DHnC"
#define SMB2_CREATE_ALLOCATION_SIZE		"AlSi"
#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST "MxAc"
#define SMB2_CREATE_TIMEWARP_REQUEST		"TWrp"
#define SMB2_CREATE_QUERY_ON_DISK_ID		"QFid"
#define SMB2_CREATE_REQUEST_LEASE		"RqLs"

struct smb2_create_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 57 */
	__u8   SecurityFlags;
	__u8   RequestedOplockLevel;
	__le32 ImpersonationLevel;
	__le64 SmbCreateFlags;
	__le64 Reserved;
	__le32 DesiredAccess;
	__le32 FileAttributes;
	__le32 ShareAccess;
	__le32 CreateDisposition;
	__le32 CreateOptions;
	__le16 NameOffset;
	__le16 NameLength;
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[0];
} __packed;

struct smb2_create_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 89 */
	__u8   OplockLevel;
	__u8   Reserved;
	__le32 CreateAction;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndofFile;
	__le32 FileAttributes;
	__le32 Reserved2;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[1];
} __packed;

struct create_context {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8 Buffer[0];
} __packed;

struct create_durable {
	struct create_context ccontext;
	__u8   Name[8];
	union {
		__u8  Reserved[16];
		struct {
			__u64 PersistentFileId;
			__u64 VolatileFileId;
		} Fid;
	} Data;
} __packed;

struct create_mxac_req {
	struct create_context ccontext;
	__u8   Name[8];
	__le64 Timestamp;
} __packed;

struct create_alloc_size_req {
	struct create_context ccontext;
	__u8   Name[8];
	__le64 AllocationSize;
} __packed;

struct create_durable_rsp {
	struct create_context ccontext;
	__u8   Name[8];
	union {
		__u8  Reserved[8];
		__u64 data;
	} Data;
} __packed;

struct create_mxac_rsp {
	struct create_context ccontext;
	__u8   Name[8];
	__le32 QueryStatus;
	__le32 MaximalAccess;
} __packed;

struct create_disk_id_rsp {
	struct create_context ccontext;
	__u8   Name[8];
	__le64 DiskFileId;
	__le64 VolumeId;
	__u8  Reserved[16];
} __packed;

#define SMB2_LEASE_NONE			__constant_cpu_to_le32(0x00)
#define SMB2_LEASE_READ_CACHING		__constant_cpu_to_le32(0x01)
#define SMB2_LEASE_HANDLE_CACHING	__constant_cpu_to_le32(0x02)
#define SMB2_LEASE_WRITE_CACHING	__constant_cpu_to_le32(0x04)

#define SMB2_LEASE_FLAG_BREAK_IN_PROGRESS __constant_cpu_to_le32(0x02)

struct lease_context {
	__le64 LeaseKeyLow;
	__le64 LeaseKeyHigh;
	__le32 LeaseState;
	__le32 LeaseFlags;
	__le64 LeaseDuration;
} __packed;

struct create_lease {
	struct create_context ccontext;
	__u8   Name[8];
	struct lease_context lcontext;
} __packed;

/* Currently defined values for close flags */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB	cpu_to_le16(0x0001)
struct smb2_close_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 24 */
	__le16 Flags;
	__le32 Reserved;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
} __packed;

struct smb2_close_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* 60 */
	__le16 Flags;
	__le32 Reserved;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */
	__le64 EndOfFile;
	__le32 Attributes;
} __packed;

struct smb2_flush_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 24 */
	__le16 Reserved1;
	__le32 Reserved2;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
} __packed;

struct smb2_flush_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;
	__le16 Reserved;
} __packed;

struct smb2_read_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__u8   Padding; /* offset from start of SMB2 header to place read */
	__u8   Reserved;
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le32 MinimumCount;
	__le32 Channel; /* Reserved MBZ */
	__le32 RemainingBytes;
	__le16 ReadChannelInfoOffset; /* Reserved MBZ */
	__le16 ReadChannelInfoLength; /* Reserved MBZ */
	__u8   Buffer[1];
} __packed;

struct smb2_read_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__u32  Reserved2;
	__u8   Buffer[1];
} __packed;

/* For write request Flags field below the following flag is defined: */
#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001

struct smb2_write_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__le16 DataOffset; /* offset from start of SMB2 header to write data */
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le32 Channel; /* Reserved MBZ */
	__le32 RemainingBytes;
	__le16 WriteChannelInfoOffset; /* Reserved MBZ */
	__le16 WriteChannelInfoLength; /* Reserved MBZ */
	__le32 Flags;
	__u8   Buffer[1];
} __packed;

struct smb2_write_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__u32  Reserved2;
	__u8   Buffer[1];
} __packed;

struct smb2_ioctl_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 57 */
	__le16 Reserved; /* offset from start of SMB2 header to write data */
	__le32 CntCode;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le32 inputoffset; /* Reserved MBZ */
	__le32 inputcount;
	__le32 maxinputresp;
	__le32 outputoffset;
	__le32 outputcount;
	__le32 maxoutputresp;
	__le32 flags;
	__le32 Reserved2;
	__u8 Buffer[1];
} __packed;

struct smb2_ioctl_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__le16 Reserved; /* offset from start of SMB2 header to write data */
	__le32 CntCode;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le32 inputoffset; /* Reserved MBZ */
	__le32 inputcount;
	__le32 outputoffset;
	__le32 outputcount;
	__le32 flags;
	__le32 Reserved2;
	__u8 Buffer[1];
} __packed;

struct validate_negotiate_info_req {
	__le32 Capabilities;
	__u8   Guid[SMB2_CLIENT_GUID_SIZE];
	__le16 SecurityMode;
	__le16 DialectCount;
	__le16 Dialects[1]; /* dialect (someday maybe list) client asked for */
} __packed;

struct validate_negotiate_info_rsp {
	__le32 Capabilities;
	__u8   Guid[SMB2_CLIENT_GUID_SIZE];
	__le16 SecurityMode;
	__le16 Dialect; /* Dialect in use for the connection */
} __packed;

struct smb_sockaddr_in {
	__le16 Port;
	__le32 IPv4address;
	__u8 Reserved[8];
} __packed;

struct smb_sockaddr_in6 {
	__le16 Port;
	__le32 FlowInfo;
	__u8 IPv6address[16];
	__le32 ScopeId;
} __packed;

#define INTERNETWORK	0x0002
#define INTERNETWORKV6	0x0017

struct sockaddr_storage_rsp {
	__le16 Family;
	union {
		struct smb_sockaddr_in addr4;
		struct smb_sockaddr_in6 addr6;
	};
} __packed;

#define RSS_CAPABLE	0x00000001
#define RDMA_CAPABLE	0x00000002

struct network_interface_info_ioctl_rsp {
	__le32 Next; /* next interface. zero if this is last one */
	__le32 IfIndex;
	__le32 Capability; /* RSS or RDMA Capable */
	__le32 Reserved;
	__le64 LinkSpeed;
	char	SockAddr_Storage[128];
} __packed;

struct file_object_buf_type1_ioctl_rsp {
	__u8 ObjectId[16];
	__u8 BirthVolumeId[16];
	__u8 BirthObjectId[16];
	__u8 DomainId[16];
} __packed;

/* Completion Filter flags for Notify */
#define FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
#define FILE_NOTIFY_CHANGE_NAME		0x00000003
#define FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004
#define FILE_NOTIFY_CHANGE_SIZE		0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020
#define FILE_NOTIFY_CHANGE_CREATION	0x00000040
#define FILE_NOTIFY_CHANGE_EA		0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY	0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800

struct smb2_notify_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 32 */
	__le16 Flags;
	__le32 OutputBufferLength;
	__u64 PersistentFileId; /* opaque endianness */
	__u64 VolatileFileId; /* opaque endianness */
	__u32 CompletionFileter;
	__u32 Reserved;
} __packed;

struct smb2_notify_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 9 */
	__le16 OutputBufferOffset;
	__le32 OutputBufferLength;
	__u8 Buffer[1];
} __packed;

/* SMB2 Notify Action Flags */
#define FILE_ACTION_ADDED		0x00000001
#define FILE_ACTION_REMOVED		0x00000002
#define FILE_ACTION_MODIFIED		0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME	0x00000005
#define FILE_ACTION_ADDED_STREAM	0x00000006
#define FILE_ACTION_REMOVED_STREAM	0x00000007
#define FILE_ACTION_MODIFIED_STREAM	0x00000008
#define FILE_ACTION_REMOVED_BY_DELETE	0x00000009

struct FileNotifyInformation {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	char FileName[0];
} __packed;

#define SMB2_LOCKFLAG_SHARED		0x0001
#define SMB2_LOCKFLAG_EXCLUSIVE		0x0002
#define SMB2_LOCKFLAG_UNLOCK		0x0004
#define SMB2_LOCKFLAG_FAIL_IMMEDIATELY	0x0010
#define SMB2_LOCKFLAG_MASK		0x0007

struct smb2_lock_element {
	__le64 Offset;
	__le64 Length;
	__le32 Flags;
	__le32 Reserved;
} __packed;

struct smb2_lock_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 48 */
	__le16 LockCount;
	__le32 Reserved;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	/* Followed by at least one */
	struct smb2_lock_element locks[1];
} __packed;

struct smb2_lock_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_echo_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__u16  Reserved;
} __packed;

struct smb2_echo_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__u16  Reserved;
} __packed;

/* search (query_directory) Flags field */
#define SMB2_RESTART_SCANS		0x01
#define SMB2_RETURN_SINGLE_ENTRY	0x02
#define SMB2_INDEX_SPECIFIED		0x04
#define SMB2_REOPEN			0x10

struct smb2_query_directory_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 33 */
	__u8   FileInformationClass;
	__u8   Flags;
	__le32 FileIndex;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__le16 FileNameOffset;
	__le16 FileNameLength;
	__le32 OutputBufferLength;
	__u8   Buffer[1];
} __packed;

struct smb2_query_directory_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 9 */
	__le16 OutputBufferOffset;
	__le32 OutputBufferLength;
	__u8   Buffer[1];
} __packed;

/* Possible InfoType values */
#define SMB2_O_INFO_FILE	0x01
#define SMB2_O_INFO_FILESYSTEM	0x02
#define SMB2_O_INFO_SECURITY	0x03
#define SMB2_O_INFO_QUOTA	0x04

struct smb2_query_info_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 41 */
	__u8   InfoType;
	__u8   FileInfoClass;
	__le32 OutputBufferLength;
	__le16 InputBufferOffset;
	__u16  Reserved;
	__le32 InputBufferLength;
	__le32 AdditionalInformation;
	__le32 Flags;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__u8   Buffer[1];
} __packed;

struct smb2_query_info_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 9 */
	__le16 OutputBufferOffset;
	__le32 OutputBufferLength;
	__u8   Buffer[1];
} __packed;

struct smb2_set_info_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 33 */
	__u8   InfoType;
	__u8   FileInfoClass;
	__le32 BufferLength;
	__le16 BufferOffset;
	__u16  Reserved;
	__le32 AdditionalInformation;
	__u64  PersistentFileId; /* opaque endianness */
	__u64  VolatileFileId; /* opaque endianness */
	__u8   Buffer[1];
} __packed;

struct smb2_set_info_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 2 */
} __packed;


/* FILE Info response size */
#define FILE_DIRECTORY_INFORMATION_SIZE       1
#define FILE_FULL_DIRECTORY_INFORMATION_SIZE  2
#define FILE_BOTH_DIRECTORY_INFORMATION_SIZE  3
#define FILE_BASIC_INFORMATION_SIZE           40
#define FILE_STANDARD_INFORMATION_SIZE        24
#define FILE_INTERNAL_INFORMATION_SIZE        8
#define FILE_EA_INFORMATION_SIZE              4
#define FILE_ACCESS_INFORMATION_SIZE          4
#define FILE_NAME_INFORMATION_SIZE            9
#define FILE_RENAME_INFORMATION_SIZE          10
#define FILE_LINK_INFORMATION_SIZE            11
#define FILE_NAMES_INFORMATION_SIZE           12
#define FILE_DISPOSITION_INFORMATION_SIZE     13
#define FILE_POSITION_INFORMATION_SIZE        14
#define FILE_FULL_EA_INFORMATION_SIZE         15
#define FILE_MODE_INFORMATION_SIZE            4
#define FILE_ALIGNMENT_INFORMATION_SIZE       4
#define FILE_ALL_INFORMATION_SIZE             100
#define FILE_ALLOCATION_INFORMATION_SIZE      19
#define FILE_END_OF_FILE_INFORMATION_SIZE     20
#define FILE_ALTERNATE_NAME_INFORMATION_SIZE  8
#define FILE_STREAM_INFORMATION_SIZE          24
#define FILE_PIPE_INFORMATION_SIZE            23
#define FILE_PIPE_LOCAL_INFORMATION_SIZE      24
#define FILE_PIPE_REMOTE_INFORMATION_SIZE     25
#define FILE_MAILSLOT_QUERY_INFORMATION_SIZE  26
#define FILE_MAILSLOT_SET_INFORMATION_SIZE    27
#define FILE_COMPRESSION_INFORMATION_SIZE     16
#define FILE_OBJECT_ID_INFORMATION_SIZE       29
/* Number 30 not defined in documents */
#define FILE_MOVE_CLUSTER_INFORMATION_SIZE    31
#define FILE_QUOTA_INFORMATION_SIZE           32
#define FILE_REPARSE_POINT_INFORMATION_SIZE   33
#define FILE_NETWORK_OPEN_INFORMATION_SIZE    56
#define FILE_ATTRIBUTE_TAG_INFORMATION_SIZE   8


/* FS Info response  size */
#define FS_DEVICE_INFORMATION_SIZE     8
#define FS_ATTRIBUTE_INFORMATION_SIZE  16
#define FS_VOLUME_INFORMATION_SIZE     24
#define FS_SIZE_INFORMATION_SIZE       24
#define FS_FULL_SIZE_INFORMATION_SIZE  32


/* FS_ATTRIBUTE_File_System_Name */
#define FS_TYPE_SUPPORT_SIZE   44
struct fs_type_info {
	char		*fs_name;
	long int        magic_number;
} __packed;

struct smb2_oplock_break {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 24 */
	__u8   OplockLevel;
	__u8   Reserved;
	__le32 Reserved2;
	__u64  PersistentFid;
	__u64  VolatileFid;
} __packed;

#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED cpu_to_le32(0x01)

struct smb2_lease_break {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 44 */
	__le16 Reserved;
	__le32 Flags;
	__u8   LeaseKey[16];
	__le32 CurrentLeaseState;
	__le32 NewLeaseState;
	__le32 BreakReason;
	__le32 AccessMaskHint;
	__le32 ShareMaskHint;
} __packed;

struct smb2_lease_ack {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 36 */
	__le16 Reserved;
	__le32 Flags;
	__u8   LeaseKey[16];
	__le32 LeaseState;
	__le64 LeaseDuration;
} __packed;

/*
 *	PDU infolevel structure definitions
 *	BB consider moving to a different header
 */

/* File System Information Classes */
#define FS_VOLUME_INFORMATION		1 /* Query */
#define FS_LABEL_INFORMATION		2 /* Set */
#define FS_SIZE_INFORMATION		3 /* Query */
#define FS_DEVICE_INFORMATION		4 /* Query */
#define FS_ATTRIBUTE_INFORMATION	5 /* Query */
#define FS_CONTROL_INFORMATION		6 /* Query, Set */
#define FS_FULL_SIZE_INFORMATION	7 /* Query */
#define FS_OBJECT_ID_INFORMATION	8 /* Query, Set */
#define FS_DRIVER_PATH_INFORMATION	9 /* Query */

struct smb2_fs_full_size_info {
	__le64 TotalAllocationUnits;
	__le64 CallerAvailableAllocationUnits;
	__le64 ActualAvailableAllocationUnits;
	__le32 SectorsPerAllocationUnit;
	__le32 BytesPerSector;
} __packed;

/* partial list of QUERY INFO levels */
#define FILE_DIRECTORY_INFORMATION	1
#define FILE_FULL_DIRECTORY_INFORMATION 2
#define FILE_BOTH_DIRECTORY_INFORMATION 3
#define FILE_BASIC_INFORMATION		4
#define FILE_STANDARD_INFORMATION	5
#define FILE_INTERNAL_INFORMATION	6
#define FILE_EA_INFORMATION	        7
#define FILE_ACCESS_INFORMATION		8
#define FILE_NAME_INFORMATION		9
#define FILE_RENAME_INFORMATION		10
#define FILE_LINK_INFORMATION		11
#define FILE_NAMES_INFORMATION		12
#define FILE_DISPOSITION_INFORMATION	13
#define FILE_POSITION_INFORMATION	14
#define FILE_FULL_EA_INFORMATION	15
#define FILE_MODE_INFORMATION		16
#define FILE_ALIGNMENT_INFORMATION	17
#define FILE_ALL_INFORMATION		18
#define FILE_ALLOCATION_INFORMATION	19
#define FILE_END_OF_FILE_INFORMATION	20
#define FILE_ALTERNATE_NAME_INFORMATION 21
#define FILE_STREAM_INFORMATION		22
#define FILE_PIPE_INFORMATION		23
#define FILE_PIPE_LOCAL_INFORMATION	24
#define FILE_PIPE_REMOTE_INFORMATION	25
#define FILE_MAILSLOT_QUERY_INFORMATION 26
#define FILE_MAILSLOT_SET_INFORMATION	27
#define FILE_COMPRESSION_INFORMATION	28
#define FILE_OBJECT_ID_INFORMATION	29
/* Number 30 not defined in documents */
#define FILE_MOVE_CLUSTER_INFORMATION	31
#define FILE_QUOTA_INFORMATION		32
#define FILE_REPARSE_POINT_INFORMATION	33
#define FILE_NETWORK_OPEN_INFORMATION	34
#define FILE_ATTRIBUTE_TAG_INFORMATION	35
#define FILE_TRACKING_INFORMATION	36
#define FILEID_BOTH_DIRECTORY_INFORMATION 37
#define FILEID_FULL_DIRECTORY_INFORMATION 38
#define FILE_VALID_DATA_LENGTH_INFORMATION 39
#define FILE_SHORT_NAME_INFORMATION	40
#define FILE_SFIO_RESERVE_INFORMATION	44
#define FILE_SFIO_VOLUME_INFORMATION	45
#define FILE_HARD_LINK_INFORMATION	46
#define FILE_NORMALIZED_NAME_INFORMATION 48
#define FILEID_GLOBAL_TX_DIRECTORY_INFORMATION 50
#define FILE_STANDARD_LINK_INFORMATION	54

#define OP_BREAK_STRUCT_SIZE_20		24
#define OP_BREAK_STRUCT_SIZE_21		36

struct smb2_file_access_info {
	__le32 AccessFlags;
} __packed;

struct smb2_file_alignment_info {
	__le32 AlignmentRequirement;
} __packed;

struct smb2_file_internal_info {
	__le64 IndexNumber;
} __packed; /* level 6 Query */

struct smb2_file_rename_info { /* encoding of request for level 10 */
	__u8   ReplaceIfExists; /* 1 = replace existing target with new */
				/* 0 = fail if target already exists */
	__u8   Reserved[7];
	__u64  RootDirectory;  /* MBZ for network operations (why says spec?) */
	__le32 FileNameLength;
	char   FileName[0];     /* New name to be assigned */
} __packed; /* level 10 Set */

struct smb2_file_link_info { /* encoding of request for level 11 */
	__u8   ReplaceIfExists; /* 1 = replace existing link with new */
				/* 0 = fail if link already exists */
	__u8   Reserved[7];
	__u64  RootDirectory;  /* MBZ for network operations (why says spec?) */
	__le32 FileNameLength;
	char   FileName[0];     /* Name to be assigned to new link */
} __packed; /* level 11 Set */

/*
 * This level 18, although with struct with same name is different from cifs
 * level 0x107. Level 0x107 has an extra u64 between AccessFlags and
 * CurrentByteOffset.
 */
struct smb2_file_all_info { /* data block encoding of response to level 18 */
	__le64 CreationTime;	/* Beginning of FILE_BASIC_INFO equivalent */
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32  Pad1;		/* End of FILE_BASIC_INFO_INFO equivalent */
	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */
	__le64 EndOfFile;	/* size ie offset to first free byte in file */
	__le32 NumberOfLinks;	/* hard links */
	__u8   DeletePending;
	__u8   Directory;
	__u16  Pad2;		/* End of FILE_STANDARD_INFO equivalent */
	__le64 IndexNumber;
	__le32 EASize;
	__le32 AccessFlags;
	__le64 CurrentByteOffset;
	__le32 Mode;
	__le32 AlignmentRequirement;
	__le32 FileNameLength;
	char   FileName[1];
} __packed; /* level 18 Query */

struct smb2_file_alt_name_info {
	__u32 FileNameLength;
	char FileName[0];
} __packed;

struct smb2_file_stream_info {
	__u32  NextEntryOffset;
	__u32  StreamNameLength;
	__le64 StreamSize;
	__le64 StreamAllocationSize;
	char   StreamName[0];
} __packed;

struct smb2_file_eof_info { /* encoding of request for level 10 */
	__le64 EndOfFile; /* new end of file value */
} __packed; /* level 20 Set */

struct smb2_file_ntwrk_info {
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 Attributes;
	__le32 Reserved;
} __packed;

struct smb2_file_standard_info {
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 NumberOfLinks;	/* hard links */
	__u8   DeletePending;
	__u8   Directory;
	__le16 Reserved;
} __packed; /* level 18 Query */

struct smb2_file_ea_info {
	__le32 EASize;
} __packed;

struct smb2_file_alloc_info {
	__le32 Attributes;
	__le32 ReparseTag;
} __packed;

struct smb2_file_disposition_info {
	__u8 DeletePending;
} __packed;

struct smb2_file_pos_info {
	__le64 CurrentByteOffset;
} __packed;

#define FILE_MODE_INFO_MASK cpu_to_le32(0x0000103e)

struct smb2_file_mode_info {
	__le32 Mode;
} __packed;

#define COMPRESSION_FORMAT_NONE 0x0000
#define COMPRESSION_FORMAT_LZNT1 0x0002

struct smb2_file_comp_info {
	__le64 CompressedFileSize;
	__le16 CompressionFormat;
	__u8 CompressionUnitShift;
	__u8 ChunkShift;
	__u8 ClusterShift;
	__u8 Reserved[3];
} __packed;

struct smb2_file_attr_tag_info {
	__le32 FileAttributes;
	__le32 ReparseTag;
} __packed;

#define SL_RESTART_SCAN	0x00000001
#define SL_RETURN_SINGLE_ENTRY	0x00000002
#define SL_INDEX_SPECIFIED	0x00000004

struct smb2_ea_info_req {
	__le32 NextEntryOffset;
	__u8   EaNameLength;
	char name[1];
} __packed; /* level 15 Query */

struct smb2_ea_info {
	__le32 NextEntryOffset;
	__u8   Flags;
	__u8   EaNameLength;
	__le16 EaValueLength;
	char name[1];
	/* optionally followed by value */
} __packed; /* level 15 Query */

struct create_ea_buf_req {
	struct create_context ccontext;
	__u8   Name[8];
	struct smb2_ea_info ea;
} __packed;

/* functions */
extern int get_smb2_cmd_val(struct smb_work *smb_work);
extern void set_smb2_rsp_status(struct smb_work *smb_work, unsigned int err);
extern int init_smb2_rsp_hdr(struct smb_work *smb_work);
extern int smb2_allocate_rsp_buf(struct smb_work *smb_work);
extern bool is_chained_smb2_message(struct smb_work *smb_work);
extern void init_smb2_neg_rsp(struct smb_work *smb_work);
extern void smb2_set_rsp_credits(struct smb_work *smb_work);
extern void smb2_set_err_rsp(struct smb_work *smb_work);
extern int smb2_check_user_session(struct smb_work *smb_work);
extern int smb2_get_cifsd_tcon(struct smb_work *smb_work);
extern int smb2_is_sign_req(struct smb_work *work, unsigned int command);
extern int smb2_check_sign_req(struct smb_work *work);
extern void smb2_set_sign_rsp(struct smb_work *work);
extern int smb3_check_sign_req(struct smb_work *work);
extern void smb3_set_sign_rsp(struct smb_work *work);
extern int find_matching_smb2_dialect(int start_index, __le16 *cli_dialects,
	__le16 dialects_count);
extern struct file_lock *smb_flock_init(struct file *f);
extern void smb2_send_interim_resp(struct smb_work *smb_work);

/* smb2 command handlers */
extern int calc_preauth_integrity_hash(struct connection *conn,
	int hash_id, char *buf, __u8 *pi_hash);
extern int smb2_negotiate(struct smb_work *smb_work);
extern int smb2_sess_setup(struct smb_work *smb_work);
extern int smb2_tree_connect(struct smb_work *smb_work);
extern int smb2_tree_disconnect(struct smb_work *smb_work);
extern int smb2_session_logoff(struct smb_work *smb_work);
extern int smb2_open(struct smb_work *smb_work);
extern int smb2_query_info(struct smb_work *smb_work);
extern int smb2_query_dir(struct smb_work *smb_work);
extern int smb2_close(struct smb_work *smb_work);
extern int smb2_close(struct smb_work *smb_work);
extern int smb2_echo(struct smb_work *smb_work);
extern int smb2_set_info(struct smb_work *smb_work);
extern int smb2_read(struct smb_work *smb_work);
extern int smb2_write(struct smb_work *smb_work);
extern int smb2_flush(struct smb_work *smb_work);
extern int smb2_cancel(struct smb_work *smb_work);
extern int smb2_lock(struct smb_work *smb_work);
extern int smb2_ioctl(struct smb_work *smb_work);
extern int smb2_oplock_break(struct smb_work *smb_work);
extern int smb2_notify(struct smb_work *smb_work);

/* smb2 sub command handlers */

extern int smb2_info_filesystem(struct smb_work *smb_work);
extern int smb2_info_file(struct smb_work *smb_work);
extern int smb2_set_info_file(struct smb_work *smb_work);
extern int smb2_set_ea(struct smb2_ea_info *eabuf, struct path *path);
#endif				/* _SMB2PDU_SERVER_H */
