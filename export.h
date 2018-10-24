// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_EXPORT_H
#define __CIFSD_EXPORT_H

#include "ntlmssp.h"

#include "smb1pdu.h"
#include "smb2pdu.h"

#include "mgmt/user_config.h"

extern int cifsd_debugging;

/* Global defines for server */
#define SERVER_MAX_MPX_COUNT 10
#define SERVER_MAX_VCS 1

#define CIFS_MAX_MSGSIZE 65536
#define MAX_CIFS_LOOKUP_BUFFER_SIZE (16*1024)

#define CIFS_DEFAULT_NON_POSIX_RSIZE (60 * 1024)
#define CIFS_DEFAULT_NON_POSIX_WSIZE (65536)
#define CIFS_DEFAULT_IOSIZE (1024 * 1024)
#define SERVER_MAX_RAW_SIZE 65536

#define SMB1_SERVER_CAPS (CAP_RAW_MODE | CAP_UNICODE | CAP_LARGE_FILES | \
			CAP_NT_SMBS | CAP_STATUS32 | CAP_LOCK_AND_READ | \
			CAP_NT_FIND | CAP_UNIX | CAP_LARGE_READ_X | \
			CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS | \
			CAP_EXTENDED_SECURITY)
#define SMB1_SERVER_SECU  (SECMODE_USER | SECMODE_PW_ENCRYPT)

#define CIFSD_MAJOR_VERSION 1
#define CIFSD_MINOR_VERSION 0
#define STR_IPC	"IPC$"
#define STR_SRV_NAME	"CIFSD SERVER"
#define STR_WRKGRP	"WORKGROUP"

#define O_SERVER 1
#define O_CLIENT 2

extern unsigned int SMBMaxBufSize;

extern int cifsd_init_registry(void);
extern void cifsd_free_registry(void);
extern struct cifsd_user *cifsd_is_user_present(char *name);
struct cifsd_share *get_cifsd_share(struct cifsd_tcp_conn *conn,
                struct cifsd_session *sess, char *sharename, bool *can_write);
extern struct cifsd_tcon *get_cifsd_tcon(struct cifsd_session *sess,
                        unsigned int tid);
struct cifsd_user *get_smb_session_user(struct cifsd_session *sess);

#endif /* __CIFSD_EXPORT_H */
