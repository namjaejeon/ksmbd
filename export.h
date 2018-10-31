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
#define CIFS_MAX_MSGSIZE 65536

#define CIFS_DEFAULT_IOSIZE (1024 * 1024)

#define STR_SRV_NAME	"CIFSD SERVER"
#define STR_WRKGRP	"WORKGROUP"

extern unsigned int SMBMaxBufSize;
#endif /* __CIFSD_EXPORT_H */
