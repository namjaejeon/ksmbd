/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_GLOB_H
#define __CIFSD_GLOB_H

#include <linux/ctype.h>
#include <linux/version.h>

#include "unicode.h"
#include "vfs_cache.h"
#include "smberr.h"

#define CIFSD_VERSION	"2.0.2"

/* @FIXME clean up this code */

extern int cifsd_debugging;
extern int cifsd_caseless_search;

#define DATA_STREAM	1
#define DIR_STREAM	2

#ifndef cifsd_pr_fmt
#ifdef SUBMOD_NAME
#define cifsd_pr_fmt(fmt)	"kcifsd: " SUBMOD_NAME ": " fmt
#else
#define cifsd_pr_fmt(fmt)	"kcifsd: " fmt
#endif
#endif

#ifdef CONFIG_CIFS_SERVER_DEBUGGING
#define cifsd_debug(fmt, ...)					\
	do {							\
		if (cifsd_debugging)				\
			pr_info(cifsd_pr_fmt("%s:%d: " fmt),	\
				__func__,			\
				__LINE__,			\
				##__VA_ARGS__);			\
	} while (0)
#else
#define cifsd_debug(fmt, ...)
#endif

#define cifsd_info(fmt, ...)					\
			pr_info(cifsd_pr_fmt(fmt), ##__VA_ARGS__)

#define cifsd_err(fmt, ...)					\
			pr_err(cifsd_pr_fmt("%s:%d: " fmt),	\
				__func__,			\
				__LINE__,			\
				##__VA_ARGS__)

#define UNICODE_LEN(x)		((x) * 2)

/* @FIXME clean up this code */
/* @FIXME clean up this code */
/* @FIXME clean up this code */

/* cifsd misc functions */
extern void ntstatus_to_dos(__u32 ntstatus, __u8 *eclass, __u16 *ecode);
#endif /* __CIFSD_GLOB_H */
