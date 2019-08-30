// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  SMB parameters and setup
 *  Copyright (C) Andrew Tridgell 1992-2000
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000
 *  Modified by Jeremy Allison 1995.
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
 *  Modified by Steve French (sfrench@us.ibm.com) 2002-2003
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include "glob.h" /* FIXME */
#include "unicode.h"
#include "encrypt.h"


