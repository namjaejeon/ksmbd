// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 */

#ifndef __CIFSD_TRANSPORT_RDMA_H_
#define __CIFSD_TRANSPORT_RDMA_H_

#ifdef CONFIG_CIFSD_SMBDIRECT
extern int cifsd_smbd_init(void);
extern int cifsd_smbd_destroy(void);
#else
int cifsd_smbd_init(void) { return 0; }
int cifsd_smbd_destroy(void) { return 0; }
#endif

#endif
