/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_TRANSPORT_TCP_H__
#define __CIFSD_TRANSPORT_TCP_H__

int cifsd_tcp_set_interfaces(char *ifc_list, int ifc_list_sz);
int cifsd_tcp_init(void);
void cifsd_tcp_destroy(void);

#endif /* __CIFSD_TRANSPORT_TCP_H__ */
