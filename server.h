/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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

#ifndef __SERVER_H__
#define __SERVER_H__

#define SERVER_STATE_STARTING_UP	0
#define SERVER_STATE_RUNNING		1
#define SERVER_STATE_SHUTTING_DOWN	2

#define SERVER_CONF_NETBIOS_NAME	0
#define SERVER_CONF_SERVER_STRING	1
#define SERVER_CONF_WORK_GROUP		2

struct cifsd_server_config {
	int		state;
	char		*conf[SERVER_CONF_WORK_GROUP + 1];

	short		signing;
	short		enforced_signing;
	short		min_protocol;
	short		max_protocol;
};

extern struct cifsd_server_config server_conf;

int cifsd_set_netbios_name(char *v);
int cifsd_set_server_string(char *v);
int cifsd_set_work_group(char *v);

char *cifsd_netbios_name(void);
char *cifsd_server_string(void);
char *cifsd_work_group(void);

static inline int cifsd_server_running(void)
{
	return server_conf.state == SERVER_STATE_STARTING_UP;
}

static inline void cifsd_server_set_running(void)
{
	server_conf.state = SERVER_STATE_STARTING_UP;
}

int cifsd_server_shutdown(void);
#endif /* __SERVER_H__ */
