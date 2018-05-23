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

#ifndef __CIFSD_BUFFER_POOL_H__
#define __CIFSD_BUFFER_POOL_H__

struct cifsd_work;

void *cifsd_alloc(size_t size);
void cifsd_free(void *ptr);

void cifsd_free_request(void *buffer);
void *cifsd_alloc_request(size_t size);
void cifsd_free_response(void *buffer);
void *cifsd_alloc_response(size_t size);

void *cifsd_realloc_response(void *ptr, size_t old_sz, size_t new_sz);

struct cifsd_work *cifsd_alloc_work_struct(void);
void cifsd_free_work_struct(struct cifsd_work *work);

void cifsd_free_file_struct(void *filp);
void *cifsd_alloc_file_struct(void);

void cifsd_destroy_buffer_pools(void);
int cifsd_init_buffer_pools(void);

#endif /* __CIFSD_BUFFER_POOL_H__ */
