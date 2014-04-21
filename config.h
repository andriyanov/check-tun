/*
 * Soft:        check-tun is a userspace daemon that encapsulates packets
 *              captured through netfilter-nfqueue to the configured
 *              destinations based on fwmark on the packet.
 * 
 * Author:      Alexey Andriyanov, <alan@al-an.info>
 *              
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2014 Alexey Andriyanov, <alan@al-an.info>
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <sys/socket.h>
#include <sys/queue.h>

#define CT_HSIZE (2 << 7)

struct ct_head;

typedef struct ct_conf
{
	struct ct_head *htable[CT_HSIZE];
	int used;
	LIST_ENTRY(ct_conf) next;
} ct_conf_t;

extern ct_conf_t *alloc_conf(void);
extern void free_conf (ct_conf_t *conf);
extern ct_conf_t *read_configuration(char *conf_file);
extern void dump_conf (ct_conf_t *conf);

extern struct sockaddr_storage *lookup_dest (ct_conf_t *conf, unsigned int fwmark);

#endif