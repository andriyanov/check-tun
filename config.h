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

#define CT_HASH(I) ((unsigned int)(I)%CT_HSIZE)

#define IP_VS_CONN_F_MASQ       0x0000          /* masquerading/NAT */
#define IP_VS_CONN_F_LOCALNODE  0x0001          /* local node */
#define IP_VS_CONN_F_TUNNEL     0x0002          /* tunneling */
#define IP_VS_CONN_F_DROUTE     0x0003          /* direct routing */
#define IP_VS_CONN_F_BYPASS     0x0004          /* cache bypass */
#define IP_VS_CONN_F_GRE_TUNNEL 0x0005          /* GRE tunneling */


struct ct_pair {
	unsigned int fwmark;
	struct sockaddr_storage dst;
	int lvs_method;
	LIST_ENTRY(ct_pair) next;
};

struct ct_head {
	LIST_HEAD(ct_hentry, ct_pair) ptr;
};


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

extern struct ct_pair *lookup_dest (ct_conf_t *conf, unsigned int fwmark);

#endif