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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include <netinet/in.h>
#include <linux/netfilter.h>	    /* for NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "nfq.h"
#include "logger.h"
#include "utils.h"

int nfq_debug = 0;
static int raw_socks[2][2];
static struct nfq_handle *h;
static struct nfq_q_handle *qh;
static struct nfnl_handle *nh;
static char buf[4*4096] __attribute__ ((aligned));
static int fd;
static ct_conf_t *current_conf;
struct sockaddr_storage bind4, bind6;

static uint16_t get_packet_family (void* packet)
{
	unsigned char byte = *((unsigned char*)packet);
	byte >>= 4;
	switch (byte) {
		case 4:
			return AF_INET;
		case 6:
			return AF_INET6;
	}
	return AF_UNSPEC;
}

static inline int *
get_raw_sock (int pkt_family, int dst_family)
{
	return &raw_socks
		[pkt_family == AF_INET ? 0 : 1]
		[dst_family == AF_INET ? 0 : 1];
}

static int
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	int id = 0;
	unsigned int mark = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct sockaddr_storage *dst;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	mark = nfq_get_nfmark(nfa);
	char *pkt;
	int pkt_len = nfq_get_payload (nfa, &pkt);
	int pkt_fam = get_packet_family (pkt);
	int sent;

	dst = lookup_dest (current_conf, mark);
	if (dst == NULL)
	{
		if (nfq_debug)
			log_message (LOG_DEBUG, "can't find destination for fwmark %d", mark);
	}
	else
	{
		sent = sendto (
			*get_raw_sock (pkt_fam, dst->ss_family),
			pkt,
			pkt_len,
			0,
			(struct sockaddr*)dst,
			sizeof (*dst)
		);
		if (nfq_debug)
		{
			if (sent < 0)
				log_message (LOG_DEBUG, "sendto %s: %s", inet_sockaddrtos (dst), strerror (errno));
			else
				log_message (LOG_DEBUG, "sent %d bytes to %s", sent, inet_sockaddrtos (dst));
		}
	}

	return nfq_set_verdict (qh, id, NF_DROP, pkt_len, pkt);
}

int nfq_init(void)
{
	// opening raw sockets
	struct {
		int pkt_family, dst_family;
	} map[] = {
		{ AF_INET , AF_INET  },
		{ AF_INET , AF_INET6 },
		{ AF_INET6, AF_INET  },
		{ AF_INET6, AF_INET6 },
		{ 0       , 0        }
	}, *p;
	struct sockaddr_storage *bind_to;
	int s;
	for (p = map; p->pkt_family != 0; p++)
	{
		s = socket (p->dst_family, SOCK_RAW, (p->pkt_family == AF_INET ? IPPROTO_IPIP : IPPROTO_IPV6));
		if (s < 0)
		{
			fprintf (stderr, "error opening raw socket: %s\n", strerror (errno));
			return -1;
		}

		// bind to source address, if specified
		bind_to = NULL;
		if (p->dst_family == AF_INET6 && bind6.ss_family == AF_INET6)
			bind_to = &bind6;
		else if (p->dst_family == AF_INET && bind4.ss_family == AF_INET)
			bind_to = &bind4;
		if (bind_to != NULL)
			if (0 != bind (s, (struct sockaddr *)bind_to, sizeof (*bind_to)))
			{
				fprintf (stderr, "bind(%s): %s\n", inet_sockaddrtos(bind_to), strerror (errno));
				return -1;
			}

		*get_raw_sock(p->pkt_family, p->dst_family) = s;
	}

	h = nfq_open();
	if (!h) {
		fprintf (stderr, "nfq_open() error");
		return -1;
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf (stderr, "nfq_unbind_pf(AF_INET) error\n");
		return -1;
	}
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf (stderr, "nfq_bind_pf(AF_INET) error\n");
		return -1;
	}

	if (nfq_unbind_pf(h, AF_INET6) < 0) {
		fprintf (stderr, "nfq_unbind_pf(AF_INET6) error\n");
		return -1;
	}
	if (nfq_bind_pf(h, AF_INET6) < 0) {
		fprintf (stderr, "nfq_bind_pf(AF_INET6) error");
		return -1;
	}

	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf (stderr, "nfq_create_queue() error\n");
		return -1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf (stderr, "nfq_set_mode(NFQNL_COPY_PACKET) error\n");
		return -1;
	}

	fd = nfq_fd(h);

	return 0;
}

int nfq_cycle_read(ct_conf_t * conf)
{
	current_conf = conf;
	int rv = recv(fd, buf, sizeof(buf), 0);
	if (rv > 0)
	{
		nfq_handle_packet(h, buf, rv);
		return 0;
	}
	else if (rv == -1 && errno != EAGAIN)
		return 0;

	if (rv == 0)
		log_message (LOG_WARNING, "NFQ socket closed");
	else
		log_message (LOG_WARNING, "recv: %s", strerror (errno));
	nfq_destroy_queue(qh);
	nfq_close(h);
}
