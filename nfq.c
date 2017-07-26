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
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter.h>	    /* for NF_DROP */
#include <net/if.h>

#include "nfq.h"
#include "logger.h"
#include "utils.h"
#include "netlink.h"

int nfq_debug = 0;
static int raw_socks[2][2];
struct sockaddr_storage bind4, bind6, remote_filter;
pthread_t *nfq_threads;

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
	nfq_thread_var_t *nfq_var = (nfq_thread_var_t *)data;
	int id;
	unsigned int mark;
	struct nfqnl_msg_packet_hdr *ph;
	struct sockaddr_storage *dst;
	unsigned char *pkt;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	mark = nfq_get_nfmark(nfa);
	int pkt_len = nfq_get_payload (nfa, &pkt);
	int pkt_fam = get_packet_family (pkt);
	int sent;

	dst = lookup_dest (nfq_var->current_conf, mark);
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

	return nfq_set_verdict (nfq_var->qh, id, NF_DROP, pkt_len, pkt);
}


static int nfq_init_thread(nfq_thread_var_t *nfq_vars)
{
	nfq_vars->h = nfq_open();
	if (!nfq_vars->h) {
		log_message (LOG_ERR, "Thread %d: nfq_open() error", nfq_vars->thread_num);
		goto error;
	}

	if (nfq_unbind_pf(nfq_vars->h, AF_INET) < 0) {
		log_message (LOG_ERR, "Thread %d: nfq_unbind_pf(AF_INET) error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}
	if (nfq_bind_pf(nfq_vars->h, AF_INET) < 0) {
		log_message (LOG_ERR, "Thread %d: nfq_bind_pf(AF_INET) error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}

	if (nfq_unbind_pf(nfq_vars->h, AF_INET6) < 0) {
		log_message (LOG_ERR, "Thread %d: nfq_unbind_pf(AF_INET6) error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}
	if (nfq_bind_pf(nfq_vars->h, AF_INET6) < 0) {
		log_message (LOG_ERR, "Thread %d: nfq_bind_pf(AF_INET6) error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}

	nfq_vars->qh = nfq_create_queue(nfq_vars->h, nfq_vars->nfq_q_num, &cb, nfq_vars);
	if (!nfq_vars->qh) {
		log_message (LOG_ERR, "Thread %d: nfq_create_queue() error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}

	if (nfq_set_mode(nfq_vars->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		log_message (LOG_ERR, "Thread %d: nfq_set_mode(NFQNL_COPY_PACKET) error: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}

	nfq_vars->fd = nfq_fd(nfq_vars->h);

#if defined SOL_NETLINK && defined NETLINK_NO_ENOBUFS
	if (setsockopt(nfq_vars->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, (int[]){1}, sizeof(int)) < 0) {
		log_message (LOG_ERR, "Thread %d: Unable to setsockopt NETLINK_NO_ENOBUFS: %s", nfq_vars->thread_num, strerror(errno));
		goto error;
	}
	if (nfq_debug)
		log_message(LOG_DEBUG, "Thread %d: set NETLINK_NO_ENOBUFS mode", nfq_vars->thread_num);
#endif
	log_message (LOG_INFO, "Thread %d initialized", nfq_vars->thread_num);
	return 0;
error:
	if (nfq_vars->qh) nfq_destroy_queue(nfq_vars->qh);
	if (nfq_vars->h)  nfq_close(nfq_vars->h);
	return -1;
}

static int nfq_cycle_read(nfq_thread_var_t *nfq_var)
{
	int rv = recv(nfq_var->fd, nfq_var->buf, sizeof(nfq_var->buf), 0);
	if (rv > 0)
	{
		if (nfq_debug)
			log_message (LOG_DEBUG, "got %d bytes from netlink", rv);
		nfq_handle_packet(nfq_var->h, nfq_var->buf, rv);
		return 0;
	}
	else if (rv == -1)
	{
		if (errno == EINTR)
			return 0;
		log_message (LOG_WARNING, "recv: %s", strerror (errno));
	}
	else // rv == 0
		log_message (LOG_WARNING, "NFQ socket closed");
	nfq_destroy_queue(nfq_var->qh);
	nfq_var->qh = 0;
	nfq_close(nfq_var->h);
	nfq_var->h = 0;
	return -1;
}

static void nfq_thread_sig(int thread_signum)
{
	(void)thread_signum;
	if (nfq_debug) log_message(LOG_DEBUG,"Thread got SIGNUM %d", thread_signum);
}

void *nfq_thread_func(void *data)
{
	struct sigaction act = {
			.sa_mask = 0,
			.sa_flags = SA_NODEFER,
			.sa_handler = &nfq_thread_sig,
	};
	if (0 > sigaction(SIGUSR1,&act,NULL)) {
		log_message(LOG_WARNING,"Singal is not set");
	}

	nfq_thread_var_t *nfq_var = (nfq_thread_var_t *)data;

	while (!nfq_var->terminated)
	{
		if (*(nfq_var->global_conf) != nfq_var->current_conf)
			nfq_var->current_conf = *(nfq_var->global_conf);
		if (nfq_cycle_read(nfq_var) == -1 && !nfq_var->terminated)
		{
			if (nfq_init_thread(nfq_var) == -1) {
				nfq_var->err = true;
				break;
			}
		}
	}
	pthread_exit(NULL);
	return 0;
}

void nfq_thread_hup(int thread_num)
{
	//no bounds checking
	pthread_kill(nfq_threads[thread_num], SIGUSR1);
}

int nfq_init_int(char *ifname)
{
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
	//first try to find address to bind if not explicitly set
	if ((bind4.ss_family != AF_INET) || ((bind6.ss_family != AF_INET6))) 
	{
		int ipv4_ifindex = 0, ipv6_ifindex = 0;
		if (*ifname) {
			if (!(ipv4_ifindex = ipv6_ifindex = if_nametoindex(ifname)))
			{
				log_message (LOG_ERR, "Interface %s is not found in system", ifname);
				perror("interface unknown");
				return -1;
			}
		}
		if (nfq_debug)
			nl_debug = 1;

		if (nl_init(getpid())) {
			log_message (LOG_WARNING, "Cannot get netlink socket, cannot find default gateway interface");
        	goto opensockets;
		}
						
		if (!ipv4_ifindex) {
			ipv4_ifindex = nl_get_iface(AF_INET);
		}
		if (bind4.ss_family != AF_INET)
			log_message (LOG_INFO, "Index of IPv4 default gateway interface: %d", ipv4_ifindex);

		if (!ipv6_ifindex)
		{
			ipv6_ifindex = nl_get_iface(AF_INET6);
		}

		if (bind6.ss_family != AF_INET6)
			log_message (LOG_INFO, "Index of IPv6 default gateway interface: %d", ipv6_ifindex);

		if ((ipv4_ifindex && bind4.ss_family != AF_INET) || (ipv6_ifindex && bind6.ss_family != AF_INET6))
			nl_fill_addresses(ipv4_ifindex, &bind4, ipv6_ifindex, &bind6);

		nl_done();

	}
	{
		char str[INET6_ADDRSTRLEN];
		log_message (LOG_INFO, "Binding IPv4 socket to %s", inet_ntoa((*(struct sockaddr_in*)&bind4).sin_addr));
		inet_ntop(AF_INET6, &(*(struct sockaddr_in6 *)&bind6).sin6_addr,str,INET6_ADDRSTRLEN);
		log_message (LOG_INFO, "Binding IPv6 socket to %s", str);
	}

opensockets:
	for (p = map; p->pkt_family != 0; p++)
	{ 
		s = socket (p->dst_family, SOCK_RAW, (p->pkt_family == AF_INET ? IPPROTO_IPIP : IPPROTO_IPV6));
		if (s < 0)
		{
			perror ("socket(SOCK_RAW)");
			return -1;
		}

		// filter out packet coming into socket (prevent copying the skb)
		if (0 != connect (s, (struct sockaddr*) &remote_filter, sizeof (remote_filter)))
		{
			perror ("connect");
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
				log_message (LOG_ERR, "bind(%s): %s", inet_sockaddrtos(bind_to), strerror (errno));
				return -1;
			}

		*get_raw_sock(p->pkt_family, p->dst_family) = s;
	}
	return 0;
}

int nfq_init_th(int thnum, nfq_thread_var_t *nfq_vars)
{
	pthread_attr_t attr;
	cpu_set_t cpuset;
	int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	int started_threads = 0;
	// opening raw sockets
	nfq_threads = MALLOC(thnum * sizeof(pthread_t));
	pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (; started_threads < thnum; started_threads++, nfq_vars++)
	{
		if (nfq_init_thread(nfq_vars) == -1)
			goto error;
		pthread_create(&nfq_threads[started_threads], &attr, nfq_thread_func, (void *)nfq_vars);
		if (nfq_vars->cpu_affinity)
		{
			CPU_ZERO(&cpuset);
			CPU_SET(nfq_vars->thread_num % cpu_count, &cpuset);
			if (pthread_setaffinity_np(nfq_threads[started_threads], sizeof(cpu_set_t), &cpuset))
			{
				log_message (LOG_WARNING, "Thread %d: Couldn't set cpu_affinity", started_threads);
			}
		}
	}
	pthread_attr_destroy(&attr);
	return 0;
error:
	pthread_attr_destroy(&attr);
	void *status;
	while(started_threads) {
		started_threads--;
		nfq_vars--;
		nfq_vars->terminated = true;
		pthread_join(nfq_threads[started_threads], &status);
	}
	return -1;
}

int nfq_done(int numth, nfq_thread_var_t *nfq_vars)
{
	void *status;
	for (int i = 0; i < numth; i++, nfq_vars++) {
		if (nfq_vars->err) continue;
		nfq_vars->terminated = true;
		pthread_join(nfq_threads[i], &status);
	}
	return 0;
}
