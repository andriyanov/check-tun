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

void *nfq_thread_func(void *data)
{
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
		nl_request_t *request;
		struct nlmsghdr *nlmsg;
    	struct rtmsg *route_msg;
		struct rtattr *route_attr;
		struct sockaddr_nl nl_sock_addr;
		struct in_addr *in4, *in4_src = 0;
		struct in6_addr *in6, *in6_src = 0;
		int nlsock = -1, route_attr_len;
		struct timeval tv = {1,0};
		int msgnum = 0;

		int ipv4_ifindex = 0, ipv6_ifindex = 0;
		if (*ifname) {
			if (!(ipv4_ifindex = ipv6_ifindex = if_nametoindex(ifname)))
			{
				log_message (LOG_ERR, "Interface %s is not found in system", ifname);
				perror("interface unknown");
				return -1;
			}
		}
	    if ((nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
			log_message (LOG_WARNING, "Cannot get netlink socket, cannot find default gateway interface");
        	goto opensockets;
		}
		setsockopt(nlsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		char *msgbuf = MALLOC(NL_MSG_BUFSIZE);
		char *rcvbuf = MALLOC(NL_RCV_BUFSIZE);
		char *rcvptr = rcvbuf;
		int rcvlen   = 0;

		bzero(&nl_sock_addr, sizeof(nl_sock_addr));
		nl_sock_addr.nl_pid = getpid();
		nl_sock_addr.nl_family = AF_NETLINK;
		bind(s, (struct sockaddr *)&nl_sock_addr, sizeof(nl_sock_addr));
						
		if (!ipv4_ifindex) {
			// make route get message to return only default gw
			bzero(msgbuf,NL_MSG_BUFSIZE);
			bzero(rcvbuf,NL_RCV_BUFSIZE);
			request = (nl_request_t *)msgbuf;
			request->nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
			request->nl.nlmsg_type  = RTM_GETROUTE;
			request->nl.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
			request->nl.nlmsg_seq   = msgnum++;
			request->nl.nlmsg_pid   = getpid();
			
			request->rt.rtm_family  = AF_INET;
			request->rt.rtm_type    = RTN_UNICAST;
			request->rt.rtm_table   = RT_TABLE_DEFAULT;
			request->rt.rtm_protocol = RTPROT_STATIC;
 			if (send(nlsock, request, request->nl.nlmsg_len, 0) < 0) {
				log_message (LOG_ERR, "Cannot send NETLINK message to dump ipv4 routes");
				goto err_free;
			}
			//iov.iov_base = rcvbuf;
			//while (1) {
			do {
				int received_bytes = recv(nlsock, rcvptr, NL_RCV_BUFSIZE - rcvlen, 0);
				if (received_bytes < 0) {
					log_message (LOG_ERR, "Cannot receive NETLINK message with ipv4 routes dump");
					goto err_free;
				}
				nlmsg = (struct nlmsghdr *)rcvptr;
				rcvptr += received_bytes;
				rcvlen += received_bytes;
				if ((NLMSG_OK(nlmsg, rcvlen) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
					log_message (LOG_ERR, "Error in received NETLINK message (IPv4)");
					goto err_free;
				}
				if (nlmsg->nlmsg_type == NLMSG_DONE)
					break;
				else {
				}
				if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
					break;
			} while ((nlmsg->nlmsg_seq != msgnum) || (nlmsg->nlmsg_pid != getpid()));
			//}
			
			for (nlmsg = (struct nlmsghdr *)rcvbuf; NLMSG_OK(nlmsg, rcvlen); nlmsg = NLMSG_NEXT(nlmsg, rcvlen))
			{
				route_msg = (struct rtmsg *)NLMSG_DATA(nlmsg);
				//Skip routes not from main route table and not default gw (dst_len > 0)
				if (nfq_debug) 
					log_message(LOG_DEBUG,"IPv4:rtm_table = %d, rtm_dst_len = %d,rtm_family = %d", route_msg->rtm_table, route_msg->rtm_dst_len, route_msg->rtm_family);
				if (route_msg->rtm_table != RT_TABLE_MAIN || route_msg->rtm_dst_len != 0)
					continue;
				// Skip non-IPv4 routes
				if (route_msg->rtm_family != AF_INET)
					continue;
				in4_src = 0; // set NULL to prefered source attribute pointer
				route_attr_len = RTM_PAYLOAD(nlmsg);
				for (route_attr = (struct rtattr *)RTM_RTA(route_msg); RTA_OK(route_attr,route_attr_len); route_attr = RTA_NEXT(route_attr, route_attr_len))
				{
					if (nfq_debug)
						log_message(LOG_DEBUG,"IPv6: rta_type = %d", route_attr->rta_type);

					switch (route_attr->rta_type)
					{
						case RTA_OIF:
							ipv4_ifindex = *(int *)RTA_DATA(route_attr);
							break;
						case RTA_PREFSRC:
							in4_src = (struct in_addr *)RTA_DATA(route_attr);
							break;
						default:
							break;
							
					}
					
				}
				if (in4_src) {
					// if default route has prefered source address, use it to bind
					bind4.ss_family = AF_INET;
					struct sockaddr_in *addr4 = (struct sockaddr_in *) &bind4;
					addr4->sin_addr = *in4_src;
				}
				// we reach this point only with default route
				if (ipv4_ifindex) break;
			}
			log_message (LOG_INFO, "Index of IPv4 default gateway interface: %d", ipv4_ifindex);
			
		}

		if (!ipv6_ifindex)
		{
			bzero(msgbuf,NL_MSG_BUFSIZE);
			bzero(rcvbuf,NL_RCV_BUFSIZE);
			request = (nl_request_t *)msgbuf;
			request->nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
			request->nl.nlmsg_type  = RTM_GETROUTE;
			request->nl.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
			request->nl.nlmsg_seq   = msgnum++;
			request->nl.nlmsg_pid   = getpid();
			
			request->rt.rtm_family  = AF_INET6;
			request->rt.rtm_type    = RTN_UNICAST;
			request->rt.rtm_table   = RT_TABLE_DEFAULT;
			request->rt.rtm_protocol = RTPROT_STATIC;
 			if (send(nlsock, request, request->nl.nlmsg_len, 0) < 0) {
				log_message (LOG_ERR, "Cannot send NETLINK message to dump ipv4 routes");
				goto err_free;
			}
			rcvptr = rcvbuf;
			rcvlen = 0;
			do {
				int received_bytes = recv(nlsock, rcvptr, NL_RCV_BUFSIZE - rcvlen, 0);
				if (received_bytes < 0) {
					log_message (LOG_ERR, "Cannot receive NETLINK message with ipv6 routes dump");
					goto err_free;
				}
				nlmsg = (struct nlmsghdr *)rcvptr;
				rcvptr += received_bytes;
				rcvlen += received_bytes;
				if ((NLMSG_OK(nlmsg, rcvlen) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
					log_message (LOG_ERR, "Error in received NETLINK message (IPv6)");
					goto err_free;
				}
				if (nlmsg->nlmsg_type == NLMSG_DONE)
					break;
				else {
				}
				if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
					break;
			} while ((nlmsg->nlmsg_seq != msgnum) || (nlmsg->nlmsg_pid != getpid()));
			
			for (nlmsg = (struct nlmsghdr *)rcvbuf; NLMSG_OK(nlmsg, rcvlen); nlmsg = NLMSG_NEXT(nlmsg, rcvlen))
			{
				route_msg = (struct rtmsg *)NLMSG_DATA(nlmsg);
				if (nfq_debug)
					log_message(LOG_DEBUG,"IPv6: rtm_table = %d, rtm_dst_len = %d, rtm_family = %d", route_msg->rtm_table, route_msg->rtm_dst_len, route_msg->rtm_family);
				//Skip routes not from main route table and not default gw (dst_len > 0)
				if (route_msg->rtm_table != RT_TABLE_MAIN || route_msg->rtm_dst_len != 0)
					continue;
				// Skip non-IPv6 routes
				if (route_msg->rtm_family != AF_INET6)
					continue;
				in6_src = 0;
				route_attr_len = RTM_PAYLOAD(nlmsg);
				for (route_attr = (struct rtattr *)RTM_RTA(route_msg); RTA_OK(route_attr,route_attr_len); route_attr = RTA_NEXT(route_attr, route_attr_len))
				{
					if (nfq_debug)
						log_message(LOG_DEBUG,"IPv6: rta_type = %d", route_attr->rta_type);
					switch (route_attr->rta_type)
					{
						case RTA_OIF:
							ipv6_ifindex = *(int *)RTA_DATA(route_attr);
							break;
						case RTA_PREFSRC:
							in6_src = (struct in6_addr *)RTA_DATA(route_attr);
							break;
						default:
							break;
							
					}
					
				}
				if (in6_src && !IN6_IS_ADDR_UNSPECIFIED(in6_src)) { // use ipv6 check helper
					bind6.ss_family = AF_INET6;
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &bind6;
					addr6->sin6_addr = *in6_src;
				}
				// we reach this point only with default route
				if (ipv6_ifindex) break;
			}
			log_message (LOG_INFO, "Index of IPv6 default gateway interface: %d", ipv6_ifindex);
			
		}
		if ((ipv4_ifindex && bind4.ss_family != AF_INET) || (ipv6_ifindex && bind6.ss_family != AF_INET6)) {
			bzero(msgbuf,NL_MSG_BUFSIZE);
			bzero(rcvbuf,NL_RCV_BUFSIZE);
			struct ifaddrmsg *ifa_msg;
			struct rtattr *ifa_attr;
			request = (nl_request_t *)msgbuf;
			request->nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
			request->nl.nlmsg_type  = RTM_GETADDR;
			request->nl.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
			request->nl.nlmsg_seq   = msgnum++;
			request->nl.nlmsg_pid   = getpid();

			if (send(nlsock, (void *)request, request->nl.nlmsg_len, 0) < 0) {
				log_message (LOG_ERR, "Cannot send NETLINK message to dump interface addresses");
				goto err_free;
			}
			rcvptr = rcvbuf;
			rcvlen = 0;
			do {
				int received_bytes = recv(nlsock, rcvptr, NL_RCV_BUFSIZE - rcvlen, 0);
				if (received_bytes < 0) {
					log_message (LOG_ERR, "Cannot receive NETLINK message with interface addresses");
					goto err_free;
				}
				nlmsg = (struct nlmsghdr *)rcvptr;
				rcvptr += received_bytes;
				rcvlen += received_bytes;
				if ((NLMSG_OK(nlmsg, rcvlen) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
					log_message (LOG_ERR, "Error in received NETLINK message (dump iface addresses)");
					goto err_free;
				}
				if (nlmsg->nlmsg_type == NLMSG_DONE)
					break;
				else {
				}
				if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
					break;
			} while ((nlmsg->nlmsg_seq != msgnum) || (nlmsg->nlmsg_pid != getpid()));

			for (nlmsg = (struct nlmsghdr *)rcvbuf; NLMSG_OK(nlmsg, rcvlen); nlmsg = NLMSG_NEXT(nlmsg, rcvlen))
			{
				ifa_msg = (struct ifaddrmsg *)NLMSG_DATA(nlmsg);
				if (nfq_debug)
					log_message(LOG_DEBUG, "IFA_MSG: family = %d, ifindex = %d, scope = %d", ifa_msg->ifa_family, ifa_msg->ifa_index, ifa_msg->ifa_scope);
				if (bind4.ss_family != AF_INET && ipv4_ifindex && ifa_msg->ifa_index == ipv4_ifindex && 
					ifa_msg->ifa_family == AF_INET  && ifa_msg->ifa_scope == RT_SCOPE_UNIVERSE)
				{
					int ifa_attr_len = IFA_PAYLOAD(nlmsg);
					bool found = false;
					for (ifa_attr = (struct rtattr *)IFA_RTA(ifa_msg); RTA_OK(ifa_attr,ifa_attr_len); ifa_attr = RTA_NEXT(ifa_attr, ifa_attr_len))
					{
						if (nfq_debug)
							log_message(LOG_DEBUG,"IFA_MSG: attribute type = %d", ifa_attr->rta_type);
						switch (ifa_attr->rta_type)
						{
							case IFA_LOCAL:
							case IFA_ADDRESS:
								{
								bind4.ss_family = AF_INET;
								struct sockaddr_in *addr = (struct sockaddr_in *)&bind4;
								addr->sin_addr = *(struct in_addr *)RTA_DATA(ifa_attr);
								found = true;
								}
								break;
							default:
								break;
								
						}
						if (found) break;
						
					}
				}
				if (bind6.ss_family != AF_INET6 && ipv6_ifindex && ifa_msg->ifa_index == ipv6_ifindex && 
					ifa_msg->ifa_family == AF_INET6  && ifa_msg->ifa_scope == RT_SCOPE_UNIVERSE)
				{
					int ifa_attr_len = IFA_PAYLOAD(nlmsg);
					bool found = false;
					for (ifa_attr = (struct rtattr *)IFA_RTA(ifa_msg); RTA_OK(ifa_attr,ifa_attr_len); ifa_attr = RTA_NEXT(ifa_attr, ifa_attr_len))
					{
						if (nfq_debug)
							log_message(LOG_DEBUG,"IFA_MSG: attribute type = %d", ifa_attr->rta_type);
						switch (ifa_attr->rta_type)
						{
							case IFA_LOCAL:
							case IFA_ADDRESS:
								{
								bind6.ss_family = AF_INET6;
								struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&bind6;
								addr->sin6_addr = *((struct in6_addr *)RTA_DATA(ifa_attr));
								found = true;
								}
								break;
							default:
								break;
								
						}
						if (found) break;
					}
				}
				if ((!ipv4_ifindex || bind4.ss_family == AF_INET) && (!ipv6_ifindex || bind6.ss_family == AF_INET6)) {
					break;
				};
			}
			
		}
err_free:
		FREE(msgbuf);
		FREE(rcvbuf);
		close(nlsock);

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
