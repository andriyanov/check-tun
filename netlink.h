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
 * Copyright (C) 2019 Vadim Fedorenko, <junjunk@github.com>
 */

#include <linux/netlink.h>	    /* for NETLINK_* */
#include <linux/rtnetlink.h>	    /* for RTM_ROUTEGET */
#include <arpa/inet.h>
#include <sys/socket.h>

#include "keepalived/memory.h"

#define NL_MSG_BUFSIZE 4096
#define NL_RCV_BUFSIZE 8192


typedef struct nl_request {
    struct nlmsghdr nl;
    union {
        struct rtmsg     rt;
        struct ifaddrmsg ifa;
    };
    char buf[0];
} nl_request_t;

typedef struct {
    char *msgbuf;
    char *rcvbuf;
    int msgnum;
    int sock;
    struct sockaddr_nl nl_sock_addr;
} nl_socket_t;

extern int nl_debug;
extern int nl_get_iface(int if_family);
extern int nl_fill_addresses(int ipv4_ifindex, struct sockaddr_storage *bind4, int ipv6_ifindex, struct sockaddr_storage *bind6);
extern int nl_init(int pid);
extern void nl_done();
