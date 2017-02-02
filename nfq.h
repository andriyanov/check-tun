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

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "config.h"
#include "keepalived/utils.h"
#include "keepalived/memory.h"

typedef struct nfq_thread_var {
    unsigned int nfq_q_num;
    unsigned int thread_num;
    bool err;
    bool terminated;
    bool cpu_affinity;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    ct_conf_t *current_conf;
    ct_conf_t **global_conf;
    char buf[8*4096] __attribute__ ((aligned));
} nfq_thread_var_t;

extern int nfq_debug;
extern struct sockaddr_storage bind4, bind6;

extern int nfq_init(int, nfq_thread_var_t *);
extern int nfq_done(int, nfq_thread_var_t *);
//extern int nfq_cycle_read(ct_conf_t *);
