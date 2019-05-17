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

#include "config.h"
#include "memory.h"
#include "parser.h"
#include "utils.h"
#include "logger.h"

static ct_conf_t * current_conf;
static struct ct_pair curr_rs;

static int lvs_method;

ct_conf_t *
alloc_conf(void)
{
	ct_conf_t * ret = MALLOC(sizeof (ct_conf_t));
	return ret;
}

void
free_conf (ct_conf_t *conf)
{
	int i;
	struct ct_head *head;
	struct ct_pair *p;

	if (conf == NULL)
		return;
	for (i = 0; i < CT_HSIZE; i++)
		if ((head = conf->htable[i]) != NULL)
			while ((p = head->ptr.lh_first) != NULL)
			{
				LIST_REMOVE(p, next);
				FREE(p);
			}
			FREE(head);
	FREE(conf);
}

static void
add_dest (ct_conf_t *conf, unsigned int fwmark, const struct sockaddr_storage *dst, int lvs)
{
	struct ct_head *head = conf->htable[CT_HASH(fwmark)];
	if (head == NULL)
	{
		head = MALLOC(sizeof (struct ct_head));
		LIST_INIT(&head->ptr);
		conf->htable[CT_HASH(fwmark)] = head;
	}
	struct ct_pair *pair = MALLOC(sizeof (struct ct_pair));
	pair->fwmark = fwmark;
	pair->dst = *dst;
	pair->lvs_method = lvs;
	LIST_INSERT_HEAD(&head->ptr, pair, next);
}

struct ct_pair *
lookup_dest (ct_conf_t *conf, unsigned int fwmark)
{
	struct ct_pair *p;
	struct ct_head *head = conf->htable[CT_HASH(fwmark)];
	if (head != NULL)
		for (p = head->ptr.lh_first; p != NULL; p = p->next.le_next)
			if (p->fwmark == fwmark)
				return p;
	return NULL;
}

static void
finalize_rs (struct ct_pair *pair)
{
	if (pair->fwmark && pair->dst.ss_family != AF_UNSPEC && lvs_method > 1)
		add_dest (current_conf, pair->fwmark, &pair->dst, lvs_method);
	pair->dst.ss_family = AF_UNSPEC;
	pair->fwmark = 0;
}

static void rs_handler (vector_t *strvec)
{
	finalize_rs(&curr_rs);
	if (0 !=
		inet_stosockaddr (vector_slot(strvec, 1), vector_slot(strvec, 2), &curr_rs.dst)
	)
		curr_rs.dst.ss_family = AF_UNSPEC;
	else
	{
		if (curr_rs.dst.ss_family == AF_INET6)
			((struct sockaddr_in6*)(&curr_rs.dst))->sin6_port = 0;
		else
			((struct sockaddr_in*)(&curr_rs.dst))->sin_port = 0;
	}
}

static void fwmark_handler (vector_t *strvec)
{
	curr_rs.fwmark = atoi (vector_slot (strvec, 1));
}

static void
lbkind_handler(vector_t *strvec)
{
    char *str = vector_slot(strvec, 1);

	if (!strcmp(str, "NAT"))
		lvs_method = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		lvs_method = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		lvs_method = IP_VS_CONN_F_TUNNEL;
	else if (!strcmp(str, "GRE"))
		lvs_method = IP_VS_CONN_F_GRE_TUNNEL;
	else
		log_message(LOG_INFO, "PARSER : unknown [%s] routing method.", str);
}

static vector_t *
check_init_keywords(void)
{
	char *checkers[] = {
		"TCP_CHECK",
		"HTTP_GET",
		"SSL_GET",
		"SMTP_CHECK",
	};
	int i;

	/* Virtual server mapping */
	install_keyword_root("virtual_server", NULL);
	install_keyword("lvs_method", &lbkind_handler);
	install_keyword("real_server", &rs_handler);
	install_sublevel();

	for (i = 0; i < sizeof(checkers)/sizeof(*checkers); i++)
	{
		install_keyword(checkers[i], NULL);
		install_sublevel();
		install_keyword("url", NULL);
		install_sublevel();
		install_keyword("dummy", NULL);
		install_sublevel_end();
		install_keyword("fwmark", &fwmark_handler);
		install_sublevel_end();
	}

	install_sublevel_end();
	return keywords;
}

ct_conf_t *
read_configuration(char *conf_file)
{
	current_stream = NULL;
	current_conf = alloc_conf();
	init_data (conf_file, &check_init_keywords);
	lvs_method = 0;
	finalize_rs (&curr_rs);

	if (current_stream == NULL)
	{
		free_conf (current_conf);
		current_conf = NULL;
	}
	return current_conf;
}

void dump_conf (ct_conf_t *conf)
{
	int i;
	struct ct_head *head;
	struct ct_pair *p;

	for (i = 0; i < CT_HSIZE; i++)
		if ((head = conf->htable[i]) != NULL)
			for (p = head->ptr.lh_first; p != NULL; p = p->next.le_next)
				printf ("fwm %d\t%s\n", p->fwmark, inet_sockaddrtos (&p->dst));
}
