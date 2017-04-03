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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <signal.h>
#include <limits.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h>

#include "config.h"
#include "nfq.h"
#include "logger.h"

static int opt_d = 0;
static int opt_q = 0;
static int opt_th = 1;
static bool opt_a = false;
static char *conf_file;
static char *pid_file;
static char abs_pid_file[PATH_MAX];
static char ifname[IF_NAMESIZE];

static ct_conf_t *conf;
static ct_conf_t *oldconf = NULL;
static int update_conf_flag = 0;
static int opt_dump_conf = 0;
static FILE* pidf = NULL;

// signal handlers config
static void exit_handler (int);
static void hup_handler (int);
static sighandler_t sig_table[NSIG] = {
	[SIGINT]  = &exit_handler,
	[SIGQUIT] = &exit_handler,
	[SIGTERM] = &exit_handler,
	[SIGHUP]  = &hup_handler,
};

static nfq_thread_var_t *nfq_thread_vars = NULL;

static void
usage (char *progname, int exit_code)
{
	printf (
"usage: %s [ -h ] [ -dDC ] [ -b SRC_IP ] [ -p PIDFILE ] [ -q QNUM ] -f conf_file\n"
"  -h     This help message\n"
"  -d     Run as daemon\n"
"  -D     Log debug messages\n"
"  -C     Dump parsed config and exit\n"
"  -b     Source IP address. Could be multiple, for inet and inet6\n"
"  -p     create pid file with specified name\n"
"  -t     create specified threads number. Default is 1\n"
"  -q     use specified nfqueue start number. Default is 0\n"
"         each thread uses its own queue (start number + thread num)\n"
"  -f     keepalived config file path\n"
"  -a     set cpu_affinity for worker threads and bind to cpus from 0 to thread num\n"
"  -i     set interface to bind\n"
, progname);
	exit(exit_code);
}

static void hup_handler (int signum)
{
	update_conf_flag = 1;
}

static void delete_pid_file (void)
{
	if (pid_file && pidf)
		unlink (abs_pid_file);
}

static void exit_handler (int signum)
{
	delete_pid_file();

	// call the default handler
	static struct sigaction act = {
		.sa_handler = SIG_DFL,
	};
	if (0 == sigaction (signum, &act, NULL))
	{
		log_message (LOG_INFO, strsignal(signum));
		raise (signum);
	}
}

static int main0 (int argc, char **argv)
{
	log_console = 1;
	log_syslog = 0;
	bzero(ifname, sizeof(ifname));
	// parse options
	char c;
	if (argc == 1)
		usage(argv[0], 1);
	while (-1 != (c = getopt(argc, argv, "ahdDCf:b:p:q:t:i:")))
		switch (c)
		{
			case 'h':
				usage(argv[0], 0);
				break;
			case 'd':
				opt_d = 1;
				break;
			case 'D':
				nfq_debug = 1;
				break;
			case 'C':
				opt_dump_conf = 1;
				break;
			case 'f':
				conf_file = optarg;
				break;
			case 'b':
			{
				struct sockaddr_storage source;
				if (0 != inet_stosockaddr (optarg, "0", &source))
				{
					fprintf (stderr, "Invalid IP to bind to: %s\n", optarg);
					return 1;
				}
				switch (source.ss_family)
				{
					case AF_INET:
						bind4 = source;
						break;
					case AF_INET6:
						bind6 = source;
						break;
					default:
						fprintf (stderr, "Invalid IP to bind to: %s\n", optarg);
						return 1;
				}
			}
				break;
			case 'p':
				pid_file = optarg;
				break;
			case 'q':
				opt_q = atoi (optarg);
				break;
			case 't':
				opt_th = atoi (optarg);
				break;
			case 'a':
				opt_a = true;
				break;
			case 'i':
				strncpy(ifname,optarg,IF_NAMESIZE);
				ifname[IF_NAMESIZE-1]=0;
				break;
			default:
				return 1;
		}

	// read config
	conf = read_configuration (conf_file);
	if (! conf)
	{
		fprintf (stderr, "Error reading config from %s. See syslog for details\n", conf_file);
		return 1;
	}
	if (opt_dump_conf)
	{
		dump_conf(conf);
		return 0;
	}

	// setup signal handlers
	struct sigaction act = {
			.sa_mask = 0,
			.sa_flags = SA_NODEFER,
	};
	int signum;
	for (signum = 0; signum < NSIG; signum++)
		if (sig_table[signum])
		{
			act.sa_handler = sig_table[signum];
			if (0 > sigaction (signum, &act, NULL))
			{
				perror("sigaction");
				return 1;
			}
		}

	// open pid fh
	if (pid_file != NULL)
	{
		pidf = fopen(pid_file, "w");
		if (! pidf)
		{
			perror (pid_file);
			return 1;
		}
		if (! realpath (pid_file, abs_pid_file))
		{
			perror ("realpath");
			return 1;
		}
	}

	// daemonize
	if (opt_d)
	{
		if (daemon(0, 0) != 0)
		{
			perror("daemon");
			return 1;
		}
		log_console = 0;
		log_syslog = 1;
	}

	// write pid
	if (pid_file != NULL)
	{
		fprintf (pidf, "%d", getpid());
		fclose (pidf);
	}

	log_message (LOG_INFO, "Initializing threads");
	// init thread-specific variables
	nfq_thread_vars = MALLOC(opt_th * sizeof(nfq_thread_var_t));
	if (!nfq_thread_vars)
	{
		delete_pid_file();
		perror("no memory for threads");
		return 1;
	}

	for (int i = 0; i < opt_th; i++)
	{
		nfq_thread_vars[i].nfq_q_num = opt_q + i;
		nfq_thread_vars[i].thread_num = i;
		nfq_thread_vars[i].current_conf = conf;
		nfq_thread_vars[i].global_conf = &conf;
		nfq_thread_vars[i].cpu_affinity = opt_a;
	}
	// init sockets
	nfq_init_int(ifname);
	if (nfq_init_th(opt_th, nfq_thread_vars))
	{
		delete_pid_file();
		perror("threads start error");
		return 1;
	}
	log_message (LOG_INFO, "started listening");

	struct timespec tm = {0, 100000};
	// main loop
	for (;;)
	{
		if (update_conf_flag)
		{
			log_message (LOG_INFO, "got SIGHUP, reloading config file");
			ct_conf_t *new_conf;
			update_conf_flag = 0;
			new_conf = read_configuration (conf_file);
			if (new_conf)
			{
				oldconf = conf;
				conf = new_conf;
			}
			bool conf_updated = false;
			while (!conf_updated)
			{
				conf_updated = true;
				for (int i = 0; i < opt_th && conf_updated; i++)
				{
					conf_updated &= (conf == nfq_thread_vars[i].current_conf);
					if (!(conf == nfq_thread_vars[i].current_conf)) nfq_thread_hup(i);
				}
				nanosleep(&tm, NULL);
			}
			free_conf(oldconf);
		}
		nanosleep(&tm, NULL);

	}

	return 0;
}

int main (int argc, char **argv)
{
	int ret = main0 (argc, argv);
	delete_pid_file();
	if (log_syslog && ret)
		log_message (LOG_WARNING, "exiting with code %d", ret);
	return ret;
}

