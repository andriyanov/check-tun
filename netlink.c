#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <syslog.h>

#include "netlink.h"
#include "logger.h"

int nl_debug = 0;
static nl_socket_t nl_socket = {NULL, NULL, 0, -1, {AF_NETLINK, 0, 0, 0}};

int nl_init(int pid)
{
	int s;
	struct timeval tv = {1,0};
	if (nl_socket.sock > 0)
		return 1;
	nl_socket.nl_sock_addr.nl_pid = pid;

	if ((nl_socket.sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		return 1;
	}
	nl_socket.msgbuf = MALLOC(NL_MSG_BUFSIZE);
	nl_socket.rcvbuf = MALLOC(NL_RCV_BUFSIZE);
	setsockopt(nl_socket.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	bind(s, (struct sockaddr *)&nl_socket.nl_sock_addr, sizeof(nl_socket.nl_sock_addr));
	return 0;
}

void nl_done()
{
	close(nl_socket.sock);
	nl_socket.sock = -1;
	FREE(nl_socket.msgbuf);
	FREE(nl_socket.rcvbuf);
}

int nl_get_iface(int if_family)
{
	nl_request_t *request;
	struct nlmsghdr *nlmsg;
	struct rtmsg *route_msg;
	struct rtattr *route_attr;
	int route_attr_len;
	int if_idx = 0;
	int pid = nl_socket.nl_sock_addr.nl_pid;
	if ((nl_socket.msgbuf == NULL) || (nl_socket.rcvbuf == NULL) || (nl_socket.sock < 1))
		return 0;
	
	const char *af_family = if_family == AF_INET ? "IPv4:" : "IPv6:";

	//char *rcvptr = rcvbuf;
	int rcvlen   = 0;

	bzero(nl_socket.msgbuf,NL_MSG_BUFSIZE);
	bzero(nl_socket.rcvbuf,NL_RCV_BUFSIZE);
	request = (nl_request_t *)nl_socket.msgbuf;
	request->nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nl.nlmsg_type  = RTM_GETROUTE;
	request->nl.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	request->nl.nlmsg_seq   = ++nl_socket.msgnum;
	request->nl.nlmsg_pid   = pid;
	
	request->rt.rtm_family  = if_family;
	request->rt.rtm_type    = RTN_UNICAST;
	request->rt.rtm_table   = RT_TABLE_DEFAULT;
	request->rt.rtm_protocol = 0;
	if (send(nl_socket.sock, request, request->nl.nlmsg_len, 0) < 0) {
		log_message (LOG_ERR, "%s Cannot send NETLINK message to dump routes", af_family);
		return 0;
	}
	//iov.iov_base = rcvbuf;
	//while (1) {
	bool done = false;
	do {
		rcvlen = recv(nl_socket.sock, nl_socket.rcvbuf, NL_RCV_BUFSIZE, 0);
		if (rcvlen < 0) {
			log_message (LOG_ERR, "%s Cannot receive NETLINK message with routes dump", af_family);
			break;
		}
		if (nl_debug) log_message (LOG_DEBUG, "%s Received %d bytes from netlink", af_family, rcvlen);
		for (nlmsg = (struct nlmsghdr *)nl_socket.rcvbuf; NLMSG_OK(nlmsg, rcvlen); nlmsg = NLMSG_NEXT(nlmsg, rcvlen))
		{
			if (nlmsg->nlmsg_type == NLMSG_ERROR) {
				log_message (LOG_ERR, "%s Error in received NETLINK message", af_family);
				done = true;
				break;
			}
			if ((nlmsg->nlmsg_seq != nl_socket.msgnum) || (nlmsg->nlmsg_pid != pid))
			{
				if (nl_debug) log_message (LOG_DEBUG, "%s pid or msgnum changed", af_family);
				done = true;
				break;
			}
			if (nlmsg->nlmsg_type == NLMSG_DONE) 
			{
				if (nl_debug) log_message (LOG_DEBUG, "%s msg_type is DONE", af_family);
				done = true;
			}
			if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
			{
				if (nl_debug) log_message (LOG_DEBUG, "%s msg_flags without F_MULTI", af_family);
				done = true;
			}
			if (if_idx) continue; // do not check other data if we got default gw iface

			route_msg = (struct rtmsg *)NLMSG_DATA(nlmsg);
			//Skip routes not from main route table and not default gw (dst_len > 0)
			if (nl_debug) 
				log_message(LOG_DEBUG,"%s rtm_table = %d, rtm_dst_len = %d,rtm_family = %d", af_family, route_msg->rtm_table, route_msg->rtm_dst_len, route_msg->rtm_family);
			if ((route_msg->rtm_table != RT_TABLE_MAIN && route_msg->rtm_table != RT_TABLE_DEFAULT)|| route_msg->rtm_dst_len != 0)
				continue;
			// Skip non-IPv4 routes
			if (route_msg->rtm_family != if_family)
				continue;
			route_attr_len = RTM_PAYLOAD(nlmsg);
			for (route_attr = (struct rtattr *)RTM_RTA(route_msg); RTA_OK(route_attr,route_attr_len); route_attr = RTA_NEXT(route_attr, route_attr_len))
			{
				if (nl_debug)
					log_message(LOG_DEBUG,"IPv4: rta_type = %d", route_attr->rta_type);

				switch (route_attr->rta_type)
				{
					case RTA_OIF:
						if_idx = *(int *)RTA_DATA(route_attr);
						break;
					default:
						break;
						
				}
				
			}
		}
	} while (!done);
	
	return if_idx;
	
}

int nl_fill_addresses(int ipv4_ifindex, struct sockaddr_storage *bind4, int ipv6_ifindex, struct sockaddr_storage *bind6)
{
	struct ifaddrmsg *ifa_msg;
	struct rtattr *ifa_attr;
	nl_request_t *request = (nl_request_t *)nl_socket.msgbuf;
	char *rcvptr;
	int rcvlen;
	bool done = false;
	struct nlmsghdr *nlmsg;
	int pid = nl_socket.nl_sock_addr.nl_pid;
	
	bzero(nl_socket.msgbuf,NL_MSG_BUFSIZE);
	bzero(nl_socket.rcvbuf,NL_RCV_BUFSIZE);
	request->nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	request->nl.nlmsg_type  = RTM_GETADDR;
	request->nl.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	request->nl.nlmsg_seq   = ++nl_socket.msgnum;
	request->nl.nlmsg_pid   = pid;

	if (send(nl_socket.sock, (void *)request, request->nl.nlmsg_len, 0) < 0) {
		log_message (LOG_ERR, "Cannot send NETLINK message to dump interface addresses");
		return 1;
	}
	do {
		rcvlen = recv(nl_socket.sock, nl_socket.rcvbuf, NL_RCV_BUFSIZE, 0);
		if (rcvlen < 0) {
			log_message (LOG_ERR, "Cannot receive NETLINK message with interface addresses");
			break;
		}
		for (nlmsg = (struct nlmsghdr *)nl_socket.rcvbuf; NLMSG_OK(nlmsg, rcvlen); nlmsg = NLMSG_NEXT(nlmsg, rcvlen))
		{
			if (nlmsg->nlmsg_type == NLMSG_ERROR) {
				log_message (LOG_ERR, "Error in received NETLINK message (dump iface addresses)");
				done = true;
				break;
			}
			if ((nlmsg->nlmsg_seq != nl_socket.msgnum) || (nlmsg->nlmsg_pid != pid)) {
				log_message (LOG_ERR, "msgnum or pid changed (dump iface addresses)");
				done = true;
				break;
			}
			if ((nlmsg->nlmsg_type == NLMSG_DONE) || ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)) {
				done = true;
				break;
			}
			
			// dump all data from netlink if we know all needed info
			if ((!ipv4_ifindex || bind4->ss_family == AF_INET) && (!ipv6_ifindex || bind6->ss_family == AF_INET6)) continue;

			ifa_msg = (struct ifaddrmsg *)NLMSG_DATA(nlmsg);
			if (nl_debug)
				log_message(LOG_DEBUG, "IFA_MSG: family = %d, ifindex = %d, scope = %d", ifa_msg->ifa_family, ifa_msg->ifa_index, ifa_msg->ifa_scope);
			if (bind4->ss_family != AF_INET && ipv4_ifindex && ifa_msg->ifa_index == ipv4_ifindex && 
				ifa_msg->ifa_family == AF_INET  && ifa_msg->ifa_scope == RT_SCOPE_UNIVERSE)
			{
				int ifa_attr_len = IFA_PAYLOAD(nlmsg);
				bool found = false;
				for (ifa_attr = (struct rtattr *)IFA_RTA(ifa_msg); RTA_OK(ifa_attr,ifa_attr_len); ifa_attr = RTA_NEXT(ifa_attr, ifa_attr_len))
				{
					if (nl_debug)
						log_message(LOG_DEBUG,"IFA_MSG: attribute type = %d", ifa_attr->rta_type);
					switch (ifa_attr->rta_type)
					{
						case IFA_LOCAL:
						case IFA_ADDRESS:
							{
							bind4->ss_family = AF_INET;
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
			if (bind6->ss_family != AF_INET6 && ipv6_ifindex && ifa_msg->ifa_index == ipv6_ifindex && 
				ifa_msg->ifa_family == AF_INET6  && ifa_msg->ifa_scope == RT_SCOPE_UNIVERSE)
			{
				int ifa_attr_len = IFA_PAYLOAD(nlmsg);
				bool found = false;
				for (ifa_attr = (struct rtattr *)IFA_RTA(ifa_msg); RTA_OK(ifa_attr,ifa_attr_len); ifa_attr = RTA_NEXT(ifa_attr, ifa_attr_len))
				{
					if (nl_debug)
						log_message(LOG_DEBUG,"IFA_MSG: attribute type = %d", ifa_attr->rta_type);
					switch (ifa_attr->rta_type)
					{
						case IFA_LOCAL:
						case IFA_ADDRESS:
							{
							bind6->ss_family = AF_INET6;
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

		}
	} while (!done);
	return 0;
}