/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "server_socket.h"
#include "dns_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

static struct addrinfo *_dns_server_getaddr(const char *host, const char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;
	const int s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		const char *error_str;
		if (s == EAI_SYSTEM) {
			error_str = strerror(errno);
		} else {
			error_str = gai_strerror(s);
		}
		tlog(TLOG_ERROR, "get addr info failed. %s.\n", error_str);
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

int _dns_create_socket(const char *host_ip, int type)
{
	int fd = -1;
	struct addrinfo *gai = NULL;
	char port_str[16];
	char ip[MAX_IP_LEN];
	char host_ip_device[MAX_IP_LEN * 2];
	int port = 0;
	char *host = NULL;
	int optval = 1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;
	const char *ifname = NULL;

	safe_strncpy(host_ip_device, host_ip, sizeof(host_ip_device));
	ifname = strstr(host_ip_device, "@");
	if (ifname) {
		*(char *)ifname = '\0';
		ifname++;
	}

	if (parse_ip(host_ip_device, ip, &port) == 0) {
		host = ip;
	}

	if (port <= 0) {
		port = DEFAULT_DNS_PORT;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _dns_server_getaddr(host, port_str, type, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, family = %d, type = %d, proto = %d, %s\n", gai->ai_family,
			 gai->ai_socktype, gai->ai_protocol, strerror(errno));
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
			tlog(TLOG_ERROR, "set socket opt failed.");
			goto errout;
		}
		/* enable TCP_FASTOPEN */
		setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	} else {
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
	}
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	if (ifname != NULL) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind service %s failed, %s\n", host_ip, strerror(errno));
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 256) != 0) {
			tlog(TLOG_ERROR, "listen failed.\n");
			goto errout;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	freeaddrinfo(gai);

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	tlog(TLOG_ERROR, "add server failed, host-ip: %s, type: %d", host_ip, type);
	return -1;
}

int dns_server_listener_match(int family, const unsigned char *address, int port, int datagram)
{
    int match = 0;
    if (!server.conn_list.next) return 0; /* no server initialized (isolated client tests) */
    pthread_mutex_lock(&server.conn_list_lock);
    struct dns_server_conn_head *conn;
    list_for_each_entry(conn, &server.conn_list, list) {
        int udp = conn->type == DNS_CONN_TYPE_UDP_SERVER;
        int stream = conn->type == DNS_CONN_TYPE_TCP_SERVER || conn->type == DNS_CONN_TYPE_TLS_SERVER ||
            conn->type == DNS_CONN_TYPE_HTTPS_SERVER || conn->type == DNS_CONN_TYPE_HTTP_SERVER;
        if ((!udp && !stream) || udp != !!datagram || conn->fd < 0) continue;
        struct sockaddr_storage bound = {0}; socklen_t size = sizeof(bound);
        if (getsockname(conn->fd, (struct sockaddr *)&bound, &size)) continue;
        unsigned char listener[16]; int listener_family = bound.ss_family, listener_port;
        if (listener_family == AF_INET) {
            struct sockaddr_in *a = (void *)&bound;
            listener_port = ntohs(a->sin_port); memcpy(listener, &a->sin_addr, 4);
        } else if (listener_family == AF_INET6) {
            struct sockaddr_in6 *a = (void *)&bound;
            listener_port = ntohs(a->sin6_port); memcpy(listener, &a->sin6_addr, 16);
            if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) {
                memmove(listener, listener + 12, 4); listener_family = AF_INET;
            }
        } else continue;
        if (listener_port != port) continue;
        const unsigned char zero[16] = {0};
        int wildcard = !memcmp(listener, zero, listener_family == AF_INET ? 4 : 16);
        if (!wildcard && family == listener_family && !memcmp(address, listener, family == AF_INET ? 4 : 16)) {
            match = 1; break;
        }
        if (!wildcard || (listener_family == AF_INET && family != AF_INET)) continue;
        if (listener_family == AF_INET6 && family == AF_INET) {
            int v6only = 1; socklen_t len = sizeof(v6only);
            if (getsockopt(conn->fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len) || v6only) continue;
        }
        match = 2;
    }
    pthread_mutex_unlock(&server.conn_list_lock);
    return match;
}
