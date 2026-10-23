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

#include "client_http3.h"
#include "upstream_policy.h"
#include "upstream_service.h"
#include "client_http3_control.h"
#include "client_socket.h"
#include "client_quic.h"
#include "conn_stream.h"

#include "smartdns/http_parse.h"

static int _dns_client_http3_has_content_length(struct http_head *http_head)
{
	const char *content_len = http_head_get_fields_value(http_head, "content-length");
	return content_len != NULL && content_len[0] != '\0';
}

int _dns_client_send_http3(struct dns_query_struct *query, struct dns_server_info *server_info, void *packet,
						   unsigned short len)
{
#if defined(OSSL_QUIC1_VERSION) && !defined (OPENSSL_NO_QUIC)
	int http_len = 0;
	int ret = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	struct client_dns_server_flag_https *https_flag = NULL;
	struct http_head *http_head = NULL;

	if (len > sizeof(inpacket_data) - 128) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		goto errout;
	}

	https_flag = &server_info->flags.https;
	http_head = http_head_init(4096, HTTP_VERSION_3_0);
	if (http_head == NULL) {
		tlog(TLOG_ERROR, "init http head failed.");
		goto errout;
	}

	http_head_set_method(http_head, HTTP_METHOD_POST);
	http_head_set_url(http_head, https_flag->path);
	http_head_set_head_type(http_head, HTTP_HEAD_REQUEST);
	http_head_add_fields(http_head, ":authority", https_flag->httphost);
	http_head_add_fields(http_head, "user-agent", "smartdns");
	http_head_add_fields(http_head, "content-type", "application/dns-message");
	http_head_add_fields(http_head, "accept", "application/dns-message");
	http_head_add_fields(http_head, "accept-encoding", "identity");
	http_head_set_data(http_head, packet, len);

	http_len = http_head_serialize(http_head, inpacket_data, DNS_IN_PACKSIZE);
	if (http_len <= 0) {
		tlog(TLOG_ERROR, "serialize http head failed.");
		goto errout;
	}

	ret = _dns_client_send_quic_data(query, server_info, inpacket_data, http_len);
	http_head_destroy(http_head);
	return ret;
errout:
	if (http_head) {
		http_head_destroy(http_head);
	}

	return -1;
#else
	tlog(TLOG_ERROR, "http3 is not supported.");
#endif
	return 0;
}

#if defined(OSSL_QUIC1_VERSION) && !defined (OPENSSL_NO_QUIC)
int _dns_client_process_recv_http3(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream)
{
	int ret = 0;
	struct http_head *http_head = NULL;
	uint8_t *pkg_data = NULL;
	int pkg_len = 0;
	int has_content_length = 0;

parse_next_section:
	http_head = http_head_init(4096, HTTP_VERSION_3_0);
	if (http_head == NULL) {
		goto errout;
	}

	ret = http_head_parse(http_head, conn_stream->recv_buff.data, conn_stream->recv_buff.len);
    if (ret < 0) {
        uint64_t fatal = ret == HTTP3_PARSE_FRAME_UNEXPECTED ? 0x105 :
                         ret == HTTP3_PARSE_PUSH_FORBIDDEN ? 0x108 :
                         ret == HTTP3_PARSE_QPACK_ERROR ? 0x200 : 0;
        if (fatal) {
            _dns_http3_connection_error(server_info, fatal);
            _dns_client_close_socket(server_info); /* existing poll guard defers teardown */
            goto errout;
        }
		if (ret == -1) {
			errno = EAGAIN;
			ret = 1;
			goto out;
		} else if (ret == -3) {
			/* repsone is too large */
			tlog(TLOG_DEBUG, "http3 response is too large.");
			conn_stream->recv_buff.len = 0;
			goto errout;
		}

		tlog(TLOG_DEBUG, "remote server not supported.");
		goto errout;
	}

    int code = http_head_get_httpcode(http_head);
    if (code >= 100 && code < 200) {
        if (ret <= 0 || ret > conn_stream->recv_buff.len) goto errout;
        conn_stream->recv_buff.len -= ret;
        memmove(conn_stream->recv_buff.data, conn_stream->recv_buff.data + ret, conn_stream->recv_buff.len);
        http_head_destroy(http_head); http_head = NULL;
        if (conn_stream->recv_buff.len) goto parse_next_section;
        if (!conn_stream->recv_done) { errno = EAGAIN; return 1; }
        return -1;
    }
	if (http_head_get_httpcode(http_head) == 0) {
		/* Malformed response is stream-local H3_MESSAGE_ERROR. */
		goto errout;
	}

	if (http_head_get_httpcode(http_head) != 200) {
		tlog(TLOG_DEBUG, "http3 server query from %s:%d failed, server return http code : %d, %s", server_info->ip,
			 server_info->port, http_head_get_httpcode(http_head), http_head_get_httpcode_msg(http_head));
		int status = http_head_get_httpcode(http_head);
        _dns_service_diagnostic_http(conn_stream->query, server_info, status);
		if (status == 429 || status == 503) {
			_dns_policy_http_error(server_info, status, http_head_get_fields_value(http_head, "retry-after"));
		} else {
			server_info->prohibit = 1;
		}
		goto errout;
	}

	pkg_data = (uint8_t *)http_head_get_data(http_head);
	pkg_len = http_head_get_data_len(http_head);
	has_content_length = _dns_client_http3_has_content_length(http_head);
	if (pkg_data == NULL || pkg_len <= 0) {
		if (has_content_length == 0 && conn_stream->recv_done == 0) {
			errno = EAGAIN;
			ret = 1;
			goto out;
		}
		goto errout;
	}

    if (!conn_stream->recv_done) { errno = EAGAIN; ret = 1; goto out; }
    if (_dns_http_age(pkg_data, pkg_len, http_head_get_fields_value(http_head, "age")) < 0) goto errout;
	if (_dns_client_recv(server_info, pkg_data, pkg_len, &server_info->addr, server_info->ai_addrlen) != 0) {
		if (has_content_length == 0 && conn_stream->recv_done == 0) {
			errno = EAGAIN;
			ret = 1;
			goto out;
		}

		goto errout;
	}
	ret = 0;
out:
	http_head_destroy(http_head);
	return ret;
errout:
    if (!_dns_http3_error(server_info) && conn_stream->quic_stream) {
        SSL_STREAM_RESET_ARGS reset = {0};
        reset.quic_error_code = 0x10e; /* H3_MESSAGE_ERROR is stream-local */
        SSL_stream_reset(conn_stream->quic_stream, &reset, sizeof(reset));
    }
	if (http_head) {
		http_head_destroy(http_head);
	}

	return -1;
}
#endif
