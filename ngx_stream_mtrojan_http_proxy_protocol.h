#ifndef _NGX_STREAM_MTROJAN_HTTP_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_STREAM_MTROJAN_HTTP_PROXY_PROTOCOL_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "ngx_stream_mtrojan_protocol.h"

#define NGX_STREAM_MTROJAN_HTTP_PROXY_NEED_MORE 1
#define NGX_STREAM_MTROJAN_HTTP_PROXY_OK 0
#define NGX_STREAM_MTROJAN_HTTP_PROXY_ERROR -1
#define NGX_STREAM_MTROJAN_HTTP_PROXY_METHOD_NOT_ALLOWED -2

int ngx_stream_mtrojan_http_proxy_looks_like_http(const uint8_t *buf,
    size_t len);
int ngx_stream_mtrojan_http_proxy_parse_connect(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_mtrojan_http_proxy_build_response(uint16_t status,
    uint8_t *out, size_t out_len, size_t *written);

#endif
