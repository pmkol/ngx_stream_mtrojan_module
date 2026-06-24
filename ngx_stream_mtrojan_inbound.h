#ifndef _NGX_STREAM_MTROJAN_INBOUND_H_INCLUDED_
#define _NGX_STREAM_MTROJAN_INBOUND_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ngx_stream_mtrojan_inbound_mtrojan = 0,
    ngx_stream_mtrojan_inbound_tls,
    ngx_stream_mtrojan_inbound_socks5,
    ngx_stream_mtrojan_inbound_http,
    ngx_stream_mtrojan_inbound_close
} ngx_stream_mtrojan_inbound_e;

ngx_stream_mtrojan_inbound_e ngx_stream_mtrojan_classify_inbound(
    const uint8_t *buf, size_t len, int socks5_enabled, int http_enabled,
    int mtrojan_enabled);

#endif
