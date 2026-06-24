#include "ngx_stream_mtrojan_inbound.h"

#include "ngx_stream_mtrojan_http_proxy_protocol.h"
#include "ngx_stream_mtrojan_socks5_protocol.h"


static int
ngx_stream_mtrojan_looks_like_tls(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < 3) {
        return 0;
    }

    return buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04;
}


ngx_stream_mtrojan_inbound_e
ngx_stream_mtrojan_classify_inbound(const uint8_t *buf, size_t len,
    int socks5_enabled, int http_enabled, int mtrojan_enabled)
{
    (void) mtrojan_enabled;

    if (buf == NULL || len == 0) {
        return ngx_stream_mtrojan_inbound_close;
    }

    if (buf[0] == NGX_STREAM_MTROJAN_SOCKS5_VERSION) {
        return socks5_enabled ? ngx_stream_mtrojan_inbound_socks5
                              : ngx_stream_mtrojan_inbound_close;
    }

    if (http_enabled && ngx_stream_mtrojan_http_proxy_looks_like_http(buf, len)) {
        return ngx_stream_mtrojan_inbound_http;
    }

    if (ngx_stream_mtrojan_looks_like_tls(buf, len)) {
        return ngx_stream_mtrojan_inbound_tls;
    }

    return ngx_stream_mtrojan_inbound_close;
}
