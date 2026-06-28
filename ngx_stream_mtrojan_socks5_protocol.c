#include "ngx_stream_mtrojan_socks5_protocol.h"
#include "ngx_stream_mtrojan_trojan.h"

#include <string.h>


static int
ngx_stream_mtrojan_socks5_addr_len(const uint8_t *buf, size_t len,
    size_t *addr_len)
{
    *addr_len = 0;

    if (len < 1) {
        return 1;
    }

    switch (buf[0]) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        *addr_len = 1 + 4 + 2;
        return len >= *addr_len ? 0 : 1;

    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        *addr_len = 1 + 16 + 2;
        return len >= *addr_len ? 0 : 1;

    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        if (len < 2) {
            *addr_len = 2;
            return 1;
        }
        *addr_len = 1 + 1 + buf[1] + 2;
        return len >= *addr_len ? 0 : 1;

    default:
        return -1;
    }
}


int
ngx_stream_mtrojan_socks5_build_greeting(uint8_t *out, size_t out_len,
    int userpass, size_t *written)
{
    if (out == NULL || written == NULL) {
        return -1;
    }

    if (userpass) {
        if (out_len < 4) {
            return -1;
        }

        out[0] = NGX_STREAM_MTROJAN_SOCKS5_VERSION;
        out[1] = 2;
        out[2] = NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH;
        out[3] = NGX_STREAM_MTROJAN_SOCKS5_METHOD_USERPASS;
        *written = 4;
        return 0;
    }

    if (out_len < 3) {
        return -1;
    }

    out[0] = NGX_STREAM_MTROJAN_SOCKS5_VERSION;
    out[1] = 1;
    out[2] = NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH;
    *written = 3;
    return 0;
}


int
ngx_stream_mtrojan_socks5_parse_method_response(const uint8_t *buf,
    size_t len, int userpass)
{
    if (buf == NULL || len < 2 || buf[0] != NGX_STREAM_MTROJAN_SOCKS5_VERSION) {
        return -1;
    }

    if (buf[1] == NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH) {
        return 0;
    }

    if (userpass && buf[1] == NGX_STREAM_MTROJAN_SOCKS5_METHOD_USERPASS) {
        return 1;
    }

    return -1;
}


int
ngx_stream_mtrojan_socks5_build_auth(const uint8_t *username,
    size_t username_len, const uint8_t *password, size_t password_len,
    uint8_t *out, size_t out_len, size_t *written)
{
    if (username == NULL || password == NULL || out == NULL || written == NULL
        || username_len == 0 || username_len > 255
        || password_len > 255 || out_len < 3 + username_len + password_len)
    {
        return -1;
    }

    out[0] = NGX_STREAM_MTROJAN_SOCKS5_AUTH_VERSION;
    out[1] = (uint8_t) username_len;
    memcpy(out + 2, username, username_len);
    out[2 + username_len] = (uint8_t) password_len;
    memcpy(out + 3 + username_len, password, password_len);
    *written = 3 + username_len + password_len;

    return 0;
}


int
ngx_stream_mtrojan_socks5_parse_auth_response(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < 2 || buf[0] != NGX_STREAM_MTROJAN_SOCKS5_AUTH_VERSION) {
        return -1;
    }

    return buf[1] == 0 ? 0 : -1;
}


int
ngx_stream_mtrojan_socks5_greeting_len(const uint8_t *buf, size_t len,
    size_t *needed)
{
    if (buf == NULL || needed == NULL) {
        return -1;
    }

    if (len < 2) {
        *needed = 2;
        return 1;
    }

    if (buf[0] != NGX_STREAM_MTROJAN_SOCKS5_VERSION) {
        return -1;
    }

    *needed = 2 + buf[1];
    return len >= *needed ? 0 : 1;
}


int
ngx_stream_mtrojan_socks5_select_method(const uint8_t *buf, size_t len)
{
    size_t i, needed;

    if (ngx_stream_mtrojan_socks5_greeting_len(buf, len, &needed) != 0
        || len < needed)
    {
        return -1;
    }

    for (i = 0; i < buf[1]; i++) {
        if (buf[2 + i] == NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH) {
            return NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH;
        }
    }

    return NGX_STREAM_MTROJAN_SOCKS5_METHOD_NONE;
}


int
ngx_stream_mtrojan_socks5_build_method_response(uint8_t method, uint8_t *out,
    size_t out_len)
{
    if (out == NULL || out_len < 2) {
        return -1;
    }

    out[0] = NGX_STREAM_MTROJAN_SOCKS5_VERSION;
    out[1] = method;

    return 0;
}


int
ngx_stream_mtrojan_socks5_build_request(uint8_t command,
    const ngx_stream_mtrojan_addr_t *addr, uint8_t *out, size_t out_len,
    size_t *written)
{
    if (addr == NULL || out == NULL || written == NULL
        || (command != NGX_STREAM_MTROJAN_SOCKS5_CMD_CONNECT
            && command != NGX_STREAM_MTROJAN_SOCKS5_CMD_UDP_ASSOCIATE))
    {
        return -1;
    }

    if (out_len < 3 + addr->wire_len) {
        return -1;
    }

    out[0] = NGX_STREAM_MTROJAN_SOCKS5_VERSION;
    out[1] = command;
    out[2] = 0;
    out[3] = addr->type;

    switch (addr->type) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        if (addr->host_len != 4 || addr->wire_len != 1 + 4 + 2) {
            return -1;
        }
        memcpy(out + 4, addr->host, 4);
        out[8] = (uint8_t) (addr->port >> 8);
        out[9] = (uint8_t) addr->port;
        *written = 10;
        return 0;

    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        if (addr->host_len != 16 || addr->wire_len != 1 + 16 + 2) {
            return -1;
        }
        memcpy(out + 4, addr->host, 16);
        out[20] = (uint8_t) (addr->port >> 8);
        out[21] = (uint8_t) addr->port;
        *written = 22;
        return 0;

    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        if (addr->host_len == 0 || addr->host_len > 255
            || addr->wire_len != 1 + 1 + addr->host_len + 2)
        {
            return -1;
        }
        out[4] = (uint8_t) addr->host_len;
        memcpy(out + 5, addr->host, addr->host_len);
        out[5 + addr->host_len] = (uint8_t) (addr->port >> 8);
        out[6 + addr->host_len] = (uint8_t) addr->port;
        *written = 7 + addr->host_len;
        return 0;

    default:
        return -1;
    }
}


int
ngx_stream_mtrojan_socks5_request_len(const uint8_t *buf, size_t len,
    size_t *needed)
{
    size_t addr_len;
    int rc;

    if (buf == NULL || needed == NULL) {
        return -1;
    }

    if (len < 4) {
        *needed = 4;
        return 1;
    }

    if (buf[0] != NGX_STREAM_MTROJAN_SOCKS5_VERSION || buf[2] != 0) {
        return -1;
    }

    if (buf[1] != NGX_STREAM_MTROJAN_SOCKS5_CMD_CONNECT
        && buf[1] != NGX_STREAM_MTROJAN_SOCKS5_CMD_UDP_ASSOCIATE)
    {
        return -1;
    }

    rc = ngx_stream_mtrojan_socks5_addr_len(buf + 3, len - 3, &addr_len);
    if (rc == 1) {
        *needed = 3 + addr_len;
        return 1;
    }

    if (rc != 0) {
        return -1;
    }

    *needed = 3 + addr_len;
    return 0;
}


int
ngx_stream_mtrojan_socks5_parse_request(const uint8_t *buf, size_t len,
    uint8_t *command, ngx_stream_mtrojan_addr_t *addr)
{
    size_t needed;

    if (command == NULL || addr == NULL
        || ngx_stream_mtrojan_socks5_request_len(buf, len, &needed) != 0
        || len < needed)
    {
        return -1;
    }

    *command = buf[1];
    return ngx_stream_trojan_parse_addr(buf + 3, needed - 3, addr);
}


int
ngx_stream_mtrojan_socks5_build_response(uint8_t status,
    const ngx_stream_mtrojan_addr_t *addr, uint8_t *out, size_t out_len,
    size_t *written)
{
    size_t req_len;

    if (addr == NULL || out == NULL || written == NULL
        || out_len < 3 + addr->wire_len)
    {
        return -1;
    }

    out[0] = NGX_STREAM_MTROJAN_SOCKS5_VERSION;
    out[1] = status;
    out[2] = 0;
    out[3] = addr->type;

    switch (addr->type) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        if (addr->host_len != 4) {
            return -1;
        }
        memcpy(out + 4, addr->host, 4);
        out[8] = (uint8_t) (addr->port >> 8);
        out[9] = (uint8_t) addr->port;
        req_len = 10;
        break;

    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        if (addr->host_len != 16) {
            return -1;
        }
        memcpy(out + 4, addr->host, 16);
        out[20] = (uint8_t) (addr->port >> 8);
        out[21] = (uint8_t) addr->port;
        req_len = 22;
        break;

    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        if (addr->host_len == 0 || addr->host_len > 255) {
            return -1;
        }
        out[4] = (uint8_t) addr->host_len;
        memcpy(out + 5, addr->host, addr->host_len);
        out[5 + addr->host_len] = (uint8_t) (addr->port >> 8);
        out[6 + addr->host_len] = (uint8_t) addr->port;
        req_len = 7 + addr->host_len;
        break;

    default:
        return -1;
    }

    *written = req_len;
    return 0;
}


int
ngx_stream_mtrojan_socks5_response_len(const uint8_t *buf, size_t len,
    size_t *needed)
{
    size_t addr_len;
    int rc;

    if (buf == NULL || needed == NULL) {
        return -1;
    }

    if (len < 4) {
        *needed = 4;
        return 1;
    }

    if (buf[0] != NGX_STREAM_MTROJAN_SOCKS5_VERSION || buf[2] != 0) {
        return -1;
    }

    rc = ngx_stream_mtrojan_socks5_addr_len(buf + 3, len - 3, &addr_len);
    if (rc == 1) {
        *needed = 3 + addr_len;
        return 1;
    }

    if (rc != 0) {
        return -1;
    }

    *needed = 3 + addr_len;
    return 0;
}


int
ngx_stream_mtrojan_socks5_parse_response(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_addr_t *addr)
{
    size_t needed;

    if (addr == NULL
        || ngx_stream_mtrojan_socks5_response_len(buf, len, &needed) != 0
        || len < needed || buf[1] != NGX_STREAM_MTROJAN_SOCKS5_STATUS_OK)
    {
        return -1;
    }

    return ngx_stream_trojan_parse_addr(buf + 3, needed - 3, addr);
}


int
ngx_stream_mtrojan_socks5_build_udp_packet(
    const ngx_stream_mtrojan_addr_t *addr, const uint8_t *payload,
    uint16_t payload_len, uint8_t *out, size_t out_len, size_t *written)
{
    size_t req_len;

    if (addr == NULL || out == NULL || written == NULL
        || (payload_len && payload == NULL)
        || out_len < 3 + addr->wire_len + payload_len)
    {
        return -1;
    }

    out[0] = 0;
    out[1] = 0;
    out[2] = 0;

    out[3] = addr->type;

    switch (addr->type) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        if (addr->host_len != 4) {
            return -1;
        }
        memcpy(out + 4, addr->host, 4);
        out[8] = (uint8_t) (addr->port >> 8);
        out[9] = (uint8_t) addr->port;
        req_len = 10;
        break;

    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        if (addr->host_len != 16) {
            return -1;
        }
        memcpy(out + 4, addr->host, 16);
        out[20] = (uint8_t) (addr->port >> 8);
        out[21] = (uint8_t) addr->port;
        req_len = 22;
        break;

    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        if (addr->host_len == 0 || addr->host_len > 255) {
            return -1;
        }
        out[4] = (uint8_t) addr->host_len;
        memcpy(out + 5, addr->host, addr->host_len);
        out[5 + addr->host_len] = (uint8_t) (addr->port >> 8);
        out[6 + addr->host_len] = (uint8_t) addr->port;
        req_len = 7 + addr->host_len;
        break;

    default:
        return -1;
    }

    if (payload_len) {
        memcpy(out + req_len, payload, payload_len);
    }
    *written = req_len + payload_len;
    return 0;
}


int
ngx_stream_mtrojan_socks5_parse_udp_packet(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_udp_frame_t *frame)
{
    if (buf == NULL || frame == NULL || len < 4
        || buf[0] != 0 || buf[1] != 0 || buf[2] != 0)
    {
        return -1;
    }

    if (ngx_stream_trojan_parse_addr(buf + 3, len - 3, &frame->addr) != 0) {
        return -1;
    }

    if (len - 3 - frame->addr.wire_len > UINT16_MAX) {
        return -1;
    }

    frame->payload = buf + 3 + frame->addr.wire_len;
    frame->payload_len = (uint16_t) (len - 3 - frame->addr.wire_len);
    frame->wire_len = len;

    return 0;
}
