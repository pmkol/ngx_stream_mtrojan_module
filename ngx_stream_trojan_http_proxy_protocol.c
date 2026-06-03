#include "ngx_stream_trojan_http_proxy_protocol.h"

#include <arpa/inet.h>
#include <string.h>


static const uint8_t *
ngx_stream_trojan_http_find_header_end(const uint8_t *buf, size_t len)
{
    size_t i;

    if (len < 4) {
        return NULL;
    }

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n'
            && buf[i + 2] == '\r' && buf[i + 3] == '\n')
        {
            return buf + i + 4;
        }
    }

    return NULL;
}


static int
ngx_stream_trojan_http_has_prefix(const uint8_t *buf, size_t len,
    const char *prefix)
{
    size_t prefix_len;

    prefix_len = strlen(prefix);
    if (len > prefix_len) {
        return memcmp(buf, prefix, prefix_len) == 0;
    }

    return memcmp(buf, prefix, len) == 0;
}


int
ngx_stream_trojan_http_proxy_looks_like_http(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return 0;
    }

    return ngx_stream_trojan_http_has_prefix(buf, len, "CONNECT ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "GET ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "POST ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "HEAD ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "PUT ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "DELETE ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "OPTIONS ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "PATCH ")
           || ngx_stream_trojan_http_has_prefix(buf, len, "TRACE ");
}


static const uint8_t *
ngx_stream_trojan_http_find_space(const uint8_t *p, const uint8_t *last)
{
    while (p < last) {
        if (*p == ' ') {
            return p;
        }

        p++;
    }

    return NULL;
}


static int
ngx_stream_trojan_http_parse_port(const uint8_t *p, const uint8_t *last,
    uint16_t *port)
{
    unsigned int value;

    if (p == last) {
        return -1;
    }

    value = 0;
    while (p < last) {
        if (*p < '0' || *p > '9') {
            return -1;
        }

        value = value * 10 + (*p - '0');
        if (value == 0 || value > 65535) {
            return -1;
        }

        p++;
    }

    *port = (uint16_t) value;
    return 0;
}


static int
ngx_stream_trojan_http_fill_host(const uint8_t *host, size_t host_len,
    uint16_t port, ngx_stream_trojan_addr_t *addr)
{
    if (host_len == 0 || host_len > 255) {
        return -1;
    }

    if (host_len <= INET_ADDRSTRLEN
        && inet_pton(AF_INET, (const char *) host, addr->host) == 1)
    {
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        addr->port = port;
        addr->wire_len = 1 + 4 + 2;
        return 0;
    }

    if (host_len <= INET6_ADDRSTRLEN
        && inet_pton(AF_INET6, (const char *) host, addr->host) == 1)
    {
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        addr->port = port;
        addr->wire_len = 1 + 16 + 2;
        return 0;
    }

    addr->type = NGX_STREAM_TROJAN_ADDR_DOMAIN;
    memcpy(addr->host, host, host_len);
    addr->host_len = host_len;
    addr->port = port;
    addr->wire_len = 1 + 1 + host_len + 2;
    return 0;
}


int
ngx_stream_trojan_http_proxy_parse_connect(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_trojan_addr_t *addr)
{
    const uint8_t *header_end, *line_end, *target, *target_end, *version;
    const uint8_t *host, *host_end, *port_start;
    uint16_t       port;
    uint8_t        host_tmp[256];
    size_t         host_len;

    if (buf == NULL || needed == NULL || addr == NULL) {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    header_end = ngx_stream_trojan_http_find_header_end(buf, len);
    if (header_end == NULL) {
        *needed = len + 1;
        return NGX_STREAM_TROJAN_HTTP_PROXY_NEED_MORE;
    }

    *needed = (size_t) (header_end - buf);
    line_end = buf;
    while (line_end + 1 < header_end) {
        if (line_end[0] == '\r' && line_end[1] == '\n') {
            break;
        }

        line_end++;
    }

    if ((size_t) (line_end - buf) < sizeof("CONNECT  HTTP/1.1") - 1) {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    if (memcmp(buf, "CONNECT ", sizeof("CONNECT ") - 1) != 0)
    {
        return ngx_stream_trojan_http_proxy_looks_like_http(buf, len)
               ? NGX_STREAM_TROJAN_HTTP_PROXY_METHOD_NOT_ALLOWED
               : NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    target = buf + sizeof("CONNECT ") - 1;
    target_end = ngx_stream_trojan_http_find_space(target, line_end);
    if (target_end == NULL || target_end == target) {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    version = target_end + 1;
    if ((size_t) (line_end - version) < sizeof("HTTP/1.0") - 1
        || memcmp(version, "HTTP/1.", sizeof("HTTP/1.") - 1) != 0)
    {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    if (*target == '[') {
        host = target + 1;
        host_end = host;
        while (host_end < target_end && *host_end != ']') {
            host_end++;
        }

        if (host_end == target_end || host_end + 1 >= target_end
            || host_end[1] != ':')
        {
            return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
        }

        port_start = host_end + 2;

    } else {
        host_end = target_end;
        while (host_end > target && host_end[-1] != ':') {
            host_end--;
        }

        if (host_end == target || host_end == target_end) {
            return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
        }

        port_start = host_end;
        host_end--;
        host = target;
    }

    if (ngx_stream_trojan_http_parse_port(port_start, target_end, &port) != 0) {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    host_len = (size_t) (host_end - host);
    if (host_len == 0 || host_len > 255) {
        return NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
    }

    memcpy(host_tmp, host, host_len);
    host_tmp[host_len] = '\0';

    return ngx_stream_trojan_http_fill_host(host_tmp, host_len, port, addr)
           == 0 ? NGX_STREAM_TROJAN_HTTP_PROXY_OK
                : NGX_STREAM_TROJAN_HTTP_PROXY_ERROR;
}


int
ngx_stream_trojan_http_proxy_build_response(uint16_t status,
    uint8_t *out, size_t out_len, size_t *written)
{
    const char *response;
    size_t      len;

    if (out == NULL || written == NULL) {
        return -1;
    }

    switch (status) {
    case 200:
        response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        break;
    case 403:
        response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        break;
    case 405:
        response = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        break;
    case 502:
        response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        break;
    default:
        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        break;
    }

    len = strlen(response);
    if (out_len < len) {
        return -1;
    }

    memcpy(out, response, len);
    *written = len;
    return 0;
}
