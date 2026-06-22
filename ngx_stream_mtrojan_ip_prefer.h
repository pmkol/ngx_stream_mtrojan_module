#ifndef NGX_STREAM_MTROJAN_IP_PREFER_H
#define NGX_STREAM_MTROJAN_IP_PREFER_H

#include <stddef.h>

#define NGX_STREAM_MTROJAN_IP_PREFER_AUTO 0
#define NGX_STREAM_MTROJAN_IP_PREFER_IPV4 1
#define NGX_STREAM_MTROJAN_IP_PREFER_IPV6 2

static inline size_t
ngx_stream_mtrojan_ip_prefer_select(const int *families, size_t n,
    int prefer, int ipv4_family, int ipv6_family)
{
    size_t i;

    if (families == NULL || n == 0) {
        return n;
    }

    if (prefer == NGX_STREAM_MTROJAN_IP_PREFER_IPV4) {
        for (i = 0; i < n; i++) {
            if (families[i] == ipv4_family) {
                return i;
            }
        }
    }

    if (prefer == NGX_STREAM_MTROJAN_IP_PREFER_IPV6) {
        for (i = 0; i < n; i++) {
            if (families[i] == ipv6_family) {
                return i;
            }
        }
    }

    return 0;
}

#endif
