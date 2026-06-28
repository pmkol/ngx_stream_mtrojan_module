#ifndef _NGX_STREAM_MTROJAN_TROJAN_H_INCLUDED_
#define _NGX_STREAM_MTROJAN_TROJAN_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "ngx_stream_mtrojan_protocol.h"

#define NGX_STREAM_TROJAN_KEY_LEN 56
#define NGX_STREAM_TROJAN_CRLF_LEN 2
#define NGX_STREAM_TROJAN_PREFIX_LEN \
    (NGX_STREAM_TROJAN_KEY_LEN + NGX_STREAM_TROJAN_CRLF_LEN)

#define NGX_STREAM_TROJAN_CMD_CONNECT 0x01
#define NGX_STREAM_TROJAN_CMD_ASSOCIATE 0x03

int ngx_stream_trojan_make_key(const char *password, uint8_t out[NGX_STREAM_TROJAN_KEY_LEN]);
int ngx_stream_trojan_make_key_len(const uint8_t *password, size_t password_len,
    uint8_t out[NGX_STREAM_TROJAN_KEY_LEN]);
int ngx_stream_trojan_key_equal(const uint8_t *a, const uint8_t *b);
int ngx_stream_trojan_parse_addr(const uint8_t *buf, size_t len, ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_trojan_parse_udp_frame(const uint8_t *buf, size_t len, ngx_stream_mtrojan_udp_frame_t *frame);
int ngx_stream_trojan_pack_udp_frame(const ngx_stream_mtrojan_addr_t *addr, const uint8_t *payload,
    uint16_t payload_len, uint8_t *out, size_t out_len, size_t *written);
const uint8_t *ngx_stream_trojan_default_fallback_response(size_t *len);

#endif
