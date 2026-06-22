#ifndef _NGX_STREAM_MTROJAN_SOCKS5_PROTOCOL_H_INCLUDED_
#define _NGX_STREAM_MTROJAN_SOCKS5_PROTOCOL_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "ngx_stream_mtrojan_protocol.h"

#define NGX_STREAM_MTROJAN_SOCKS5_VERSION 0x05
#define NGX_STREAM_MTROJAN_SOCKS5_AUTH_VERSION 0x01
#define NGX_STREAM_MTROJAN_SOCKS5_METHOD_NO_AUTH 0x00
#define NGX_STREAM_MTROJAN_SOCKS5_METHOD_USERPASS 0x02
#define NGX_STREAM_MTROJAN_SOCKS5_METHOD_NONE 0xff
#define NGX_STREAM_MTROJAN_SOCKS5_CMD_CONNECT 0x01
#define NGX_STREAM_MTROJAN_SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define NGX_STREAM_MTROJAN_SOCKS5_STATUS_OK 0x00
#define NGX_STREAM_MTROJAN_SOCKS5_STATUS_GENERAL_FAILURE 0x01
#define NGX_STREAM_MTROJAN_SOCKS5_MAX_PACKET \
    (3 + NGX_STREAM_MTROJAN_MAX_ADDR_LEN + NGX_STREAM_MTROJAN_MAX_UDP_PAYLOAD)

int ngx_stream_mtrojan_socks5_build_greeting(uint8_t *out, size_t out_len,
    int userpass, size_t *written);
int ngx_stream_mtrojan_socks5_parse_method_response(const uint8_t *buf,
    size_t len, int userpass);
int ngx_stream_mtrojan_socks5_build_auth(const uint8_t *username,
    size_t username_len, const uint8_t *password, size_t password_len,
    uint8_t *out, size_t out_len, size_t *written);
int ngx_stream_mtrojan_socks5_parse_auth_response(const uint8_t *buf,
    size_t len);
int ngx_stream_mtrojan_socks5_greeting_len(const uint8_t *buf, size_t len,
    size_t *needed);
int ngx_stream_mtrojan_socks5_select_method(const uint8_t *buf, size_t len);
int ngx_stream_mtrojan_socks5_build_method_response(uint8_t method,
    uint8_t *out, size_t out_len);
int ngx_stream_mtrojan_socks5_build_request(uint8_t command,
    const ngx_stream_mtrojan_addr_t *addr, uint8_t *out, size_t out_len,
    size_t *written);
int ngx_stream_mtrojan_socks5_request_len(const uint8_t *buf, size_t len,
    size_t *needed);
int ngx_stream_mtrojan_socks5_parse_request(const uint8_t *buf, size_t len,
    uint8_t *command, ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_mtrojan_socks5_build_response(uint8_t status,
    const ngx_stream_mtrojan_addr_t *addr, uint8_t *out, size_t out_len,
    size_t *written);
int ngx_stream_mtrojan_socks5_response_len(const uint8_t *buf, size_t len,
    size_t *needed);
int ngx_stream_mtrojan_socks5_parse_response(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_mtrojan_socks5_build_udp_packet(
    const ngx_stream_mtrojan_addr_t *addr, const uint8_t *payload,
    uint16_t payload_len, uint8_t *out, size_t out_len, size_t *written);
int ngx_stream_mtrojan_socks5_parse_udp_packet(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_udp_frame_t *frame);

#endif
