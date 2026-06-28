#include "ngx_stream_mtrojan_protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NGX_STREAM_MTROJAN_TCP_BASE_LEN 6
#define NGX_STREAM_MTROJAN_UDP_INIT_BASE_LEN \
    (1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN + 4)
#define NGX_STREAM_MTROJAN_UDP_DATA_BASE_LEN NGX_STREAM_MTROJAN_FLOW_ID_LEN
#define NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX 2
#define NGX_STREAM_MTROJAN_KEY_EPOCH_LEN 4

static int
ngx_stream_mtrojan_valid_flow_protection(
    ngx_stream_mtrojan_flow_protection_e flow_protection)
{
    return flow_protection == NGX_STREAM_MTROJAN_PROTECT_BOOTSTRAP
           || flow_protection == NGX_STREAM_MTROJAN_PROTECT_HANDSHAKE
           || flow_protection == NGX_STREAM_MTROJAN_PROTECT_FULL;
}

static int
ngx_stream_mtrojan_valid_no_key_flow_protection(
    ngx_stream_mtrojan_flow_protection_e flow_protection)
{
    return flow_protection == NGX_STREAM_MTROJAN_PROTECT_BOOTSTRAP;
}

static int
ngx_stream_mtrojan_valid_cmd(ngx_stream_mtrojan_cmd_e cmd)
{
    return cmd == NGX_STREAM_MTROJAN_CMD_CONNECT
           || cmd == NGX_STREAM_MTROJAN_CMD_ASSOCIATE;
}

static int
ngx_stream_mtrojan_valid_addr(uint8_t type, size_t addr_len)
{
    switch (type) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        return addr_len == 4;
    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        return addr_len == 16;
    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        return addr_len > 0
               && addr_len <= NGX_STREAM_MTROJAN_ADDR_DATA_MAX_LEN;
    default:
        return 0;
    }
}

static void
ngx_stream_mtrojan_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t) (value >> 8);
    dst[1] = (uint8_t) value;
}

static void
ngx_stream_mtrojan_write_u32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t) (value >> 24);
    dst[1] = (uint8_t) (value >> 16);
    dst[2] = (uint8_t) (value >> 8);
    dst[3] = (uint8_t) value;
}

static uint16_t
ngx_stream_mtrojan_read_u16(const uint8_t *src)
{
    return (uint16_t) (((uint16_t) src[0] << 8) | src[1]);
}

static uint32_t
ngx_stream_mtrojan_read_u32(const uint8_t *src)
{
    return ((uint32_t) src[0] << 24)
           | ((uint32_t) src[1] << 16)
           | ((uint32_t) src[2] << 8)
           | (uint32_t) src[3];
}

static size_t
ngx_stream_mtrojan_addr_header_size(uint8_t type, size_t addr_len)
{
    if (!ngx_stream_mtrojan_valid_addr(type, addr_len)) {
        return 0;
    }

    return 1 + 1 + addr_len + 2;
}

static int
ngx_stream_mtrojan_write_addr(uint8_t *dst, size_t dst_len, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port, size_t *written)
{
    size_t need;

    if (dst == NULL || addr == NULL || written == NULL
        || !ngx_stream_mtrojan_valid_addr(type, addr_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_addr_header_size(type, addr_len);
    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    dst[0] = type;
    dst[1] = (uint8_t) addr_len;
    memcpy(&dst[2], addr, addr_len);
    ngx_stream_mtrojan_write_u16(&dst[2 + addr_len], port);

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

static int
ngx_stream_mtrojan_read_addr(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_addr_t *addr, size_t *consumed)
{
    uint8_t type;
    size_t addr_len, need;

    if (src == NULL || addr == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < 4) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    type = src[0];
    addr_len = src[1];
    if (!ngx_stream_mtrojan_valid_addr(type, addr_len)) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_addr_header_size(type, addr_len);
    if (src_len < need) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    memset(addr, 0, sizeof(*addr));
    addr->type = type;
    addr->host_len = addr_len;
    memcpy(addr->host, &src[2], addr_len);
    addr->port = ngx_stream_mtrojan_read_u16(&src[2 + addr_len]);
    addr->wire_len = need;

    *consumed = need;
    return NGX_STREAM_MTROJAN_OK;
}

static int
ngx_stream_mtrojan_payload_valid(const uint8_t *payload, size_t payload_len)
{
    return payload_len == 0 || payload != NULL;
}

ngx_stream_mtrojan_udp_packet_class_e
ngx_stream_mtrojan_udp_packet_class(const uint8_t *src, size_t src_len)
{
    if (src == NULL || src_len == 0) {
        return NGX_STREAM_MTROJAN_PACKET_RESERVED2;
    }

    return (ngx_stream_mtrojan_udp_packet_class_e) (src[0] & 0xc0);
}

void
ngx_stream_mtrojan_flow_id_prepare(
    uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN])
{
    if (flow_id != NULL) {
        flow_id[0] &= 0x3f;
    }
}

int
ngx_stream_mtrojan_flow_id_valid(
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN])
{
    return flow_id != NULL
           && (flow_id[0] & 0xc0) == NGX_STREAM_MTROJAN_PACKET_DATA;
}

void
ngx_stream_mtrojan_key_udp_nonce_prepare(
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN])
{
    if (nonce != NULL) {
        nonce[0] = (uint8_t) ((nonce[0] & 0x3f)
                              | NGX_STREAM_MTROJAN_PACKET_INIT);
    }
}

int
ngx_stream_mtrojan_key_udp_nonce_valid(
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN])
{
    return nonce != NULL
           && (nonce[0] & 0xc0) == NGX_STREAM_MTROJAN_PACKET_INIT;
}

size_t
ngx_stream_mtrojan_tcp_bootstrap_header_size(uint8_t type, size_t addr_len)
{
    if (!ngx_stream_mtrojan_valid_addr(type, addr_len)) {
        return 0;
    }

    return 2 + ngx_stream_mtrojan_addr_header_size(type, addr_len);
}

size_t
ngx_stream_mtrojan_tcp_bootstrap_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t header;

    header = ngx_stream_mtrojan_tcp_bootstrap_header_size(type, addr_len);
    if (header == 0
        || payload_len > NGX_STREAM_MTROJAN_BOOTSTRAP_PAYLOAD_MAX)
    {
        return 0;
    }

    return header + payload_len;
}

static int
ngx_stream_mtrojan_encode_tcp_bootstrap_impl(uint8_t *dst, size_t dst_len,
    ngx_stream_mtrojan_cmd_e cmd,
    ngx_stream_mtrojan_flow_protection_e flow_protection, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written, int key_mode)
{
    size_t addr_written, need;
    int rc;

    if (dst == NULL || written == NULL
        || !ngx_stream_mtrojan_valid_cmd(cmd)
        || !(key_mode
             ? ngx_stream_mtrojan_valid_flow_protection(flow_protection)
             : ngx_stream_mtrojan_valid_no_key_flow_protection(flow_protection))
        || !ngx_stream_mtrojan_payload_valid(payload, payload_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_tcp_bootstrap_size(type, addr_len, payload_len);
    if (need == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    dst[0] = (uint8_t) cmd;
    dst[1] = (uint8_t) flow_protection;
    rc = ngx_stream_mtrojan_write_addr(&dst[2], dst_len - 2, type, addr,
                                       addr_len, port, &addr_written);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[2 + addr_written], payload, payload_len);
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_encode_tcp_bootstrap(uint8_t *dst, size_t dst_len,
    ngx_stream_mtrojan_cmd_e cmd,
    ngx_stream_mtrojan_flow_protection_e flow_protection, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    return ngx_stream_mtrojan_encode_tcp_bootstrap_impl(
        dst, dst_len, cmd, flow_protection, type, addr, addr_len, port,
        payload, payload_len, written, 0);
}

static int
ngx_stream_mtrojan_decode_tcp_bootstrap_impl(const uint8_t *src,
    size_t src_len, ngx_stream_mtrojan_tcp_bootstrap_t *bootstrap,
    size_t *consumed, int key_mode)
{
    size_t addr_consumed;
    ngx_stream_mtrojan_cmd_e cmd;
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    int rc;

    if (src == NULL || bootstrap == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_TCP_BASE_LEN) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    cmd = (ngx_stream_mtrojan_cmd_e) src[0];
    if (!ngx_stream_mtrojan_valid_cmd(cmd)) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    flow_protection = (ngx_stream_mtrojan_flow_protection_e) src[1];
    if (!(key_mode
          ? ngx_stream_mtrojan_valid_flow_protection(flow_protection)
          : ngx_stream_mtrojan_valid_no_key_flow_protection(flow_protection)))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    memset(bootstrap, 0, sizeof(*bootstrap));
    rc = ngx_stream_mtrojan_read_addr(&src[2], src_len - 2, &bootstrap->addr,
                                      &addr_consumed);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    bootstrap->cmd = cmd;
    bootstrap->flow_protection = flow_protection;
    bootstrap->payload = &src[2 + addr_consumed];
    bootstrap->payload_len = src_len - 2 - addr_consumed;
    *consumed = 2 + addr_consumed;

    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_decode_tcp_bootstrap(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_tcp_bootstrap_t *bootstrap, size_t *consumed)
{
    return ngx_stream_mtrojan_decode_tcp_bootstrap_impl(
        src, src_len, bootstrap, consumed, 0);
}

size_t
ngx_stream_mtrojan_udp_init_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t addr_header;

    addr_header = ngx_stream_mtrojan_addr_header_size(type, addr_len);
    if (addr_header == 0
        || payload_len > NGX_STREAM_MTROJAN_BOOTSTRAP_PAYLOAD_MAX)
    {
        return 0;
    }

    return 1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN + addr_header + payload_len;
}

int
ngx_stream_mtrojan_encode_udp_init(uint8_t *dst, size_t dst_len,
    ngx_stream_mtrojan_flow_protection_e flow_protection,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN], uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    size_t addr_written, need;
    int rc;

    if (dst == NULL || written == NULL
        || !ngx_stream_mtrojan_valid_no_key_flow_protection(flow_protection)
        || !ngx_stream_mtrojan_flow_id_valid(flow_id)
        || !ngx_stream_mtrojan_payload_valid(payload, payload_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_udp_init_size(type, addr_len, payload_len);
    if (need == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    dst[0] = (uint8_t) (NGX_STREAM_MTROJAN_PACKET_INIT
                        | ((uint8_t) flow_protection & 0x3f));
    memcpy(&dst[1], flow_id, NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    rc = ngx_stream_mtrojan_write_addr(
        &dst[1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN],
        dst_len - 1 - NGX_STREAM_MTROJAN_FLOW_ID_LEN, type, addr, addr_len,
        port, &addr_written);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN + addr_written],
               payload, payload_len);
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_decode_udp_init(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_udp_init_t *frame, size_t *consumed)
{
    size_t addr_consumed;
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_UDP_INIT_BASE_LEN) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    if (ngx_stream_mtrojan_udp_packet_class(src, src_len)
        != NGX_STREAM_MTROJAN_PACKET_INIT)
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    flow_protection = (ngx_stream_mtrojan_flow_protection_e) (src[0] & 0x3f);
    if (!ngx_stream_mtrojan_valid_no_key_flow_protection(flow_protection)
        || !ngx_stream_mtrojan_flow_id_valid(&src[1]))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    memcpy(frame->flow_id, &src[1], NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    rc = ngx_stream_mtrojan_read_addr(
        &src[1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN],
        src_len - 1 - NGX_STREAM_MTROJAN_FLOW_ID_LEN, &frame->addr,
        &addr_consumed);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    frame->flow_protection = flow_protection;
    frame->payload = &src[1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN + addr_consumed];
    frame->payload_len = src_len - 1 - NGX_STREAM_MTROJAN_FLOW_ID_LEN
                         - addr_consumed;
    *consumed = 1 + NGX_STREAM_MTROJAN_FLOW_ID_LEN + addr_consumed;

    return NGX_STREAM_MTROJAN_OK;
}

size_t
ngx_stream_mtrojan_udp_data_size(size_t payload_len)
{
    return NGX_STREAM_MTROJAN_FLOW_ID_LEN + payload_len;
}

int
ngx_stream_mtrojan_encode_udp_data(uint8_t *dst, size_t dst_len,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN],
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    size_t need;

    if (dst == NULL || written == NULL
        || !ngx_stream_mtrojan_flow_id_valid(flow_id)
        || !ngx_stream_mtrojan_payload_valid(payload, payload_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_udp_data_size(payload_len);
    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    memcpy(dst, flow_id, NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    if (payload_len != 0) {
        memcpy(&dst[NGX_STREAM_MTROJAN_FLOW_ID_LEN], payload, payload_len);
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_decode_udp_data(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_udp_data_t *frame, size_t *consumed)
{
    if (src == NULL || frame == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_UDP_DATA_BASE_LEN) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    if (ngx_stream_mtrojan_udp_packet_class(src, src_len)
        != NGX_STREAM_MTROJAN_PACKET_DATA)
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    memcpy(frame->flow_id, src, NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    frame->payload = &src[NGX_STREAM_MTROJAN_FLOW_ID_LEN];
    frame->payload_len = src_len - NGX_STREAM_MTROJAN_FLOW_ID_LEN;
    *consumed = src_len;

    return NGX_STREAM_MTROJAN_OK;
}

size_t
ngx_stream_mtrojan_udp_stream_frame_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t addr_header, frame_len;

    addr_header = ngx_stream_mtrojan_addr_header_size(type, addr_len);
    if (addr_header == 0) {
        return 0;
    }

    frame_len = addr_header + payload_len;
    if (frame_len > UINT16_MAX) {
        return 0;
    }

    return NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX + frame_len;
}

int
ngx_stream_mtrojan_encode_udp_stream_frame(uint8_t *dst, size_t dst_len,
    uint8_t type, const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    size_t addr_written, frame_len, need;
    int rc;

    if (dst == NULL || written == NULL
        || !ngx_stream_mtrojan_payload_valid(payload, payload_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_udp_stream_frame_size(type, addr_len,
                                                    payload_len);
    if (need == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    frame_len = need - NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX;
    ngx_stream_mtrojan_write_u16(dst, (uint16_t) frame_len);
    rc = ngx_stream_mtrojan_write_addr(
        &dst[NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX],
        dst_len - NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX, type, addr,
        addr_len, port, &addr_written);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX + addr_written],
               payload, payload_len);
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_decode_udp_stream_frame(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_udp_stream_frame_t *frame, size_t *consumed)
{
    uint16_t frame_len;
    size_t addr_consumed, need;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    frame_len = ngx_stream_mtrojan_read_u16(src);
    need = NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX + frame_len;
    if (src_len < need) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    memset(frame, 0, sizeof(*frame));
    rc = ngx_stream_mtrojan_read_addr(
        &src[NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX], frame_len,
        &frame->addr, &addr_consumed);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    frame->payload = &src[NGX_STREAM_MTROJAN_UDP_STREAM_LEN_PREFIX
                          + addr_consumed];
    frame->payload_len = frame_len - addr_consumed;
    *consumed = need;

    return NGX_STREAM_MTROJAN_OK;
}

static void
ngx_stream_mtrojan_cleanse(void *ptr, size_t len)
{
    volatile uint8_t *p;

    p = (volatile uint8_t *) ptr;
    while (len-- != 0) {
        *p++ = 0;
    }
}

static int
ngx_stream_mtrojan_key_crypto_valid(
    const ngx_stream_mtrojan_key_crypto_t *crypto)
{
    return crypto != NULL && crypto->seal != NULL && crypto->open != NULL;
}

size_t
ngx_stream_mtrojan_key_wire_size(size_t plain_len)
{
    if (plain_len > NGX_STREAM_MTROJAN_KEY_PLAIN_MAX) {
        return 0;
    }

    return NGX_STREAM_MTROJAN_KEY_NONCE_LEN + plain_len
           + NGX_STREAM_MTROJAN_KEY_TAG_LEN;
}

int
ngx_stream_mtrojan_key_protect(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    const uint8_t *plain, size_t plain_len, size_t *written)
{
    size_t need;
    int rc;

    if (dst == NULL || written == NULL || nonce == NULL
        || !ngx_stream_mtrojan_key_crypto_valid(crypto)
        || !ngx_stream_mtrojan_payload_valid(plain, plain_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_key_wire_size(plain_len);
    if (need == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    memcpy(dst, nonce, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    rc = crypto->seal(crypto->ctx, nonce, plain, plain_len,
                      &dst[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
                      &dst[NGX_STREAM_MTROJAN_KEY_NONCE_LEN + plain_len]);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        ngx_stream_mtrojan_cleanse(&dst[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
                                   plain_len
                                   + NGX_STREAM_MTROJAN_KEY_TAG_LEN);
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_key_unprotect(const uint8_t *src, size_t src_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto, uint8_t *plain,
    size_t plain_len, uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    size_t *plain_written)
{
    const uint8_t *ciphertext, *tag;
    size_t ciphertext_len;
    int rc;

    if (src == NULL || plain == NULL || nonce == NULL || plain_written == NULL
        || !ngx_stream_mtrojan_key_crypto_valid(crypto))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                  + NGX_STREAM_MTROJAN_KEY_TAG_LEN)
    {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    ciphertext_len = src_len - NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                     - NGX_STREAM_MTROJAN_KEY_TAG_LEN;
    if (ciphertext_len > NGX_STREAM_MTROJAN_KEY_PLAIN_MAX) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (ciphertext_len > plain_len) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    memcpy(nonce, src, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    ciphertext = &src[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    tag = &src[NGX_STREAM_MTROJAN_KEY_NONCE_LEN + ciphertext_len];

    rc = crypto->open(crypto->ctx, nonce, ciphertext, ciphertext_len, tag,
                      plain);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        ngx_stream_mtrojan_cleanse(plain, ciphertext_len);
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    *plain_written = ciphertext_len;
    return NGX_STREAM_MTROJAN_OK;
}

static size_t
ngx_stream_mtrojan_key_tcp_wire_size(size_t plain_len)
{
    if (plain_len > NGX_STREAM_MTROJAN_KEY_PLAIN_MAX
        || plain_len > UINT16_MAX)
    {
        return 0;
    }

    return NGX_STREAM_MTROJAN_KEY_NONCE_LEN
           + NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN + plain_len
           + NGX_STREAM_MTROJAN_KEY_TAG_LEN;
}

static int
ngx_stream_mtrojan_key_tcp_protect(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    const uint8_t *plain, size_t plain_len, size_t *written)
{
    size_t need;
    uint8_t *ciphertext, *tag;
    int rc;

    if (dst == NULL || written == NULL || nonce == NULL
        || !ngx_stream_mtrojan_key_crypto_valid(crypto)
        || !ngx_stream_mtrojan_payload_valid(plain, plain_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = ngx_stream_mtrojan_key_tcp_wire_size(plain_len);
    if (need == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (dst_len < need) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    memcpy(dst, nonce, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    ngx_stream_mtrojan_write_u16(&dst[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
                                 (uint16_t) plain_len);
    ciphertext = &dst[NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                      + NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN];
    tag = &ciphertext[plain_len];

    rc = crypto->seal(crypto->ctx, nonce, plain, plain_len, ciphertext, tag);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        ngx_stream_mtrojan_cleanse(ciphertext,
                                   plain_len
                                   + NGX_STREAM_MTROJAN_KEY_TAG_LEN);
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    *written = need;
    return NGX_STREAM_MTROJAN_OK;
}

static int
ngx_stream_mtrojan_key_tcp_unprotect(const uint8_t *src, size_t src_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto, uint8_t *plain,
    size_t plain_len, uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    size_t *plain_written, size_t *wire_consumed)
{
    const uint8_t *ciphertext, *tag;
    size_t ciphertext_len, need;
    int rc;

    if (src == NULL || plain == NULL || nonce == NULL || plain_written == NULL
        || wire_consumed == NULL || !ngx_stream_mtrojan_key_crypto_valid(crypto))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                  + NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN)
    {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    ciphertext_len = ngx_stream_mtrojan_read_u16(
        &src[NGX_STREAM_MTROJAN_KEY_NONCE_LEN]);
    if (ciphertext_len > NGX_STREAM_MTROJAN_KEY_PLAIN_MAX) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    need = NGX_STREAM_MTROJAN_KEY_NONCE_LEN
           + NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN + ciphertext_len
           + NGX_STREAM_MTROJAN_KEY_TAG_LEN;
    if (src_len < need) {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    if (ciphertext_len > plain_len) {
        return NGX_STREAM_MTROJAN_ERR_NO_SPACE;
    }

    memcpy(nonce, src, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    ciphertext = &src[NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                      + NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN];
    tag = &ciphertext[ciphertext_len];

    rc = crypto->open(crypto->ctx, nonce, ciphertext, ciphertext_len, tag,
                      plain);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        ngx_stream_mtrojan_cleanse(plain, ciphertext_len);
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    *plain_written = ciphertext_len;
    *wire_consumed = need;
    return NGX_STREAM_MTROJAN_OK;
}

static size_t
ngx_stream_mtrojan_key_tcp_plain_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t tcp_size;

    tcp_size = ngx_stream_mtrojan_tcp_bootstrap_size(type, addr_len,
                                                     payload_len);
    if (tcp_size == 0) {
        return 0;
    }

    return NGX_STREAM_MTROJAN_KEY_EPOCH_LEN + tcp_size;
}

size_t
ngx_stream_mtrojan_key_tcp_bootstrap_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t plain_len;

    plain_len = ngx_stream_mtrojan_key_tcp_plain_size(type, addr_len,
                                                      payload_len);
    if (plain_len == 0) {
        return 0;
    }

    return ngx_stream_mtrojan_key_tcp_wire_size(plain_len);
}

int
ngx_stream_mtrojan_encode_key_tcp_bootstrap(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN], uint32_t epoch,
    ngx_stream_mtrojan_cmd_e cmd,
    ngx_stream_mtrojan_flow_protection_e flow_protection, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    uint8_t *plain;
    size_t plain_len, tcp_written;
    int rc;

    if (written == NULL || !ngx_stream_mtrojan_valid_cmd(cmd)) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    plain_len = ngx_stream_mtrojan_key_tcp_plain_size(type, addr_len,
                                                      payload_len);
    if (plain_len == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    plain = (uint8_t *) malloc(plain_len);
    if (plain == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    ngx_stream_mtrojan_write_u32(plain, epoch);
    rc = ngx_stream_mtrojan_encode_tcp_bootstrap_impl(
        &plain[NGX_STREAM_MTROJAN_KEY_EPOCH_LEN],
        plain_len - NGX_STREAM_MTROJAN_KEY_EPOCH_LEN, cmd, flow_protection,
        type, addr, addr_len, port, payload, payload_len, &tcp_written, 1);
    if (rc == NGX_STREAM_MTROJAN_OK) {
        rc = ngx_stream_mtrojan_key_tcp_protect(
            dst, dst_len, crypto, nonce, plain,
            NGX_STREAM_MTROJAN_KEY_EPOCH_LEN + tcp_written, written);
    }

    ngx_stream_mtrojan_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

int
ngx_stream_mtrojan_decode_key_tcp_bootstrap(const uint8_t *src,
    size_t src_len, const ngx_stream_mtrojan_key_crypto_t *crypto,
    uint8_t *plain, size_t plain_len,
    ngx_stream_mtrojan_key_tcp_bootstrap_t *bootstrap, size_t *consumed)
{
    ngx_stream_mtrojan_tcp_bootstrap_t tcp;
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    size_t plain_written, tcp_consumed, wire_consumed;
    int rc;

    if (bootstrap == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    rc = ngx_stream_mtrojan_key_tcp_unprotect(src, src_len, crypto, plain,
                                              plain_len, nonce,
                                              &plain_written,
                                              &wire_consumed);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    if (plain_written < NGX_STREAM_MTROJAN_KEY_EPOCH_LEN
                        + NGX_STREAM_MTROJAN_TCP_BASE_LEN)
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    rc = ngx_stream_mtrojan_decode_tcp_bootstrap_impl(
        &plain[NGX_STREAM_MTROJAN_KEY_EPOCH_LEN],
        plain_written - NGX_STREAM_MTROJAN_KEY_EPOCH_LEN, &tcp,
        &tcp_consumed, 1);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    memset(bootstrap, 0, sizeof(*bootstrap));
    bootstrap->epoch = ngx_stream_mtrojan_read_u32(plain);
    memcpy(bootstrap->nonce, nonce, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    bootstrap->cmd = tcp.cmd;
    bootstrap->flow_protection = tcp.flow_protection;
    bootstrap->addr = tcp.addr;
    bootstrap->payload = tcp.payload;
    bootstrap->payload_len = tcp.payload_len;
    *consumed = wire_consumed;

    return NGX_STREAM_MTROJAN_OK;
}

static size_t
ngx_stream_mtrojan_key_udp_init_plain_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t addr_header;

    addr_header = ngx_stream_mtrojan_addr_header_size(type, addr_len);
    if (addr_header == 0) {
        return 0;
    }

    return NGX_STREAM_MTROJAN_KEY_EPOCH_LEN + 1
           + NGX_STREAM_MTROJAN_FLOW_ID_LEN + addr_header + payload_len;
}

size_t
ngx_stream_mtrojan_key_udp_init_size(uint8_t type, size_t addr_len,
    size_t payload_len)
{
    size_t plain_len;

    plain_len = ngx_stream_mtrojan_key_udp_init_plain_size(type, addr_len,
                                                           payload_len);
    if (plain_len == 0) {
        return 0;
    }

    return ngx_stream_mtrojan_key_wire_size(plain_len);
}

int
ngx_stream_mtrojan_encode_key_udp_init(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN], uint32_t epoch,
    ngx_stream_mtrojan_flow_protection_e flow_protection,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN], uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written)
{
    uint8_t *plain;
    uint8_t wire_nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    size_t plain_len, addr_written, off;
    int rc;

    if (nonce == NULL || written == NULL
        || !ngx_stream_mtrojan_valid_flow_protection(flow_protection)
        || !ngx_stream_mtrojan_flow_id_valid(flow_id)
        || !ngx_stream_mtrojan_payload_valid(payload, payload_len))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    plain_len = ngx_stream_mtrojan_key_udp_init_plain_size(type, addr_len,
                                                           payload_len);
    if (plain_len == 0) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    plain = (uint8_t *) malloc(plain_len);
    if (plain == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    off = 0;
    ngx_stream_mtrojan_write_u32(&plain[off], epoch);
    off += NGX_STREAM_MTROJAN_KEY_EPOCH_LEN;
    plain[off++] = (uint8_t) flow_protection;
    memcpy(&plain[off], flow_id, NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    off += NGX_STREAM_MTROJAN_FLOW_ID_LEN;

    rc = ngx_stream_mtrojan_write_addr(&plain[off], plain_len - off, type,
                                       addr, addr_len, port, &addr_written);
    if (rc == NGX_STREAM_MTROJAN_OK) {
        off += addr_written;
        if (payload_len != 0) {
            memcpy(&plain[off], payload, payload_len);
        }

        memcpy(wire_nonce, nonce, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
        ngx_stream_mtrojan_key_udp_nonce_prepare(wire_nonce);
        rc = ngx_stream_mtrojan_key_protect(dst, dst_len, crypto, wire_nonce,
                                            plain, plain_len, written);
    }

    ngx_stream_mtrojan_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

int
ngx_stream_mtrojan_decode_key_udp_init(const uint8_t *src, size_t src_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto, uint8_t *plain,
    size_t plain_len, ngx_stream_mtrojan_key_udp_init_t *frame,
    size_t *consumed)
{
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    size_t plain_written, addr_consumed, off;
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    if (src_len < NGX_STREAM_MTROJAN_KEY_NONCE_LEN
                  + NGX_STREAM_MTROJAN_KEY_TAG_LEN)
    {
        return NGX_STREAM_MTROJAN_ERR_AGAIN;
    }

    if (!ngx_stream_mtrojan_key_udp_nonce_valid(src)) {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    rc = ngx_stream_mtrojan_key_unprotect(src, src_len, crypto, plain,
                                          plain_len, nonce, &plain_written);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    if (plain_written < NGX_STREAM_MTROJAN_KEY_EPOCH_LEN + 1
                        + NGX_STREAM_MTROJAN_FLOW_ID_LEN + 4)
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    off = NGX_STREAM_MTROJAN_KEY_EPOCH_LEN;
    flow_protection = (ngx_stream_mtrojan_flow_protection_e) plain[off++];
    if (!ngx_stream_mtrojan_valid_flow_protection(flow_protection)
        || !ngx_stream_mtrojan_flow_id_valid(&plain[off]))
    {
        return NGX_STREAM_MTROJAN_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    frame->epoch = ngx_stream_mtrojan_read_u32(plain);
    memcpy(frame->nonce, nonce, NGX_STREAM_MTROJAN_KEY_NONCE_LEN);
    frame->flow_protection = flow_protection;
    memcpy(frame->flow_id, &plain[off], NGX_STREAM_MTROJAN_FLOW_ID_LEN);
    off += NGX_STREAM_MTROJAN_FLOW_ID_LEN;

    rc = ngx_stream_mtrojan_read_addr(&plain[off], plain_written - off,
                                      &frame->addr, &addr_consumed);
    if (rc != NGX_STREAM_MTROJAN_OK) {
        return rc;
    }

    off += addr_consumed;
    frame->payload = &plain[off];
    frame->payload_len = plain_written - off;
    *consumed = src_len;

    return NGX_STREAM_MTROJAN_OK;
}

int
ngx_stream_mtrojan_parse_addr(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_addr_t *addr)
{
    size_t consumed;

    return ngx_stream_mtrojan_read_addr(buf, len, addr, &consumed);
}

static int
ngx_stream_mtrojan_tail_has_colon(const uint8_t *data, size_t len)
{
    size_t i, start;

    start = len > 5 ? len - 5 : 0;

    for (i = start; i < len; i++) {
        if (data[i] == ':') {
            return 1;
        }
    }

    return 0;
}

int
ngx_stream_mtrojan_normalize_ip_literal(ngx_stream_mtrojan_addr_t *addr)
{
    uint8_t last;
    struct in_addr in;
    struct in6_addr in6;
    char text[INET6_ADDRSTRLEN];

    if (addr == NULL || addr->type != NGX_STREAM_MTROJAN_ADDR_DOMAIN
        || addr->host_len == 0 || addr->host_len >= sizeof(text))
    {
        return 0;
    }

    last = addr->host[addr->host_len - 1];

    if ((last < '0' || last > '9')
        && !ngx_stream_mtrojan_tail_has_colon(addr->host, addr->host_len))
    {
        return 0;
    }

    memcpy(text, addr->host, addr->host_len);
    text[addr->host_len] = '\0';

    if (inet_pton(AF_INET, text, &in) == 1) {
        addr->type = NGX_STREAM_MTROJAN_ADDR_IPV4;
        memcpy(addr->host, &in, sizeof(in));
        addr->host_len = sizeof(in);
        addr->wire_len = 1 + addr->host_len + 2;
        return 1;
    }

    if (inet_pton(AF_INET6, text, &in6) == 1) {
        addr->type = NGX_STREAM_MTROJAN_ADDR_IPV6;
        memcpy(addr->host, &in6, sizeof(in6));
        addr->host_len = sizeof(in6);
        addr->wire_len = 1 + addr->host_len + 2;
        return 1;
    }

    return 0;
}

int
ngx_stream_mtrojan_addr_to_text(const ngx_stream_mtrojan_addr_t *addr,
    char *out, size_t out_len)
{
    int n;

    if (addr == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    switch (addr->type) {
    case NGX_STREAM_MTROJAN_ADDR_IPV4:
        if (addr->host_len != 4) {
            return -1;
        }
        n = snprintf(out, out_len, "%u.%u.%u.%u:%u",
                     addr->host[0], addr->host[1], addr->host[2],
                     addr->host[3], (unsigned) addr->port);
        break;

    case NGX_STREAM_MTROJAN_ADDR_DOMAIN:
        n = snprintf(out, out_len, "%.*s:%u", (int) addr->host_len,
                     (const char *) addr->host, (unsigned) addr->port);
        break;

    case NGX_STREAM_MTROJAN_ADDR_IPV6:
        if (addr->host_len != 16) {
            return -1;
        }
        n = snprintf(out, out_len,
                     "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                     addr->host[0], addr->host[1], addr->host[2],
                     addr->host[3], addr->host[4], addr->host[5],
                     addr->host[6], addr->host[7], addr->host[8],
                     addr->host[9], addr->host[10], addr->host[11],
                     addr->host[12], addr->host[13], addr->host[14],
                     addr->host[15], (unsigned) addr->port);
        break;

    default:
        return -1;
    }

    if (n < 0 || (size_t) n >= out_len) {
        return -1;
    }

    return 0;
}

int
ngx_stream_mtrojan_use_nginx_resolver(uint8_t addr_type,
    int resolver_configured)
{
    return addr_type == NGX_STREAM_MTROJAN_ADDR_DOMAIN && resolver_configured;
}
