#ifndef _NGX_STREAM_MTROJAN_PROTOCOL_H_INCLUDED_
#define _NGX_STREAM_MTROJAN_PROTOCOL_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define NGX_STREAM_MTROJAN_ADDR_DATA_MAX_LEN 255
#define NGX_STREAM_MTROJAN_MAX_ADDR_LEN (1 + 1 + NGX_STREAM_MTROJAN_ADDR_DATA_MAX_LEN + 2)
#define NGX_STREAM_MTROJAN_MAX_UDP_PAYLOAD 65535

#define NGX_STREAM_MTROJAN_FLOW_ID_LEN 8
#define NGX_STREAM_MTROJAN_KEY_NONCE_LEN 12
#define NGX_STREAM_MTROJAN_KEY_TCP_LEN_LEN 2
#define NGX_STREAM_MTROJAN_KEY_TAG_LEN 16
#define NGX_STREAM_MTROJAN_BOOTSTRAP_PAYLOAD_MAX 16384
#define NGX_STREAM_MTROJAN_KEY_PLAIN_MAX 32768
#define NGX_STREAM_MTROJAN_UDP_DATAGRAM_SAFE_MAX 1200

#define NGX_STREAM_MTROJAN_ADDR_IPV4 0x01
#define NGX_STREAM_MTROJAN_ADDR_DOMAIN 0x03
#define NGX_STREAM_MTROJAN_ADDR_IPV6 0x04

typedef enum {
    NGX_STREAM_MTROJAN_OK = 0,
    NGX_STREAM_MTROJAN_ERR_INVALID = -1,
    NGX_STREAM_MTROJAN_ERR_AGAIN = -2,
    NGX_STREAM_MTROJAN_ERR_NO_SPACE = -3
} ngx_stream_mtrojan_status_e;

typedef enum {
    NGX_STREAM_MTROJAN_PROTECT_BOOTSTRAP = 0,
    NGX_STREAM_MTROJAN_PROTECT_HANDSHAKE = 1,
    NGX_STREAM_MTROJAN_PROTECT_FULL = 2
} ngx_stream_mtrojan_flow_protection_e;

typedef enum {
    NGX_STREAM_MTROJAN_CMD_CONNECT = 0x01,
    NGX_STREAM_MTROJAN_CMD_ASSOCIATE = 0x03
} ngx_stream_mtrojan_cmd_e;

typedef enum {
    NGX_STREAM_MTROJAN_PACKET_DATA = 0x00,
    NGX_STREAM_MTROJAN_PACKET_RESERVED1 = 0x40,
    NGX_STREAM_MTROJAN_PACKET_INIT = 0x80,
    NGX_STREAM_MTROJAN_PACKET_RESERVED2 = 0xc0
} ngx_stream_mtrojan_udp_packet_class_e;

typedef struct {
    uint8_t type;
    uint8_t host[NGX_STREAM_MTROJAN_ADDR_DATA_MAX_LEN];
    size_t host_len;
    uint16_t port;
    size_t wire_len;
} ngx_stream_mtrojan_addr_t;

typedef struct {
    ngx_stream_mtrojan_addr_t addr;
    uint16_t payload_len;
    const uint8_t *payload;
    size_t wire_len;
} ngx_stream_mtrojan_udp_frame_t;

typedef struct {
    ngx_stream_mtrojan_cmd_e cmd;
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    ngx_stream_mtrojan_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_tcp_bootstrap_t;

typedef struct {
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN];
    ngx_stream_mtrojan_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_udp_init_t;

typedef struct {
    uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN];
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_udp_data_t;

typedef struct {
    ngx_stream_mtrojan_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_udp_stream_frame_t;

typedef struct {
    uint32_t epoch;
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    ngx_stream_mtrojan_cmd_e cmd;
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    ngx_stream_mtrojan_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_key_tcp_bootstrap_t;

typedef struct {
    uint32_t epoch;
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN];
    ngx_stream_mtrojan_flow_protection_e flow_protection;
    uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN];
    ngx_stream_mtrojan_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} ngx_stream_mtrojan_key_udp_init_t;

typedef int (*ngx_stream_mtrojan_key_seal_pt)(void *ctx,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    const uint8_t *plain, size_t plain_len, uint8_t *ciphertext,
    uint8_t tag[NGX_STREAM_MTROJAN_KEY_TAG_LEN]);

typedef int (*ngx_stream_mtrojan_key_open_pt)(void *ctx,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[NGX_STREAM_MTROJAN_KEY_TAG_LEN], uint8_t *plain);

typedef struct {
    void *ctx;
    ngx_stream_mtrojan_key_seal_pt seal;
    ngx_stream_mtrojan_key_open_pt open;
} ngx_stream_mtrojan_key_crypto_t;

ngx_stream_mtrojan_udp_packet_class_e ngx_stream_mtrojan_udp_packet_class(
    const uint8_t *src, size_t src_len);

void ngx_stream_mtrojan_flow_id_prepare(
    uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN]);
int ngx_stream_mtrojan_flow_id_valid(
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN]);

void ngx_stream_mtrojan_key_udp_nonce_prepare(
    uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN]);
int ngx_stream_mtrojan_key_udp_nonce_valid(
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN]);

size_t ngx_stream_mtrojan_tcp_bootstrap_header_size(uint8_t type,
    size_t addr_len);
size_t ngx_stream_mtrojan_tcp_bootstrap_size(uint8_t type, size_t addr_len,
    size_t payload_len);
int ngx_stream_mtrojan_encode_tcp_bootstrap(uint8_t *dst, size_t dst_len,
    ngx_stream_mtrojan_cmd_e cmd,
    ngx_stream_mtrojan_flow_protection_e flow_protection, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_tcp_bootstrap(const uint8_t *src,
    size_t src_len, ngx_stream_mtrojan_tcp_bootstrap_t *bootstrap,
    size_t *consumed);

size_t ngx_stream_mtrojan_udp_init_size(uint8_t type, size_t addr_len,
    size_t payload_len);
int ngx_stream_mtrojan_encode_udp_init(uint8_t *dst, size_t dst_len,
    ngx_stream_mtrojan_flow_protection_e flow_protection,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN], uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_udp_init(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_udp_init_t *frame, size_t *consumed);

size_t ngx_stream_mtrojan_udp_data_size(size_t payload_len);
int ngx_stream_mtrojan_encode_udp_data(uint8_t *dst, size_t dst_len,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN],
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_udp_data(const uint8_t *src, size_t src_len,
    ngx_stream_mtrojan_udp_data_t *frame, size_t *consumed);

size_t ngx_stream_mtrojan_udp_stream_frame_size(uint8_t type,
    size_t addr_len, size_t payload_len);
int ngx_stream_mtrojan_encode_udp_stream_frame(uint8_t *dst, size_t dst_len,
    uint8_t type, const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_udp_stream_frame(const uint8_t *src,
    size_t src_len, ngx_stream_mtrojan_udp_stream_frame_t *frame,
    size_t *consumed);

size_t ngx_stream_mtrojan_key_wire_size(size_t plain_len);
int ngx_stream_mtrojan_key_protect(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    const uint8_t *plain, size_t plain_len, size_t *written);
int ngx_stream_mtrojan_key_unprotect(const uint8_t *src, size_t src_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto, uint8_t *plain,
    size_t plain_len, uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN],
    size_t *plain_written);

size_t ngx_stream_mtrojan_key_tcp_bootstrap_size(uint8_t type,
    size_t addr_len, size_t payload_len);
int ngx_stream_mtrojan_encode_key_tcp_bootstrap(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN], uint32_t epoch,
    ngx_stream_mtrojan_cmd_e cmd,
    ngx_stream_mtrojan_flow_protection_e flow_protection, uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_key_tcp_bootstrap(const uint8_t *src,
    size_t src_len, const ngx_stream_mtrojan_key_crypto_t *crypto,
    uint8_t *plain, size_t plain_len,
    ngx_stream_mtrojan_key_tcp_bootstrap_t *bootstrap, size_t *consumed);

size_t ngx_stream_mtrojan_key_udp_init_size(uint8_t type, size_t addr_len,
    size_t payload_len);
int ngx_stream_mtrojan_encode_key_udp_init(uint8_t *dst, size_t dst_len,
    const ngx_stream_mtrojan_key_crypto_t *crypto,
    const uint8_t nonce[NGX_STREAM_MTROJAN_KEY_NONCE_LEN], uint32_t epoch,
    ngx_stream_mtrojan_flow_protection_e flow_protection,
    const uint8_t flow_id[NGX_STREAM_MTROJAN_FLOW_ID_LEN], uint8_t type,
    const uint8_t *addr, size_t addr_len, uint16_t port,
    const uint8_t *payload, size_t payload_len, size_t *written);
int ngx_stream_mtrojan_decode_key_udp_init(const uint8_t *src,
    size_t src_len, const ngx_stream_mtrojan_key_crypto_t *crypto,
    uint8_t *plain, size_t plain_len, ngx_stream_mtrojan_key_udp_init_t *frame,
    size_t *consumed);

int ngx_stream_mtrojan_parse_addr(const uint8_t *buf, size_t len,
    ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_mtrojan_normalize_ip_literal(ngx_stream_mtrojan_addr_t *addr);
int ngx_stream_mtrojan_addr_to_text(const ngx_stream_mtrojan_addr_t *addr,
    char *out, size_t out_len);
int ngx_stream_mtrojan_use_nginx_resolver(uint8_t addr_type,
    int resolver_configured);

#endif
