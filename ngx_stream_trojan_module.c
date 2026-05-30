#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <netdb.h>

#include "ngx_stream_trojan_protocol.h"


#define NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE 32768


typedef struct {
    u_char data[NGX_STREAM_TROJAN_KEY_LEN];
} ngx_stream_trojan_key_t;


typedef struct {
    ngx_flag_t   enable;
    ngx_array_t *keys;
    ngx_addr_t  *fallback;
    ngx_msec_t   connect_timeout;
    ngx_msec_t   timeout;
    ngx_msec_t   udp_timeout;
    size_t       buffer_size;
} ngx_stream_trojan_srv_conf_t;


typedef enum {
    ngx_stream_trojan_state_prefix = 0,
    ngx_stream_trojan_state_request,
    ngx_stream_trojan_state_connecting,
    ngx_stream_trojan_state_proxy,
    ngx_stream_trojan_state_udp
} ngx_stream_trojan_state_e;


typedef enum {
    ngx_stream_trojan_peer_none = 0,
    ngx_stream_trojan_peer_fallback,
    ngx_stream_trojan_peer_tcp
} ngx_stream_trojan_peer_e;


typedef struct {
    ngx_stream_session_t       *session;
    ngx_stream_trojan_srv_conf_t *conf;

    ngx_stream_trojan_state_e   state;
    ngx_stream_trojan_peer_e    peer_kind;

    u_char                      prefix[NGX_STREAM_TROJAN_PREFIX_LEN];
    size_t                      prefix_len;

    u_char                      request[1 + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 2];
    size_t                      request_len;
    u_char                      command;
    ngx_stream_trojan_addr_t    target;

    ngx_peer_connection_t       peer;
    ngx_str_t                   peer_name;
    ngx_connection_t           *upstream;

    ngx_buf_t                  *client_buffer;
    ngx_buf_t                  *upstream_buffer;
    ngx_buf_t                  *pending_to_upstream;

    ngx_connection_t           *udp4;
#if (NGX_HAVE_INET6)
    ngx_connection_t           *udp6;
#endif
    u_char                     *udp_in;
    size_t                      udp_in_len;
    u_char                     *udp_out;
    ngx_buf_t                  *udp_pending_to_client;
} ngx_stream_trojan_ctx_t;


static void ngx_stream_trojan_handler(ngx_stream_session_t *s);
static void ngx_stream_trojan_read_client(ngx_event_t *ev);
static void ngx_stream_trojan_peer_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev);
static void ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len);
static void ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_addr_t *addr);
static ngx_int_t ngx_stream_trojan_test_connect(ngx_connection_t *c);
static void ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof);
static ngx_int_t ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_resolve_addr(ngx_pool_t *pool,
    ngx_log_t *log, ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa,
    socklen_t socklen, ngx_stream_trojan_addr_t *addr);
static ngx_connection_t *ngx_stream_trojan_create_udp_connection(
    ngx_stream_trojan_ctx_t *ctx, int family);
static ngx_int_t ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx,
    ngx_uint_t rc);

static void *ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t ngx_stream_trojan_commands[] = {

    { ngx_string("trojan"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, enable),
      NULL },

    { ngx_string("trojan_password"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_trojan_password,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_fallback"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_fallback,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("trojan_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, timeout),
      NULL },

    { ngx_string("trojan_udp_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, udp_timeout),
      NULL },

    { ngx_string("trojan_buffer_size"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, buffer_size),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t ngx_stream_trojan_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_stream_trojan_create_srv_conf,     /* create server configuration */
    ngx_stream_trojan_merge_srv_conf       /* merge server configuration */
};


ngx_module_t ngx_stream_trojan_module = {
    NGX_MODULE_V1,
    &ngx_stream_trojan_module_ctx,
    ngx_stream_trojan_commands,
    NGX_STREAM_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_trojan_handler(ngx_stream_session_t *s)
{
    ngx_connection_t              *c;
    ngx_stream_trojan_ctx_t       *ctx;
    ngx_stream_trojan_srv_conf_t  *tscf;

    c = s->connection;
    tscf = ngx_stream_get_module_srv_conf(s, ngx_stream_trojan_module);

    if (!tscf->enable || tscf->keys == NULL || tscf->keys->nelts == 0) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_trojan_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->conf = tscf;
    ctx->state = ngx_stream_trojan_state_prefix;

    ngx_stream_set_ctx(s, ctx, ngx_stream_trojan_module);

    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;

    ngx_stream_trojan_process_prefix(ctx);
}


static void
ngx_stream_trojan_read_client(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "trojan client timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    switch (ctx->state) {
    case ngx_stream_trojan_state_prefix:
        ngx_stream_trojan_process_prefix(ctx);
        break;

    case ngx_stream_trojan_state_request:
        ngx_stream_trojan_process_request(ctx);
        break;

    case ngx_stream_trojan_state_proxy:
        ngx_stream_trojan_process_proxy(ctx);
        break;

    case ngx_stream_trojan_state_udp:
        ngx_stream_trojan_process_udp_client(ctx);
        break;

    default:
        break;
    }
}


static ngx_int_t
ngx_stream_trojan_key_valid(ngx_stream_trojan_srv_conf_t *tscf, u_char *key)
{
    ngx_uint_t                i;
    ngx_stream_trojan_key_t  *keys;

    keys = tscf->keys->elts;

    for (i = 0; i < tscf->keys->nelts; i++) {
        if (ngx_stream_trojan_key_equal(key, keys[i].data)) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             i;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        if (ctx->prefix_len == NGX_STREAM_TROJAN_PREFIX_LEN) {
            break;
        }

        n = c->recv(c, ctx->prefix + ctx->prefix_len,
                    NGX_STREAM_TROJAN_PREFIX_LEN - ctx->prefix_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        for (i = ctx->prefix_len; i < ctx->prefix_len + (size_t) n; i++) {
            if (ctx->prefix[i] == LF && i < NGX_STREAM_TROJAN_KEY_LEN + 1) {
                ctx->prefix_len += (size_t) n;
                ngx_stream_trojan_start_fallback(ctx, ctx->prefix,
                                                 ctx->prefix_len);
                return;
            }
        }

        ctx->prefix_len += (size_t) n;
    }

    if (ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN] != CR
        || ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN + 1] != LF
        || ngx_stream_trojan_key_valid(ctx->conf, ctx->prefix) != NGX_OK)
    {
        ngx_stream_trojan_start_fallback(ctx, ctx->prefix, ctx->prefix_len);
        return;
    }

    ctx->state = ngx_stream_trojan_state_request;
    ngx_stream_trojan_process_request(ctx);
}


static ngx_int_t
ngx_stream_trojan_request_needed(u_char *buf, size_t len, size_t *needed)
{
    size_t addr_len;

    if (len < 2) {
        *needed = 2;
        return NGX_AGAIN;
    }

    if (buf[0] != NGX_STREAM_TROJAN_CMD_CONNECT
        && buf[0] != NGX_STREAM_TROJAN_CMD_ASSOCIATE)
    {
        return NGX_ERROR;
    }

    switch (buf[1]) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        addr_len = 1 + 4 + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 3) {
            *needed = 3;
            return NGX_AGAIN;
        }
        addr_len = 1 + 1 + buf[2] + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        addr_len = 1 + 16 + 2;
        break;

    default:
        return NGX_ERROR;
    }

    *needed = 1 + addr_len + 2;

    if (len < *needed) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             needed;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        rc = ngx_stream_trojan_request_needed(ctx->request, ctx->request_len,
                                              &needed);

        if (rc == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        if (rc == NGX_OK) {
            break;
        }

        if (needed > sizeof(ctx->request)) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = c->recv(c, ctx->request + ctx->request_len,
                    needed - ctx->request_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->request_len += (size_t) n;
    }

    if (ctx->request[needed - 2] != CR || ctx->request[needed - 1] != LF) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    if (ngx_stream_trojan_parse_addr(ctx->request + 1, needed - 3,
                                     &ctx->target)
        != 0)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    ctx->command = ctx->request[0];

    if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
        ngx_stream_trojan_start_tcp(ctx);
        return;
    }

    ngx_stream_trojan_start_udp(ctx);
}


static ngx_buf_t *
ngx_stream_trojan_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t  *b;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NULL;
    }

    b->tag = (ngx_buf_tag_t) &ngx_stream_trojan_module;
    return b;
}


static ngx_int_t
ngx_stream_trojan_set_pending(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    ctx->pending_to_upstream = ngx_stream_trojan_create_temp_buf(
        ctx->session->connection->pool, len ? len : 1);

    if (ctx->pending_to_upstream == NULL) {
        return NGX_ERROR;
    }

    if (len) {
        ngx_memcpy(ctx->pending_to_upstream->last, data, len);
        ctx->pending_to_upstream->last += len;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    if (ctx->conf->fallback == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
        return;
    }

    if (ngx_stream_trojan_set_pending(ctx, data, len) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_fallback;
    ngx_stream_trojan_connect(ctx, ctx->conf->fallback);
}


static void
ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_addr_t  addr;

    if (ngx_stream_trojan_resolve_addr(ctx->session->connection->pool,
                                       ctx->session->connection->log,
                                       &ctx->target, &addr)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_set_pending(ctx, NULL, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_tcp;
    ngx_stream_trojan_connect(ctx, &addr);
}


static void
ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_pool_t  *pool;

    pool = ctx->session->connection->pool;

    ctx->udp_in = ngx_pnalloc(pool, NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD
                              + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4);
    ctx->udp_out = ngx_pnalloc(pool, NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD
                               + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4);

    if (ctx->udp_in == NULL || ctx->udp_out == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_stream_trojan_state_udp;
    ctx->session->connection->write->handler =
        ngx_stream_trojan_udp_client_write_handler;
    ngx_add_timer(ctx->session->connection->read, ctx->conf->udp_timeout);
    ngx_stream_trojan_process_udp_client(ctx);
}


static void
ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx, ngx_addr_t *addr)
{
    ngx_int_t          rc;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    ctx->state = ngx_stream_trojan_state_connecting;

    ngx_memzero(&ctx->peer, sizeof(ngx_peer_connection_t));
    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer.name = &addr->name;
    ctx->peer.type = SOCK_STREAM;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.tries = 1;
    ctx->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    pc = ctx->peer.connection;
    ctx->upstream = pc;

    pc->data = ctx;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc == NGX_AGAIN) {
        pc->read->handler = ngx_stream_trojan_peer_handler;
        pc->write->handler = ngx_stream_trojan_peer_handler;
        ngx_add_timer(pc->write, ctx->conf->connect_timeout);
        return;
    }

    ngx_stream_trojan_init_proxy(ctx);
}


static void
ngx_stream_trojan_peer_handler(ngx_event_t *ev)
{
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (ev->timedout) {
            ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream timed out");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    } else if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream idle timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ngx_stream_trojan_init_proxy(ctx);
        return;
    }

    ngx_stream_trojan_process_proxy(ctx);
}


static ngx_int_t
ngx_stream_trojan_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                        "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    ctx->client_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                           ctx->conf->buffer_size);
    ctx->upstream_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                             ctx->conf->buffer_size);

    if (ctx->client_buffer == NULL || ctx->upstream_buffer == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;
    pc->read->handler = ngx_stream_trojan_peer_handler;
    pc->write->handler = ngx_stream_trojan_peer_handler;

    ctx->state = ngx_stream_trojan_state_proxy;
    ngx_stream_trojan_set_proxy_timeout(ctx);
    ngx_stream_trojan_process_proxy(ctx);
}


static void
ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, ctx->conf->timeout);
    }

    if (pc && !pc->read->timer_set) {
        ngx_add_timer(pc->read, ctx->conf->timeout);
    }
}


static void
ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_uint_t         client_eof, upstream_eof;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;
    client_eof = c->read->eof || c->read->error;
    upstream_eof = pc->read->eof || pc->read->error;

    if (ctx->pending_to_upstream
        && ctx->pending_to_upstream->pos < ctx->pending_to_upstream->last)
    {
        if (ngx_stream_trojan_process_direction(ctx, NULL, pc,
                                                ctx->pending_to_upstream,
                                                &client_eof)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_stream_trojan_process_direction(ctx, c, pc, ctx->client_buffer,
                                            &client_eof)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_process_direction(ctx, pc, c, ctx->upstream_buffer,
                                            &upstream_eof)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (client_eof && upstream_eof
        && ctx->client_buffer->pos == ctx->client_buffer->last
        && ctx->upstream_buffer->pos == ctx->upstream_buffer->last)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    ngx_handle_read_event(c->read, 0);
    ngx_handle_write_event(c->write, 0);
    ngx_handle_read_event(pc->read, 0);
    ngx_handle_write_event(pc->write, 0);
}


static ngx_int_t
ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof)
{
    ssize_t  n;

    if (buf == NULL || dst == NULL) {
        return NGX_OK;
    }

    while (buf->pos < buf->last) {
        n = dst->send(dst, buf->pos, buf->last - buf->pos);

        if (n == NGX_AGAIN) {
            return NGX_OK;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        buf->pos += n;
    }

    buf->pos = buf->start;
    buf->last = buf->start;

    if (src == NULL || *src_eof || !src->read->ready) {
        return NGX_OK;
    }

    n = src->recv(src, buf->last, buf->end - buf->last);

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    if (n == 0) {
        *src_eof = 1;
        src->read->eof = 1;
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        *src_eof = 1;
        src->read->error = 1;
        return NGX_OK;
    }

    buf->last += n;

    while (buf->pos < buf->last) {
        n = dst->send(dst, buf->pos, buf->last - buf->pos);

        if (n == NGX_AGAIN) {
            return NGX_OK;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        buf->pos += n;
    }

    buf->pos = buf->start;
    buf->last = buf->start;

    (void) ctx;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    u_char               *p;

    ngx_memzero(out, sizeof(ngx_addr_t));

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        ngx_memcpy(&sin->sin_addr, addr->host, 4);

        out->sockaddr = (struct sockaddr *) sin;
        out->socklen = sizeof(struct sockaddr_in);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        sin6 = ngx_pcalloc(pool, sizeof(struct sockaddr_in6));
        if (sin6 == NULL) {
            return NGX_ERROR;
        }

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        ngx_memcpy(&sin6->sin6_addr, addr->host, 16);

        out->sockaddr = (struct sockaddr *) sin6;
        out->socklen = sizeof(struct sockaddr_in6);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        p = ngx_pnalloc(pool, addr->host_len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(p, addr->host, addr->host_len);
        p[addr->host_len] = '\0';
        (void) p;
        return NGX_DECLINED;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_stream_trojan_resolve_addr(ngx_pool_t *pool, ngx_log_t *log,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    char                  host[256];
    char                  service[6];
    int                   rc;
    struct addrinfo       hints;
    struct addrinfo      *res, *rp;
    struct sockaddr      *sa;
    socklen_t             socklen;

    if (addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        return ngx_stream_trojan_addr_to_ngx_addr(pool, addr, out);
    }

    if (addr->host_len == 0 || addr->host_len >= sizeof(host)) {
        return NGX_ERROR;
    }

    ngx_memcpy(host, addr->host, addr->host_len);
    host[addr->host_len] = '\0';
    ngx_snprintf((u_char *) service, sizeof(service), "%ui%Z",
                 (ngx_uint_t) addr->port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, service, &hints, &res);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "getaddrinfo(\"%s\") failed: %s", host,
                      gai_strerror(rc));
        return NGX_ERROR;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            socklen = rp->ai_addrlen;
            sa = ngx_pnalloc(pool, socklen);
            if (sa == NULL) {
                freeaddrinfo(res);
                return NGX_ERROR;
            }

            ngx_memcpy(sa, rp->ai_addr, socklen);
            out->sockaddr = sa;
            out->socklen = socklen;
            out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
            if (out->name.data == NULL) {
                freeaddrinfo(res);
                return NGX_ERROR;
            }
            out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                          out->name.data,
                                          NGX_SOCKADDR_STRLEN, 1);
            freeaddrinfo(res);
            return NGX_OK;
        }
    }

    freeaddrinfo(res);
    return NGX_ERROR;
}


static ngx_connection_t *
ngx_stream_trojan_create_udp_connection(ngx_stream_trojan_ctx_t *ctx, int family)
{
    ngx_socket_t       fd;
    ngx_connection_t  *uc;

    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_socket_n " failed");
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_nonblocking_n " failed");
        ngx_close_socket(fd);
        return NULL;
    }

    uc = ngx_get_connection(fd, ctx->session->connection->log);
    if (uc == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uc->data = ctx;
    uc->log = ctx->session->connection->log;
    uc->read->handler = ngx_stream_trojan_udp_read_handler;
    uc->write->handler = ngx_stream_trojan_udp_read_handler;

    if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(uc);
        return NULL;
    }

    return uc;
}


static void
ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t                         n;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_stream_trojan_udp_frame_t   frame;

    c = ctx->session->connection;

    for ( ;; ) {
        rc = ngx_stream_trojan_parse_udp_frame(ctx->udp_in, ctx->udp_in_len,
                                               &frame);

        if (rc == 0) {
            if (ngx_stream_trojan_send_udp_frame(ctx, &frame) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (frame.wire_len < ctx->udp_in_len) {
                ngx_memmove(ctx->udp_in, ctx->udp_in + frame.wire_len,
                            ctx->udp_in_len - frame.wire_len);
            }
            ctx->udp_in_len -= frame.wire_len;
            continue;
        }

        if (ctx->udp_in_len == NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD
                           + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = c->recv(c, ctx->udp_in + ctx->udp_in_len,
                    NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD
                    + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4 - ctx->udp_in_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->udp_in_len += (size_t) n;
    }
}


static ngx_int_t
ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    ssize_t              n;
    ngx_connection_t    *uc;
    struct sockaddr_in   sin;
    char                 host[256];
    char                 service[6];
    int                  rc;
    struct addrinfo      hints;
    struct addrinfo     *res, *rp;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  sin6;
#endif
    struct sockaddr     *sa;
    socklen_t            socklen;
    ngx_uint_t           free_res;

    res = NULL;
    free_res = 0;

    switch (frame->addr.type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        if (ctx->udp4 == NULL) {
            ctx->udp4 = ngx_stream_trojan_create_udp_connection(ctx, AF_INET);
            if (ctx->udp4 == NULL) {
                return NGX_ERROR;
            }
        }

        ngx_memzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(frame->addr.port);
        ngx_memcpy(&sin.sin_addr, frame->addr.host, 4);
        uc = ctx->udp4;
        sa = (struct sockaddr *) &sin;
        socklen = sizeof(sin);
        break;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        if (ctx->udp6 == NULL) {
            ctx->udp6 = ngx_stream_trojan_create_udp_connection(ctx, AF_INET6);
            if (ctx->udp6 == NULL) {
                return NGX_ERROR;
            }
        }

        ngx_memzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(frame->addr.port);
        ngx_memcpy(&sin6.sin6_addr, frame->addr.host, 16);
        uc = ctx->udp6;
        sa = (struct sockaddr *) &sin6;
        socklen = sizeof(sin6);
        break;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (frame->addr.host_len == 0 || frame->addr.host_len >= sizeof(host)) {
            return NGX_ERROR;
        }

        ngx_memcpy(host, frame->addr.host, frame->addr.host_len);
        host[frame->addr.host_len] = '\0';
        ngx_snprintf((u_char *) service, sizeof(service), "%ui%Z",
                     (ngx_uint_t) frame->addr.port);

        ngx_memzero(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        rc = getaddrinfo(host, service, &hints, &res);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log, 0,
                          "getaddrinfo(\"%s\") failed: %s", host,
                          gai_strerror(rc));
            return NGX_ERROR;
        }

        for (rp = res; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) {
                if (ctx->udp4 == NULL) {
                    ctx->udp4 = ngx_stream_trojan_create_udp_connection(ctx,
                                                                        AF_INET);
                    if (ctx->udp4 == NULL) {
                        freeaddrinfo(res);
                        return NGX_ERROR;
                    }
                }

                uc = ctx->udp4;
                sa = rp->ai_addr;
                socklen = rp->ai_addrlen;
                free_res = 1;
                goto send;
            }

#if (NGX_HAVE_INET6)
            if (rp->ai_family == AF_INET6) {
                if (ctx->udp6 == NULL) {
                    ctx->udp6 = ngx_stream_trojan_create_udp_connection(ctx,
                                                                        AF_INET6);
                    if (ctx->udp6 == NULL) {
                        freeaddrinfo(res);
                        return NGX_ERROR;
                    }
                }

                uc = ctx->udp6;
                sa = rp->ai_addr;
                socklen = rp->ai_addrlen;
                free_res = 1;
                goto send;
            }
#endif
        }

        freeaddrinfo(res);
        return NGX_ERROR;

    default:
        return NGX_ERROR;
    }

send:
    n = sendto(uc->fd, frame->payload, frame->payload_len, 0, sa, socklen);
    if (free_res) {
        freeaddrinfo(res);
    }

    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      err, "sendto() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->udp_pending_to_client;

    if (b == NULL) {
        return NGX_OK;
    }

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    b->pos = b->start;
    b->last = b->start;
    ctx->udp_pending_to_client = NULL;

    return NGX_OK;
}


static void
ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
    }
}


static ngx_int_t
ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa, socklen_t socklen,
    ngx_stream_trojan_addr_t *addr)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_memzero(addr, sizeof(*addr));

    if (sa->sa_family == AF_INET && socklen >= (socklen_t) sizeof(struct sockaddr_in)) {
        sin = (struct sockaddr_in *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        ngx_memcpy(addr->host, &sin->sin_addr, 4);
        addr->port = ntohs(sin->sin_port);
        addr->wire_len = 1 + 4 + 2;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6 && socklen >= (socklen_t) sizeof(struct sockaddr_in6)) {
        sin6 = (struct sockaddr_in6 *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        ngx_memcpy(addr->host, &sin6->sin6_addr, 16);
        addr->port = ntohs(sin6->sin6_port);
        addr->wire_len = 1 + 16 + 2;
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static void
ngx_stream_trojan_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                    n;
    size_t                     written;
    ngx_connection_t          *uc, *c;
    ngx_stream_trojan_ctx_t   *ctx;
    ngx_stream_trojan_addr_t   addr;
    struct sockaddr_storage    ss;
    socklen_t                  socklen;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    c = ctx->session->connection;

    for ( ;; ) {
        if (ngx_stream_trojan_flush_udp_client(ctx) != NGX_OK) {
            return;
        }

        socklen = sizeof(ss);
        n = recvfrom(uc->fd,
                     ctx->udp_out + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4,
                     NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD, 0,
                     (struct sockaddr *) &ss, &socklen);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_ERR, c->log, err, "recvfrom() failed");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        if (ngx_stream_trojan_sockaddr_to_addr((struct sockaddr *) &ss,
                                               socklen, &addr)
            != NGX_OK)
        {
            continue;
        }

        if (ngx_stream_trojan_pack_udp_frame(&addr,
                                             ctx->udp_out
                                             + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4,
                                             (uint16_t) n,
                                             ctx->udp_out,
                                             NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD
                                             + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4,
                                             &written)
            != 0)
        {
            continue;
        }

        ctx->udp_pending_to_client = ngx_stream_trojan_create_temp_buf(
            c->pool, written);
        if (ctx->udp_pending_to_client == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memcpy(ctx->udp_pending_to_client->last, ctx->udp_out, written);
        ctx->udp_pending_to_client->last += written;

        if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx, ngx_uint_t rc)
{
    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    if (ctx->udp4) {
        ngx_close_connection(ctx->udp4);
        ctx->udp4 = NULL;
    }

#if (NGX_HAVE_INET6)
    if (ctx->udp6) {
        ngx_close_connection(ctx->udp6);
        ctx->udp6 = NULL;
    }
#endif

    ngx_stream_finalize_session(ctx->session, rc);
}


static void *
ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_trojan_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->udp_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_trojan_srv_conf_t *prev = parent;
    ngx_stream_trojan_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 600000);
    ngx_conf_merge_msec_value(conf->udp_timeout, prev->udp_timeout, 600000);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE);

    if (conf->keys == NULL) {
        conf->keys = prev->keys;
    }

    if (conf->fallback == NULL) {
        conf->fallback = prev->fallback;
    }

    if (conf->enable && (conf->keys == NULL || conf->keys->nelts == 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan is on but no trojan_password is configured");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_uint_t                i;
    ngx_str_t                *value;
    ngx_stream_trojan_key_t  *key;

    if (tscf->keys == NULL) {
        tscf->keys = ngx_array_create(cf->pool, 2, sizeof(ngx_stream_trojan_key_t));
        if (tscf->keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        key = ngx_array_push(tscf->keys);
        if (key == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_stream_trojan_make_key_len(value[i].data, value[i].len,
                                           key->data)
            != 0)
        {
            return NGX_CONF_ERROR;
        }
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_url_t    u;
    ngx_str_t   *value;

    if (tscf->fallback != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 80;
    u.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in trojan_fallback \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }

    if (u.naddrs < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_fallback \"%V\" resolved to no addresses",
                           &u.url);
        return NGX_CONF_ERROR;
    }

    tscf->fallback = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
    if (tscf->fallback == NULL) {
        return NGX_CONF_ERROR;
    }

    *tscf->fallback = u.addrs[0];

    (void) cmd;
    return NGX_CONF_OK;
}
