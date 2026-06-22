# ngx_stream_mtrojan_module

Mtrojan protocol module for Nginx stream.

`ngx_stream_mtrojan_module` implements the Mtrojan protocol inside Nginx's
stream subsystem, with compatibility support for the original Trojan protocol.
It enables Nginx to act as an Mtrojan or Trojan server while retaining the
performance and deployment model of native stream modules.

The module supports Mtrojan, Trojan over TLS, TCP relay, and UDP relay.

## Trojan Features

- Trojan over TLS in the Nginx stream subsystem.
- Native Nginx stream integration.
- One or more static authentication passwords.
- TCP and UDP traffic relay.
- Fallback forwarding for non-Trojan traffic.
- Configurable timeouts and buffer sizes.
- Nginx asynchronous resolver support for domain targets when `resolver` is configured.
- Default HTTP 503 response when `trojan_fallback` is not configured.

## Build

Build against an Nginx source tree with stream enabled. Stream SSL is required
only when using the Trojan over TLS mode.

```sh
./configure \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=/path/to/ngx_stream_mtrojan_module
make
```

For dynamic module builds, use `--add-dynamic-module` instead of
`--add-module` if your Nginx version supports it.

## Example

Enable Trojan over TLS mode:

```nginx
stream {
    server {
        listen 443 ssl;
        server_name example.com;

        resolver 1.1.1.1 8.8.8.8 valid=60s;
        resolver_timeout 5s;

        ssl_certificate     /path/to/fullchain.pem;
        ssl_certificate_key /path/to/private.key;

        trojan on;
        trojan_password pass1234 word5678;
        trojan_fallback 127.0.0.1:8080;
        trojan_connect_timeout 60s;
        trojan_timeout 10m;
        trojan_udp_timeout 10m;
        trojan_buffer_size 32k;
    }
}

http {
    server {
        listen 127.0.0.1:8080;
        root /var/www/html;
    }
}
```

- The stream server must terminate TLS. `ssl_preread` alone is not enough
  because the Trojan password header is inside the TLS application data.

- Without `resolver`, domain targets use system DNS.
