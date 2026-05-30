# ngx_stream_trojan_module

A Trojan protocol server module for Nginx stream.

`ngx_stream_trojan_module` implements the Trojan protocol directly inside
Nginx's stream subsystem, enabling Nginx to act as a Trojan server while
retaining the performance and deployment model of native stream modules.

The module supports Trojan over TLS, TCP relay, UDP relay, and configurable
fallback forwarding for non-Trojan traffic.

## Features

- Trojan over TLS in the Nginx stream subsystem.
- Native Nginx stream integration.
- One or more static authentication passwords.
- TCP and UDP traffic relay.
- Fallback forwarding for non-Trojan traffic.
- Configurable timeouts and buffer sizes.

## Build

Build against an Nginx source tree with stream and stream SSL enabled:

```sh
./configure \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=/path/to/ngx_stream_trojan_module
make
```

For dynamic module builds, use `--add-dynamic-module` instead of
`--add-module` if your Nginx version supports it.

## Example

```nginx
stream {
    server {
        listen 443 ssl;
        server_name example.com;

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

The stream server must terminate TLS. `ssl_preread` alone is not enough because
the Trojan password header is inside the TLS application data.
