# TLS Certificates

Production nginx expects certificate files here by default:

```text
nginx/certs/fullchain.pem
nginx/certs/privkey.pem
```

These files are ignored by git.

If your certificates live somewhere else, mount or copy them here, or override:

```env
LOKI_NGINX_CERTS_HOST_DIR=/etc/letsencrypt
LOKI_NGINX_CERTIFICATE=/etc/nginx/certs/live/loki-p-watcher.shmoza.net/fullchain.pem
LOKI_NGINX_CERTIFICATE_KEY=/etc/nginx/certs/live/loki-p-watcher.shmoza.net/privkey.pem
```

Do not commit private keys.
