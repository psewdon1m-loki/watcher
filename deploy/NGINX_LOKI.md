# Server nginx: `loki`

Watcher does not run nginx in Docker. Its API and web containers bind only to
`127.0.0.1`, while the server-managed nginx site terminates TLS and exposes the
public routes.

Copy `deploy/nginx-loki.locations.conf` from the same immutable source revision
as the release to `/etc/nginx/snippets/loki-watcher.locations.conf`. Add this
line **inside the HTTPS `server {}` block** in
`/etc/nginx/sites-available/loki`:

```nginx
include /etc/nginx/snippets/loki-watcher.locations.conf;
```

Keep the existing `listen`, `server_name`, certificate, ACME and PasarGuard
directives in `loki`. The Watcher include deliberately claims only
`/api/v1/`; do not replace it with `/api/`, because that would intercept
PasarGuard's `/api/user/...` endpoints.

The default include expects these loopback bindings:

```text
127.0.0.1:18080  Watcher API
127.0.0.1:18081  Watcher web
```

If the two `LOKI_WATCHER_*_PORT` values are changed, update the corresponding
ports in the include before reloading nginx. PasarGuard subscription URLs must
continue to use their configured PasarGuard origin (including `:8000` when
that is how the panel exposes `/sub/...`); public Watcher `/sub/...` routes on
the normal HTTPS origin remain owned by Watcher.

Validate and reload atomically:

```sh
sudo nginx -t && sudo systemctl reload nginx
```

Never expose ports `18080` or `18081` on a public interface.
