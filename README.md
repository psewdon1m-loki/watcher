# Loki Watcher

Local control-plane backend for Loki Proxy.

## Services

- `api`: receives client enrollment, signed telemetry batches, command polling, update state reports and update manifests.
- `web`: static dashboard container.
- `nginx`: production HTTPS entrypoint on ports `80` and `443`.
- `worker`: retention cleanup for old events and delivered commands.
- `backup`: scheduled SQLite backups into the `watcher-backups` Docker volume.

## Run

```powershell
Copy-Item .env.example .env
docker compose up --build
```

For production on `loki-p-watcher.shmoza.net`, put TLS files here before
starting compose:

```text
nginx/certs/fullchain.pem
nginx/certs/privkey.pem
```

Then set production credentials and host values in `.env`:

```env
LOKI_WATCHER_DASHBOARD_USERNAME=<admin-user>
LOKI_WATCHER_DASHBOARD_PASSWORD=<strong-password>
LOKI_WATCHER_PUBLIC_URL=https://loki-p-watcher.shmoza.net
LOKI_WATCHER_PUBLIC_SNI=loki-p-watcher.shmoza.net
LOKI_NGINX_HTTP_PORT=80
LOKI_NGINX_HTTPS_PORT=443
LOKI_NGINX_CERTS_HOST_DIR=./nginx/certs
LOKI_NGINX_CERTIFICATE=/etc/nginx/certs/fullchain.pem
LOKI_NGINX_CERTIFICATE_KEY=/etc/nginx/certs/privkey.pem
```

If you use the standard Certbot directory directly, set:

```env
LOKI_NGINX_CERTS_HOST_DIR=/etc/letsencrypt
LOKI_NGINX_CERTIFICATE=/etc/nginx/certs/live/loki-p-watcher.shmoza.net/fullchain.pem
LOKI_NGINX_CERTIFICATE_KEY=/etc/nginx/certs/live/loki-p-watcher.shmoza.net/privkey.pem
```

In that mode nginx reads the certificate from `/etc/letsencrypt/...` through
the Docker bind mount. Restart nginx after renewal:

```bash
docker compose restart nginx
```

Start in production:

```bash
docker compose up -d --build
```

Public ports:

```text
80/tcp   HTTP redirect and ACME webroot challenge
443/tcp  HTTPS API, dashboard, manifest and assets
```

The API and web containers are also bound to localhost for diagnostics:

```text
127.0.0.1:18080 -> api
127.0.0.1:18081 -> web
```

Do not expose `18080` or `18081` publicly.

Client development defaults to:

```text
LOKI_TELEMETRY_ENDPOINT=http://127.0.0.1:18080
LOKI_TELEMETRY_UPLOAD_INTERVAL_MINUTES=60
LOKI_TELEMETRY_COMMAND_POLL_SECONDS=300
LOKI_UPDATE_MANIFEST_URL=http://127.0.0.1:18080/manifest.json
```

For production, put the real HTTPS host in `LOKI_TELEMETRY_ENDPOINT` and `LOKI_UPDATE_MANIFEST_URL` so the hostname, certificate and TLS SNI match. `LOKI_TELEMETRY_SNI` is only a routing host override for local/dev reverse proxy setups.

## Updates

Watcher is the source of truth for client update metadata:

- `GET /manifest.json`: client update manifest.
- `GET /assets/<file>`: installer/rule-set files extracted from a bundled GitHub Release zip when needed.
- `POST /api/v1/update-state`: client update state report.
- `POST /api/v1/request-data`: queue `check_updates` commands for online clients.

GitHub Releases stay as artifact storage. The preferred release asset is one bundle zip named like `LokiClientRelease-<version>-win-x64.zip` containing the installer, `manifest.json`, and rule-set zip files. Separate release assets still work as a fallback.

Watcher rewrites installer and rule-set URLs in `/manifest.json` to its own
`/assets/<file>` endpoints. `/assets/<file>` serves the file from the release
bundle zip when present, or downloads the matching separate GitHub Release asset
when the bundle is unavailable. This keeps client update traffic pointed at the
Watcher host instead of GitHub.

## Backups

The dashboard can create and restore a zip backup through the Dashboard section. The backup contains the SQLite watcher database, including client identities, telemetry events, commands, update state, retained log payloads and server-side settings stored in the database.

The scheduled backup service writes one zip dump per interval to the separate `watcher-backups` volume. Default interval is 24 hours and default retention is 30 days. Do not run `docker compose down -v` in production unless you intentionally want to delete both `watcher-data` and `watcher-backups`.

## Security Notes

- Operational telemetry and update state are mandatory in the client. The app setting controls optional log-line upload only.
- The client does not send original IP. The API derives it from the request source.
- After enrollment, telemetry batches and command polling are signed with HMAC SHA-256.
- Deleting a client from the dashboard removes its server-side row, events and commands. A still-installed client can enroll again on the next telemetry/launch cycle.
- Dashboard auth is controlled by `LOKI_WATCHER_DASHBOARD_USERNAME` and `LOKI_WATCHER_DASHBOARD_PASSWORD`. Legacy bearer-token auth via `LOKI_WATCHER_DASHBOARD_TOKEN` still works when username/password are not set.
- Text log payloads are cleared from old events after `LOKI_WATCHER_LOG_RETENTION_DAYS`, default 7 days. Core telemetry events remain stored until an operator deletes clients or restores/replaces the database.
