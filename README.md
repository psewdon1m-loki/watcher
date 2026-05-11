# Loki Watcher

Local telemetry backend for Loki Proxy.

## Services

- `api`: receives client enrollment, signed telemetry batches and command polling.
- `web`: static dashboard at `http://127.0.0.1:18081`.
- `worker`: retention cleanup for old events and delivered commands.

## Run

```powershell
docker compose up --build
```

Client development defaults to:

```text
LOKI_TELEMETRY_ENDPOINT=http://127.0.0.1:18080
LOKI_TELEMETRY_UPLOAD_INTERVAL_MINUTES=60
LOKI_TELEMETRY_COMMAND_POLL_SECONDS=300
```

For production, put the real HTTPS host in `LOKI_TELEMETRY_ENDPOINT` so the hostname, certificate and TLS SNI match. `LOKI_TELEMETRY_SNI` is only a routing host override for local/dev reverse proxy setups.

## Backups

The dashboard can download and restore a zip backup through the Dashboard section. The backup contains the SQLite watcher database, including client identities, enrollment links, telemetry events, commands and retained log payloads.

## Security Notes

- Operational telemetry is mandatory in the client. The app setting controls optional log-line upload only.
- The client does not send original IP. The API derives it from the request source.
- After enrollment, telemetry batches and command polling are signed with HMAC SHA-256.
- Deleting a client from the dashboard removes its server-side row, events and commands. A still-installed client can enroll again on the next telemetry/launch cycle.
- Dashboard auth is controlled by `LOKI_WATCHER_DASHBOARD_TOKEN`. Set it before exposing the service outside localhost.
- Text log payloads are cleared from old events after `LOKI_WATCHER_LOG_RETENTION_DAYS`, default 30 days. Core telemetry events remain stored until an operator deletes clients or restores/replaces the database.
