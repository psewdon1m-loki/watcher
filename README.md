# Loki Watcher

Local control-plane backend for Loki Proxy.

## Services

- `api`: receives client enrollment, signed telemetry/analytics batches, command polling, update state reports and update manifests.
- `web`: static dashboard container.
- `worker`: retention cleanup for old events, analytics reports and delivered commands.
- `backup`: scheduled encrypted recovery archives into the `watcher-backups` Docker volume.

Production nginx is managed separately on the host and is not part of Docker Compose.

## Operator Interface

The dashboard follows the shared operational UI contract from
`../.docs/UI_UX_SPECIFICATION.md` and provides:

- `Dashboard`: host CPU, RAM, disk, activated clients, issued connections and total client traffic;
- `Connections`: stable client-facing subscriptions, direct VLESS values, integration sources and complete source rescanning;
- `Clients`: expandable enrolled client cards, retained events and operator commands;
- `Analytics`: retained `fail analytics` and `full analytics` JSON reports, filterable by client and type;
- `Register`: searchable mutable key/value records for repositories, domains and related configuration;
- `Settings`: appearance, Sidebar behavior, security snapshot, backup/restore and retained audit events;
- `Documentation`: an operator guide available from the fixed bottom Sidebar group.

Issued connections, Register values and administrative audit events are stored
in the main SQLite database and included in Watcher backups.

## Run

```powershell
Copy-Item .env.example .env
```

Set a non-empty dashboard username and a strong password in `.env`. Compose
fails closed when either value is missing:

```dotenv
LOKI_WATCHER_DASHBOARD_USERNAME=<admin-user>
LOKI_WATCHER_DASHBOARD_PASSWORD=<strong-password>
LOKI_WATCHER_BACKUP_ENCRYPTION_KEY=<base64url-encoded-32-byte-recovery-key>
LOKI_WATCHER_LOCAL_CONTROL_TOKEN=<random-local-updater-token>
LOKI_WATCHER_IP_GEOLOOKUP_ENABLED=0
LOKI_WATCHER_PUBLIC_SNI=cake.shmoza.net
LOKI_WATCHER_PASARGUARD_API_KEY=<panel-api-key>
LOKI_WATCHER_CONNECTION_SCAN_INTERVAL_MINUTES=15
LOKI_WATCHER_LOG_RETENTION_DAYS=30
LOKI_WATCHER_TELEMETRY_RETENTION_DAYS=30
```

Start the services in detached mode:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f --tail=100
```

`docker compose up` without `-d` intentionally stays attached to service logs.
Seeing `api` become healthy and the first backup complete means startup
succeeded; the command is not hung.

The containers listen only on localhost:

```text
127.0.0.1:18080 -> API
127.0.0.1:18081 -> dashboard
```

Configure the separately managed host nginx to route API/update traffic to
`18080` and dashboard traffic to `18081`, for example:

```nginx
location /api/          { proxy_pass http://127.0.0.1:18080; }
location /sub/          { access_log off; proxy_pass http://127.0.0.1:18080; }
location = /health      { proxy_pass http://127.0.0.1:18080; }
location = /manifest.json { proxy_pass http://127.0.0.1:18080; }
location = /manifest.json.sig { proxy_pass http://127.0.0.1:18080; }
location /assets/       { proxy_pass http://127.0.0.1:18080; }
location /              { proxy_pass http://127.0.0.1:18081; }
```

Do not expose `18080` or `18081` publicly.

The `/sub/` path carries an opaque bearer token. Do not record full subscription
paths in reverse-proxy, CDN or analytics logs. Watcher redacts these tokens from
its own HTTP access log.

## PasarGuard orchestration

Watcher treats the connection ID as the permanent external identity. For a
PasarGuard-managed connection, that exact string is sent as PasarGuard
`username`; PasarGuard's numeric database user ID is stored only as a technical
binding. The selected PasarGuard user template must therefore have no username
prefix or suffix.

Configure the integration and client timing in Watcher → Register:

```text
watcher.public_sni                    public hostname; HTTPS URL is derived from it
github.repository                     client releases as owner/repository
watcher.server_repository             server and updater releases as owner/repository
pasarguard.base_url                   panel API origin, for example https://panel.example.com
pasarguard.user_template_id           numeric user-template ID
pasarguard.api_key                    secret panel API key
clients.heartbeat_interval_seconds    normal client contact interval, default 60
```

`LOKI_WATCHER_PASARGUARD_BASE_URL` and
`LOKI_WATCHER_PASARGUARD_USER_TEMPLATE_ID` seed their Register rows on a new
database. `LOKI_WATCHER_PASARGUARD_API_KEY` is retained as an optional initial
seed for `pasarguard.api_key`; runtime requests read the Register value. The
dashboard treats that row as write-only: list and update responses expose only
whether a key is configured. Because Register is complete server state, the key
is included only inside the encrypted database member of application backups.

Create a dedicated PasarGuard API key for the integration. It needs
`templates.read` plus `users.create`, `users.read` and `users.revoke_sub` for
the same ownership scope in which Watcher creates users. Inheriting a broad
owner role works for initial testing, but is not the recommended production
policy.

The operator workflow is:

1. Add a connection. Paste direct VLESS URIs into it when needed; there is no
   separate manual/PasarGuard connection type.
2. Open its card and select **Set new connection → PasarGuard**. Watcher creates or safely
   adopts its own marked user, imports the upstream subscription and caches all
   inner proxy URIs.
3. Give consumers the stable Watcher URL shown in the card. By default it
   returns a Base64 subscription; `?format=raw` returns one URI per line and
   `?format=json` returns the Loki client contract with the permanent ID,
   immutable creation time, editable monthly renewal date, tracking flag and
   inner VLESS configurations.
4. Use **Check all sources** to refresh cached inner URIs or **Reset** to rotate
   PasarGuard proxy credentials. Reset preserves the permanent ID and Watcher
   URL while invalidating old upstream credentials.

Scheduled synchronization uses Settings → Connections and is constrained to a
1–15 minute interval. A failed source refresh
keeps the last known working inner set so the Watcher URL remains usable while
PasarGuard is temporarily unavailable. The signed
`POST /api/v1/client/connections/initialize` endpoint idempotently allocates a
connection to an enrolled Windows client, provisions PasarGuard and returns its
stable `/sub/{token}` machine URL.

The source Compose profile builds local images. It also enforces non-root
containers, read-only root filesystems, dropped capabilities,
`no-new-privileges`, bounded tmpfs and rotated Docker JSON logs. A short-lived
`init-permissions` container has only `CAP_CHOWN`, touches only the two named
volumes and exits before the non-root API starts; this also migrates volumes
created by older root-running releases without deleting their data.

## Production bootstrap

Production releases use immutable OCI image digests and a checksummed bundle.
Run the bootstrap from an immutable source revision, not a moving branch URL:

```bash
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  'https://raw.githubusercontent.com/psewdon1m-loki/watcher/<commit>/deploy/bootstrap.sh' \
  | sudo sh
```

That single command asks for the operator username, a hidden password and the
public SNI before it mutates the host. It installs supported distribution
packages (including Docker Engine and Compose v2 when absent), installs verified
files under `/opt/vpnenus-watcher`, generates recovery/local-control secrets
without printing them, starts the immutable release and waits for loopback
health. Non-interactive automation may pass the three matching
`LOKI_WATCHER_*` variables instead. Verify the result with:

```bash
sudo vpn-enus-watcher status
```

An existing installation is never overwritten by bootstrap. Use `repair` or
the local updater instead.

The application still binds only to loopback. Public nginx/TLS is intentionally
host-managed; the bootstrap does not claim public readiness until that proxy's
certificate and `/health` route have been checked.

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

- `github.repository` in Register selects the client GitHub repository.
- Enrollment and heartbeat responses deliver the derived GitHub manifest URL,
  Watcher fallback URL, channel and Watcher endpoint to the client.
- `GET /manifest.json`: client update manifest.
- `GET /assets/<file>`: installer/rule-set files extracted from a bundled GitHub Release zip when needed.
- `POST /api/v1/update-state`: client update state report.
- `POST /api/v1/request-data`: queue `check_updates` commands for online clients.

GitHub Releases stay as artifact storage. The preferred release asset is one bundle zip named like `LokiClientRelease-<version>-win-x64.zip` containing the installer, `manifest.json`, and rule-set zip files. Separate release assets still work as a fallback.

The client normally reads the release manifest directly from the repository
selected in Register. In unsigned compatibility mode Watcher remains the
fallback and rewrites installer and rule-set URLs in `/manifest.json` to
`/assets/<file>`, while also including a direct GitHub `fallbackUrl` for each
separately published asset.

To enforce detached manifest signatures, set
`updates.manifest_public_key_pem` in Register. Watcher then distributes the key
and the client requires `manifest.json.sig` (base64 RSA/SHA-256) from the
release. In this mode Watcher verifies the upstream signature and serves the
exact, unmodified `manifest.json` and `manifest.json.sig` bytes on its fallback
endpoints. A missing or invalid upstream signature fails closed with 502.

## Observability and log export

Audit rows have unique event/request IDs, UTC time, severity/outcome, typed
actor/target, transport method, bounded redacted context and a structured
error. Retention is the strictest of 10,000 entries, 30 days and 64 MiB. The
Settings stream initially loads 200 rows and uses cursor pagination.

Log export is authenticated, audited, generated incrementally in a private
spool and delivered with `Cache-Control: no-store, private`. Its manifested ZIP
contains the complete retained audit/telemetry stream in `events.jsonl`, plus
`errors.json` and `README.txt`.
Central recursive redaction runs before serialization. Container output rotates
independently: API/web use 3 × 10 MiB, worker/backup 2 × 5 MiB.

## Backups and recovery

Dashboard and scheduled backups share format v2. The database is encrypted with
AES-256-GCM; the manifest is authenticated with HMAC-SHA256 and records every
data member's SHA-256, uncompressed size and table counts. The external
`LOKI_WATCHER_BACKUP_ENCRYPTION_KEY` is not included and must be escrowed
separately.

Restore is complete replacement. It spools the request, checks ZIP member/count/
size/ratio/path limits, authenticates the manifest, verifies every digest,
decrypts into staging, validates schema/integrity/foreign keys/counts and creates
a fresh encrypted pre-restore snapshot before applying. Failed mutation or
health invariants restore that snapshot. New archives use database schema
generation 3. Existing generation-1 and generation-2 archives remain restorable: they are
validated against the legacy complete-state contract and migrated to generation
3 by the normal API startup migration immediately after replacement.

Normal API/worker/backup database access shares an advisory lock stored beside
the SQLite file. Restore takes that lock exclusively from the pre-restore
snapshot through apply, invariant checks and any rollback, preventing another
container from writing across the replacement boundary.

Scheduled archives are limited by the newest 20 files, 30 days and 2 GiB total.
Do not run `docker compose down -v` in production unless intentionally deleting
both `watcher-data` and `watcher-backups`.

Use the root CLI to persist an encrypted copy outside Docker volumes and to
perform a validated replacement restore:

```bash
sudo vpn-enus-watcher backup /srv/offsite/watcher-backups/
sudo vpn-enus-watcher restore /srv/offsite/watcher-backups/vpn-enus-watcher-backup-YYYYMMDD-HHMMSS.zip
```

Backup creation refuses to overwrite a file, writes through a private temporary
file, fsyncs it and reports its SHA-256. The external encryption key from
`/opt/vpnenus-watcher/.env` must be escrowed separately; copying only the ZIP is
not a recoverable disaster-recovery set.

## CI, releases and local updates

Pull requests and main pushes run syntax, API/security/backup tests, Compose
validation and an exact container health smoke. A stable `vX.Y.Z` tag builds
API/web/worker images once, publishes their immutable digests with SBOM and
provenance under candidate tags, smoke-tests those exact digests, promotes the
same image objects to semantic tags and creates a checksummed release bundle
plus narrow manifest. CI actions are pinned to full commits, Python packages
are exact-version and wheel-hash locked, and the shared Python base image is
pinned by OCI index digest.

Production install registers Watcher with the host-wide root updater and starts
`vpnenus-updater.service`. The application joins only the dedicated Unix-socket
group; neither API nor web receives the Docker socket. Repository policy comes
from one live Register key:

```text
watcher.server_repository   owner/repository for Watcher and updater releases
```

The updater validates the Register snapshot and stores a root-owned
checksummed last-known-good policy, so a temporary API failure does not disable
an already registered installation. Release checks still work informationally
when the host daemon is unavailable, but installation stays disabled.

Server updates can be started in Settings → Release or through the local CLI:

```bash
sudo vpn-enus-watcher update-check
sudo vpn-enus-watcher update --version X.Y.Z
sudo vpn-enus-watcher update-job <request-id>
```

The API submits only an exact version and request ID over
`/run/vpnenus-updater/updater.sock`. The daemon reloads its root-owned service
profile and Register/LKG policy, independently resolves the exact non-draft
release, persists and verifies an encrypted backup, validates the release
contract, pulls images by digest before mutation, atomically applies release
locks, polls health and rolls runtime/data back on failure. Jobs are idempotent
by request ID; interrupted jobs become explicit terminal states; terminal jobs,
backups and rollback snapshots retain the newest 20 and 30 days.

Updater self-update is a separate privileged operation in its own transient
systemd unit, so restarting the updater daemon cannot kill the replacement
helper:

```bash
sudo vpn-enus-watcher updater-self-update --release-version X.Y.Z
sudo vpn-enus-watcher updater-self-update-job <request-id>
```

It takes the same repository from `watcher.server_repository`, retains the previous
updater files, installs atomically, restarts the service, polls Unix-socket
health and restores/restarts the previous version on failure. Updater state is
stored under `/var/lib/vpnenus-updater`; root-owned service profiles live under
`/etc/vpnenus-updater/profiles.d`.

Checksums are corruption and release-binding controls, not publisher
signatures. See `docs/UNIFICATION_COMPLIANCE.md` for implemented guarantees and
remaining boundaries.

## Security Notes

- Operational telemetry and update state are mandatory in the client. The app setting controls optional log-line upload only.
- The client does not send original IP. The API derives it from the request source and, when `LOKI_WATCHER_IP_GEOLOOKUP_ENABLED=1`, resolves a best-effort region/provider for public IPs.
- Enrollment, telemetry batches, update state and command polling are signed with HMAC SHA-256. Re-enrollment cannot replace an existing client secret.
- Deleting a client from the dashboard removes its server-side row, events, analytics and commands. A still-installed client can enroll again on the next telemetry/launch cycle.
- Dashboard auth is controlled by `LOKI_WATCHER_DASHBOARD_USERNAME` and `LOKI_WATCHER_DASHBOARD_PASSWORD`. Legacy bearer-token auth via `LOKI_WATCHER_DASHBOARD_TOKEN` still works when username/password are not set.
- Dashboard authentication is rate-limited per reverse-proxy-derived source: ten failed requests in 60 seconds cause a five-minute block. The supplied nginx template overwrites, rather than trusts, incoming forwarding headers.
- Ordinary subscription imports require HTTPS, validate every redirect and reject DNS results for loopback, private, link-local, reserved and metadata destinations. The only HTTP/private-origin exception is the exact operator-configured PasarGuard origin.
- Public-IP geolocation is disabled by default. Enabling it is an explicit privacy decision because the configured external lookup receives the observed public IP.
- The nginx template rejects unexpected Host/SNI values, disables subscription access logging and adds HSTS, CSP and other browser hardening headers. Application containers remain loopback-only behind that boundary.
- Text log payloads and core telemetry events are retained for 30 days by default. The limits are controlled by `LOKI_WATCHER_LOG_RETENTION_DAYS` and `LOKI_WATCHER_TELEMETRY_RETENTION_DAYS`.
- Analytics JSON is retained for 30 days by default and also capped at 512 MiB globally. The strictest of `LOKI_WATCHER_ANALYTICS_RETENTION_DAYS` and `LOKI_WATCHER_ANALYTICS_MAX_BYTES` wins. Heartbeats remain ordinary telemetry and are never listed on the Analytics page.
- Administrative audit events use the strictest of 10,000 entries, 30 days and 64 MiB by default. Configure these with `LOKI_WATCHER_AUDIT_MAX_ENTRIES`, `LOKI_WATCHER_AUDIT_RETENTION_DAYS` and `LOKI_WATCHER_AUDIT_MAX_BYTES`.
