# Watcher operational unification status

This file maps Watcher to Parts II–VII of `.docs/UNIFICATION_SPECIFICATION.md`.
It deliberately distinguishes enforced behavior from external trust and work
that is not claimed as implemented.

## Part II — observability, audit and log export

Implemented:

- audit events are transactional and bounded by 10,000 rows, 30 days and
  64 MiB estimated retained content;
- each new event carries an event ID, UTC timestamp, severity/outcome, stable
  action, typed actor/target, request ID, method, bounded context and optional
  structured error;
- a central recursive serializer redacts sensitive keys, authorization/cookie
  material, private keys, subscription tokens and connection URIs;
- one telemetry batch is at most 200 events and one retained event is at most
  64 KiB; oversized context is visibly summarized;
- the web stream loads 200 rows initially, supports cursor pagination and is
  hard-capped at 1,000 rows per request;
- log export is authenticated/audited, spooled, streamed to the response,
  `no-store, private`, timestamped and bounded by 64 MiB compressed, 128 MiB
  uncompressed, four files and 120 seconds;
- Docker output rotates independently: 3 × 10 MiB for API/web and 2 × 5 MiB
  for worker/backup.

The optional `raw/` archive member is absent because Watcher has no separate
application JSONL writer; container output remains in Docker's rotated logging
driver and is not copied into the application export.

## Part III — backup and recovery

Recovery contract:

- RPO: scheduled interval, 24 hours by default;
- RTO: operator restore plus validation/health, bounded by the 128 MiB upload
  and 256 MiB uncompressed limits;
- scope: complete Watcher server state;
- semantics: replace, never merge;
- compatibility: backup format 2 and database schema generation 3 for new
  archives, with controlled generation-1 restore and immediate migration;
- external dependency: the separately escrowed 32-byte backup encryption key.

The archive allow-list is `manifest.json`, `data/watcher.db.enc`, `README.txt`.
State is AES-256-GCM ciphertext. The manifest is HMAC-SHA256 authenticated with
the external recovery key and contains per-member SHA-256, uncompressed bytes
and table record counts. `.env`, the recovery key, cache/build output and
container images are absent.

Restore spools first and validates all member names, duplicates, paths, links,
compressed/uncompressed/member/count/ratio limits, manifest authentication,
digests, schema, SQLite integrity, foreign keys and counts before live mutation.
A fresh encrypted pre-restore archive is verified. SQLite's backup API applies
the staged database and the pre-restore database is reapplied on a failed apply
or invariant check. A shared-volume advisory barrier lets normal API, worker and
backup database access run concurrently, while restore holds exclusive access
from the pre-restore snapshot until apply or rollback has completed.

Automated tests cover a real round trip, corruption-before-mutation, missing/
traversal/link archive shapes and post-apply invariant failure with verified
pre-restore rollback. External recovery-key escrow and restoration on a
separate disaster-recovery host remain an operator/infrastructure test, not
something this repository can prove alone.

`vpn-enus-watcher backup TARGET` atomically writes a bounded encrypted archive
outside the Docker volumes and prints its SHA-256; `restore SOURCE` sends that
archive only to the loopback control endpoint and relies on the same staged,
authenticated replacement/rollback contract.

Generation-1 and generation-2 restore accept only their historical complete
table sets. They do not weaken generation-3 validation: new archives must
include `connection_sources`, `analytics_reports` and their authenticated
record counts. After a legacy replacement, `init_db` creates and backfills the
missing schema before the service reports restore success.

## Part IV — bootstrap and deployment

`deploy/bootstrap.sh` selects the highest stable non-draft semantic GitHub
release, validates manifest role/tag/version, allow-listed URLs, bundle bounds
and SHA-256, performs safe extraction and refuses an existing installation.
It must itself be downloaded from an immutable commit or independently trusted
channel; a moving raw URL is explicitly outside later checksum protection.

One-command bootstrap collects only username, hidden password and public SNI
before host mutation (or accepts the equivalent variables for automation),
installs supported distribution prerequisites, writes a mode-0600 environment,
and generates backup/local-control secrets without printing them. Install
validates platform, prerequisites, password/URL/SNI/ports, immutable GHCR
digests and Compose before pull/start. Health, not process start, gates success;
diagnostics are limited to 100 lines.

Release containers run non-root with a read-only root filesystem, tmpfs,
dropped capabilities, no-new-privileges, loopback publishing and rotated logs.
An init-only container holds only `CAP_CHOWN`, normalizes ownership on the two
named data volumes and must complete before the non-root API starts.
Host nginx/TLS remains separately managed and therefore public verified HTTPS
health is an operator deployment check.

## Part V — CI, releases and local updates

CI has separate pre-merge/main and semantic-tag workflows. A release tag must
match `vX.Y.Z`. Tests precede candidate publication. Images are built once,
published with SBOM/provenance, smoke-tested by immutable digest and only those
same image objects are promoted to semantic tags. The deterministic bundle binds Compose/scripts,
version, image digests, bundle SHA-256/size, minimum updater and schema
generation.

The dashboard never receives Docker access and cannot submit arbitrary image,
URL or shell commands. One root-owned systemd updater daemon serves the host
through a mode-0660 Unix socket and a dedicated group. Watcher has its own
root-owned profile and update-control token; mutation tokens are compared in
constant time. Requests carry only an exact version and request ID. A host-wide
lock serializes application and updater mutations.

The server/updater repository paths and stable channel come from namespaced
Watcher Register records. The daemon authenticates to the local policy endpoint,
validates schema/revision/checksum and keeps a root-owned last-known-good copy.
It independently resolves the exact non-draft release and does not trust the UI
discovery result. Informational discovery remains available when the daemon is
absent, while installation is fail-closed.

Every application update first persists a non-empty encrypted backup and its
SHA-256, validates release identity, exact bundle members, Compose checksum,
immutable images and minimum updater version, then pulls before atomic apply.
Loopback health gates success. Failure restores deployment files/version first,
starts the old runtime, restores logical data and checks health again. Reused
request IDs return the existing job. Startup reconciliation maps interrupted
states to explicit terminal outcomes. Jobs/backups/rollback snapshots retain
the newest 20 and 30 days.

Updater self-update is explicit and runs in a separate transient systemd unit.
It reads the shared `watcher.server_repository` from the same Register/LKG policy, compares
semantic versions, verifies the bounded release bundle, preserves the current
updater and unit, installs atomically, restarts/polls socket health and always
attempts previous-file restart on a post-mutation failure. Self-update jobs and
previous copies use the same count/age retention and interrupted transient jobs
are reconciled after daemon startup.

CI actions are pinned to immutable commits. Python dependencies are pinned with
wheel hashes for supported Linux x86-64/aarch64 and Windows development, the
Python 3.12 Alpine base image is digest-pinned, and release/updater Linux
contract tests run in CI in addition to API, recovery and container smoke
suites. A pinned Trivy action blocks HIGH/CRITICAL dependency, configuration,
secret and final-image-layer findings before digest promotion; the final bundle
is scanned again before GitHub Release upload.

## Part VII — security and exposure control

The production Compose contract publishes API and web only on loopback; normal
containers run non-root with read-only roots, no added capabilities and
`no-new-privileges`. The host nginx template enforces the configured Host/SNI,
overwrites client-supplied forwarding headers, applies request/connection rate
limits and timeouts, disables subscription-path access logs, and emits HSTS,
CSP, frame, MIME and referrer protections.

Dashboard credentials are compared in constant time after PBKDF2 verification,
wrong usernames take a dummy PBKDF2 path, and ten failures in 60 seconds block
the source for five minutes. CORS is allow-listed and the dashboard keeps the
operator password only in the live password input, not browser storage.

Server-side subscription retrieval requires HTTPS, rejects non-global DNS
destinations and revalidates every redirect. The sole private/insecure-origin
exception is restricted to the exact operator-configured PasarGuard origin.
Public-IP geolocation is opt-in and disabled by default. Repository guards,
CodeQL, advisory audits, final artifact/image scanning and Dependabot cover
accidental credentials, static analysis, vulnerable packages/base layers and
dependency drift.

Known boundaries, stated precisely:

- the server release manifest is checksummed but not asymmetrically signed;
- GitHub transport/repository controls are the publisher-authentication trust
  source; a checksum is not a signature;
- browser end-to-end CI is represented by container/HTTP health smoke; full
  responsive browser automation remains a future gate;
- the privileged daemon and self-update rollback are contract-tested on Linux,
  but a real systemd + Docker host failure injection test remains an external
  release acceptance step;
- public TLS health and a clean external disaster-recovery restore require
  deployment infrastructure and are not claimed by repository-local tests.
