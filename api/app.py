from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import tempfile
import sqlite3
import threading
import time
import uuid
import zipfile
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http import HTTPStatus
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen
from urllib.error import HTTPError, URLError

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from common.backup_contract import (
    BackupContractError,
    DATABASE_SCHEMA_GENERATION,
    MAX_COMPRESSED_BYTES as BACKUP_MAX_COMPRESSED_BYTES,
    MAX_MEMBER_BYTES as BACKUP_MAX_MEMBER_BYTES,
    MAX_MEMBER_COUNT as BACKUP_MAX_MEMBER_COUNT,
    MAX_UNCOMPRESSED_BYTES as BACKUP_MAX_UNCOMPRESSED_BYTES,
    create_backup_archive,
    decode_backup_key,
    sha256_file,
    snapshot_database,
    validate_and_decrypt_archive,
)
from common.database_lock import database_access


DB_PATH = os.environ.get("LOKI_WATCHER_DB", os.path.join(os.getcwd(), "watcher.db"))
DASHBOARD_TOKEN = os.environ.get("LOKI_WATCHER_DASHBOARD_TOKEN", "")
DASHBOARD_USERNAME = os.environ.get("LOKI_WATCHER_DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.environ.get("LOKI_WATCHER_DASHBOARD_PASSWORD", "").strip()
LOCAL_CONTROL_TOKEN = os.environ.get("LOKI_WATCHER_LOCAL_CONTROL_TOKEN", "").strip()
MAX_SKEW_SECONDS = 300
ONLINE_WINDOW_SECONDS = int(os.environ.get("LOKI_WATCHER_ONLINE_WINDOW_SECONDS", "600"))
LOG_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_LOG_RETENTION_DAYS", "30"))
TELEMETRY_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_TELEMETRY_RETENTION_DAYS", "30"))
ANALYTICS_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_ANALYTICS_RETENTION_DAYS", "30"))
ANALYTICS_MAX_BYTES = int(os.environ.get("LOKI_WATCHER_ANALYTICS_MAX_BYTES", str(512 * 1024 * 1024)))
MAX_BACKUP_BYTES = BACKUP_MAX_COMPRESSED_BYTES
MAX_JSON_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_JSON_BYTES", str(1024 * 1024)))
MAX_ANALYTICS_REQUEST_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_ANALYTICS_REQUEST_BYTES", str(16 * 1024 * 1024)))
MAX_ANALYTICS_REPORT_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_ANALYTICS_REPORT_BYTES", str(8 * 1024 * 1024)))
MAX_ANALYTICS_REPORTS_PER_BATCH = 20
MAX_TELEMETRY_EVENTS_PER_BATCH = 200
MAX_TELEMETRY_EVENT_BYTES = 64 * 1024
MAX_SUBSCRIPTION_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_SUBSCRIPTION_BYTES", str(2 * 1024 * 1024)))
CONNECTION_SCAN_INTERVAL_MINUTES_DEFAULT = min(
    15,
    max(1, int(os.environ.get("LOKI_WATCHER_CONNECTION_SCAN_INTERVAL_MINUTES", "15"))),
)
CONNECTION_SCAN_POLL_SECONDS = 30
PASARGUARD_API_KEY = os.environ.get("LOKI_WATCHER_PASARGUARD_API_KEY", "").strip()
PASARGUARD_BASE_URL_DEFAULT = os.environ.get("LOKI_WATCHER_PASARGUARD_BASE_URL", "").strip().rstrip("/")
PASARGUARD_TEMPLATE_ID_DEFAULT = os.environ.get("LOKI_WATCHER_PASARGUARD_USER_TEMPLATE_ID", "").strip()
PASARGUARD_TIMEOUT_SECONDS = min(60, max(2, int(os.environ.get("LOKI_WATCHER_PASARGUARD_TIMEOUT_SECONDS", "20"))))
PASARGUARD_MAX_RESPONSE_BYTES = min(MAX_SUBSCRIPTION_BYTES, 2 * 1024 * 1024)
PASSWORD_HASH_ITERATIONS = 310000
MIN_OPERATOR_PASSWORD_LENGTH = 12
AUDIT_MAX_ENTRIES = int(os.environ.get("LOKI_WATCHER_AUDIT_MAX_ENTRIES", "10000"))
AUDIT_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_AUDIT_RETENTION_DAYS", "30"))
AUDIT_MAX_BYTES = int(os.environ.get("LOKI_WATCHER_AUDIT_MAX_BYTES", str(64 * 1024 * 1024)))
AUDIT_INITIAL_PAGE = 200
AUDIT_MAX_PAGE = 1000
AUDIT_CONTEXT_MAX_BYTES = int(os.environ.get("LOKI_WATCHER_AUDIT_CONTEXT_MAX_BYTES", "16384"))
AUDIT_MESSAGE_MAX_CHARS = 1024
LOG_EXPORT_MAX_UNCOMPRESSED_BYTES = int(os.environ.get("LOKI_WATCHER_LOG_EXPORT_MAX_UNCOMPRESSED_BYTES", str(128 * 1024 * 1024)))
LOG_EXPORT_MAX_COMPRESSED_BYTES = int(os.environ.get("LOKI_WATCHER_LOG_EXPORT_MAX_COMPRESSED_BYTES", str(64 * 1024 * 1024)))
LOG_EXPORT_MAX_SECONDS = int(os.environ.get("LOKI_WATCHER_LOG_EXPORT_MAX_SECONDS", "120"))
OPERATIONAL_LOG_FILE_BYTES = 10 * 1024 * 1024
OPERATIONAL_LOG_FILE_COUNT = 3
OPERATIONAL_LOG_TOTAL_BYTES = OPERATIONAL_LOG_FILE_BYTES * OPERATIONAL_LOG_FILE_COUNT
GITHUB_REPOSITORY = os.environ.get("LOKI_WATCHER_GITHUB_REPOSITORY", "psewdon1m-loki/client").strip()
GITHUB_RELEASE = "latest"
GITHUB_TOKEN = os.environ.get("LOKI_WATCHER_GITHUB_TOKEN", "").strip()
UPDATE_CHANNEL = "stable"
UPDATE_CACHE_SECONDS = max(0, int(os.environ.get("LOKI_WATCHER_UPDATE_CACHE_SECONDS", "300")))
WATCHER_PUBLIC_SNI = os.environ.get("LOKI_WATCHER_PUBLIC_SNI", "cake.shmoza.net").strip()
WATCHER_PUBLIC_URL = f"https://{WATCHER_PUBLIC_SNI}"
WATCHER_VERSION = os.environ.get("LOKI_WATCHER_VERSION", "0.1.0").strip() or "0.1.0"
WATCHER_SERVER_REPOSITORY = os.environ.get("LOKI_WATCHER_SERVER_REPOSITORY", "psewdon1m-loki/watcher").strip()
UPDATER_SOCKET_PATH = os.environ.get("LOKI_WATCHER_UPDATER_SOCKET", "/run/vpnenus-updater/updater.sock").strip()
UPDATER_SERVICE_ID = "watcher"
UPDATER_RESPONSE_MAX_BYTES = 1024 * 1024
CORS_ALLOWED_ORIGINS = {
    item.strip().rstrip("/")
    for item in os.environ.get(
        "LOKI_WATCHER_CORS_ALLOWED_ORIGINS",
        f"{WATCHER_PUBLIC_URL},http://127.0.0.1:18081,http://localhost:18081",
    ).split(",")
    if item.strip()
}
IP_GEOLOOKUP_ENABLED = os.environ.get("LOKI_WATCHER_IP_GEOLOOKUP_ENABLED", "0").strip().lower() not in {"0", "false", "no", "off"}
RULE_SET_IDS = ["russia-smart", "global", "whitelist", "blacklist"]
REGISTER_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
REGISTER_SNI_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SECRET_REGISTER_KEYS = frozenset({"pasarguard.api_key"})
OBSOLETE_REGISTER_KEYS = frozenset({
    "github.release",
    "update.channel",
    "update.rule_set_ids",
    "watcher.public_url",
    "watcher.release_channel",
    "watcher.updater_repository",
})
CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT = 60
ANALYTICS_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
ANALYTICS_REPORT_TYPES = frozenset({"fail_analytics", "full_analytics"})
SERVER_RELEASE_VERSION_RE = re.compile(r"^(\d{1,9})\.(\d{1,9})\.(\d{1,9})$")
SERVER_RELEASE_MANIFEST_ASSET = "vpn-enus-watcher-release.json"
SERVER_RELEASE_MAX_BYTES = 1024 * 1024
SERVER_RELEASE_IMAGE_RE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")
_manifest_cache_body: bytes | None = None
_manifest_cache_signature: bytes | None = None
_manifest_cache_expires_at = 0.0
_manifest_cache_lock = threading.Lock()
_ip_info_cache: dict[str, dict[str, str]] = {}
_request_context = threading.local()
_restore_lock = threading.Lock()
_pasarguard_operation_lock = threading.Lock()
_client_connection_initialization_lock = threading.Lock()
_dashboard_auth_lock = threading.Lock()
_dashboard_auth_failures: dict[str, list[float]] = {}
_dashboard_auth_blocked_until: dict[str, float] = {}
DASHBOARD_AUTH_WINDOW_SECONDS = 60
DASHBOARD_AUTH_MAX_FAILURES = 10
DASHBOARD_AUTH_BLOCK_SECONDS = 300
PASARGUARD_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,128}$")


class RequestBodyError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


class SubscriptionScanError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


class PasarGuardError(Exception):
    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message or code


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent API credentials from being forwarded to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UpdaterBridgeError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: str | None = None) -> None:
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    database_lock = database_access(path)
    database_lock.__enter__()
    try:
        db = sqlite3.connect(path)
    except sqlite3.Error:
        database_lock.__exit__(None, None, None)
        raise
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                display_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                username TEXT,
                machine_name TEXT,
                platform TEXT NOT NULL DEFAULT 'unknown',
                app_version TEXT,
                os TEXT,
                windows_version TEXT,
                installed_at TEXT,
                original_ip TEXT,
                last_ip TEXT,
                region TEXT NOT NULL DEFAULT 'unknown',
                provider TEXT,
                device_json TEXT NOT NULL DEFAULT '{}',
                routing_mode TEXT,
                connections_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'unknown',
                total_traffic_bytes INTEGER NOT NULL DEFAULT 0,
                traffic_metering_mode TEXT,
                auto_updates_enabled INTEGER,
                logs_upload_enabled INTEGER,
                update_manifest_url TEXT,
                update_fallback_manifest_url TEXT,
                update_last_check_success INTEGER,
                update_last_check_message TEXT,
                update_active_rule_set TEXT,
                update_rule_sets_json TEXT NOT NULL DEFAULT '[]',
                update_last_seen_at TEXT,
                connection_id TEXT,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                traffic_delta_bytes INTEGER NOT NULL DEFAULT 0,
                traffic_total_bytes INTEGER NOT NULL DEFAULT 0,
                message TEXT,
                payload_json TEXT NOT NULL,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            );

            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                type TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            );

            CREATE TABLE IF NOT EXISTS analytics_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                report_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                engine_version TEXT,
                status TEXT,
                summary_json TEXT NOT NULL DEFAULT '{}',
                payload_json TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            );

            CREATE TABLE IF NOT EXISTS issued_connections (
                id TEXT PRIMARY KEY,
                telegram_id TEXT,
                telegram_username TEXT,
                subscription_url TEXT NOT NULL,
                configurations_json TEXT NOT NULL DEFAULT '[]',
                verify_tls INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                public_token TEXT,
                revision INTEGER NOT NULL DEFAULT 1,
                provisioning_state TEXT NOT NULL DEFAULT 'active',
                provider_error TEXT,
                last_scan_at TEXT,
                last_scan_status TEXT,
                last_scan_message TEXT,
                subscription_renewal_date TEXT,
                track_subscription INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_sources (
                id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                external_user_id TEXT,
                external_username TEXT,
                template_id INTEGER,
                subscription_url TEXT NOT NULL DEFAULT '',
                configurations_json TEXT NOT NULL DEFAULT '[]',
                verify_tls INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                credentials_fingerprint TEXT,
                reset_from_fingerprint TEXT,
                last_sync_at TEXT,
                last_sync_status TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (connection_id) REFERENCES issued_connections(id)
            );

            CREATE TABLE IF NOT EXISTS watcher_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operator_credentials (
                username TEXT PRIMARY KEY,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS register_entries (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                status TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                target_type TEXT,
                actor TEXT,
                actor_type TEXT,
                message TEXT,
                request_id TEXT,
                transport_method TEXT,
                context_json TEXT NOT NULL DEFAULT '{}',
                error_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_client_created ON events(client_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_commands_client_status ON commands(client_id, status);
            CREATE INDEX IF NOT EXISTS idx_analytics_received ON analytics_reports(received_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_analytics_client_received ON analytics_reports(client_id, received_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_analytics_type_received ON analytics_reports(report_type, received_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_connection_sources_connection ON connection_sources(connection_id, status);
            """
        )
        for statement in [
            "ALTER TABLE clients ADD COLUMN username TEXT",
            "ALTER TABLE clients ADD COLUMN machine_name TEXT",
            "ALTER TABLE clients ADD COLUMN platform TEXT NOT NULL DEFAULT 'unknown'",
            "ALTER TABLE clients ADD COLUMN app_version TEXT",
            "ALTER TABLE clients ADD COLUMN os TEXT",
            "ALTER TABLE clients ADD COLUMN windows_version TEXT",
            "ALTER TABLE clients ADD COLUMN installed_at TEXT",
            "ALTER TABLE clients ADD COLUMN original_ip TEXT",
            "ALTER TABLE clients ADD COLUMN last_ip TEXT",
            "ALTER TABLE clients ADD COLUMN region TEXT NOT NULL DEFAULT 'unknown'",
            "ALTER TABLE clients ADD COLUMN provider TEXT",
            "ALTER TABLE clients ADD COLUMN routing_mode TEXT",
            "ALTER TABLE clients ADD COLUMN connections_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN traffic_metering_mode TEXT",
            "ALTER TABLE clients ADD COLUMN auto_updates_enabled INTEGER",
            "ALTER TABLE clients ADD COLUMN logs_upload_enabled INTEGER",
            "ALTER TABLE clients ADD COLUMN update_manifest_url TEXT",
            "ALTER TABLE clients ADD COLUMN update_fallback_manifest_url TEXT",
            "ALTER TABLE clients ADD COLUMN update_last_check_success INTEGER",
            "ALTER TABLE clients ADD COLUMN update_last_check_message TEXT",
            "ALTER TABLE clients ADD COLUMN update_active_rule_set TEXT",
            "ALTER TABLE clients ADD COLUMN update_rule_sets_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN update_last_seen_at TEXT",
            "ALTER TABLE clients ADD COLUMN connection_id TEXT",
            "ALTER TABLE commands ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE issued_connections ADD COLUMN verify_tls INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE issued_connections ADD COLUMN last_scan_at TEXT",
            "ALTER TABLE issued_connections ADD COLUMN last_scan_status TEXT",
            "ALTER TABLE issued_connections ADD COLUMN last_scan_message TEXT",
            "ALTER TABLE issued_connections ADD COLUMN telegram_username TEXT",
            "ALTER TABLE issued_connections ADD COLUMN public_token TEXT",
            "ALTER TABLE issued_connections ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE issued_connections ADD COLUMN provisioning_state TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE issued_connections ADD COLUMN provider_error TEXT",
            "ALTER TABLE issued_connections ADD COLUMN subscription_renewal_date TEXT",
            "ALTER TABLE issued_connections ADD COLUMN track_subscription INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE audit_events ADD COLUMN event_id TEXT",
            "ALTER TABLE audit_events ADD COLUMN severity TEXT NOT NULL DEFAULT 'info'",
            "ALTER TABLE audit_events ADD COLUMN target_type TEXT",
            "ALTER TABLE audit_events ADD COLUMN actor_type TEXT",
            "ALTER TABLE audit_events ADD COLUMN request_id TEXT",
            "ALTER TABLE audit_events ADD COLUMN transport_method TEXT",
            "ALTER TABLE audit_events ADD COLUMN error_json TEXT",
        ]:
            try:
                db.execute(statement)
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        db.execute("UPDATE audit_events SET event_id = lower(hex(randomblob(16))) WHERE event_id IS NULL OR event_id = ''")
        db.execute("UPDATE audit_events SET severity = CASE WHEN status IN ('error', 'denied') THEN 'error' ELSE 'info' END WHERE severity IS NULL OR severity = ''")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_event_id ON audit_events(event_id)")
        db.execute("UPDATE issued_connections SET telegram_username = telegram_id WHERE telegram_username IS NULL")
        db.execute("UPDATE issued_connections SET status = 'disabled' WHERE status = 'revoked'")
        db.execute("UPDATE clients SET last_ip = original_ip WHERE last_ip IS NULL OR last_ip = ''")
        for row in db.execute("SELECT client_id, device_json FROM clients WHERE platform IS NULL OR platform = '' OR platform = 'unknown'").fetchall():
            try:
                device = json.loads(row[1] or "{}")
            except json.JSONDecodeError:
                device = {}
            platform = platform_for_device(device)
            if platform != "unknown":
                db.execute("UPDATE clients SET platform = ? WHERE client_id = ?", (platform, row[0]))
        db.execute(
            """
            UPDATE issued_connections
            SET subscription_renewal_date = CASE
                WHEN length(substr(created_at, 1, 10)) = 10 THEN substr(created_at, 1, 10)
                ELSE ?
            END
            WHERE subscription_renewal_date IS NULL OR subscription_renewal_date = ''
            """,
            (date.today().isoformat(),),
        )
        for row in db.execute("SELECT id FROM issued_connections WHERE public_token IS NULL OR public_token = ''").fetchall():
            db.execute("UPDATE issued_connections SET public_token = ? WHERE id = ?", (secrets.token_urlsafe(32), row[0]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_issued_connections_public_token ON issued_connections(public_token)")
        now = utc_now()
        register_defaults = [
            ("watcher.public_sni", WATCHER_PUBLIC_SNI, "Public TLS server name for Watcher traffic."),
            ("github.repository", GITHUB_REPOSITORY, "GitHub owner/repository used for client update artifacts."),
            ("updates.manifest_public_key_pem", "", "Optional RSA public key used by clients to require signed update manifests."),
            ("watcher.server_repository", WATCHER_SERVER_REPOSITORY, "GitHub repository used by the privileged Watcher server updater."),
            ("pasarguard.base_url", PASARGUARD_BASE_URL_DEFAULT, "PasarGuard panel origin used for user provisioning and reset."),
            ("pasarguard.user_template_id", PASARGUARD_TEMPLATE_ID_DEFAULT, "PasarGuard user template ID used for new connections."),
            ("pasarguard.api_key", PASARGUARD_API_KEY, "Secret PasarGuard API key used for provisioning, synchronization and reset."),
            ("clients.heartbeat_interval_seconds", str(CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT), "Normal client heartbeat, command-poll and telemetry contact interval in seconds."),
        ]
        db.executemany(
            """
            INSERT OR IGNORE INTO register_entries (key, value, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [(key, value, description, now, now) for key, value, description in register_defaults],
        )
        db.execute(
            """
            UPDATE register_entries
            SET value = 'psewdon1m-loki/client', description = ?, updated_at = ?
            WHERE key = 'github.repository' AND value = 'psewdon1m-loki/pc-client'
            """,
            ("GitHub owner/repository used for client update artifacts.", now),
        )
        obsolete_placeholders = ",".join("?" for _ in OBSOLETE_REGISTER_KEYS)
        db.execute(
            f"DELETE FROM register_entries WHERE key IN ({obsolete_placeholders})",
            tuple(sorted(OBSOLETE_REGISTER_KEYS)),
        )
        db.execute(
            """
            INSERT OR IGNORE INTO connection_sources
                (id, connection_id, provider, subscription_url, configurations_json, verify_tls,
                 status, last_sync_at, last_sync_status, last_error, created_at, updated_at)
            SELECT id || ':manual', id, 'manual', subscription_url, configurations_json, verify_tls,
                   'active', last_scan_at, last_scan_status, last_scan_message, created_at, updated_at
            FROM issued_connections
            WHERE NOT EXISTS (
                SELECT 1 FROM connection_sources source WHERE source.connection_id = issued_connections.id
            )
            """
        )
        db.execute(
            """
            INSERT OR IGNORE INTO watcher_settings (key, value, updated_at)
            VALUES ('connections.scan_interval_minutes', ?, ?)
            """,
            (str(CONNECTION_SCAN_INTERVAL_MINUTES_DEFAULT), now),
        )
        db.commit()
    finally:
        db.close()
        database_lock.__exit__(None, None, None)


@contextmanager
def connect(path: str | None = None):
    path = path or DB_PATH
    with database_access(path):
        db = sqlite3.connect(path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()


def setting_int(db: sqlite3.Connection, key: str, default: int, minimum: int, maximum: int) -> int:
    row = db.execute("SELECT value FROM watcher_settings WHERE key = ?", (key,)).fetchone()
    try:
        value = int(row["value"]) if row is not None else default
    except (TypeError, ValueError):
        value = default
    return min(maximum, max(minimum, value))


def connection_scan_interval_minutes(db: sqlite3.Connection | None = None) -> int:
    if db is not None:
        return setting_int(
            db,
            "connections.scan_interval_minutes",
            CONNECTION_SCAN_INTERVAL_MINUTES_DEFAULT,
            1,
            15,
        )
    with connect() as connection:
        return connection_scan_interval_minutes(connection)


def register_value(db: sqlite3.Connection, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM register_entries WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    return str(row["value"] or "").strip()


def watcher_public_sni(db: sqlite3.Connection) -> str:
    value = register_value(db, "watcher.public_sni", WATCHER_PUBLIC_SNI).lower().rstrip(".")
    return value if REGISTER_SNI_RE.fullmatch(value) else WATCHER_PUBLIC_SNI


def watcher_public_url(db: sqlite3.Connection) -> str:
    return f"https://{watcher_public_sni(db)}"


def current_watcher_public_identity() -> tuple[str, str]:
    with connect() as db:
        sni = watcher_public_sni(db)
    return f"https://{sni}", sni


def github_repository(db: sqlite3.Connection | None = None) -> str:
    if db is None:
        with connect() as connection:
            return github_repository(connection)
    value = register_value(db, "github.repository", GITHUB_REPOSITORY)
    return value if REGISTER_REPOSITORY_RE.fullmatch(value) else GITHUB_REPOSITORY


def client_update_policy(db: sqlite3.Connection) -> dict[str, Any]:
    repository = github_repository(db)
    watcher_url = watcher_public_url(db)
    public_key_pem = register_value(db, "updates.manifest_public_key_pem")
    policy = {
        "repository": repository,
        "manifestUrl": f"https://github.com/{repository}/releases/latest/download/manifest.json",
        "fallbackManifestUrl": f"{watcher_url}/manifest.json",
        "channel": UPDATE_CHANNEL,
        "watcherEndpoint": watcher_url,
        "watcherSni": watcher_public_sni(db),
        "requireManifestSignature": bool(public_key_pem),
    }
    if public_key_pem:
        policy["manifestPublicKeyPem"] = public_key_pem
    return policy


def client_runtime_config(db: sqlite3.Connection) -> dict[str, Any]:
    return {
        "heartbeatIntervalSeconds": client_heartbeat_interval_seconds(db),
        "updatePolicy": client_update_policy(db),
    }


def client_heartbeat_interval_seconds(db: sqlite3.Connection) -> int:
    raw_value = register_value(
        db,
        "clients.heartbeat_interval_seconds",
        str(CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT),
    )
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT
    return min(86400, max(15, value))


def pasarguard_client_settings() -> tuple[str, str]:
    with connect() as db:
        base_url = register_value(db, "pasarguard.base_url", PASARGUARD_BASE_URL_DEFAULT).rstrip("/")
        api_key = register_value(db, "pasarguard.api_key", PASARGUARD_API_KEY)
    if not base_url:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_base_url_missing", "Set pasarguard.base_url in Register.")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_base_url_invalid", "PasarGuard base URL is invalid.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_base_url_invalid", "PasarGuard base URL must be an origin without a path.")
    if not api_key:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_api_key_missing", "Set pasarguard.api_key in Register.")
    return base_url, api_key


def pasarguard_settings() -> tuple[str, int, str]:
    base_url, api_key = pasarguard_client_settings()
    with connect() as db:
        raw_template_id = register_value(db, "pasarguard.user_template_id", PASARGUARD_TEMPLATE_ID_DEFAULT)
    try:
        template_id = int(raw_template_id)
    except (TypeError, ValueError) as exc:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_template_id_missing", "Set pasarguard.user_template_id in Register.") from exc
    if template_id <= 0:
        raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_template_id_invalid", "PasarGuard template ID must be positive.")
    return base_url, template_id, api_key


def password_digest(password: str, salt: bytes, iterations: int = PASSWORD_HASH_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def verify_operator_password(username: str, password: str) -> bool:
    if not DASHBOARD_USERNAME or not hmac.compare_digest(username, DASHBOARD_USERNAME):
        password_digest(password, b"\0" * 16)
        return False
    try:
        with connect() as db:
            row = db.execute(
                "SELECT password_salt, password_hash, iterations FROM operator_credentials WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error:
        row = None
    if row is None:
        return hmac.compare_digest(password, DASHBOARD_PASSWORD)
    try:
        salt = base64.b64decode(row["password_salt"], validate=True)
        expected = base64.b64decode(row["password_hash"], validate=True)
        actual = password_digest(password, salt, int(row["iterations"]))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    add_cors_headers(handler)
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature,x-watcher-control-token,x-request-id")
    handler.send_header("Access-Control-Expose-Headers", "content-disposition")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("X-Request-Id", getattr(handler, "request_id", uuid.uuid4().hex))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(payload)


def binary_response(handler: BaseHTTPRequestHandler, status: int, payload: bytes, content_type: str, file_name: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
    add_cors_headers(handler)
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature,x-watcher-control-token,x-request-id")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("Access-Control-Expose-Headers", "content-disposition,x-request-id")
    handler.send_header("X-Request-Id", getattr(handler, "request_id", uuid.uuid4().hex))
    handler.send_header("Cache-Control", "no-store, private")
    handler.end_headers()
    handler.wfile.write(payload)


def subscription_response(handler: BaseHTTPRequestHandler, configurations: list[str], response_format: str) -> None:
    raw = "\n".join(configurations).encode("utf-8")
    payload = raw if response_format == "raw" else base64.b64encode(raw)
    etag = f'"{hashlib.sha256(payload).hexdigest()}"'
    if handler.headers.get("If-None-Match") == etag:
        handler.send_response(HTTPStatus.NOT_MODIFIED)
        handler.send_header("ETag", etag)
        handler.send_header("Cache-Control", "private, max-age=300, stale-if-error=86400")
        handler.end_headers()
        return
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("ETag", etag)
    handler.send_header("Cache-Control", "private, max-age=300, stale-if-error=86400")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(payload)


def file_response(handler: BaseHTTPRequestHandler, status: int, path: str, content_type: str, file_name: str) -> None:
    size = os.path.getsize(path)
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(size))
    handler.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
    add_cors_headers(handler)
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature,x-watcher-control-token,x-request-id")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("Access-Control-Expose-Headers", "content-disposition,x-request-id")
    handler.send_header("X-Request-Id", getattr(handler, "request_id", uuid.uuid4().hex))
    handler.send_header("Cache-Control", "no-store, private")
    handler.end_headers()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            handler.wfile.write(chunk)


def spool_request_body(handler: BaseHTTPRequestHandler, target_path: str, maximum_bytes: int) -> int:
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except ValueError as exc:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "invalid_content_length") from exc
    if length <= 0:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "invalid_backup_size")
    if length > maximum_bytes:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "invalid_backup_size")
    remaining = length
    with open(target_path, "wb") as target:
        os.chmod(target_path, 0o600)
        while remaining:
            chunk = handler.rfile.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RequestBodyError(HTTPStatus.BAD_REQUEST, "incomplete_request_body")
            target.write(chunk)
            remaining -= len(chunk)
    return length


def add_cors_headers(handler: BaseHTTPRequestHandler) -> None:
    origin = (handler.headers.get("Origin") or "").strip().rstrip("/")
    allowed_origins = CORS_ALLOWED_ORIGINS
    try:
        public_url, _ = current_watcher_public_identity()
        allowed = origin in allowed_origins or origin == public_url
    except sqlite3.Error:
        allowed = origin in allowed_origins
    if allowed:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")


def updater_socket_request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    mutation: bool = False,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    if not UPDATER_SOCKET_PATH:
        raise UpdaterBridgeError(HTTPStatus.SERVICE_UNAVAILABLE, "updater_unavailable", "Local updater socket is not configured.")
    if not hasattr(socket, "AF_UNIX"):
        raise UpdaterBridgeError(HTTPStatus.SERVICE_UNAVAILABLE, "updater_unavailable", "Unix sockets are unavailable on this host.")
    payload = b"" if body is None else json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = {
        "Host": "localhost",
        "Connection": "close",
        "Accept": "application/json",
        "Content-Length": str(len(payload)),
        "X-Updater-Service": UPDATER_SERVICE_ID,
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    if mutation:
        if not LOCAL_CONTROL_TOKEN:
            raise UpdaterBridgeError(HTTPStatus.SERVICE_UNAVAILABLE, "updater_unavailable", "Local update-control token is not configured.")
        headers["X-Updater-Control-Token"] = LOCAL_CONTROL_TOKEN
    request_head = "\r\n".join(
        [f"{method} {path} HTTP/1.1", *[f"{key}: {value}" for key, value in headers.items()], "", ""]
    ).encode("ascii")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(UPDATER_SOCKET_PATH)
        connection.sendall(request_head + payload)
        response = HTTPResponse(connection)
        response.begin()
        declared_length = response.getheader("Content-Length")
        if declared_length is not None and int(declared_length) > UPDATER_RESPONSE_MAX_BYTES:
            raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "updater_response_too_large", "Local updater response exceeded its limit.")
        raw = response.read(UPDATER_RESPONSE_MAX_BYTES + 1)
        if len(raw) > UPDATER_RESPONSE_MAX_BYTES:
            raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "updater_response_too_large", "Local updater response exceeded its limit.")
        try:
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "updater_response_invalid", "Local updater returned invalid JSON.") from exc
        if not isinstance(value, dict):
            raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "updater_response_invalid", "Local updater returned an invalid response.")
        return response.status, value
    except UpdaterBridgeError:
        raise
    except (OSError, ValueError) as exc:
        raise UpdaterBridgeError(HTTPStatus.SERVICE_UNAVAILABLE, "updater_unavailable", "Local updater socket is unavailable.") from exc
    finally:
        connection.close()


def updater_status_snapshot() -> dict[str, Any]:
    try:
        status, value = updater_socket_request("GET", f"/v1/services/{UPDATER_SERVICE_ID}/status", timeout=1.0)
        if status != HTTPStatus.OK:
            raise UpdaterBridgeError(status, str(value.get("error") or "updater_status_failed"), str(value.get("message") or "Updater status failed."))
        return value
    except UpdaterBridgeError as exc:
        return {
            "serviceId": UPDATER_SERVICE_ID,
            "available": False,
            "busy": False,
            "updaterVersion": None,
            "installed": {"version": WATCHER_VERSION, "images": {}},
            "latestJob": None,
            "reason": exc.message,
        }


def updater_policy_document() -> dict[str, Any]:
    with connect() as db:
        row = db.execute(
            "SELECT key, value, updated_at FROM register_entries WHERE key = 'watcher.server_repository'",
        ).fetchone()
    server_repository = str(row["value"] or "").strip() if row is not None else ""
    if not REGISTER_REPOSITORY_RE.fullmatch(server_repository):
        raise UpdaterBridgeError(HTTPStatus.CONFLICT, "updater_policy_invalid", "Register contains an invalid Watcher repository path.")
    revision_source = {"repository": dict(row), "channel": UPDATE_CHANNEL}
    revision = hashlib.sha256(json.dumps(revision_source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    policy = {
        "schemaVersion": 1,
        "serviceId": UPDATER_SERVICE_ID,
        "revision": revision,
        "generatedAt": utc_now(),
        "channel": UPDATE_CHANNEL,
        # Keep both protocol roles for backward compatibility. They intentionally
        # resolve to the same monorepository and no longer require two Register keys.
        "repositories": {"server": server_repository, "updater": server_repository},
    }
    policy["checksumSha256"] = hashlib.sha256(
        json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return policy


def server_release_version_tuple(value: str) -> tuple[int, int, int]:
    match = SERVER_RELEASE_VERSION_RE.fullmatch(value)
    if not match:
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_contract_invalid", "Server release version is invalid.")
    return tuple(map(int, match.groups()))


def github_json_bounded(url: str, *, asset_hosts: set[str]) -> Any:
    parsed = urlparse(url)
    try:
        invalid_source = parsed.scheme != "https" or parsed.hostname not in asset_hosts or parsed.port not in {None, 443} or parsed.username or parsed.password
    except ValueError as exc:
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_source_invalid", "Server release source is not allow-listed.") from exc
    if invalid_source:
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_source_invalid", "Server release source is not allow-listed.")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": f"vpn-enus-watcher/{WATCHER_VERSION}"}
    if GITHUB_TOKEN and parsed.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        with urlopen(Request(url, headers=headers), timeout=20) as response:
            final = urlparse(response.geturl())
            raw = response.read(SERVER_RELEASE_MAX_BYTES + 1)
        if final.scheme != "https" or final.hostname not in asset_hosts or final.port not in {None, 443} or len(raw) > SERVER_RELEASE_MAX_BYTES:
            raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_source_invalid", "Server release response was rejected.")
        return json.loads(raw.decode("utf-8"))
    except UpdaterBridgeError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_discovery_failed", "Server release discovery failed.") from exc


def discover_server_release_without_updater() -> dict[str, Any]:
    policy = updater_policy_document()
    repository = policy["repositories"]["server"]
    releases = github_json_bounded(
        f"https://api.github.com/repos/{repository}/releases?per_page=100",
        asset_hosts={"api.github.com"},
    )
    if not isinstance(releases, list):
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_discovery_failed", "Server release list is invalid.")
    candidates: list[tuple[tuple[int, int, int], str, dict[str, Any], dict[str, Any]]] = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag = str(release.get("tag_name") or "")
        if not tag.startswith("v"):
            continue
        match = SERVER_RELEASE_VERSION_RE.fullmatch(tag[1:])
        if not match:
            continue
        asset = next(
            (
                item for item in release.get("assets", [])
                if isinstance(item, dict) and item.get("name") == SERVER_RELEASE_MANIFEST_ASSET
            ),
            None,
        )
        if asset:
            candidates.append((tuple(map(int, match.groups())), tag[1:], release, asset))
    if not candidates:
        raise UpdaterBridgeError(HTTPStatus.NOT_FOUND, "release_not_found", "No stable Watcher server release was found.")
    _, version, release, asset = sorted(candidates, key=lambda item: item[0])[-1]
    manifest_url = str(asset.get("browser_download_url") or "")
    manifest = github_json_bounded(
        manifest_url,
        asset_hosts={"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"},
    )
    images = manifest.get("images") if isinstance(manifest, dict) and isinstance(manifest.get("images"), dict) else {}
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 1
        or manifest.get("databaseSchemaGeneration") != DATABASE_SCHEMA_GENERATION
        or manifest.get("componentRole") != "watcher-control-plane"
        or manifest.get("version") != version
        or manifest.get("channel") != "stable"
        or any(not SERVER_RELEASE_IMAGE_RE.fullmatch(str(images.get(role) or "")) for role in ("api", "web", "worker"))
    ):
        raise UpdaterBridgeError(HTTPStatus.BAD_GATEWAY, "release_contract_invalid", "Server release contract is invalid.")
    installed_tuple = server_release_version_tuple(WATCHER_VERSION)
    return {
        "serviceId": UPDATER_SERVICE_ID,
        "installed": {"version": WATCHER_VERSION, "images": {}},
        "availableRelease": {
            "version": version,
            "tag": f"v{version}",
            "publishedAt": release.get("published_at"),
            "releaseNotesUrl": manifest.get("releaseNotesUrl") or release.get("html_url"),
            "images": images,
            "minimumUpdaterVersion": manifest.get("minimumUpdaterVersion"),
        },
        "updateAvailable": server_release_version_tuple(version) > installed_tuple,
        "policy": {"revision": policy["revision"], "source": "live-register", "repository": repository},
        "informationalOnly": True,
    }


def read_json(handler: BaseHTTPRequestHandler, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except ValueError as exc:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "invalid_content_length") from exc
    if length < 0:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "invalid_content_length")
    if length > max_bytes:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_too_large")
    raw = handler.rfile.read(length) if length > 0 else b""
    if not raw:
        return {}, raw
    try:
        return json.loads(raw.decode("utf-8")), raw
    except UnicodeDecodeError as exc:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "invalid_utf8") from exc


def github_api_url() -> str:
    return f"https://api.github.com/repos/{github_repository()}/releases/latest"


def request_bytes(url: str, timeout: int = 30) -> bytes:
    headers = {
        "Accept": "application/vnd.github+json, application/octet-stream;q=0.9, */*;q=0.8",
        "User-Agent": "loki-watcher/1.0",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def request_json(url: str, timeout: int = 30) -> dict[str, Any]:
    return json.loads(request_bytes(url, timeout=timeout).decode("utf-8"))


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_url(url: str) -> str:
    digest = hashlib.sha256()
    headers = {"User-Agent": "loki-watcher/1.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=60) as response:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def release_assets(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(asset.get("name", "")): asset
        for asset in release.get("assets", [])
        if asset.get("name") and asset.get("browser_download_url")
    }


def asset_url(asset: dict[str, Any]) -> str:
    return str(asset["browser_download_url"])


def release_version(release: dict[str, Any]) -> str:
    tag = str(release.get("tag_name") or GITHUB_RELEASE)
    return tag[1:] if tag.lower().startswith("v") else tag


def release_tag(release: dict[str, Any]) -> str:
    return str(release.get("tag_name") or ("v" + release_version(release)))


def public_asset_url(file_name: str) -> str:
    public_url, _ = current_watcher_public_identity()
    return f"{public_url}/assets/{file_name}"


def bundle_asset(assets: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    for name, asset in sorted(assets.items(), reverse=True):
        if name.startswith("LokiClientRelease-") and name.endswith(".zip"):
            return asset
    return None


def read_bundle_entries(asset: dict[str, Any] | None) -> dict[str, bytes]:
    if asset is None:
        return {}
    try:
        payload = request_bytes(asset_url(asset), timeout=60)
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            return {
                name.rsplit("/", 1)[-1]: archive.read(name)
                for name in archive.namelist()
                if not name.endswith("/")
            }
    except (HTTPError, URLError, TimeoutError, OSError, zipfile.BadZipFile):
        return {}


def release_bundle_entries(release: dict[str, Any], assets: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    return read_bundle_entries(bundle_asset(assets))


def read_upstream_manifest(assets: dict[str, dict[str, Any]], bundle_entries: dict[str, bytes]) -> dict[str, Any] | None:
    asset = assets.get("manifest.json")
    if asset:
        return json.loads(request_bytes(asset_url(asset)).decode("utf-8-sig"))
    if "manifest.json" in bundle_entries:
        return json.loads(bundle_entries["manifest.json"].decode("utf-8-sig"))
    return None


def read_upstream_release_file(
    file_name: str,
    assets: dict[str, dict[str, Any]],
    bundle_entries: dict[str, bytes],
) -> bytes | None:
    asset = assets.get(file_name)
    if asset:
        return request_bytes(asset_url(asset))
    return bundle_entries.get(file_name)


def configured_manifest_public_key() -> str:
    with connect(DB_PATH) as db:
        return register_value(db, "updates.manifest_public_key_pem").strip()


def verify_manifest_signature(payload: bytes, signature_payload: bytes, public_key_pem: str) -> None:
    try:
        signature_text = signature_payload.decode("utf-8").strip()
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (ValueError, UnicodeEncodeError):
            signature = signature_payload
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("manifest_public_key_must_be_rsa")
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("invalid_upstream_manifest_signature") from exc


def signed_upstream_manifest_contract(public_key_pem: str) -> tuple[bytes, bytes]:
    release = request_json(github_api_url())
    assets = release_assets(release)
    bundle_entries = release_bundle_entries(release, assets)
    manifest = read_upstream_release_file("manifest.json", assets, bundle_entries)
    signature = read_upstream_release_file("manifest.json.sig", assets, bundle_entries)
    if manifest is None or signature is None:
        raise ValueError("signed_upstream_manifest_contract_missing")
    json.loads(manifest.decode("utf-8-sig"))
    verify_manifest_signature(manifest, signature, public_key_pem)
    return manifest, signature


def discover_installer(release: dict[str, Any], assets: dict[str, dict[str, Any]], bundle_entries: dict[str, bytes]) -> dict[str, Any] | None:
    candidates = sorted(
        name
        for name in assets
        if name.startswith("LokiClientSetup-") and name.endswith("-win-x64.exe")
    )
    if candidates:
        file_name = candidates[-1]
        asset = assets[file_name]
        return {
            "url": public_asset_url(file_name),
            "fallbackUrl": asset_url(asset),
            "sha256": sha256_url(asset_url(asset)),
            "bytes": int(asset.get("size") or 0),
            "mandatory": False,
        }

    bundled = sorted(
        name
        for name in bundle_entries
        if name.startswith("LokiClientSetup-") and name.endswith("-win-x64.exe")
    )
    if not bundled:
        return None
    file_name = bundled[-1]
    return {
        "url": public_asset_url(file_name),
        "sha256": sha256_bytes(bundle_entries[file_name]),
        "bytes": len(bundle_entries[file_name]),
        "mandatory": False,
    }


def discover_rule_sets(release: dict[str, Any], assets: dict[str, dict[str, Any]], bundle_entries: dict[str, bytes]) -> list[dict[str, Any]]:
    version = release_version(release)
    result: list[dict[str, Any]] = []
    for rule_set_id in RULE_SET_IDS:
        file_name = f"{rule_set_id}.zip"
        asset = assets.get(file_name)
        if asset:
            result.append({
                "id": rule_set_id,
                "version": version,
                "url": public_asset_url(file_name),
                "fallbackUrl": asset_url(asset),
                "sha256": sha256_url(asset_url(asset)),
                "bytes": int(asset.get("size") or 0),
            })
            continue
        if file_name in bundle_entries:
            result.append({
                "id": rule_set_id,
                "version": version,
                "url": public_asset_url(file_name),
                "sha256": sha256_bytes(bundle_entries[file_name]),
                "bytes": len(bundle_entries[file_name]),
            })
    return result


def build_manifest() -> dict[str, Any]:
    release = request_json(github_api_url())
    assets = release_assets(release)
    bundle_entries = release_bundle_entries(release, assets)
    manifest = read_upstream_manifest(assets, bundle_entries) or {
        "channel": UPDATE_CHANNEL,
        "version": release_version(release),
        "minimumVersion": release_version(release),
        "publishedAt": release.get("published_at") or utc_now(),
        "installer": None,
        "ruleSets": [],
        "watcher": None,
    }

    manifest["channel"] = UPDATE_CHANNEL
    manifest["version"] = manifest.get("version") or release_version(release)
    manifest["minimumVersion"] = manifest.get("minimumVersion") or manifest["version"]
    manifest["publishedAt"] = manifest.get("publishedAt") or release.get("published_at") or utc_now()
    manifest["installer"] = discover_installer(release, assets, bundle_entries) or manifest.get("installer")

    discovered_rule_sets = discover_rule_sets(release, assets, bundle_entries)
    merged = {
        str(item.get("id")): item
        for item in manifest.get("ruleSets", [])
        if isinstance(item, dict) and str(item.get("id") or "") in RULE_SET_IDS
    }
    for rule_set in discovered_rule_sets:
        merged[rule_set["id"]] = rule_set
    manifest["ruleSets"] = [merged[rule_set_id] for rule_set_id in RULE_SET_IDS if rule_set_id in merged]
    public_url, public_sni = current_watcher_public_identity()
    manifest["watcher"] = {"endpoint": public_url, "sni": public_sni}
    repository = github_repository()
    manifest["repository"] = repository
    manifest["fallbackManifestUrl"] = f"https://github.com/{repository}/releases/latest/download/manifest.json"
    return manifest


def cached_manifest_bytes() -> bytes:
    global _manifest_cache_body, _manifest_cache_signature, _manifest_cache_expires_at
    with _manifest_cache_lock:
        now = time.time()
        if _manifest_cache_body is not None and now < _manifest_cache_expires_at:
            return _manifest_cache_body
        public_key_pem = configured_manifest_public_key()
        if public_key_pem:
            body, signature = signed_upstream_manifest_contract(public_key_pem)
        else:
            body = json.dumps(build_manifest(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            signature = None
        _manifest_cache_body = body
        _manifest_cache_signature = signature
        _manifest_cache_expires_at = now + UPDATE_CACHE_SECONDS
        return body


def cached_manifest_signature_bytes() -> bytes:
    cached_manifest_bytes()
    with _manifest_cache_lock:
        if _manifest_cache_signature is None:
            raise ValueError("manifest_signature_not_configured")
        return _manifest_cache_signature


def invalidate_manifest_cache() -> None:
    global _manifest_cache_body, _manifest_cache_signature, _manifest_cache_expires_at
    with _manifest_cache_lock:
        _manifest_cache_body = None
        _manifest_cache_signature = None
        _manifest_cache_expires_at = 0.0


def cached_manifest() -> dict[str, Any]:
    return json.loads(cached_manifest_bytes().decode("utf-8"))


def dashboard_manifest_snapshot() -> dict[str, Any]:
    """Return cached update metadata without blocking dashboard login on GitHub."""
    if _manifest_cache_body is not None:
        try:
            return json.loads(_manifest_cache_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    public_url, public_sni = current_watcher_public_identity()
    return {
        "channel": UPDATE_CHANNEL,
        "version": None,
        "minimumVersion": None,
        "publishedAt": None,
        "installer": None,
        "watcher": {"endpoint": public_url, "sni": public_sni},
        "ruleSets": [],
    }


def release_file_bytes(file_name: str) -> bytes | None:
    release = request_json(github_api_url())
    assets = release_assets(release)
    entries = release_bundle_entries(release, assets)
    if file_name in entries:
        return entries[file_name]

    asset = assets.get(file_name)
    if asset is None:
        return None
    return request_bytes(asset_url(asset), timeout=120)


def client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def dashboard_auth_rate_limited(handler: BaseHTTPRequestHandler) -> bool:
    key = client_ip(handler)
    now = time.monotonic()
    with _dashboard_auth_lock:
        blocked_until = _dashboard_auth_blocked_until.get(key, 0.0)
        if blocked_until > now:
            return True
        _dashboard_auth_blocked_until.pop(key, None)
        recent = [value for value in _dashboard_auth_failures.get(key, []) if now - value <= DASHBOARD_AUTH_WINDOW_SECONDS]
        if recent:
            _dashboard_auth_failures[key] = recent
        else:
            _dashboard_auth_failures.pop(key, None)
        return False


def record_dashboard_auth_failure(handler: BaseHTTPRequestHandler) -> bool:
    key = client_ip(handler)
    now = time.monotonic()
    with _dashboard_auth_lock:
        blocked_until = _dashboard_auth_blocked_until.get(key, 0.0)
        if blocked_until > now:
            return True
        recent = [value for value in _dashboard_auth_failures.get(key, []) if now - value <= DASHBOARD_AUTH_WINDOW_SECONDS]
        recent.append(now)
        if len(recent) >= DASHBOARD_AUTH_MAX_FAILURES:
            _dashboard_auth_failures.pop(key, None)
            _dashboard_auth_blocked_until[key] = now + DASHBOARD_AUTH_BLOCK_SECONDS
            return True
        _dashboard_auth_failures[key] = recent
        return False


def clear_dashboard_auth_failures(handler: BaseHTTPRequestHandler) -> None:
    key = client_ip(handler)
    with _dashboard_auth_lock:
        _dashboard_auth_failures.pop(key, None)
        _dashboard_auth_blocked_until.pop(key, None)


def region_for_ip(value: str) -> str:
    return network_info_for_ip(value)["region"]


def network_info_for_ip(value: str) -> dict[str, str]:
    value = (value or "").strip()
    if not value:
        return {"region": "unknown", "provider": "unknown"}
    cached = _ip_info_cache.get(value)
    if cached is not None:
        return cached

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        info = {"region": "unknown", "provider": "unknown"}
        _ip_info_cache[value] = info
        return info
    if address.is_private or address.is_loopback or address.is_link_local:
        info = {"region": "local/private", "provider": "local/private"}
        _ip_info_cache[value] = info
        return info
    if not IP_GEOLOOKUP_ENABLED:
        info = {"region": "unknown", "provider": "unknown"}
        _ip_info_cache[value] = info
        return info

    try:
        payload = request_json(f"http://ip-api.com/json/{value}?fields=status,country,regionName,city,isp", timeout=2)
        if payload.get("status") == "success":
            place_parts = [
                str(part).strip()
                for part in [payload.get("country"), payload.get("city") or payload.get("regionName")]
                if part and str(part).strip()
            ]
            info = {
                "region": ", ".join(place_parts) if place_parts else "unknown",
                "provider": str(payload.get("isp") or "unknown"),
            }
            _ip_info_cache[value] = info
            return info
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
        pass

    info = {"region": "unknown", "provider": "unknown"}
    _ip_info_cache[value] = info
    return info


def touch_client_contact(
    db: sqlite3.Connection,
    client_id: str,
    handler: BaseHTTPRequestHandler,
    now: str | None = None,
) -> None:
    ip = client_ip(handler)
    network = network_info_for_ip(ip)
    db.execute(
        """
        UPDATE clients
        SET last_ip = ?, region = ?, provider = ?, last_seen_at = ?
        WHERE client_id = ?
        """,
        (ip, network["region"], network["provider"], now or utc_now(), client_id),
    )


def dashboard_authorized(handler: BaseHTTPRequestHandler) -> bool:
    if dashboard_auth_rate_limited(handler):
        return False
    if DASHBOARD_USERNAME or DASHBOARD_PASSWORD:
        header = handler.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        username, separator, password = decoded.partition(":")
        authorized = separator == ":" and verify_operator_password(username, password)
        if authorized:
            clear_dashboard_auth_failures(handler)
        return authorized
    if not DASHBOARD_TOKEN:
        clear_dashboard_auth_failures(handler)
        return True
    authorized = hmac.compare_digest(handler.headers.get("Authorization", ""), f"Bearer {DASHBOARD_TOKEN}")
    if authorized:
        clear_dashboard_auth_failures(handler)
    return authorized


def local_control_authorized(handler: BaseHTTPRequestHandler) -> bool:
    supplied = handler.headers.get("X-Watcher-Control-Token", "")
    return bool(LOCAL_CONTROL_TOKEN and supplied and hmac.compare_digest(supplied, LOCAL_CONTROL_TOKEN))


def backup_authorized(handler: BaseHTTPRequestHandler) -> bool:
    return dashboard_authorized(handler) or local_control_authorized(handler)


def backup_actor(handler: BaseHTTPRequestHandler) -> str:
    return "local-updater" if local_control_authorized(handler) else dashboard_actor(handler)


def auth_required_response(handler: BaseHTTPRequestHandler) -> None:
    rate_limited = record_dashboard_auth_failure(handler)
    try:
        with connect() as db:
            write_audit(
                db,
                "denied",
                "security.authorization",
                urlparse(handler.path).path,
                dashboard_actor(handler),
                "Operator authorization denied.",
                target_type="api-route",
            )
    except sqlite3.Error:
        pass
    error_code = "dashboard_auth_rate_limited" if rate_limited else "dashboard_auth_required"
    payload = json.dumps({"error": error_code}, separators=(",", ":")).encode("utf-8")
    handler.send_response(HTTPStatus.TOO_MANY_REQUESTS if rate_limited else HTTPStatus.UNAUTHORIZED)
    if rate_limited:
        handler.send_header("Retry-After", str(DASHBOARD_AUTH_BLOCK_SECONDS))
    else:
        handler.send_header("WWW-Authenticate", 'Basic realm="VPNENUS"')
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    add_cors_headers(handler)
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature,x-watcher-control-token,x-request-id")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("X-Request-Id", getattr(handler, "request_id", uuid.uuid4().hex))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(payload)


def dashboard_actor(handler: BaseHTTPRequestHandler) -> str:
    header = handler.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
            username = decoded.partition(":")[0].strip()
            return username or "dashboard"
        except (ValueError, UnicodeDecodeError):
            pass
    return "dashboard-token" if header.startswith("Bearer ") else "dashboard"


SENSITIVE_LOG_KEYS = re.compile(
    r"(?:password|passphrase|secret|token|authorization|cookie|private[_-]?key|client[_-]?secret|api[_-]?key|session)",
    re.IGNORECASE,
)
CONNECTION_URI_RE = re.compile(r"^(?:vless|vmess|trojan|ss|socks|hysteria2?|hy2|tuic)://", re.IGNORECASE)


def redact_log_string(value: str) -> str:
    if CONNECTION_URI_RE.match(value.strip()):
        return "[REDACTED_CONNECTION_URI]"
    if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
        return "[REDACTED_PRIVATE_KEY]"
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", value)
    try:
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            path = re.sub(r"(?i)(/(?:sub|token|invite|enroll)/)[^/?#]+", r"\1[REDACTED]", parsed.path)
            query = urlencode(
                [(key, "[REDACTED]" if SENSITIVE_LOG_KEYS.search(key) else item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)]
            )
            value = urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, query, parsed.fragment))
    except ValueError:
        pass
    if len(value) > 4096:
        return f"{value[:4096]}…[TRUNCATED {len(value) - 4096} chars]"
    return value


def redact_for_logging(value: Any, *, key_hint: str = "", depth: int = 0) -> Any:
    if SENSITIVE_LOG_KEYS.search(key_hint):
        return "[REDACTED]"
    if depth >= 6:
        return "[TRUNCATED_DEPTH]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 50:
                result["_truncated"] = f"{len(value) - 50} fields omitted"
                break
            result[str(key)[:128]] = redact_for_logging(item, key_hint=str(key), depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        result = [redact_for_logging(item, depth=depth + 1) for item in value[:50]]
        if len(value) > 50:
            result.append(f"[TRUNCATED {len(value) - 50} items]")
        return result
    if isinstance(value, str):
        return redact_log_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_log_string(str(value))


def redact_analytics_payload(value: Any, *, key_hint: str = "", depth: int = 0) -> Any:
    """Preserve diagnostic structure while enforcing the central secret policy."""
    if SENSITIVE_LOG_KEYS.search(key_hint):
        return "[REDACTED]"
    if depth >= 32:
        return "[TRUNCATED_DEPTH]"
    if isinstance(value, dict):
        return {
            str(key)[:128]: redact_analytics_payload(item, key_hint=str(key), depth=depth + 1)
            for key, item in list(value.items())[:2000]
        }
    if isinstance(value, list):
        return [redact_analytics_payload(item, depth=depth + 1) for item in value[:10000]]
    if isinstance(value, str):
        return redact_log_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_log_string(str(value))


def analytics_report_row(row: sqlite3.Row, *, include_payload: bool = False) -> dict[str, Any]:
    item = dict(row)
    for source, target in (("summary_json", "summary"), ("payload_json", "payload")):
        if source not in item:
            continue
        encoded = item.pop(source)
        if target == "payload" and not include_payload:
            continue
        try:
            item[target] = json.loads(encoded or "{}")
        except json.JSONDecodeError:
            item[target] = {"invalid": True}
    return item


def bounded_context_json(context: dict[str, Any] | None) -> str:
    sanitized = redact_for_logging(context or {})
    encoded = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= AUDIT_CONTEXT_MAX_BYTES:
        return encoded
    return json.dumps(
        {
            "truncated": True,
            "originalSha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            "message": "Context exceeded the configured audit-event limit.",
        },
        separators=(",", ":"),
    )


def structured_error(error: dict[str, Any] | Exception | None) -> str | None:
    if error is None:
        return None
    if isinstance(error, dict):
        source = error
        error_type = source.get("type")
        code = source.get("code")
        message = source.get("message")
        cause = source.get("cause")
        stack_trace = source.get("stackTrace") or source.get("stack_trace")
    else:
        error_type = type(error).__name__
        code = None
        message = str(error)
        cause = None
        stack_trace = None
    return json.dumps(
        redact_for_logging(
            {
                "type": error_type,
                "code": code,
                "message": message,
                "cause": cause,
                "stackTrace": stack_trace,
            }
        ),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def infer_actor_type(actor: str) -> str:
    if actor.startswith("watcher-") or actor == "system":
        return "system"
    if actor.startswith("client:"):
        return "client"
    return "operator"


def write_audit(
    db: sqlite3.Connection,
    status: str,
    action: str,
    target: str | None,
    actor: str,
    message: str,
    context: dict[str, Any] | None = None,
    *,
    severity: str | None = None,
    actor_type: str | None = None,
    target_type: str | None = None,
    request_id: str | None = None,
    transport_method: str | None = None,
    error: dict[str, Any] | Exception | None = None,
) -> str:
    outcome = status if status in {"success", "error", "denied"} else "error"
    event_id = uuid.uuid4().hex
    request_id = request_id or getattr(_request_context, "request_id", None)
    transport_method = transport_method or getattr(_request_context, "transport_method", None)
    safe_message = redact_log_string(str(message))[:AUDIT_MESSAGE_MAX_CHARS]
    context_json = bounded_context_json(context)
    error_json = structured_error(error)
    db.execute(
        """
        INSERT INTO audit_events
            (event_id, created_at, severity, status, action, target, target_type, actor,
             actor_type, message, request_id, transport_method, context_json, error_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            utc_now(),
            severity or ("error" if outcome in {"error", "denied"} else "info"),
            outcome,
            str(action)[:128],
            redact_log_string(str(target))[:512] if target is not None else None,
            (target_type or str(action).partition(".")[0] or "resource")[:64],
            redact_log_string(str(actor))[:256],
            (actor_type or infer_actor_type(actor))[:64],
            safe_message,
            str(request_id)[:128] if request_id else None,
            str(transport_method)[:16] if transport_method else None,
            context_json,
            error_json,
        ),
    )
    if AUDIT_RETENTION_DAYS > 0:
        audit_cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat()
        db.execute("DELETE FROM audit_events WHERE created_at < ?", (audit_cutoff,))
    if AUDIT_MAX_ENTRIES > 0:
        db.execute(
            """
            DELETE FROM audit_events
            WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)
            """,
            (AUDIT_MAX_ENTRIES,),
        )
    if AUDIT_MAX_BYTES > 0:
        db.execute(
            """
            WITH sized AS (
                SELECT id,
                       SUM(
                           length(COALESCE(event_id, '')) + length(created_at) + length(COALESCE(severity, '')) +
                           length(status) + length(action) +
                           length(COALESCE(target, '')) + length(COALESCE(actor, '')) +
                           length(COALESCE(target_type, '')) + length(COALESCE(actor_type, '')) +
                           length(COALESCE(message, '')) + length(COALESCE(request_id, '')) +
                           length(COALESCE(transport_method, '')) + length(context_json) + length(COALESCE(error_json, ''))
                       ) OVER (ORDER BY id DESC) AS running_bytes
                FROM audit_events
            )
            DELETE FROM audit_events WHERE id IN (
                SELECT id FROM sized WHERE running_bytes > ?
            )
            """,
            (AUDIT_MAX_BYTES,),
        )
    return event_id


def _json_object(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _audit_export_row(row: sqlite3.Row) -> dict[str, Any]:
    item = _json_object(row)
    for source, target in (("context_json", "context"), ("error_json", "error")):
        raw = item.pop(source, None)
        try:
            item[target] = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            item[target] = {"type": "StoredJsonError", "message": "Stored structured value was invalid."}
    return redact_for_logging(item)


def _telemetry_export_row(row: sqlite3.Row) -> dict[str, Any]:
    item = _json_object(row)
    raw = item.pop("payload_json", None)
    try:
        item["context"] = redact_for_logging(json.loads(raw) if raw else {})
    except json.JSONDecodeError:
        item["context"] = {"type": "StoredJsonError", "message": "Stored telemetry context was invalid."}
    return redact_for_logging(item)


def _write_jsonl(
    db: sqlite3.Connection,
    query: str,
    params: tuple[Any, ...],
    path: str,
    transform,
    budget: dict[str, Any],
    mode: str = "wb",
) -> tuple[int, int, str]:
    count = 0
    digest = hashlib.sha256()
    cursor = db.execute(query, params)
    with open(path, mode) as target:
        while rows := cursor.fetchmany(250):
            if time.monotonic() - budget["started"] > LOG_EXPORT_MAX_SECONDS:
                raise RequestBodyError(HTTPStatus.REQUEST_TIMEOUT, "log_export_timeout")
            for row in rows:
                payload = json.dumps(transform(row), ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                if len(payload) > MAX_JSON_BYTES:
                    payload = json.dumps(
                        {"eventId": row["event_id"] if "event_id" in row.keys() else row["id"], "truncated": True, "reason": "event_export_limit"},
                        separators=(",", ":"),
                    ).encode("utf-8") + b"\n"
                budget["bytes"] += len(payload)
                if budget["bytes"] > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
                    raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
                target.write(payload)
                digest.update(payload)
                count += 1
    return count, os.path.getsize(path), digest.hexdigest()


def _write_errors_json(db: sqlite3.Connection, audit_max_id: int, path: str, budget: dict[str, Any]) -> tuple[int, int, str]:
    digest = hashlib.sha256()
    count = 0
    first = True
    audit_query = """
        SELECT * FROM audit_events
        WHERE id <= ? AND (status IN ('error', 'denied') OR error_json IS NOT NULL)
        ORDER BY id
    """
    telemetry_query = """
        SELECT id, client_id, created_at, type, status, message, payload_json
        FROM events
        WHERE status NOT IN ('', 'ok', 'success', 'connected', 'online')
        ORDER BY id
    """
    with open(path, "wb") as target:
        target.write(b"[")
        digest.update(b"[")
        budget["bytes"] += 1
        for kind, cursor in (("audit", db.execute(audit_query, (audit_max_id,))), ("telemetry", db.execute(telemetry_query))):
            while rows := cursor.fetchmany(250):
                if time.monotonic() - budget["started"] > LOG_EXPORT_MAX_SECONDS:
                    raise RequestBodyError(HTTPStatus.REQUEST_TIMEOUT, "log_export_timeout")
                for row in rows:
                    item = _audit_export_row(row) if kind == "audit" else _telemetry_export_row(row)
                    error = item.get("error") if isinstance(item.get("error"), dict) else {}
                    entry = {
                        "eventId": item.get("event_id") or f"telemetry-{item.get('id')}",
                        "occurredAt": item.get("created_at"),
                        "actor": item.get("actor") or item.get("client_id"),
                        "action": item.get("action") or item.get("type"),
                        "target": item.get("target") or item.get("client_id"),
                        "summary": item.get("message"),
                        "originalRecordedMessage": error.get("message") or item.get("message"),
                        "errorType": error.get("type") or ("DeniedOperation" if item.get("status") == "denied" else "TelemetryStatus"),
                        "errorCode": error.get("code") or item.get("status"),
                        "recordedCause": error.get("cause"),
                        "recordedStackTrace": error.get("stackTrace"),
                        "requestId": item.get("request_id"),
                        "transportMethod": item.get("transport_method"),
                        "context": item.get("context"),
                    }
                    payload = (b"" if first else b",") + json.dumps(redact_for_logging(entry), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    first = False
                    budget["bytes"] += len(payload)
                    if budget["bytes"] > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
                        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
                    target.write(payload)
                    digest.update(payload)
                    count += 1
        target.write(b"]")
        digest.update(b"]")
        budget["bytes"] += 1
    return count, os.path.getsize(path), digest.hexdigest()


def build_log_export(zip_path: str, audit_max_id: int) -> dict[str, Any]:
    work_dir = os.path.dirname(zip_path)
    audit_path = os.path.join(work_dir, "events.jsonl")
    errors_path = os.path.join(work_dir, "errors.json")
    readme_path = os.path.join(work_dir, "README.txt")
    budget: dict[str, Any] = {"bytes": 0, "started": time.monotonic()}
    with connect() as db:
        audit_count, _, _ = _write_jsonl(
            db,
            "SELECT * FROM audit_events WHERE id <= ? ORDER BY id",
            (audit_max_id,),
            audit_path,
            lambda row: {"stream": "audit", **_audit_export_row(row)},
            budget,
        )
        telemetry_count, _, _ = _write_jsonl(
            db,
            "SELECT * FROM events ORDER BY id",
            (),
            audit_path,
            lambda row: {"stream": "telemetry", **_telemetry_export_row(row)},
            budget,
            "ab",
        )
        error_count, error_bytes, error_digest = _write_errors_json(db, audit_max_id, errors_path, budget)
    event_bytes = os.path.getsize(audit_path)
    event_digest = sha256_file(audit_path)
    readme = (
        "VPNЭНУС Watcher structured log export.\n"
        "All timestamps are UTC; the dashboard renders them in the operator's locale.\n"
        "Secrets and credential-bearing URLs are recursively redacted before serialization.\n"
        "events.jsonl contains the complete retained audit and telemetry event stream; use the stream field to distinguish them.\n"
        "Use eventId and requestId to correlate errors.json entries.\n"
        f"Retention: audit {AUDIT_RETENTION_DAYS} days/{AUDIT_MAX_ENTRIES} entries/{AUDIT_MAX_BYTES} bytes; telemetry {TELEMETRY_RETENTION_DAYS} days.\n"
    ).encode("utf-8")
    with open(readme_path, "wb") as readme_file:
        readme_file.write(readme)
    budget["bytes"] += len(readme)
    if budget["bytes"] > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
    members = {
        "events.jsonl": {"records": audit_count + telemetry_count, "bytes": event_bytes, "sha256": event_digest, "description": "Complete retained audit and sanitized client telemetry stream; each row names its stream."},
        "errors.json": {"records": error_count, "bytes": error_bytes, "sha256": error_digest, "description": "Expanded structured errors selected by outcome/error fields."},
        "README.txt": {"records": 0, "bytes": len(readme), "sha256": hashlib.sha256(readme).hexdigest(), "description": "Retention, redaction and correlation guidance."},
    }
    manifest = {
        "format": "vpn-enus-log-export",
        "schemaVersion": 1,
        "serviceRole": "watcher-control-plane",
        "createdAt": utc_now(),
        "snapshotAuditMaxId": audit_max_id,
        "exportAuditEventIncluded": False,
        "counts": {"audit": audit_count, "telemetry": telemetry_count, "errors": error_count},
        "storedByteEstimate": budget["bytes"],
        "retention": {
            "audit": {"count": AUDIT_MAX_ENTRIES, "days": AUDIT_RETENTION_DAYS, "bytes": AUDIT_MAX_BYTES},
            "telemetryDays": TELEMETRY_RETENTION_DAYS,
            "logPayloadDays": LOG_RETENTION_DAYS,
            "container": {"files": OPERATIONAL_LOG_FILE_COUNT, "bytesPerFile": OPERATIONAL_LOG_FILE_BYTES, "totalBytes": OPERATIONAL_LOG_TOTAL_BYTES},
        },
        "limits": {"uncompressedBytes": LOG_EXPORT_MAX_UNCOMPRESSED_BYTES, "compressedBytes": LOG_EXPORT_MAX_COMPRESSED_BYTES, "durationSeconds": LOG_EXPORT_MAX_SECONDS, "fileCount": 4},
        "files": members,
    }
    manifest_path = os.path.join(work_dir, "manifest.json")
    manifest_payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    if budget["bytes"] + len(manifest_payload) > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
    with open(manifest_path, "wb") as manifest_file:
        manifest_file.write(manifest_payload)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        for member in ("manifest.json", "events.jsonl", "errors.json", "README.txt"):
            archive.write(os.path.join(work_dir, member), member)
    if os.path.getsize(zip_path) > LOG_EXPORT_MAX_COMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_compressed_budget_exceeded")
    return manifest


def build_client_log_export(client_id: str, work_dir: str, zip_path: str) -> dict[str, Any]:
    event_cutoff = (datetime.now(timezone.utc) - timedelta(days=TELEMETRY_RETENTION_DAYS)).isoformat()
    events_path = os.path.join(work_dir, "events.jsonl")
    logs_path = os.path.join(work_dir, "logs.txt")
    readme_path = os.path.join(work_dir, "README.txt")
    budget: dict[str, Any] = {"bytes": 0, "started": time.monotonic()}
    with connect() as db:
        event_count, event_bytes, event_digest = _write_jsonl(
            db,
            """
            SELECT id, client_id, created_at, type, status, traffic_delta_bytes,
                   traffic_total_bytes, message, payload_json
            FROM events WHERE client_id = ? AND created_at >= ? ORDER BY id
            """,
            (client_id, event_cutoff),
            events_path,
            _telemetry_export_row,
            budget,
        )
        cursor = db.execute(
            "SELECT created_at, type, status, message, payload_json FROM events WHERE client_id = ? AND created_at >= ? ORDER BY id",
            (client_id, event_cutoff),
        )
        log_lines = 0
        digest = hashlib.sha256()
        with open(logs_path, "wb") as target:
            while rows := cursor.fetchmany(250):
                for row in rows:
                    try:
                        context = redact_for_logging(json.loads(row["payload_json"] or "{}"))
                    except json.JSONDecodeError:
                        context = {}
                    if time.monotonic() - budget["started"] > LOG_EXPORT_MAX_SECONDS:
                        raise RequestBodyError(HTTPStatus.REQUEST_TIMEOUT, "log_export_timeout")
                    lines = [f"{row['created_at']} [{row['type']}] {row['status']}"]
                    if row["message"]:
                        lines.append(redact_log_string(str(row["message"])))
                    if isinstance(context, dict):
                        lines.extend(redact_log_string(str(line)) for line in (context.get("logLines") or [])[:1000])
                    payload = ("\n".join(lines) + "\n\n").encode("utf-8")
                    budget["bytes"] += len(payload)
                    if budget["bytes"] > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
                        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
                    target.write(payload)
                    digest.update(payload)
                    log_lines += len(lines)
    readme = b"Sanitized retained client events and uploaded log lines. Timestamps are UTC.\n"
    with open(readme_path, "wb") as target:
        target.write(readme)
    budget["bytes"] += len(readme)
    if budget["bytes"] > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
    manifest = {
        "format": "vpn-enus-client-log-export",
        "schemaVersion": 1,
        "createdAt": utc_now(),
        "clientId": client_id,
        "retentionDays": TELEMETRY_RETENTION_DAYS,
        "limits": {
            "uncompressedBytes": LOG_EXPORT_MAX_UNCOMPRESSED_BYTES,
            "compressedBytes": LOG_EXPORT_MAX_COMPRESSED_BYTES,
            "durationSeconds": LOG_EXPORT_MAX_SECONDS,
            "fileCount": 4,
        },
        "files": {
            "events.jsonl": {"records": event_count, "bytes": event_bytes, "sha256": event_digest},
            "logs.txt": {"records": log_lines, "bytes": os.path.getsize(logs_path), "sha256": digest.hexdigest()},
            "README.txt": {"records": 0, "bytes": len(readme), "sha256": hashlib.sha256(readme).hexdigest()},
        },
    }
    manifest_path = os.path.join(work_dir, "manifest.json")
    manifest_payload = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if budget["bytes"] + len(manifest_payload) > LOG_EXPORT_MAX_UNCOMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_budget_exceeded")
    with open(manifest_path, "wb") as target:
        target.write(manifest_payload)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        for name in ("manifest.json", "events.jsonl", "logs.txt", "README.txt"):
            archive.write(os.path.join(work_dir, name), name)
    if os.path.getsize(zip_path) > LOG_EXPORT_MAX_COMPRESSED_BYTES:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "log_export_compressed_budget_exceeded")
    return manifest


def decoded_configurations(raw: str | None) -> list[str]:
    try:
        configurations = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item) for item in configurations] if isinstance(configurations, list) else []


def connection_source_rows(db: sqlite3.Connection, connection_id: str) -> list[sqlite3.Row]:
    return db.execute(
        """
        SELECT id, connection_id, provider, external_user_id, external_username, template_id,
               subscription_url, configurations_json, verify_tls, status, credentials_fingerprint,
               reset_from_fingerprint, last_sync_at, last_sync_status, last_error, created_at, updated_at
        FROM connection_sources WHERE connection_id = ? ORDER BY created_at, id
        """,
        (connection_id,),
    ).fetchall()


def connection_source_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["configurations"] = decoded_configurations(item.pop("configurations_json", "[]"))
    item["verify_tls"] = bool(item.get("verify_tls"))
    item.pop("credentials_fingerprint", None)
    item["reset_pending"] = bool(item.pop("reset_from_fingerprint", None))
    return item


def public_subscription_url(base_url: str, token: str | None) -> str:
    return f"{base_url.rstrip('/')}/sub/{token}" if token else ""


def issued_connection_row(
    row: sqlite3.Row,
    *,
    base_url: str | None = None,
    sources: list[sqlite3.Row] | None = None,
) -> dict[str, Any]:
    item = dict(row)
    item["configurations"] = decoded_configurations(item.pop("configurations_json", "[]"))
    item["verify_tls"] = bool(item.get("verify_tls"))
    item["track_subscription"] = bool(item.get("track_subscription"))
    item["telegram_username"] = item.get("telegram_username") or item.get("telegram_id") or ""
    item["public_subscription_url"] = public_subscription_url(base_url or WATCHER_PUBLIC_URL, item.get("public_token"))
    if sources is not None:
        item["sources"] = [connection_source_dict(source) for source in sources]
        item["provider"] = item["sources"][0]["provider"] if len(item["sources"]) == 1 else "aggregate"
    else:
        item["sources"] = []
        item["provider"] = "manual"
    return item


def validate_connection_payload(body: dict[str, Any], *, connection_id: str | None = None) -> tuple[dict[str, Any] | None, str | None]:
    item_id = (connection_id or str(body.get("id") or "").strip() or f"connection-{uuid.uuid4().hex[:12]}")
    status = str(body.get("status") or "active").strip().lower()
    verify_tls = bool(body.get("verifyTls", True))
    raw_configurations = body.get("configurations", [])
    renewal_date = str(body.get("subscriptionRenewalDate") or date.today().isoformat()).strip()
    track_subscription = bool(body.get("trackSubscription", True))
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", item_id):
        return None, "invalid_connection_id"
    if status not in {"active", "disabled"}:
        return None, "invalid_connection_status"
    if not isinstance(raw_configurations, list) or len(raw_configurations) > 100:
        return None, "configurations_must_be_a_list"
    try:
        date.fromisoformat(renewal_date)
    except ValueError:
        return None, "invalid_subscription_renewal_date"
    configurations: list[str] = []
    for value in raw_configurations:
        text = str(value).strip()
        if not text or len(text) > 8192:
            return None, "invalid_configuration"
        if not text.lower().startswith("vless://"):
            return None, "direct_connection_must_be_vless"
        configurations.append(text)
    return {
        "id": item_id,
        "status": status,
        "verifyTls": verify_tls,
        "subscriptionRenewalDate": renewal_date,
        "trackSubscription": track_subscription,
        "configurations": configurations,
    }, None


def parse_subscription_payload(payload: bytes) -> list[str]:
    if not payload:
        return []

    def protocol_lines(text: str) -> list[str]:
        supported = {"vless", "vmess", "trojan", "ss", "socks", "hysteria", "hysteria2", "hy2", "tuic"}
        result: list[str] = []
        for line in re.split(r"[\r\n]+", text.lstrip("\ufeff")):
            value = line.strip()
            match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", value)
            if match and match.group(1).lower() in supported:
                result.append(value)
        return result

    def json_protocol_strings(value: Any) -> list[str]:
        if isinstance(value, str):
            return protocol_lines(value)
        if isinstance(value, list):
            return [item for child in value for item in json_protocol_strings(child)]
        if isinstance(value, dict):
            return [item for child in value.values() for item in json_protocol_strings(child)]
        return []

    text = payload.decode("utf-8-sig", errors="replace").strip()
    candidates = protocol_lines(text)
    if not candidates:
        compact = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
        compact += "=" * ((4 - len(compact) % 4) % 4)
        try:
            decoded = base64.b64decode(compact).decode("utf-8-sig")
            candidates = protocol_lines(decoded)
            if not candidates:
                try:
                    candidates = json_protocol_strings(json.loads(decoded))
                except json.JSONDecodeError:
                    pass
        except (ValueError, UnicodeDecodeError):
            pass
    if not candidates:
        try:
            candidates = json_protocol_strings(json.loads(text))
        except json.JSONDecodeError:
            pass

    unique: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def pasarguard_request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url, api_key = pasarguard_client_settings()
    url = f"{base_url}{path}"
    payload = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "User-Agent": "LokiWatcher/1.0",
        "X-Api-Key": api_key,
        "X-Request-Id": getattr(_request_context, "request_id", uuid.uuid4().hex),
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=payload, headers=headers, method=method)
    opener = build_opener(NoRedirectHandler(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=PASARGUARD_TIMEOUT_SECONDS) as response:
            raw = response.read(PASARGUARD_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raw = exc.read(PASARGUARD_MAX_RESPONSE_BYTES + 1)
        message = f"PasarGuard returned HTTP {exc.code}."
        try:
            error_body = json.loads(raw.decode("utf-8")) if raw else {}
            detail = error_body.get("detail") if isinstance(error_body, dict) else None
            if isinstance(detail, str) and detail.strip():
                message = detail.strip()[:512]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        client_status = exc.code if 400 <= exc.code < 500 else HTTPStatus.BAD_GATEWAY
        raise PasarGuardError(client_status, f"pasarguard_http_{exc.code}", message) from exc
    except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_unavailable", "PasarGuard is unavailable.") from exc
    if len(raw) > PASARGUARD_MAX_RESPONSE_BYTES:
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_response_too_large")
    if not raw:
        return {}
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_invalid_response") from exc
    if not isinstance(result, dict):
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_invalid_response")
    return result


def pasarguard_get_user_by_username(username: str) -> dict[str, Any] | None:
    try:
        return pasarguard_request("GET", f"/api/user/by-username/{quote(username, safe='')}")
    except PasarGuardError as exc:
        if exc.code == "pasarguard_http_404":
            return None
        raise


def pasarguard_get_user_by_id(user_id: str) -> dict[str, Any]:
    return pasarguard_request("GET", f"/api/user/by-id/{quote(str(user_id), safe='')}")


def validate_pasarguard_template_for_permanent_id(template_id: int) -> None:
    template = pasarguard_request("GET", f"/api/user_template/{template_id}")
    if template.get("username_prefix") or template.get("username_suffix"):
        raise PasarGuardError(
            HTTPStatus.CONFLICT,
            "pasarguard_template_changes_username",
            "PasarGuard template username prefix and suffix must be empty so the permanent ID stays identical.",
        )


def pasarguard_credentials_fingerprint(user: dict[str, Any]) -> str | None:
    settings = user.get("proxy_settings")
    if not isinstance(settings, dict):
        return None
    encoded = json.dumps(settings, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def upsert_connection_source(
    db: sqlite3.Connection,
    *,
    connection_id: str,
    provider: str,
    subscription_url: str,
    configurations: list[str],
    verify_tls: bool,
    external_user_id: str | None = None,
    external_username: str | None = None,
    template_id: int | None = None,
    credentials_fingerprint: str | None = None,
    reset_from_fingerprint: str | None = None,
    sync_status: str | None = None,
    error: str | None = None,
) -> None:
    now = utc_now()
    source_id = f"{connection_id}:{provider}"
    db.execute(
        """
        INSERT INTO connection_sources
            (id, connection_id, provider, external_user_id, external_username, template_id,
             subscription_url, configurations_json, verify_tls, status, credentials_fingerprint,
             reset_from_fingerprint, last_sync_at, last_sync_status, last_error, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            external_user_id = COALESCE(excluded.external_user_id, connection_sources.external_user_id),
            external_username = COALESCE(excluded.external_username, connection_sources.external_username),
            template_id = COALESCE(excluded.template_id, connection_sources.template_id),
            subscription_url = excluded.subscription_url,
            configurations_json = excluded.configurations_json,
            verify_tls = excluded.verify_tls,
            credentials_fingerprint = COALESCE(excluded.credentials_fingerprint, connection_sources.credentials_fingerprint),
            reset_from_fingerprint = excluded.reset_from_fingerprint,
            last_sync_at = COALESCE(excluded.last_sync_at, connection_sources.last_sync_at),
            last_sync_status = COALESCE(excluded.last_sync_status, connection_sources.last_sync_status),
            last_error = excluded.last_error,
            updated_at = excluded.updated_at
        """,
        (
            source_id,
            connection_id,
            provider,
            external_user_id,
            external_username,
            template_id,
            subscription_url,
            json.dumps(configurations, ensure_ascii=False, separators=(",", ":")),
            int(verify_tls),
            credentials_fingerprint,
            reset_from_fingerprint,
            now if sync_status else None,
            sync_status,
            error,
            now,
            now,
        ),
    )


def aggregate_connection_sources(db: sqlite3.Connection, connection_id: str) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for row in connection_source_rows(db, connection_id):
        if row["status"] != "active":
            continue
        for value in decoded_configurations(row["configurations_json"]):
            if value not in seen:
                seen.add(value)
                unique.append(value)
    return unique


def subscription_origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    return parsed.scheme, parsed.hostname.lower().rstrip("."), port


def validate_subscription_url(subscription_url: str, trusted_origin: str | None = None) -> None:
    parsed = urlparse(subscription_url)
    origin = subscription_origin(subscription_url)
    trusted = origin is not None and trusted_origin is not None and origin == subscription_origin(trusted_origin)
    if origin is None or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("invalid_subscription_url")
    if parsed.scheme != "https" and not trusted:
        raise ValueError("subscription_https_required")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(parsed.hostname, origin[2], type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise ValueError("subscription_dns_failed") from exc
    if not addresses or (not trusted and any(not address.is_global for address in addresses)):
        raise ValueError("subscription_private_address_denied")


def fetch_subscription(subscription_url: str, verify_tls: bool, *, trusted_origin: str | None = None) -> list[str]:
    current_url = subscription_url
    payload = b""
    for _ in range(4):
        validate_subscription_url(current_url, trusted_origin)
        parsed = urlparse(current_url)
        request = Request(current_url, headers={"Accept": "text/plain, application/json;q=0.9, */*;q=0.8", "User-Agent": "LokiWatcher/1.0"})
        context = None if verify_tls or parsed.scheme != "https" else ssl._create_unverified_context()
        opener = build_opener(NoRedirectHandler(), HTTPSHandler(context=context))
        try:
            with opener.open(request, timeout=20) as response:
                payload = response.read(MAX_SUBSCRIPTION_BYTES + 1)
            break
        except HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308} or not exc.headers.get("Location"):
                raise
            current_url = urljoin(current_url, exc.headers["Location"])
    else:
        raise ValueError("subscription_redirect_limit_exceeded")
    if len(payload) > MAX_SUBSCRIPTION_BYTES:
        raise ValueError("subscription_too_large")
    configurations = parse_subscription_payload(payload)
    if not configurations:
        raise ValueError("subscription_contains_no_supported_connections")
    return configurations


def refresh_issued_connection(connection_id: str, actor: str) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
        sources = connection_source_rows(db, connection_id) if row is not None else []
        pasarguard_origin = register_value(db, "pasarguard.base_url", PASARGUARD_BASE_URL_DEFAULT).rstrip("/")
    if row is None:
        raise SubscriptionScanError(HTTPStatus.NOT_FOUND, "connection_not_found")
    if not sources:
        sources = [row]

    successful = 0
    errors: list[str] = []
    for source in sources:
        source_url = str(source["subscription_url"] or "").strip()
        if source["status"] != "active":
            continue
        if "provider" in source.keys() and source["provider"] == "direct" and not source_url:
            if decoded_configurations(source["configurations_json"]):
                successful += 1
            continue
        if not source_url:
            continue
        try:
            source_configurations = fetch_subscription(
                source_url,
                bool(source["verify_tls"]),
                trusted_origin=pasarguard_origin if "provider" in source.keys() and source["provider"] == "pasarguard" else None,
            )
        except ValueError as exc:
            error = str(exc)
            errors.append(error)
        except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError):
            error = "subscription_fetch_failed"
            errors.append(error)
        else:
            successful += 1
            if "provider" in source.keys():
                with connect() as db:
                    upsert_connection_source(
                        db,
                        connection_id=connection_id,
                        provider=source["provider"],
                        external_user_id=source["external_user_id"],
                        external_username=source["external_username"],
                        template_id=source["template_id"],
                        subscription_url=source_url,
                        configurations=source_configurations,
                        verify_tls=bool(source["verify_tls"]),
                        credentials_fingerprint=source["credentials_fingerprint"],
                        reset_from_fingerprint=source["reset_from_fingerprint"],
                        sync_status="success",
                    )
            continue
        if "provider" in source.keys():
            with connect() as db:
                db.execute(
                    """
                    UPDATE connection_sources
                    SET last_sync_at = ?, last_sync_status = 'error', last_error = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (utc_now(), error, utc_now(), source["id"]),
                )

    now = utc_now()
    if successful:
        with connect() as db:
            configurations = aggregate_connection_sources(db, connection_id)
            db.execute(
                """
                UPDATE issued_connections
                SET configurations_json = ?, revision = revision + 1, updated_at = ?, last_scan_at = ?,
                    last_scan_status = 'success', last_scan_message = ?, provisioning_state = 'active',
                    provider_error = NULL
                WHERE id = ?
                """,
                (
                    json.dumps(configurations, ensure_ascii=False, separators=(",", ":")),
                    now,
                    now,
                    f"Stored {len(configurations)} inner connections from {successful} source(s).",
                    connection_id,
                ),
            )
            write_audit(
                db,
                "success",
                "connection.scan",
                connection_id,
                actor,
                f"Subscription scan stored {len(configurations)} aggregated inner connections.",
                {"successfulSources": successful, "failedSources": len(errors)},
            )
        return {"configurations": configurations, "count": len(configurations), "updatedAt": now}

    error = errors[0] if errors else "subscription_source_not_ready"
    scan_status = HTTPStatus.BAD_REQUEST if error.startswith("invalid_") or error == "subscription_contains_no_supported_connections" else HTTPStatus.BAD_GATEWAY
    with connect() as db:
        db.execute(
            """
            UPDATE issued_connections
            SET last_scan_at = ?, last_scan_status = 'error', last_scan_message = ?,
                provisioning_state = CASE WHEN provisioning_state = 'active' THEN 'degraded' ELSE provisioning_state END,
                provider_error = ?
            WHERE id = ?
            """,
            (now, error, error, connection_id),
        )
        write_audit(
            db,
            "error",
            "connection.scan",
            connection_id,
            actor,
            "All subscription source scans failed; the last good snapshot was preserved.",
            {"failedSources": len(errors)},
            error={"type": "SubscriptionScanError", "code": error, "message": error},
        )
    raise SubscriptionScanError(scan_status, error)


def load_issued_connection(connection_id: str) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
        if row is None:
            raise PasarGuardError(HTTPStatus.NOT_FOUND, "connection_not_found")
        return issued_connection_row(
            row,
            base_url=watcher_public_url(db),
            sources=connection_source_rows(db, connection_id),
        )


def validate_pasarguard_user_identity(connection_id: str, user: dict[str, Any]) -> tuple[str, str, str]:
    username = str(user.get("username") or "")
    external_user_id = str(user.get("id") or "")
    subscription_url = str(user.get("subscription_url") or "").strip()
    if subscription_url.startswith("/") and not subscription_url.startswith("//"):
        base_url, _ = pasarguard_client_settings()
        subscription_url = urljoin(f"{base_url}/", subscription_url.lstrip("/"))
    if username != connection_id:
        raise PasarGuardError(
            HTTPStatus.CONFLICT,
            "pasarguard_username_mismatch",
            "PasarGuard template must not add a username prefix or suffix; username must equal connection ID.",
        )
    if not external_user_id:
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_user_id_missing")
    parsed = urlparse(subscription_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_subscription_url_missing")
    return external_user_id, username, subscription_url


def set_pasarguard_connection_error(connection_id: str, code: str, actor: str, message: str) -> None:
    now = utc_now()
    with connect() as db:
        db.execute(
            """
            UPDATE issued_connections SET provisioning_state = 'error', provider_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (code, now, connection_id),
        )
        db.execute(
            """
            UPDATE connection_sources SET last_sync_at = ?, last_sync_status = 'error', last_error = ?, updated_at = ?
            WHERE connection_id = ? AND provider = 'pasarguard'
            """,
            (now, code, now, connection_id),
        )
        write_audit(
            db,
            "error",
            "connection.pasarguard",
            connection_id,
            actor,
            message,
            error={"type": "PasarGuardError", "code": code, "message": message},
        )


def provision_pasarguard_connection(connection_id: str, actor: str) -> dict[str, Any]:
    with _pasarguard_operation_lock:
        _, template_id, _ = pasarguard_settings()
        with connect() as db:
            row = db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
            if row is None:
                raise PasarGuardError(HTTPStatus.NOT_FOUND, "connection_not_found")
            if not PASARGUARD_USERNAME_RE.fullmatch(connection_id) or re.search(r"[._@-]{2}", connection_id):
                raise PasarGuardError(HTTPStatus.BAD_REQUEST, "connection_id_not_valid_pasarguard_username")
            source = db.execute(
                "SELECT * FROM connection_sources WHERE connection_id = ? AND provider = 'pasarguard'",
                (connection_id,),
            ).fetchone()
            if source is None:
                upsert_connection_source(
                    db,
                    connection_id=connection_id,
                    provider="pasarguard",
                    subscription_url="",
                    configurations=[],
                    verify_tls=True,
                )
                source = db.execute(
                    "SELECT * FROM connection_sources WHERE connection_id = ? AND provider = 'pasarguard'",
                    (connection_id,),
                ).fetchone()
            db.execute(
                "UPDATE issued_connections SET provisioning_state = 'provisioning', provider_error = NULL, updated_at = ? WHERE id = ?",
                (utc_now(), connection_id),
            )

        try:
            user: dict[str, Any] | None = None
            if source["external_user_id"]:
                try:
                    user = pasarguard_get_user_by_id(str(source["external_user_id"]))
                except PasarGuardError as exc:
                    if exc.code != "pasarguard_http_404":
                        raise
            if user is None:
                user = pasarguard_get_user_by_username(connection_id)
            marker = f"managed-by=vpnenus-watcher; connection={connection_id}"
            if user is not None and not source["external_user_id"] and marker not in str(user.get("note") or ""):
                raise PasarGuardError(
                    HTTPStatus.CONFLICT,
                    "pasarguard_user_already_exists",
                    "A PasarGuard user with this permanent ID already exists and is not managed by Watcher.",
                )
            if user is None:
                validate_pasarguard_template_for_permanent_id(template_id)
                user = pasarguard_request(
                    "POST",
                    "/api/user/from_template",
                    {"user_template_id": template_id, "username": connection_id, "note": marker},
                )
            external_user_id, external_username, subscription_url = validate_pasarguard_user_identity(connection_id, user)
            fingerprint = pasarguard_credentials_fingerprint(user)
            with connect() as db:
                existing_configs = decoded_configurations(source["configurations_json"])
                upsert_connection_source(
                    db,
                    connection_id=connection_id,
                    provider="pasarguard",
                    external_user_id=external_user_id,
                    external_username=external_username,
                    template_id=template_id,
                    subscription_url=subscription_url,
                    configurations=existing_configs,
                    verify_tls=True,
                    credentials_fingerprint=fingerprint,
                )
                db.execute(
                    """
                    UPDATE issued_connections SET subscription_url = ?, verify_tls = 1,
                        provisioning_state = 'provisioning', provider_error = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (subscription_url, utc_now(), connection_id),
                )
                write_audit(
                    db,
                    "success",
                    "connection.pasarguard.provision",
                    connection_id,
                    actor,
                    "PasarGuard user identity was provisioned; importing its subscription snapshot.",
                    {"externalUserId": external_user_id, "templateId": template_id},
                )
            refresh_issued_connection(connection_id, actor)
            return load_issued_connection(connection_id)
        except SubscriptionScanError as exc:
            set_pasarguard_connection_error(connection_id, exc.code, actor, "PasarGuard user was created but subscription import failed.")
            raise PasarGuardError(exc.status, exc.code, "PasarGuard subscription import failed.") from exc
        except PasarGuardError as exc:
            set_pasarguard_connection_error(connection_id, exc.code, actor, exc.message)
            raise


def reset_pasarguard_connection(connection_id: str, actor: str) -> dict[str, Any]:
    with _pasarguard_operation_lock:
        with connect() as db:
            row = db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
            source = db.execute(
                "SELECT * FROM connection_sources WHERE connection_id = ? AND provider = 'pasarguard'",
                (connection_id,),
            ).fetchone()
            if row is None:
                raise PasarGuardError(HTTPStatus.NOT_FOUND, "connection_not_found")
            if source is None or not source["external_user_id"]:
                raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_user_not_provisioned")
            db.execute(
                "UPDATE issued_connections SET provisioning_state = 'resetting', provider_error = NULL, updated_at = ? WHERE id = ?",
                (utc_now(), connection_id),
            )

        try:
            user = pasarguard_get_user_by_id(str(source["external_user_id"]))
            current_external_id, _, _ = validate_pasarguard_user_identity(connection_id, user)
            if current_external_id != str(source["external_user_id"]):
                raise PasarGuardError(HTTPStatus.CONFLICT, "pasarguard_user_id_mismatch")
            current_fingerprint = pasarguard_credentials_fingerprint(user)
            pending_fingerprint = str(source["reset_from_fingerprint"] or "") or None
            if pending_fingerprint is None:
                if current_fingerprint is None:
                    raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_proxy_settings_missing")
                pending_fingerprint = current_fingerprint
                with connect() as db:
                    db.execute(
                        "UPDATE connection_sources SET reset_from_fingerprint = ?, updated_at = ? WHERE id = ?",
                        (pending_fingerprint, utc_now(), source["id"]),
                    )
            if current_fingerprint == pending_fingerprint:
                user = pasarguard_request(
                    "POST",
                    f"/api/user/by-id/{quote(str(source['external_user_id']), safe='')}/revoke_sub",
                )
            external_user_id, external_username, subscription_url = validate_pasarguard_user_identity(connection_id, user)
            new_fingerprint = pasarguard_credentials_fingerprint(user)
            if new_fingerprint is None or new_fingerprint == pending_fingerprint:
                raise PasarGuardError(HTTPStatus.BAD_GATEWAY, "pasarguard_credentials_not_rotated")
            with connect() as db:
                upsert_connection_source(
                    db,
                    connection_id=connection_id,
                    provider="pasarguard",
                    external_user_id=external_user_id,
                    external_username=external_username,
                    template_id=source["template_id"],
                    subscription_url=subscription_url,
                    configurations=decoded_configurations(source["configurations_json"]),
                    verify_tls=True,
                    credentials_fingerprint=new_fingerprint,
                    reset_from_fingerprint=pending_fingerprint,
                )
                db.execute(
                    "UPDATE issued_connections SET subscription_url = ?, verify_tls = 1, updated_at = ? WHERE id = ?",
                    (subscription_url, utc_now(), connection_id),
                )
            refresh_issued_connection(connection_id, actor)
            with connect() as db:
                db.execute(
                    "UPDATE connection_sources SET reset_from_fingerprint = NULL, updated_at = ? WHERE id = ?",
                    (utc_now(), source["id"]),
                )
                write_audit(
                    db,
                    "success",
                    "connection.pasarguard.reset",
                    connection_id,
                    actor,
                    "PasarGuard credentials and upstream subscription were reset without changing the permanent ID.",
                    {"externalUserId": external_user_id},
                )
            return load_issued_connection(connection_id)
        except SubscriptionScanError as exc:
            set_pasarguard_connection_error(connection_id, exc.code, actor, "PasarGuard credentials were reset but the new subscription import failed.")
            raise PasarGuardError(exc.status, exc.code, "New PasarGuard subscription import failed.") from exc
        except PasarGuardError as exc:
            set_pasarguard_connection_error(connection_id, exc.code, actor, exc.message)
            raise


def scan_due_connections() -> int:
    with connect() as db:
        interval_minutes = connection_scan_interval_minutes(db)
        rows = db.execute(
            """
            SELECT id, last_scan_at FROM issued_connections
            WHERE status = 'active' AND provisioning_state IN ('active', 'degraded')
            ORDER BY created_at
            """
        ).fetchall()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=interval_minutes)
    scanned = 0
    for row in rows:
        last_scan_at = row["last_scan_at"]
        if last_scan_at:
            try:
                if datetime.fromisoformat(last_scan_at) > cutoff:
                    continue
            except ValueError:
                pass
        try:
            refresh_issued_connection(row["id"], "watcher-scheduler")
        except SubscriptionScanError:
            pass
        scanned += 1
    return scanned


def run_connection_scanner(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            scan_due_connections()
        except sqlite3.Error as exc:
            print(f"connection scanner database error: {exc}")
        except Exception as exc:
            print(f"connection scanner unexpected error: {type(exc).__name__}")
        stop_event.wait(CONNECTION_SCAN_POLL_SECONDS)


def validate_register_payload(body: dict[str, Any], *, existing_key: str | None = None) -> tuple[dict[str, str] | None, str | None]:
    key = (existing_key or str(body.get("key") or "").strip())
    value = str(body.get("value") or "")
    description = str(body.get("description") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", key):
        return None, "invalid_register_key"
    if len(value) > 16384:
        return None, "register_value_too_long"
    if len(description) > 1024:
        return None, "register_description_too_long"
    if key in {"github.repository", "watcher.server_repository"}:
        value = value.strip()
        if not REGISTER_REPOSITORY_RE.fullmatch(value):
            return None, "invalid_github_repository"
    if key == "watcher.public_sni":
        value = value.strip().lower().rstrip(".")
        if not REGISTER_SNI_RE.fullmatch(value):
            return None, "invalid_watcher_public_sni"
    if key == "clients.heartbeat_interval_seconds":
        try:
            heartbeat_seconds = int(value)
        except (TypeError, ValueError):
            return None, "invalid_client_heartbeat_interval"
        if not 15 <= heartbeat_seconds <= 86400:
            return None, "invalid_client_heartbeat_interval"
        value = str(heartbeat_seconds)
    if key == "updates.manifest_public_key_pem":
        value = value.strip().replace("\\n", "\n")
        if value:
            try:
                public_key = serialization.load_pem_public_key(value.encode("utf-8"))
            except (TypeError, ValueError, UnsupportedAlgorithm):
                return None, "invalid_manifest_public_key"
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
                return None, "invalid_manifest_public_key"
    return {"key": key, "value": value, "description": description}, None


def safe_register_entry(value: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(value)
    if item.get("key") in SECRET_REGISTER_KEYS:
        item["configured"] = bool(str(item.get("value") or "").strip())
        item["secret"] = True
        item["value"] = ""
    else:
        item["configured"] = True
        item["secret"] = False
    return item


def device_value(device: dict[str, Any], name: str) -> str | None:
    value = device.get(name)
    return str(value) if value is not None and str(value).strip() else None


def platform_for_device(device: dict[str, Any]) -> str:
    value = str(device.get("platform") or device.get("deviceType") or "").strip().lower()
    if "android" in value:
        return "android"
    if "windows" in value:
        return "windows"
    return "unknown"


def client_online_window_seconds(heartbeat_interval_seconds: int) -> int:
    return max(ONLINE_WINDOW_SECONDS, heartbeat_interval_seconds * 2)


def is_online(last_seen_at: str | None, heartbeat_interval_seconds: int = CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT) -> bool:
    if not last_seen_at:
        return False
    try:
        seen = datetime.fromisoformat(last_seen_at)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - seen).total_seconds() <= client_online_window_seconds(heartbeat_interval_seconds)


def client_row(row: sqlite3.Row, heartbeat_interval_seconds: int = CLIENT_HEARTBEAT_INTERVAL_SECONDS_DEFAULT) -> dict[str, Any]:
    item = dict(row)
    item["online"] = is_online(item.get("last_seen_at"), heartbeat_interval_seconds)
    item["reachability_status"] = "online" if item["online"] else "offline"
    try:
        item["device"] = json.loads(item.get("device_json") or "{}")
    except json.JSONDecodeError:
        item["device"] = {}
    try:
        item["connections"] = json.loads(item.get("connections_json") or "[]")
    except json.JSONDecodeError:
        item["connections"] = []
    try:
        item["update_rule_sets"] = json.loads(item.get("update_rule_sets_json") or "[]")
    except json.JSONDecodeError:
        item["update_rule_sets"] = []
    item["auto_updates_enabled"] = bool(item.get("auto_updates_enabled")) if item.get("auto_updates_enabled") is not None else None
    item["logs_upload_enabled"] = bool(item.get("logs_upload_enabled")) if item.get("logs_upload_enabled") is not None else None
    item["update_report_status"] = "reported" if item.get("update_last_seen_at") else "waiting"
    return item


def sign(secret: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method.upper(), path, timestamp, body_hash]).encode("utf-8")
    key = base64.urlsafe_b64decode(secret + "=" * ((4 - len(secret) % 4) % 4))
    return base64.b64encode(hmac.new(key, canonical, hashlib.sha256).digest()).decode("ascii")


def verify_signature_with_secret(
    handler: BaseHTTPRequestHandler,
    raw_body: bytes,
    secret: str,
    expected_client_id: str | None = None,
) -> tuple[bool, str | None]:
    client_id = handler.headers.get("X-Loki-Client-Id", "")
    timestamp = handler.headers.get("X-Loki-Timestamp", "")
    signature = handler.headers.get("X-Loki-Signature", "")
    if not client_id or not timestamp or not signature:
        return False, None
    if expected_client_id is not None and not hmac.compare_digest(client_id, expected_client_id):
        return False, client_id
    try:
        if abs(time.time() - int(timestamp)) > MAX_SKEW_SECONDS:
            return False, client_id
        expected = sign(secret, handler.command, urlparse(handler.path).path, timestamp, raw_body)
    except (ValueError, TypeError):
        return False, client_id
    return hmac.compare_digest(signature, expected), client_id


def verify_client_signature(handler: BaseHTTPRequestHandler, raw_body: bytes, db: sqlite3.Connection) -> tuple[bool, str | None]:
    client_id = handler.headers.get("X-Loki-Client-Id", "")
    if not client_id:
        return False, None

    row = db.execute("SELECT client_secret FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    if row is None:
        return False, client_id
    return verify_signature_with_secret(handler, raw_body, row["client_secret"], client_id)


def count_by(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) if row.get(key) is not None else "-")
        counts[value] = counts.get(value, 0) + 1
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def manifest_rule_sets(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for item in manifest.get("ruleSets", [])
        if isinstance(item, dict) and item.get("id")
    }


def dashboard_rule_sets(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    actual = manifest_rule_sets(manifest)
    ordered_ids = RULE_SET_IDS or sorted(actual)
    result: list[dict[str, Any]] = []
    for rule_set_id in ordered_ids:
        item = dict(actual.get(rule_set_id) or {})
        item["id"] = rule_set_id
        item["status"] = "available" if item.get("url") and item.get("sha256") else "missing asset"
        item["version"] = item.get("version") or manifest.get("version")
        result.append(item)
    return result


def system_stats(clients: list[dict[str, Any]], issued_connections: int = 0) -> dict[str, Any]:
    total = sum(int(client.get("total_traffic_bytes") or 0) for client in clients)
    cpu_usage = None
    try:
        load1, _, _ = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        cpu_usage = round(min(100.0, (load1 / cpu_count) * 100.0), 1)
    except (OSError, AttributeError):
        pass

    ram_usage = None
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as file:
            for line in file:
                key, value = line.split(":", 1)
                meminfo[key] = int(value.strip().split()[0]) * 1024
        total_mem = meminfo.get("MemTotal")
        available_mem = meminfo.get("MemAvailable")
        if total_mem and available_mem is not None:
            ram_usage = {
                "usedBytes": total_mem - available_mem,
                "totalBytes": total_mem,
                "percent": round(((total_mem - available_mem) / total_mem) * 100, 1),
            }
    except (OSError, ValueError):
        pass

    disk_usage = None
    try:
        import shutil
        disk = shutil.disk_usage(os.path.dirname(DB_PATH) or ".")
        disk_usage = {
            "usedBytes": disk.used,
            "totalBytes": disk.total,
            "percent": round((disk.used / disk.total) * 100, 1) if disk.total else None,
        }
    except OSError:
        pass

    return {
        "totalTrafficBytes": total,
        "cpuUsagePercent": cpu_usage,
        "ram": ram_usage,
        "disk": disk_usage,
        "installedClients": len(clients),
        "activatedClients": len(clients),
        "issuedConnections": issued_connections,
    }


def dashboard_payload() -> dict[str, Any]:
    with connect() as db:
        rows = db.execute(
            """
            SELECT client_id, display_id, username, machine_name, platform, app_version, original_ip, last_ip,
                   region, provider, status, routing_mode, connections_json, total_traffic_bytes,
                   traffic_metering_mode, last_seen_at, device_json,
                   auto_updates_enabled, logs_upload_enabled, update_manifest_url,
                   update_fallback_manifest_url, update_last_check_success, update_last_check_message,
                   update_active_rule_set, update_rule_sets_json, update_last_seen_at
            FROM clients
            ORDER BY last_seen_at DESC;
            """
        ).fetchall()
        issued_connections = db.execute("SELECT COUNT(*) FROM issued_connections").fetchone()[0]
        client_repository = github_repository(db)
        heartbeat_interval_seconds = client_heartbeat_interval_seconds(db)
    clients = [client_row(row, heartbeat_interval_seconds) for row in rows]
    manifest = dashboard_manifest_snapshot()
    system = system_stats(clients, int(issued_connections))
    system["heartbeatIntervalSeconds"] = heartbeat_interval_seconds
    system["onlineWindowSeconds"] = client_online_window_seconds(heartbeat_interval_seconds)
    return {
        "system": system,
        "updates": {
            "channel": manifest.get("channel"),
            "version": manifest.get("version"),
            "minimumVersion": manifest.get("minimumVersion"),
            "publishedAt": manifest.get("publishedAt"),
            "installer": manifest.get("installer"),
            "watcher": manifest.get("watcher"),
            "ruleSets": dashboard_rule_sets(manifest),
            "githubRepository": client_repository,
            "githubRelease": GITHUB_RELEASE,
        },
        "summary": {
            "totalClients": len(clients),
            "versions": count_by(clients, "app_version"),
            "ruleSets": count_by(clients, "routing_mode"),
            "watcherEndpoints": count_by(clients, "update_manifest_url"),
            "updateReports": count_by(clients, "update_report_status"),
            "autoUpdates": count_by(clients, "auto_updates_enabled"),
            "logsUpload": count_by(clients, "logs_upload_enabled"),
        },
        "clients": clients,
    }


class WatcherHandler(BaseHTTPRequestHandler):
    server_version = "Watcher"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        super().end_headers()

    def begin_request(self) -> None:
        supplied = (self.headers.get("X-Request-Id") or "").strip()
        self.request_id = supplied if re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", supplied) else uuid.uuid4().hex
        _request_context.request_id = self.request_id
        _request_context.transport_method = self.command

    def do_OPTIONS(self) -> None:
        self.begin_request()
        json_response(self, HTTPStatus.NO_CONTENT, {})

    def do_GET(self) -> None:
        self.begin_request()
        init_db()
        path = urlparse(self.path).path
        if path == "/health":
            json_response(self, HTTPStatus.OK, {"status": "ok"})
            return

        if path.startswith("/sub/"):
            self.handle_public_subscription(path)
            return

        if path == "/manifest.json":
            try:
                payload = cached_manifest_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                add_cors_headers(self)
                self.end_headers()
                self.wfile.write(payload)
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError) as exc:
                json_response(self, HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return

        if path == "/manifest.json.sig":
            try:
                payload = cached_manifest_signature_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                add_cors_headers(self)
                self.end_headers()
                self.wfile.write(payload)
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError) as exc:
                json_response(self, HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return

        if path.startswith("/assets/"):
            file_name = path.rsplit("/", 1)[-1]
            if not file_name or "/" in file_name or "\\" in file_name:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_asset"})
                return
            payload = release_file_bytes(file_name)
            if payload is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "asset_not_found"})
                return
            content_type = "application/zip" if file_name.endswith(".zip") else "application/octet-stream"
            binary_response(self, HTTPStatus.OK, payload, content_type, file_name)
            return

        if path == "/api/v1/dashboard":
            if not dashboard_authorized(self):
                auth_required_response(self)
                return
            try:
                json_response(self, HTTPStatus.OK, dashboard_payload())
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                json_response(self, HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return

        if path.startswith("/api/v1/commands/"):
            self.handle_commands(path)
            return

        if path == "/api/v1/clients":
            self.handle_clients()
            return

        if path == "/api/v1/analytics":
            self.handle_analytics()
            return

        if path.startswith("/api/v1/analytics/"):
            self.handle_analytics_detail(path)
            return

        if path == "/api/v1/connections":
            self.handle_connections()
            return

        if path == "/api/v1/register":
            self.handle_register()
            return

        if path == "/api/v1/settings":
            self.handle_settings()
            return

        if path == "/api/v1/updater/policy":
            self.handle_updater_policy()
            return

        if path in {"/api/v1/server-updates/status", "/api/v1/server-updates/check"} or path.startswith("/api/v1/server-updates/jobs/"):
            self.handle_server_update_query(path)
            return

        if path == "/api/v1/audit":
            self.handle_audit()
            return

        if path == "/api/v1/logs/download":
            self.handle_logs_download()
            return

        if path.startswith("/api/v1/clients/") and path.endswith("/logs.zip"):
            self.handle_client_logs_download(path)
            return

        if path.startswith("/api/v1/clients/"):
            self.handle_client_detail(path)
            return

        if path == "/api/v1/backups/download":
            self.handle_backup_download()
            return

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        self.begin_request()
        init_db()
        path = urlparse(self.path).path
        try:
            if path == "/api/v1/enroll":
                self.handle_enroll()
                return

            if path == "/api/v1/client/connections/initialize":
                self.handle_initialize_client_connection()
                return

            if path == "/api/v1/telemetry/batch":
                self.handle_batch()
                return

            if path == "/api/v1/analytics/batch":
                self.handle_analytics_batch()
                return

            if path == "/api/v1/update-state":
                self.handle_update_state()
                return

            if path == "/api/v1/request-data":
                self.handle_request_data()
                return

            if path.startswith("/api/v1/commands/") and path.endswith("/collect-now"):
                self.handle_collect_now(path)
                return

            if path.startswith("/api/v1/commands/"):
                self.handle_create_command(path)
                return

            if path == "/api/v1/backups/upload":
                self.handle_backup_upload()
                return

            if path == "/api/v1/settings/password":
                self.handle_change_password()
                return

            if path == "/api/v1/server-updates/jobs":
                self.handle_start_server_update()
                return

            if path == "/api/v1/connections":
                self.handle_create_connection()
                return

            if path == "/api/v1/connections/scan":
                self.handle_scan_subscription()
                return

            if path.startswith("/api/v1/connections/") and path.endswith("/scan"):
                self.handle_rescan_connection(path)
                return

            if path.startswith("/api/v1/connections/") and path.endswith("/pasarguard/provision"):
                self.handle_pasarguard_provision(path)
                return

            if path.startswith("/api/v1/connections/") and path.endswith("/pasarguard/reset"):
                self.handle_pasarguard_reset(path)
                return

            if path == "/api/v1/register":
                self.handle_create_register_entry()
                return

            json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except RequestBodyError as exc:
            json_response(self, exc.status, {"error": exc.code})

    def do_PUT(self) -> None:
        self.begin_request()
        init_db()
        path = urlparse(self.path).path
        try:
            if path == "/api/v1/settings/connections":
                self.handle_update_connection_settings()
                return
            if path.startswith("/api/v1/connections/"):
                self.handle_update_connection(path)
                return
            if path.startswith("/api/v1/register/"):
                self.handle_update_register_entry(path)
                return
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except RequestBodyError as exc:
            json_response(self, exc.status, {"error": exc.code})

    def do_DELETE(self) -> None:
        self.begin_request()
        init_db()
        path = urlparse(self.path).path
        if path.startswith("/api/v1/clients/"):
            self.handle_delete_client(path)
            return

        if path.startswith("/api/v1/connections/"):
            self.handle_delete_connection(path)
            return

        if path.startswith("/api/v1/register/"):
            self.handle_delete_register_entry(path)
            return

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def handle_update_state(self) -> None:
        try:
            body, raw = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        client_id = str(body.get("clientId", "")).strip()
        display_id = str(body.get("displayId", "")).strip()
        if not client_id or not display_id:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "missing_identity"})
            return

        ip = client_ip(self)
        network = network_info_for_ip(ip)
        platform = platform_for_device(body)
        now = utc_now()
        with connect() as db:
            ok, signed_client_id = verify_client_signature(self, raw, db)
            if not ok or signed_client_id != client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return

            db.execute(
                """
                UPDATE clients SET
                    display_id = ?,
                    last_ip = ?,
                    region = ?,
                    provider = ?,
                    platform = CASE WHEN ? = 'unknown' THEN platform ELSE ? END,
                    app_version = COALESCE(?, app_version),
                    routing_mode = COALESCE(?, routing_mode),
                    auto_updates_enabled = ?,
                    logs_upload_enabled = ?,
                    update_manifest_url = ?,
                    update_fallback_manifest_url = ?,
                    update_last_check_success = ?,
                    update_last_check_message = ?,
                    update_active_rule_set = ?,
                    update_rule_sets_json = ?,
                    update_last_seen_at = ?,
                    last_seen_at = ?
                WHERE client_id = ?;
                """,
                (
                    display_id,
                    ip,
                    network["region"],
                    network["provider"],
                    platform,
                    platform,
                    body.get("appVersion"),
                    body.get("routingMode"),
                    1 if body.get("autoUpdatesEnabled") else 0,
                    1 if body.get("logsUploadEnabled") else 0,
                    body.get("updateManifestUrl"),
                    body.get("updateFallbackManifestUrl"),
                    1 if body.get("lastCheckSuccess") else 0,
                    body.get("lastCheckMessage"),
                    body.get("activeRuleSet"),
                    json.dumps(body.get("ruleSets") if isinstance(body.get("ruleSets"), list) else [], separators=(",", ":")),
                    now,
                    now,
                    client_id,
                ),
            )
        json_response(self, HTTPStatus.OK, {"status": "accepted"})

    def handle_request_data(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        queued = []
        skipped = []
        with connect() as db:
            heartbeat_interval_seconds = client_heartbeat_interval_seconds(db)
            rows = db.execute("SELECT client_id, display_id, last_seen_at FROM clients ORDER BY last_seen_at DESC").fetchall()
            for row in rows:
                if not is_online(row["last_seen_at"], heartbeat_interval_seconds):
                    skipped.append({"clientId": row["client_id"], "displayId": row["display_id"], "reason": "offline"})
                    continue
                command_id = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO commands (id, client_id, type, payload_json, status, created_at) VALUES (?, ?, 'check_updates', '{}', 'pending', ?)",
                    (command_id, row["client_id"], utc_now()),
                )
                queued.append({"clientId": row["client_id"], "displayId": row["display_id"], "commandId": command_id})
            write_audit(
                db,
                "success",
                "clients.request_updates",
                "online-clients",
                dashboard_actor(self),
                f"Queued update checks for {len(queued)} clients; skipped {len(skipped)} offline clients.",
            )

        json_response(self, HTTPStatus.OK, {"status": "queued", "queued": len(queued), "skipped": skipped, "failed": [], "clients": queued})

    def handle_enroll(self) -> None:
        try:
            body, raw = read_json(self)
            client_id = str(body.get("clientId", "")).strip()
            display_id = str(body.get("displayId", "")).strip()
            client_secret = str(body.get("clientSecret", "")).strip()
            device = body.get("device") if isinstance(body.get("device"), dict) else {}
            if not client_id or not display_id or not client_secret:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "missing_identity"})
                return
            if len(client_id) > 128 or len(display_id) > 128 or len(client_secret) > 256:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_identity"})
                return
            signed, signed_client_id = verify_signature_with_secret(self, raw, client_secret, client_id)
            if not signed or signed_client_id != client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return

            ip = client_ip(self)
            network = network_info_for_ip(ip)
            now = utc_now()
            with connect() as db:
                existing = db.execute(
                    "SELECT client_secret FROM clients WHERE client_id = ?",
                    (client_id,),
                ).fetchone()
                if existing is not None and existing["client_secret"] and not hmac.compare_digest(existing["client_secret"], client_secret):
                    write_audit(
                        db,
                        "denied",
                        "client.enroll",
                        client_id,
                        f"client:{client_id}",
                        "Enrollment rejected because the stable identity already has another credential.",
                        actor_type="client",
                        target_type="client",
                    )
                    json_response(self, HTTPStatus.CONFLICT, {"error": "client_identity_conflict"})
                    return
                db.execute(
                    """
                    INSERT INTO clients (
                        client_id, display_id, client_secret, username, machine_name, platform, app_version,
                        os, windows_version, installed_at, original_ip, last_ip, region, provider, device_json,
                        status, total_traffic_bytes, created_at, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disconnected', 0, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        display_id = excluded.display_id,
                        client_secret = CASE WHEN clients.client_secret = '' THEN excluded.client_secret ELSE clients.client_secret END,
                        username = excluded.username,
                        machine_name = excluded.machine_name,
                        platform = excluded.platform,
                        app_version = excluded.app_version,
                        os = excluded.os,
                        windows_version = excluded.windows_version,
                        installed_at = COALESCE(clients.installed_at, excluded.installed_at),
                        original_ip = CASE WHEN clients.original_ip IS NULL OR clients.original_ip = '' THEN excluded.original_ip ELSE clients.original_ip END,
                        last_ip = excluded.last_ip,
                        region = excluded.region,
                        provider = excluded.provider,
                        device_json = excluded.device_json,
                        last_seen_at = excluded.last_seen_at;
                    """,
                    (
                        client_id,
                        display_id,
                        client_secret,
                        device_value(device, "userName"),
                        device_value(device, "machineName"),
                        platform_for_device(device),
                        device_value(device, "appVersion"),
                        device_value(device, "os"),
                        device_value(device, "windowsVersion"),
                        device_value(device, "installedAt"),
                        ip,
                        ip,
                        network["region"],
                        network["provider"],
                        json.dumps(device),
                        now,
                        now,
                    ),
                )
                write_audit(
                    db,
                    "success",
                    "client.enroll",
                    client_id,
                    f"client:{client_id}",
                    "Client enrollment accepted.",
                    {"created": existing is None, "displayId": display_id},
                    actor_type="client",
                    target_type="client",
                )
            with connect() as db:
                runtime_config = client_runtime_config(db)
            json_response(
                self,
                HTTPStatus.OK,
                {
                    "status": "enrolled",
                    "clientConfig": runtime_config,
                },
            )
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})

    def handle_analytics_batch(self) -> None:
        try:
            body, raw = read_json(self, max_bytes=MAX_ANALYTICS_REQUEST_BYTES)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        reports = body.get("reports")
        requested_client_id = str(body.get("clientId") or "").strip()
        if not requested_client_id:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "missing_identity"})
            return
        if not isinstance(reports, list) or not reports:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "analytics_reports_required"})
            return
        if len(reports) > MAX_ANALYTICS_REPORTS_PER_BATCH:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "too_many_analytics_reports"})
            return

        prepared: list[dict[str, Any]] = []
        for report in reports:
            if not isinstance(report, dict):
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_report"})
                return
            report_id = str(report.get("reportId") or "").strip()
            report_type = str(report.get("type") or "").strip().lower()
            occurred_at = str(report.get("occurredAt") or "").strip()
            schema_version = str(report.get("schemaVersion") or "1.0").strip()[:32]
            engine_version = str(report.get("engineVersion") or "").strip()[:64] or None
            status = str(report.get("status") or "").strip()[:64] or None
            summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
            payload = report.get("payload")
            if not ANALYTICS_REPORT_ID_RE.fullmatch(report_id):
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_report_id"})
                return
            if report_type not in ANALYTICS_REPORT_TYPES:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_report_type"})
                return
            if not isinstance(payload, dict):
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "analytics_payload_required"})
                return
            try:
                parsed_time = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
                if parsed_time.tzinfo is None:
                    raise ValueError("timezone required")
                occurred_at = parsed_time.astimezone(timezone.utc).isoformat()
            except ValueError:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_timestamp"})
                return
            safe_payload = redact_analytics_payload(payload)
            safe_summary = redact_analytics_payload(summary)
            payload_json = json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":"))
            payload_bytes = len(payload_json.encode("utf-8"))
            if payload_bytes > MAX_ANALYTICS_REPORT_BYTES:
                json_response(self, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "analytics_report_too_large", "reportId": report_id})
                return
            prepared.append({
                "report_id": report_id,
                "report_type": report_type,
                "occurred_at": occurred_at,
                "schema_version": schema_version or "1.0",
                "engine_version": engine_version,
                "status": status,
                "summary_json": json.dumps(safe_summary, ensure_ascii=False, separators=(",", ":")),
                "payload_json": payload_json,
                "payload_bytes": payload_bytes,
            })
        if len({report["report_id"] for report in prepared}) != len(prepared):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "duplicate_analytics_report_id"})
            return

        accepted: list[str] = []
        with connect() as db:
            ok, signed_client_id = verify_client_signature(self, raw, db)
            if not ok or signed_client_id != requested_client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return
            now = utc_now()
            touch_client_contact(db, requested_client_id, self, now)
            existing_owners: dict[str, str] = {}
            for report in prepared:
                existing = db.execute(
                    "SELECT client_id FROM analytics_reports WHERE report_id = ?",
                    (report["report_id"],),
                ).fetchone()
                if existing is not None:
                    existing_owners[report["report_id"]] = existing["client_id"]
            if any(owner != requested_client_id for owner in existing_owners.values()):
                json_response(self, HTTPStatus.CONFLICT, {"error": "analytics_report_id_conflict"})
                return
            for report in prepared:
                if report["report_id"] in existing_owners:
                    accepted.append(report["report_id"])
                    continue
                db.execute(
                    """
                    INSERT INTO analytics_reports (
                        report_id, client_id, report_type, occurred_at, received_at,
                        schema_version, engine_version, status, summary_json,
                        payload_json, payload_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report["report_id"], requested_client_id, report["report_type"],
                        report["occurred_at"], now, report["schema_version"],
                        report["engine_version"], report["status"], report["summary_json"],
                        report["payload_json"], report["payload_bytes"],
                    ),
                )
                accepted.append(report["report_id"])

        json_response(self, HTTPStatus.OK, {"status": "accepted", "acceptedReportIds": accepted})

    def handle_batch(self) -> None:
        try:
            body, raw = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        with connect() as db:
            ok, client_id = verify_client_signature(self, raw, db)
            if not ok or not client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return

            events = body.get("events")
            device = body.get("device") if isinstance(body.get("device"), dict) else {}
            if not isinstance(events, list):
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "events_required"})
                return
            if len(events) > MAX_TELEMETRY_EVENTS_PER_BATCH:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "too_many_events"})
                return

            ip = client_ip(self)
            network = network_info_for_ip(ip)
            now = utc_now()
            status = "unknown"
            total = 0
            routing_mode = None
            connections_json = None
            traffic_metering_mode = None
            logs_upload_enabled = None
            auto_updates_enabled = None
            for event in events:
                if not isinstance(event, dict):
                    continue
                safe_event = redact_for_logging(event)
                payload_json = json.dumps(safe_event, ensure_ascii=False, separators=(",", ":"))
                if len(payload_json.encode("utf-8")) > MAX_TELEMETRY_EVENT_BYTES:
                    payload_json = json.dumps(
                        {
                            "truncated": True,
                            "originalSha256": hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
                            "type": str(event.get("type") or "event")[:128],
                            "message": "Telemetry event exceeded the per-event storage limit.",
                        },
                        separators=(",", ":"),
                    )
                status = str(event.get("connectionStatus") or status)[:64]
                total = max(total, int(event.get("trafficTotalBytes") or 0))
                if event.get("routingMode"):
                    routing_mode = str(event.get("routingMode"))
                if isinstance(event.get("connections"), list):
                    connections_json = json.dumps(event.get("connections"), separators=(",", ":"))
                if event.get("trafficMeteringMode"):
                    traffic_metering_mode = str(event.get("trafficMeteringMode"))[:64]
                if "logsUploadEnabled" in event:
                    logs_upload_enabled = 1 if event.get("logsUploadEnabled") else 0
                if "autoUpdatesEnabled" in event:
                    auto_updates_enabled = 1 if event.get("autoUpdatesEnabled") else 0
                db.execute(
                    """
                    INSERT INTO events (
                        client_id, created_at, type, status, traffic_delta_bytes,
                        traffic_total_bytes, message, payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        client_id,
                        str(event.get("timestamp") or now),
                        str(event.get("type") or "event")[:128],
                        status,
                        int(event.get("trafficDeltaBytes") or 0),
                        int(event.get("trafficTotalBytes") or 0),
                        redact_log_string(str(event.get("message")))[:AUDIT_MESSAGE_MAX_CHARS] if event.get("message") is not None else None,
                        payload_json,
                    ),
                )

            db.execute(
                """
                UPDATE clients SET
                    last_ip = ?,
                    region = ?,
                    provider = ?,
                    username = COALESCE(?, username),
                    machine_name = COALESCE(?, machine_name),
                    platform = CASE WHEN ? = 'unknown' THEN platform ELSE ? END,
                    app_version = COALESCE(?, app_version),
                    os = COALESCE(?, os),
                    windows_version = COALESCE(?, windows_version),
                    installed_at = COALESCE(installed_at, ?),
                    device_json = ?,
                    routing_mode = COALESCE(?, routing_mode),
                    connections_json = COALESCE(?, connections_json),
                    status = ?,
                    total_traffic_bytes = MAX(total_traffic_bytes, ?),
                    traffic_metering_mode = COALESCE(?, traffic_metering_mode),
                    logs_upload_enabled = COALESCE(?, logs_upload_enabled),
                    auto_updates_enabled = COALESCE(?, auto_updates_enabled),
                    last_seen_at = ?
                WHERE client_id = ?;
                """,
                (
                    ip,
                    network["region"],
                    network["provider"],
                    device_value(device, "userName"),
                    device_value(device, "machineName"),
                    platform_for_device(device),
                    platform_for_device(device),
                    device_value(device, "appVersion"),
                    device_value(device, "os"),
                    device_value(device, "windowsVersion"),
                    device_value(device, "installedAt"),
                    json.dumps(device),
                    routing_mode,
                    connections_json,
                    status,
                    total,
                    traffic_metering_mode,
                    logs_upload_enabled,
                    auto_updates_enabled,
                    now,
                    client_id,
                ),
            )

        with connect() as db:
            runtime_config = client_runtime_config(db)
        json_response(
            self,
            HTTPStatus.OK,
            {
                "status": "accepted",
                "count": len(events),
                "clientConfig": runtime_config,
            },
        )

    def handle_commands(self, path: str) -> None:
        with connect() as db:
            ok, client_id = verify_client_signature(self, b"", db)
            requested_client_id = path.rsplit("/", 1)[-1]
            if not ok or client_id != requested_client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return

            touch_client_contact(db, client_id, self)

            rows = db.execute(
                "SELECT id, type, payload_json FROM commands WHERE client_id = ? AND status = 'pending' ORDER BY created_at LIMIT 20",
                (client_id,),
            ).fetchall()
            command_ids = [row["id"] for row in rows]
            if command_ids:
                db.executemany(
                    "UPDATE commands SET status = 'delivered', delivered_at = ? WHERE id = ?",
                    [(utc_now(), command_id) for command_id in command_ids],
                )

        commands = []
        for row in rows:
            item = {"id": row["id"], "type": row["type"]}
            try:
                item["payload"] = json.loads(row["payload_json"] or "{}")
            except json.JSONDecodeError:
                item["payload"] = {}
            commands.append(item)

        json_response(self, HTTPStatus.OK, {"commands": commands})

    def handle_connections(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        with connect() as db:
            rows = db.execute(
                """
                SELECT id, telegram_id, telegram_username, subscription_url, configurations_json,
                       verify_tls, status, public_token, revision, provisioning_state, provider_error,
                       last_scan_at, last_scan_status, last_scan_message, subscription_renewal_date,
                       track_subscription, created_at, updated_at
                FROM issued_connections
                ORDER BY created_at DESC, id
                """
            ).fetchall()
            base_url = watcher_public_url(db)
            items = [
                issued_connection_row(row, base_url=base_url, sources=connection_source_rows(db, row["id"]))
                for row in rows
            ]
        json_response(self, HTTPStatus.OK, {"connections": items})

    def handle_create_connection(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        item, error = validate_connection_payload(body)
        if error or item is None:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            return
        now = utc_now()
        public_token = secrets.token_urlsafe(32)
        provisioning_state = "active" if item["configurations"] else "draft"
        try:
            with connect() as db:
                db.execute(
                    """
                    INSERT INTO issued_connections
                        (id, telegram_id, telegram_username, subscription_url, configurations_json,
                         verify_tls, status, public_token, revision, provisioning_state,
                         subscription_renewal_date, track_subscription, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["id"], None, None, "",
                        json.dumps(item["configurations"], ensure_ascii=False, separators=(",", ":")),
                        int(item["verifyTls"]), item["status"],
                        public_token, provisioning_state, item["subscriptionRenewalDate"],
                        int(item["trackSubscription"]), now, now,
                    ),
                )
                upsert_connection_source(
                    db,
                    connection_id=item["id"],
                    provider="direct",
                    subscription_url="",
                    configurations=item["configurations"],
                    verify_tls=item["verifyTls"],
                )
                write_audit(db, "success", "connection.create", item["id"], dashboard_actor(self), "Issued connection created.")
        except sqlite3.IntegrityError:
            json_response(self, HTTPStatus.CONFLICT, {"error": "connection_already_exists"})
            return
        json_response(self, HTTPStatus.CREATED, {"connection": load_issued_connection(item["id"])})

    def handle_update_connection(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        connection_id = unquote(path.removeprefix("/api/v1/connections/")).strip()
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        with connect() as db:
            existing_connection = db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
        if existing_connection is None:
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "connection_not_found"})
            return
        if "subscriptionRenewalDate" not in body:
            body["subscriptionRenewalDate"] = existing_connection["subscription_renewal_date"]
        if "trackSubscription" not in body:
            body["trackSubscription"] = bool(existing_connection["track_subscription"])
        item, error = validate_connection_payload(body, connection_id=connection_id)
        if error or item is None:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            return
        now = utc_now()
        with connect() as db:
            upsert_connection_source(
                db,
                connection_id=item["id"],
                provider="direct",
                subscription_url="",
                configurations=item["configurations"],
                verify_tls=item["verifyTls"],
            )
            configurations = aggregate_connection_sources(db, item["id"])
            provisioning_state = "active" if configurations else "draft"
            result = db.execute(
                """
                UPDATE issued_connections
                SET configurations_json = ?, verify_tls = ?, status = ?, provisioning_state = ?,
                    subscription_renewal_date = ?, track_subscription = ?, provider_error = NULL,
                    revision = revision + 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(configurations, ensure_ascii=False, separators=(",", ":")),
                    int(item["verifyTls"]), item["status"], provisioning_state,
                    item["subscriptionRenewalDate"], int(item["trackSubscription"]), now, item["id"],
                ),
            )
            if result.rowcount == 0:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "connection_not_found"})
                return
            write_audit(db, "success", "connection.update", item["id"], dashboard_actor(self), "Issued connection updated.")
        json_response(self, HTTPStatus.OK, {"connection": load_issued_connection(item["id"])})

    def handle_initialize_client_connection(self) -> None:
        try:
            body, raw = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        client_id = str(body.get("clientId") or "").strip()
        if not client_id:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "missing_identity"})
            return

        with _client_connection_initialization_lock:
            with connect() as db:
                ok, signed_client_id = verify_client_signature(self, raw, db)
                if not ok or signed_client_id != client_id:
                    json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                    return
                client = db.execute(
                    "SELECT connection_id FROM clients WHERE client_id = ?",
                    (client_id,),
                ).fetchone()
                if client is None:
                    json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                    return
                touch_client_contact(db, client_id, self)

                connection_id = str(client["connection_id"] or "").strip()
                connection = (
                    db.execute("SELECT * FROM issued_connections WHERE id = ?", (connection_id,)).fetchone()
                    if connection_id
                    else None
                )
                created = connection is None
                if created:
                    connection_id = f"client-{uuid.uuid4().hex[:20]}"
                    now = utc_now()
                    db.execute(
                        """
                        INSERT INTO issued_connections
                            (id, telegram_id, telegram_username, subscription_url, configurations_json,
                             verify_tls, status, public_token, revision, provisioning_state,
                             subscription_renewal_date, track_subscription, created_at, updated_at)
                        VALUES (?, NULL, NULL, '', '[]', 1, 'active', ?, 1, 'draft', ?, 1, ?, ?)
                        """,
                        (connection_id, secrets.token_urlsafe(32), date.today().isoformat(), now, now),
                    )
                    upsert_connection_source(
                        db,
                        connection_id=connection_id,
                        provider="direct",
                        subscription_url="",
                        configurations=[],
                        verify_tls=True,
                    )
                    db.execute(
                        "UPDATE clients SET connection_id = ? WHERE client_id = ?",
                        (connection_id, client_id),
                    )
                    write_audit(
                        db,
                        "success",
                        "client.connection.create",
                        connection_id,
                        f"client:{client_id}",
                        "A stable managed connection was allocated to the client.",
                        {"clientId": client_id},
                        actor_type="client",
                        target_type="connection",
                    )

            try:
                current = load_issued_connection(connection_id)
                pasar_source = next(
                    (source for source in current.get("sources", []) if source.get("provider") == "pasarguard"),
                    None,
                )
                if not pasar_source or not pasar_source.get("external_user_id") or not current.get("configurations"):
                    current = provision_pasarguard_connection(connection_id, f"client:{client_id}")
            except PasarGuardError as exc:
                json_response(self, exc.status, {"error": exc.code, "message": exc.message})
                return

            with connect() as db:
                runtime_config = client_runtime_config(db)
            json_response(
                self,
                HTTPStatus.CREATED if created else HTTPStatus.OK,
                {
                    "status": "ready",
                    "created": created,
                    "connectionId": current["id"],
                    "subscriptionUrl": current["public_subscription_url"],
                    "createdAt": current["created_at"],
                    "updatedAt": current["updated_at"],
                    "count": len(current.get("configurations", [])),
                    "clientConfig": runtime_config,
                },
            )

    def handle_scan_subscription(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        subscription_url = str(body.get("subscriptionUrl") or "").strip()
        verify_tls = bool(body.get("verifyTls", True))
        try:
            configurations = fetch_subscription(subscription_url, verify_tls)
        except ValueError as exc:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError):
            json_response(self, HTTPStatus.BAD_GATEWAY, {"error": "subscription_fetch_failed"})
            return
        json_response(self, HTTPStatus.OK, {"configurations": configurations, "count": len(configurations)})

    def handle_rescan_connection(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        connection_id = unquote(path.removeprefix("/api/v1/connections/").removesuffix("/scan")).strip()
        try:
            result = refresh_issued_connection(connection_id, dashboard_actor(self))
        except SubscriptionScanError as exc:
            json_response(self, exc.status, {"error": exc.code})
            return
        json_response(self, HTTPStatus.OK, result)

    def handle_pasarguard_provision(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        connection_id = unquote(
            path.removeprefix("/api/v1/connections/").removesuffix("/pasarguard/provision")
        ).strip("/")
        try:
            connection = provision_pasarguard_connection(connection_id, dashboard_actor(self))
        except PasarGuardError as exc:
            json_response(self, exc.status, {"error": exc.code, "message": exc.message})
            return
        json_response(self, HTTPStatus.OK, {"connection": connection})

    def handle_pasarguard_reset(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        connection_id = unquote(
            path.removeprefix("/api/v1/connections/").removesuffix("/pasarguard/reset")
        ).strip("/")
        try:
            connection = reset_pasarguard_connection(connection_id, dashboard_actor(self))
        except PasarGuardError as exc:
            json_response(self, exc.status, {"error": exc.code, "message": exc.message})
            return
        json_response(self, HTTPStatus.OK, {"connection": connection})

    def handle_public_subscription(self, path: str) -> None:
        token = unquote(path.removeprefix("/sub/")).strip("/")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "subscription_not_found"})
            return
        with connect() as db:
            row = db.execute(
                """
                SELECT id, configurations_json, subscription_renewal_date, track_subscription, created_at
                FROM issued_connections
                WHERE public_token = ? AND status = 'active' AND provisioning_state IN ('active', 'degraded')
                """,
                (token,),
            ).fetchone()
        if row is None:
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "subscription_not_found"})
            return
        configurations = decoded_configurations(row["configurations_json"])
        if not configurations:
            json_response(self, HTTPStatus.SERVICE_UNAVAILABLE, {"error": "subscription_not_ready"})
            return
        requested = str(parse_qs(urlparse(self.path).query).get("format", [""])[0]).lower()
        if requested in {"raw", "links"}:
            response_format = "raw"
        elif requested in {"", "base64", "links_base64"}:
            response_format = "base64"
        elif requested in {"json", "loki"}:
            json_response(
                self,
                HTTPStatus.OK,
                {
                    "type": "loki-managed-subscription",
                    "version": 1,
                    "connectionId": row["id"],
                    "createdAt": row["created_at"],
                    "subscriptionRenewalDate": row["subscription_renewal_date"],
                    "trackSubscription": bool(row["track_subscription"]),
                    "configurations": configurations,
                },
            )
            return
        else:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "unsupported_subscription_format"})
            return
        subscription_response(self, configurations, response_format)

    def handle_delete_connection(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        connection_id = unquote(path.removeprefix("/api/v1/connections/")).strip()
        with connect() as db:
            db.execute("DELETE FROM connection_sources WHERE connection_id = ?", (connection_id,))
            result = db.execute("DELETE FROM issued_connections WHERE id = ?", (connection_id,))
            if result.rowcount == 0:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "connection_not_found"})
                return
            write_audit(db, "success", "connection.delete", connection_id, dashboard_actor(self), "Issued connection deleted.")
        json_response(self, HTTPStatus.OK, {"status": "deleted", "id": connection_id})

    def handle_register(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        with connect() as db:
            rows = db.execute(
                "SELECT key, value, description, created_at, updated_at FROM register_entries ORDER BY key"
            ).fetchall()
        json_response(self, HTTPStatus.OK, {"entries": [safe_register_entry(row) for row in rows]})

    def handle_create_register_entry(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        item, error = validate_register_payload(body)
        if error or item is None:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            return
        now = utc_now()
        try:
            with connect() as db:
                db.execute(
                    "INSERT INTO register_entries (key, value, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (item["key"], item["value"], item["description"], now, now),
                )
                write_audit(db, "success", "register.create", item["key"], dashboard_actor(self), "Register value created.")
        except sqlite3.IntegrityError:
            json_response(self, HTTPStatus.CONFLICT, {"error": "register_key_already_exists"})
            return
        if item["key"] in {"github.repository", "watcher.public_sni"}:
            invalidate_manifest_cache()
        json_response(
            self,
            HTTPStatus.CREATED,
            {"entry": safe_register_entry({**item, "created_at": now, "updated_at": now})},
        )

    def handle_update_register_entry(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        key = unquote(path.removeprefix("/api/v1/register/")).strip()
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        item, error = validate_register_payload(body, existing_key=key)
        if error or item is None:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            return
        now = utc_now()
        with connect() as db:
            if key in SECRET_REGISTER_KEYS and body.get("preserveSecret") is True and not item["value"]:
                existing = db.execute("SELECT value FROM register_entries WHERE key = ?", (key,)).fetchone()
                if existing is not None:
                    item["value"] = str(existing["value"] or "")
            if key in SECRET_REGISTER_KEYS and body.get("clearSecret") is True:
                item["value"] = ""
            result = db.execute(
                "UPDATE register_entries SET value = ?, description = ?, updated_at = ? WHERE key = ?",
                (item["value"], item["description"], now, key),
            )
            if result.rowcount == 0:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "register_key_not_found"})
                return
            write_audit(db, "success", "register.update", key, dashboard_actor(self), "Register value updated.")
        if key in {"github.repository", "watcher.public_sni"}:
            invalidate_manifest_cache()
        json_response(
            self,
            HTTPStatus.OK,
            {"entry": safe_register_entry({**item, "updated_at": now})},
        )

    def handle_delete_register_entry(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        key = unquote(path.removeprefix("/api/v1/register/")).strip()
        with connect() as db:
            result = db.execute("DELETE FROM register_entries WHERE key = ?", (key,))
            if result.rowcount == 0:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "register_key_not_found"})
                return
            write_audit(db, "success", "register.delete", key, dashboard_actor(self), "Register value deleted.")
        if key in {"github.repository", "watcher.public_sni"}:
            invalidate_manifest_cache()
        json_response(self, HTTPStatus.OK, {"status": "deleted", "key": key})

    def handle_updater_policy(self) -> None:
        if not local_control_authorized(self):
            json_response(self, HTTPStatus.FORBIDDEN, {"error": "local_control_auth_required"})
            return
        try:
            policy = updater_policy_document()
        except UpdaterBridgeError as exc:
            json_response(self, exc.status, {"error": exc.code, "message": exc.message})
            return
        json_response(self, HTTPStatus.OK, policy)

    def handle_server_update_query(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        if path == "/api/v1/server-updates/status":
            daemon_path = f"/v1/services/{UPDATER_SERVICE_ID}/status"
            timeout = 2.0
        elif path == "/api/v1/server-updates/check":
            daemon_path = f"/v1/services/{UPDATER_SERVICE_ID}/releases/check"
            timeout = 30.0
        else:
            request_id = path.removeprefix("/api/v1/server-updates/jobs/")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", request_id):
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_request_id"})
                return
            daemon_path = f"/v1/services/{UPDATER_SERVICE_ID}/jobs/{request_id}"
            timeout = 3.0
        try:
            status, response = updater_socket_request("GET", daemon_path, timeout=timeout)
        except UpdaterBridgeError as exc:
            if path == "/api/v1/server-updates/check" and exc.code == "updater_unavailable":
                try:
                    json_response(self, HTTPStatus.OK, discover_server_release_without_updater())
                except UpdaterBridgeError as discovery_error:
                    json_response(self, discovery_error.status, {"error": discovery_error.code, "message": discovery_error.message})
                return
            json_response(self, exc.status, {"error": exc.code, "message": exc.message})
            return
        json_response(self, status, response)

    def handle_start_server_update(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        if not isinstance(body, dict) or set(body) - {"version", "requestId"}:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_update_request"})
            return
        version = str(body.get("version") or "").strip()
        request_id = str(body.get("requestId") or uuid.uuid4().hex).strip()
        if not SERVER_RELEASE_VERSION_RE.fullmatch(version):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_version"})
            return
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", request_id):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_request_id"})
            return
        actor = dashboard_actor(self)
        try:
            status, response = updater_socket_request(
                "POST",
                f"/v1/services/{UPDATER_SERVICE_ID}/jobs",
                body={"requestId": request_id, "version": version},
                mutation=True,
                timeout=5.0,
            )
        except UpdaterBridgeError as exc:
            with connect() as db:
                write_audit(
                    db,
                    "error",
                    "server.update.request",
                    version,
                    actor,
                    "Watcher server update request could not reach the privileged updater.",
                    {"requestId": request_id},
                    target_type="server-release",
                    error={"type": "UpdaterBridgeError", "code": exc.code, "message": exc.message},
                )
            json_response(self, exc.status, {"error": exc.code, "message": exc.message})
            return
        outcome = "success" if 200 <= status < 300 else "error"
        with connect() as db:
            write_audit(
                db,
                outcome,
                "server.update.request",
                version,
                actor,
                "Watcher server update request accepted by the privileged updater." if outcome == "success" else "Watcher server update request was rejected by the privileged updater.",
                {"requestId": request_id, "daemonStatus": status, "idempotent": bool(response.get("idempotent"))},
                target_type="server-release",
                error=None if outcome == "success" else {"type": "UpdaterRejection", "code": response.get("error"), "message": response.get("message")},
            )
        json_response(self, status, response)

    def handle_settings(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        with connect() as db:
            scan_interval_minutes = connection_scan_interval_minutes(db)
            heartbeat_interval_seconds = client_heartbeat_interval_seconds(db)
            repository_rows = db.execute(
                """
                SELECT key, value FROM register_entries
                WHERE key IN (
                    'watcher.server_repository',
                    'github.repository',
                    'watcher.public_sni',
                    'pasarguard.base_url',
                    'pasarguard.user_template_id',
                    'pasarguard.api_key',
                    'clients.heartbeat_interval_seconds'
                )
                """
            ).fetchall()
            client_repository = github_repository(db)
            public_sni = watcher_public_sni(db)
        repository_values = {row["key"]: row["value"] for row in repository_rows}
        public_url = f"https://{public_sni}"
        server_repository = repository_values.get("watcher.server_repository", WATCHER_SERVER_REPOSITORY)
        updater_status = updater_status_snapshot()
        json_response(
            self,
            HTTPStatus.OK,
            {
                "security": {
                    "authentication": "basic" if DASHBOARD_USERNAME or DASHBOARD_PASSWORD else "bearer",
                    "ipGeolookupEnabled": IP_GEOLOOKUP_ENABLED,
                    "maxJsonBytes": MAX_JSON_BYTES,
                    "maxAnalyticsRequestBytes": MAX_ANALYTICS_REQUEST_BYTES,
                    "maxAnalyticsReportBytes": MAX_ANALYTICS_REPORT_BYTES,
                    "maxSubscriptionBytes": MAX_SUBSCRIPTION_BYTES,
                    "onlineWindowSeconds": client_online_window_seconds(heartbeat_interval_seconds),
                },
                "retention": {
                    "logDays": LOG_RETENTION_DAYS,
                    "telemetryDays": TELEMETRY_RETENTION_DAYS,
                    "analyticsDays": ANALYTICS_RETENTION_DAYS,
                    "analyticsMaxBytes": ANALYTICS_MAX_BYTES,
                    "auditMaxEntries": AUDIT_MAX_ENTRIES,
                    "auditRetentionDays": AUDIT_RETENTION_DAYS,
                    "auditMaxBytes": AUDIT_MAX_BYTES,
                    "auditInitialPage": AUDIT_INITIAL_PAGE,
                    "auditMaxPage": AUDIT_MAX_PAGE,
                    "containerFileBytes": OPERATIONAL_LOG_FILE_BYTES,
                    "containerFileCount": OPERATIONAL_LOG_FILE_COUNT,
                    "containerTotalBytes": OPERATIONAL_LOG_TOTAL_BYTES,
                    "exportMaxCompressedBytes": LOG_EXPORT_MAX_COMPRESSED_BYTES,
                    "exportMaxUncompressedBytes": LOG_EXPORT_MAX_UNCOMPRESSED_BYTES,
                    "exportMaxSeconds": LOG_EXPORT_MAX_SECONDS,
                },
                "updates": {
                    "clientRepository": client_repository,
                    "serverRepository": server_repository,
                    "githubRelease": GITHUB_RELEASE,
                    "channel": UPDATE_CHANNEL,
                    "installedVersion": WATCHER_VERSION,
                    "localUpdater": "root-owned Unix-socket daemon" if updater_status.get("available") else "unavailable",
                    "releaseCheckEnabled": True,
                    "webInstallEnabled": bool(updater_status.get("available")),
                    "webInstallReason": "The API submits only an exact desired version and request ID over the registered Unix-socket profile." if updater_status.get("available") else str(updater_status.get("reason") or "The privileged local updater is not installed or reachable."),
                    "imageIdentity": "immutable OCI digest in release deployments",
                    "manifestAuthentication": "GitHub release transport plus checksums; server manifest is not asymmetrically signed",
                    "publicUrl": public_url,
                    "publicSni": public_sni,
                    "ruleSetIds": RULE_SET_IDS,
                    "daemon": updater_status,
                },
                "backup": {
                    "formatVersion": 2,
                    "databaseSchemaGeneration": DATABASE_SCHEMA_GENERATION,
                    "scope": "complete",
                    "restoreMode": "replace",
                    "encryption": "AES-256-GCM",
                    "externalKeyRequired": True,
                    "maxUploadBytes": BACKUP_MAX_COMPRESSED_BYTES,
                    "maxUncompressedBytes": BACKUP_MAX_UNCOMPRESSED_BYTES,
                    "maxMemberBytes": BACKUP_MAX_MEMBER_BYTES,
                    "maxMemberCount": BACKUP_MAX_MEMBER_COUNT,
                },
                "connections": {
                    "scanIntervalMinutes": scan_interval_minutes,
                    "scanEnabled": True,
                    "minimumMinutes": 1,
                    "maximumMinutes": 15,
                    "pasarguard": {
                        "baseUrl": repository_values.get("pasarguard.base_url", ""),
                        "userTemplateId": repository_values.get("pasarguard.user_template_id", ""),
                        "apiKeyConfigured": bool(str(repository_values.get("pasarguard.api_key", "")).strip()),
                    },
                },
                "clients": {
                    "heartbeatIntervalSeconds": heartbeat_interval_seconds,
                    "minimumHeartbeatIntervalSeconds": 15,
                    "maximumHeartbeatIntervalSeconds": 86400,
                },
            },
        )

    def handle_update_connection_settings(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        raw_interval = body.get("scanIntervalMinutes")
        if isinstance(raw_interval, bool):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_scan_interval"})
            return
        try:
            scan_interval_minutes = int(raw_interval)
        except (TypeError, ValueError):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_scan_interval"})
            return
        if scan_interval_minutes < 1 or scan_interval_minutes > 15:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_scan_interval"})
            return
        now = utc_now()
        with connect() as db:
            db.execute(
                """
                INSERT INTO watcher_settings (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                ("connections.scan_interval_minutes", str(scan_interval_minutes), now),
            )
            write_audit(
                db,
                "success",
                "settings.connections.update",
                "connections.scan_interval_minutes",
                dashboard_actor(self),
                f"Connection scan interval set to {scan_interval_minutes} minutes.",
            )
        json_response(
            self,
            HTTPStatus.OK,
            {"scanIntervalMinutes": scan_interval_minutes, "scanEnabled": True},
        )

    def handle_change_password(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD:
            json_response(self, HTTPStatus.CONFLICT, {"error": "password_change_unavailable"})
            return
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        current_password = str(body.get("currentPassword") or "")
        new_password = str(body.get("newPassword") or "")
        repeat_password = str(body.get("repeatPassword") or "")
        if not verify_operator_password(DASHBOARD_USERNAME, current_password):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "current_password_incorrect"})
            return
        if new_password != repeat_password:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "new_passwords_do_not_match"})
            return
        if len(new_password) < MIN_OPERATOR_PASSWORD_LENGTH:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "new_password_too_short"})
            return
        if hmac.compare_digest(current_password, new_password):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "new_password_must_differ"})
            return
        salt = os.urandom(16)
        digest = password_digest(new_password, salt)
        now = utc_now()
        with connect() as db:
            db.execute(
                """
                INSERT INTO operator_credentials
                    (username, password_salt, password_hash, iterations, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_salt = excluded.password_salt,
                    password_hash = excluded.password_hash,
                    iterations = excluded.iterations,
                    updated_at = excluded.updated_at
                """,
                (
                    DASHBOARD_USERNAME,
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(digest).decode("ascii"),
                    PASSWORD_HASH_ITERATIONS,
                    now,
                ),
            )
            write_audit(
                db,
                "success",
                "security.password.change",
                DASHBOARD_USERNAME,
                dashboard_actor(self),
                "Operator password changed.",
            )
        json_response(self, HTTPStatus.OK, {"status": "password_changed", "updatedAt": now})

    def handle_audit(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            limit = min(AUDIT_MAX_PAGE, max(1, int((query.get("limit") or [str(AUDIT_INITIAL_PAGE)])[0])))
        except ValueError:
            limit = AUDIT_INITIAL_PAGE
        try:
            before_id = max(0, int((query.get("beforeId") or ["0"])[0]))
        except ValueError:
            before_id = 0
        with connect() as db:
            rows = db.execute(
                """
                SELECT id, event_id, created_at, severity, status, action, target, target_type,
                       actor, actor_type, message, request_id, transport_method
                FROM audit_events
                WHERE (? = 0 OR id < ?)
                ORDER BY id DESC LIMIT ?
                """,
                (before_id, before_id, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        json_response(
            self,
            HTTPStatus.OK,
            {
                "events": [dict(row) for row in page],
                "hasMore": has_more,
                "nextBeforeId": page[-1]["id"] if has_more and page else None,
                "limit": limit,
            },
        )

    def handle_logs_download(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        actor = dashboard_actor(self)
        with connect() as db:
            snapshot_audit_id = int(db.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events").fetchone()[0])
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "vpn-enus-watcher-logs.zip")
            try:
                manifest = build_log_export(zip_path, snapshot_audit_id)
            except RequestBodyError as exc:
                with connect() as db:
                    write_audit(
                        db,
                        "error",
                        "logs.download",
                        "watcher",
                        actor,
                        "Watcher log export failed.",
                        error={"type": "LogExportError", "code": exc.code, "message": exc.code},
                    )
                json_response(self, exc.status, {"error": exc.code})
                return
            except (OSError, sqlite3.Error, zipfile.BadZipFile) as exc:
                with connect() as db:
                    write_audit(
                        db,
                        "error",
                        "logs.download",
                        "watcher",
                        actor,
                        "Watcher log export failed.",
                        error={"type": type(exc).__name__, "code": "log_export_failed", "message": "Log export could not be generated."},
                    )
                json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "log_export_failed"})
                return
            with connect() as db:
                write_audit(
                    db,
                    "success",
                    "logs.download",
                    "watcher",
                    actor,
                    "Watcher log archive generated.",
                    {"snapshotAuditMaxId": snapshot_audit_id, "exportAuditEventIncluded": False, "counts": manifest["counts"]},
                )
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            file_response(self, HTTPStatus.OK, zip_path, "application/zip", f"vpn-enus-watcher-logs-{stamp}.zip")

    def handle_analytics(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        query = parse_qs(urlparse(self.path).query)
        report_type = str((query.get("type") or [""])[0]).strip().lower()
        client_id = str((query.get("clientId") or [""])[0]).strip()
        try:
            before_id = max(0, int((query.get("beforeId") or ["0"])[0] or "0"))
            limit = min(200, max(1, int((query.get("limit") or ["100"])[0] or "100")))
        except ValueError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_cursor"})
            return
        if report_type and report_type not in ANALYTICS_REPORT_TYPES:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_report_type"})
            return

        predicates: list[str] = []
        parameters: list[Any] = []
        if before_id > 0:
            predicates.append("a.id < ?")
            parameters.append(before_id)
        if report_type:
            predicates.append("a.report_type = ?")
            parameters.append(report_type)
        if client_id:
            predicates.append("a.client_id = ?")
            parameters.append(client_id)
        where = "WHERE " + " AND ".join(predicates) if predicates else ""
        with connect() as db:
            rows = db.execute(
                f"""
                SELECT a.id, a.report_id, a.client_id, a.report_type, a.occurred_at,
                       a.received_at, a.schema_version, a.engine_version, a.status,
                       a.summary_json, a.payload_bytes,
                       c.display_id AS client_display_id, c.machine_name AS client_machine_name
                FROM analytics_reports a
                JOIN clients c ON c.client_id = a.client_id
                {where}
                ORDER BY a.id DESC
                LIMIT ?
                """,
                (*parameters, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        json_response(self, HTTPStatus.OK, {
            "reports": [analytics_report_row(row) for row in page],
            "hasMore": has_more,
            "nextBeforeId": page[-1]["id"] if has_more and page else None,
            "retention": {"days": ANALYTICS_RETENTION_DAYS, "maxBytes": ANALYTICS_MAX_BYTES},
        })

    def handle_analytics_detail(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return
        report_id = unquote(path.removeprefix("/api/v1/analytics/")).strip()
        if not ANALYTICS_REPORT_ID_RE.fullmatch(report_id):
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_analytics_report_id"})
            return
        with connect() as db:
            row = db.execute(
                """
                SELECT a.*, c.display_id AS client_display_id, c.machine_name AS client_machine_name
                FROM analytics_reports a
                JOIN clients c ON c.client_id = a.client_id
                WHERE a.report_id = ?
                """,
                (report_id,),
            ).fetchone()
        if row is None:
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "analytics_report_not_found"})
            return
        json_response(self, HTTPStatus.OK, {"report": analytics_report_row(row, include_payload=True)})

    def handle_clients(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        with connect() as db:
            rows = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, platform, app_version, original_ip, last_ip,
                       region, provider, status, routing_mode, connections_json, total_traffic_bytes,
                       traffic_metering_mode, last_seen_at, device_json,
                       auto_updates_enabled, logs_upload_enabled, update_manifest_url,
                       update_fallback_manifest_url, update_last_check_success, update_last_check_message,
                       update_active_rule_set, update_rule_sets_json, update_last_seen_at
                FROM clients
                ORDER BY last_seen_at DESC;
                """
            ).fetchall()
            heartbeat_interval_seconds = client_heartbeat_interval_seconds(db)
        json_response(self, HTTPStatus.OK, {"clients": [client_row(row, heartbeat_interval_seconds) for row in rows]})

    def handle_client_detail(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.rsplit("/", 1)[-1]
        event_cutoff = (datetime.now(timezone.utc) - timedelta(days=TELEMETRY_RETENTION_DAYS)).isoformat()
        with connect() as db:
            client = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, platform, app_version, os, windows_version,
                       installed_at, original_ip, last_ip, region, provider, status, routing_mode, connections_json,
                       total_traffic_bytes, traffic_metering_mode, last_seen_at, device_json,
                       auto_updates_enabled, logs_upload_enabled, update_manifest_url,
                       update_fallback_manifest_url, update_last_check_success, update_last_check_message,
                       update_active_rule_set, update_rule_sets_json, update_last_seen_at
                FROM clients WHERE client_id = ?;
                """,
                (client_id,),
            ).fetchone()
            if client is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
            events = db.execute(
                """
                SELECT id, created_at, type, status, traffic_delta_bytes, traffic_total_bytes, message, payload_json
                FROM events
                WHERE client_id = ? AND created_at >= ?
                ORDER BY created_at DESC LIMIT 500;
                """,
                (client_id, event_cutoff),
            ).fetchall()
            heartbeat_interval_seconds = client_heartbeat_interval_seconds(db)

        json_response(self, HTTPStatus.OK, {"client": client_row(client, heartbeat_interval_seconds), "events": [dict(row) for row in events]})

    def handle_client_logs_download(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.removeprefix("/api/v1/clients/").removesuffix("/logs.zip")
        with connect() as db:
            client = db.execute("SELECT client_id, display_id FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if client is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
        actor = dashboard_actor(self)
        safe_display = "".join(ch for ch in str(client["display_id"]) if ch.isalnum() or ch in "-_") or "client"
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, f"{safe_display}-logs.zip")
            try:
                manifest = build_client_log_export(client_id, temp_dir, zip_path)
            except RequestBodyError as exc:
                with connect() as db:
                    write_audit(
                        db,
                        "error",
                        "client.logs.download",
                        client_id,
                        actor,
                        "Client log export failed.",
                        error={"type": "LogExportError", "code": exc.code, "message": exc.code},
                    )
                json_response(self, exc.status, {"error": exc.code})
                return
            except (OSError, sqlite3.Error, zipfile.BadZipFile) as exc:
                with connect() as db:
                    write_audit(
                        db,
                        "error",
                        "client.logs.download",
                        client_id,
                        actor,
                        "Client log export failed.",
                        error={"type": type(exc).__name__, "code": "log_export_failed", "message": "Client log export could not be generated."},
                    )
                json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "log_export_failed"})
                return
            with connect() as db:
                write_audit(
                    db,
                    "success",
                    "client.logs.download",
                    client_id,
                    actor,
                    "Sanitized client log archive generated.",
                    {"eventCount": manifest["files"]["events.jsonl"]["records"], "retentionDays": TELEMETRY_RETENTION_DAYS},
                )
            file_response(self, HTTPStatus.OK, zip_path, "application/zip", f"{safe_display}-logs.zip")

    def handle_collect_now(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.split("/")[-2]
        command_id = uuid.uuid4().hex
        with connect() as db:
            exists = db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if exists is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
            db.execute(
                "INSERT INTO commands (id, client_id, type, payload_json, status, created_at) VALUES (?, ?, 'collect_now', '{}', 'pending', ?)",
                (command_id, client_id, utc_now()),
            )
            write_audit(db, "success", "client.collect_now", client_id, dashboard_actor(self), "Immediate telemetry collection queued.")
        json_response(self, HTTPStatus.OK, {"status": "queued", "commandId": command_id})

    def handle_create_command(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.rsplit("/", 1)[-1]
        try:
            body, _ = read_json(self)
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        command_type = str(body.get("type", "")).strip()
        payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
        if command_type not in {"collect_now", "check_updates", "set_watcher_endpoint"}:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "unsupported_command"})
            return

        command_id = uuid.uuid4().hex
        with connect() as db:
            exists = db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if exists is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
            db.execute(
                "INSERT INTO commands (id, client_id, type, payload_json, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
                (command_id, client_id, command_type, json.dumps(payload, separators=(",", ":")), utc_now()),
            )
            write_audit(db, "success", f"client.{command_type}", client_id, dashboard_actor(self), "Client command queued.")
        json_response(self, HTTPStatus.OK, {"status": "queued", "commandId": command_id})

    def handle_backup_download(self) -> None:
        if not backup_authorized(self):
            auth_required_response(self)
            return

        init_db()
        actor = backup_actor(self)
        with connect() as db:
            write_audit(db, "success", "backup.download", "watcher", actor, "Encrypted system recovery archive requested.")
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "vpn-enus-watcher-backup.zip")
            try:
                create_backup_archive(
                    DB_PATH,
                    zip_path,
                    source="local-updater" if actor == "local-updater" else "operator-download",
                    key=decode_backup_key(),
                )
            except (BackupContractError, OSError, sqlite3.Error) as raw_error:
                error_code = raw_error.code if isinstance(raw_error, BackupContractError) else "backup_generation_failed"
                with connect() as db:
                    write_audit(
                        db,
                        "error",
                        "backup.download",
                        "watcher",
                        actor,
                        "Encrypted system recovery archive could not be generated.",
                        error={"type": type(raw_error).__name__, "code": error_code, "message": "Encrypted backup generation failed."},
                    )
                json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": error_code})
                return
            file_stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            file_response(self, HTTPStatus.OK, zip_path, "application/zip", f"vpn-enus-watcher-backup-{file_stamp}.zip")

    def handle_backup_upload(self) -> None:
        if not backup_authorized(self):
            auth_required_response(self)
            return

        actor = backup_actor(self)
        if not _restore_lock.acquire(blocking=False):
            json_response(self, HTTPStatus.CONFLICT, {"error": "restore_in_progress"})
            return
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "upload.zip")
            restored_db_path = os.path.join(temp_dir, "watcher.db")
            pre_restore_db_path = os.path.join(temp_dir, "pre-restore.db")
            pre_restore_archive_path = os.path.join(temp_dir, "pre-restore.zip")
            mutation_started = False
            database_lock = None
            try:
                spool_request_body(self, zip_path, BACKUP_MAX_COMPRESSED_BYTES)
                archive_digest = sha256_file(zip_path)
                manifest = validate_and_decrypt_archive(zip_path, restored_db_path, key=decode_backup_key())
                pending_database_lock = database_access(DB_PATH, exclusive=True)
                pending_database_lock.__enter__()
                database_lock = pending_database_lock
                snapshot_database(DB_PATH, pre_restore_db_path)
                create_backup_archive(DB_PATH, pre_restore_archive_path, source="pre-restore-rollback", key=decode_backup_key())
                pre_restore_digest = sha256_file(pre_restore_archive_path)
                if not pre_restore_digest:
                    raise BackupContractError("pre_restore_snapshot_invalid")

                mutation_started = True
                source = sqlite3.connect(restored_db_path, timeout=30)
                target = sqlite3.connect(DB_PATH, timeout=30)
                try:
                    source.backup(target)
                finally:
                    target.close()
                    source.close()
                init_db()
                with connect() as db:
                    integrity = db.execute("PRAGMA integrity_check").fetchone()
                    if not integrity or integrity[0] != "ok":
                        raise BackupContractError("restore_health_check_failed")
                    write_audit(
                        db,
                        "success",
                        "backup.restore",
                        "watcher",
                        actor,
                        "Encrypted system recovery archive restored with replace semantics.",
                        {
                            "archiveSha256": archive_digest,
                            "preRestoreArchiveSha256": pre_restore_digest,
                            "sourceVersion": manifest.get("sourceVersion"),
                            "scope": manifest.get("scope"),
                            "restoreMode": manifest.get("restoreMode"),
                            "databaseSchemaGeneration": manifest.get("databaseSchemaGeneration"),
                        },
                    )
            except RequestBodyError as exc:
                try:
                    with connect() as db:
                        write_audit(
                            db,
                            "error",
                            "backup.restore",
                            "watcher",
                            actor,
                            "Encrypted system recovery upload was rejected before mutation.",
                            error={"type": "RequestBodyError", "code": exc.code, "message": exc.code},
                        )
                except sqlite3.Error:
                    pass
                json_response(self, exc.status, {"error": exc.code})
                return
            except (BackupContractError, sqlite3.Error, OSError) as raw_error:
                exc = raw_error if isinstance(raw_error, BackupContractError) else BackupContractError("restore_io_failed")
                if mutation_started and os.path.exists(pre_restore_db_path):
                    try:
                        rollback_source = sqlite3.connect(pre_restore_db_path, timeout=30)
                        rollback_target = sqlite3.connect(DB_PATH, timeout=30)
                        try:
                            rollback_source.backup(rollback_target)
                        finally:
                            rollback_target.close()
                            rollback_source.close()
                        init_db()
                    except (sqlite3.Error, OSError):
                        exc = BackupContractError("restore_rollback_failed")
                try:
                    with connect() as db:
                        write_audit(
                            db,
                            "error",
                            "backup.restore",
                            "watcher",
                            actor,
                            "Encrypted system recovery archive was rejected or rolled back.",
                            error={"type": "BackupContractError", "code": exc.code, "message": exc.code},
                        )
                except sqlite3.Error:
                    pass
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": exc.code})
                return
            finally:
                if database_lock is not None:
                    database_lock.__exit__(None, None, None)
                _restore_lock.release()

        json_response(
            self,
            HTTPStatus.OK,
            {"status": "restored", "archiveSha256": archive_digest, "restoreMode": "replace"},
        )

    def handle_delete_client(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.rsplit("/", 1)[-1]
        with connect() as db:
            exists = db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if exists is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
            db.execute("DELETE FROM commands WHERE client_id = ?", (client_id,))
            db.execute("DELETE FROM events WHERE client_id = ?", (client_id,))
            db.execute("DELETE FROM analytics_reports WHERE client_id = ?", (client_id,))
            db.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
            write_audit(db, "success", "client.delete", client_id, dashboard_actor(self), "Client, retained events, analytics and queued commands deleted.")

        json_response(self, HTTPStatus.OK, {"status": "deleted"})

    def log_message(self, format: str, *args: Any) -> None:
        message = re.sub(r"(?i)(/sub/)[A-Za-z0-9_-]+", r"\1[REDACTED]", format % args)
        print(f"{self.address_string()} - {message}")


def validate_runtime_configuration() -> None:
    has_basic_auth = bool(DASHBOARD_USERNAME and DASHBOARD_PASSWORD)
    has_token_auth = bool(DASHBOARD_TOKEN)
    if not has_basic_auth and not has_token_auth:
        raise RuntimeError(
            "Dashboard authentication is required. Set both "
            "LOKI_WATCHER_DASHBOARD_USERNAME and LOKI_WATCHER_DASHBOARD_PASSWORD."
        )
    if bool(DASHBOARD_USERNAME) != bool(DASHBOARD_PASSWORD):
        raise RuntimeError("Dashboard username and password must be configured together.")
    if LOCAL_CONTROL_TOKEN and len(LOCAL_CONTROL_TOKEN) < 32:
        raise RuntimeError("LOKI_WATCHER_LOCAL_CONTROL_TOKEN must contain at least 32 characters.")
    try:
        decode_backup_key()
    except BackupContractError as exc:
        raise RuntimeError(f"Backup encryption configuration is invalid: {exc.code}.") from exc


def run_server(port: int = 8080) -> None:
    validate_runtime_configuration()
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", port), WatcherHandler)
    scanner_stop = threading.Event()
    scanner = threading.Thread(
        target=run_connection_scanner,
        args=(scanner_stop,),
        name="connection-subscription-scanner",
        daemon=True,
    )
    scanner.start()
    print(f"Loki watcher API listening on {port}")
    try:
        server.serve_forever()
    finally:
        scanner_stop.set()
        scanner.join(timeout=2)
        server.server_close()


if __name__ == "__main__":
    run_server(int(os.environ.get("PORT", "8080")))
