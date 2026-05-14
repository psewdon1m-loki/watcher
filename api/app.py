from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import shutil
import tempfile
import sqlite3
import time
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


DB_PATH = os.environ.get("LOKI_WATCHER_DB", os.path.join(os.getcwd(), "watcher.db"))
DASHBOARD_TOKEN = os.environ.get("LOKI_WATCHER_DASHBOARD_TOKEN", "")
DASHBOARD_USERNAME = os.environ.get("LOKI_WATCHER_DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.environ.get("LOKI_WATCHER_DASHBOARD_PASSWORD", "").strip()
MAX_SKEW_SECONDS = 300
ONLINE_WINDOW_SECONDS = int(os.environ.get("LOKI_WATCHER_ONLINE_WINDOW_SECONDS", "600"))
LOG_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_LOG_RETENTION_DAYS", "7"))
MAX_BACKUP_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_BACKUP_BYTES", str(256 * 1024 * 1024)))
GITHUB_REPOSITORY = os.environ.get("LOKI_WATCHER_GITHUB_REPOSITORY", "psewdon1m-loki/pc-client").strip()
GITHUB_RELEASE = os.environ.get("LOKI_WATCHER_GITHUB_RELEASE", "latest").strip() or "latest"
GITHUB_TOKEN = os.environ.get("LOKI_WATCHER_GITHUB_TOKEN", "").strip()
UPDATE_CHANNEL = os.environ.get("LOKI_WATCHER_UPDATE_CHANNEL", "stable").strip() or "stable"
UPDATE_CACHE_SECONDS = max(0, int(os.environ.get("LOKI_WATCHER_UPDATE_CACHE_SECONDS", "300")))
WATCHER_PUBLIC_URL = os.environ.get("LOKI_WATCHER_PUBLIC_URL", "https://loki-p-watcher.shmoza.net").strip().rstrip("/")
WATCHER_PUBLIC_SNI = os.environ.get("LOKI_WATCHER_PUBLIC_SNI", "loki-p-watcher.shmoza.net").strip()
IP_GEOLOOKUP_ENABLED = os.environ.get("LOKI_WATCHER_IP_GEOLOOKUP_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
RULE_SET_IDS = [
    item.strip()
    for item in os.environ.get("LOKI_WATCHER_RULE_SET_IDS", "russia-smart,global,whitelist,blacklist").split(",")
    if item.strip()
]
_manifest_cache_body: bytes | None = None
_manifest_cache_expires_at = 0.0
_ip_info_cache: dict[str, dict[str, str]] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: str | None = None) -> None:
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                display_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                username TEXT,
                machine_name TEXT,
                app_version TEXT,
                os TEXT,
                windows_version TEXT,
                installed_at TEXT,
                original_ip TEXT,
                region TEXT NOT NULL DEFAULT 'unknown',
                provider TEXT,
                device_json TEXT NOT NULL DEFAULT '{}',
                routing_mode TEXT,
                connections_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'unknown',
                total_traffic_bytes INTEGER NOT NULL DEFAULT 0,
                auto_updates_enabled INTEGER,
                logs_upload_enabled INTEGER,
                update_manifest_url TEXT,
                update_fallback_manifest_url TEXT,
                update_last_check_success INTEGER,
                update_last_check_message TEXT,
                update_active_rule_set TEXT,
                update_rule_sets_json TEXT NOT NULL DEFAULT '[]',
                update_last_seen_at TEXT,
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

            CREATE INDEX IF NOT EXISTS idx_events_client_created ON events(client_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_commands_client_status ON commands(client_id, status);
            """
        )
        for statement in [
            "ALTER TABLE clients ADD COLUMN username TEXT",
            "ALTER TABLE clients ADD COLUMN machine_name TEXT",
            "ALTER TABLE clients ADD COLUMN app_version TEXT",
            "ALTER TABLE clients ADD COLUMN os TEXT",
            "ALTER TABLE clients ADD COLUMN windows_version TEXT",
            "ALTER TABLE clients ADD COLUMN installed_at TEXT",
            "ALTER TABLE clients ADD COLUMN original_ip TEXT",
            "ALTER TABLE clients ADD COLUMN region TEXT NOT NULL DEFAULT 'unknown'",
            "ALTER TABLE clients ADD COLUMN provider TEXT",
            "ALTER TABLE clients ADD COLUMN routing_mode TEXT",
            "ALTER TABLE clients ADD COLUMN connections_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN auto_updates_enabled INTEGER",
            "ALTER TABLE clients ADD COLUMN logs_upload_enabled INTEGER",
            "ALTER TABLE clients ADD COLUMN update_manifest_url TEXT",
            "ALTER TABLE clients ADD COLUMN update_fallback_manifest_url TEXT",
            "ALTER TABLE clients ADD COLUMN update_last_check_success INTEGER",
            "ALTER TABLE clients ADD COLUMN update_last_check_message TEXT",
            "ALTER TABLE clients ADD COLUMN update_active_rule_set TEXT",
            "ALTER TABLE clients ADD COLUMN update_rule_sets_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN update_last_seen_at TEXT",
            "ALTER TABLE commands ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'",
        ]:
            try:
                db.execute(statement)
            except sqlite3.OperationalError:
                pass
        db.commit()
    finally:
        db.close()


@contextmanager
def connect(path: str | None = None):
    path = path or DB_PATH
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()


def json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature")
    handler.send_header("Access-Control-Expose-Headers", "content-disposition")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
    handler.end_headers()
    handler.wfile.write(payload)


def binary_response(handler: BaseHTTPRequestHandler, status: int, payload: bytes, content_type: str, file_name: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
    handler.end_headers()
    handler.wfile.write(payload)


def read_json(handler: BaseHTTPRequestHandler) -> tuple[dict[str, Any], bytes]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length > 0 else b""
    if not raw:
        return {}, raw
    return json.loads(raw.decode("utf-8")), raw


def github_api_url() -> str:
    if GITHUB_RELEASE.lower() == "latest":
        return f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
    return f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/tags/{GITHUB_RELEASE}"


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
    return f"{WATCHER_PUBLIC_URL}/assets/{file_name}"


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


def discover_installer(release: dict[str, Any], assets: dict[str, dict[str, Any]], bundle_entries: dict[str, bytes]) -> dict[str, Any] | None:
    candidates = sorted(
        name
        for name in assets
        if name.startswith("LokiClientSetup-") and name.endswith("-win-x64.exe")
    )
    if candidates:
        file_name = candidates[-1]
        asset = assets[file_name]
        return {"url": public_asset_url(file_name), "sha256": sha256_url(asset_url(asset)), "mandatory": False}

    bundled = sorted(
        name
        for name in bundle_entries
        if name.startswith("LokiClientSetup-") and name.endswith("-win-x64.exe")
    )
    if not bundled:
        return None
    file_name = bundled[-1]
    return {"url": public_asset_url(file_name), "sha256": sha256_bytes(bundle_entries[file_name]), "mandatory": False}


def discover_rule_sets(release: dict[str, Any], assets: dict[str, dict[str, Any]], bundle_entries: dict[str, bytes]) -> list[dict[str, Any]]:
    version = release_version(release)
    result: list[dict[str, Any]] = []
    for rule_set_id in RULE_SET_IDS:
        file_name = f"{rule_set_id}.zip"
        asset = assets.get(file_name)
        if asset:
            result.append({"id": rule_set_id, "version": version, "url": public_asset_url(file_name), "sha256": sha256_url(asset_url(asset))})
            continue
        if file_name in bundle_entries:
            result.append({"id": rule_set_id, "version": version, "url": public_asset_url(file_name), "sha256": sha256_bytes(bundle_entries[file_name])})
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

    manifest["channel"] = manifest.get("channel") or UPDATE_CHANNEL
    manifest["version"] = manifest.get("version") or release_version(release)
    manifest["minimumVersion"] = manifest.get("minimumVersion") or manifest["version"]
    manifest["publishedAt"] = manifest.get("publishedAt") or release.get("published_at") or utc_now()
    manifest["installer"] = discover_installer(release, assets, bundle_entries) or manifest.get("installer")

    discovered_rule_sets = discover_rule_sets(release, assets, bundle_entries)
    merged = {str(item.get("id")): item for item in manifest.get("ruleSets", []) if isinstance(item, dict) and item.get("id")}
    for rule_set in discovered_rule_sets:
        merged[rule_set["id"]] = rule_set
    manifest["ruleSets"] = list(merged.values())
    manifest["watcher"] = {"endpoint": WATCHER_PUBLIC_URL, "sni": WATCHER_PUBLIC_SNI}
    return manifest


def cached_manifest_bytes() -> bytes:
    global _manifest_cache_body, _manifest_cache_expires_at
    now = time.time()
    if _manifest_cache_body is not None and now < _manifest_cache_expires_at:
        return _manifest_cache_body
    body = json.dumps(build_manifest(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    _manifest_cache_body = body
    _manifest_cache_expires_at = now + UPDATE_CACHE_SECONDS
    return body


def cached_manifest() -> dict[str, Any]:
    return json.loads(cached_manifest_bytes().decode("utf-8"))


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


def dashboard_authorized(handler: BaseHTTPRequestHandler) -> bool:
    if DASHBOARD_USERNAME or DASHBOARD_PASSWORD:
        header = handler.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        username, separator, password = decoded.partition(":")
        return separator == ":" and hmac.compare_digest(username, DASHBOARD_USERNAME) and hmac.compare_digest(password, DASHBOARD_PASSWORD)
    if not DASHBOARD_TOKEN:
        return True
    return handler.headers.get("Authorization", "") == f"Bearer {DASHBOARD_TOKEN}"


def auth_required_response(handler: BaseHTTPRequestHandler) -> None:
    payload = json.dumps({"error": "dashboard_auth_required"}, separators=(",", ":")).encode("utf-8")
    handler.send_response(HTTPStatus.UNAUTHORIZED)
    handler.send_header("WWW-Authenticate", 'Basic realm="Loki Watcher"')
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "authorization,content-type,x-loki-client-id,x-loki-display-id,x-loki-timestamp,x-loki-signature")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
    handler.end_headers()
    handler.wfile.write(payload)


def device_value(device: dict[str, Any], name: str) -> str | None:
    value = device.get(name)
    return str(value) if value is not None and str(value).strip() else None


def is_online(last_seen_at: str | None) -> bool:
    if not last_seen_at:
        return False
    try:
        seen = datetime.fromisoformat(last_seen_at)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - seen).total_seconds() <= ONLINE_WINDOW_SECONDS


def client_row(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["online"] = is_online(item.get("last_seen_at"))
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


def verify_client_signature(handler: BaseHTTPRequestHandler, raw_body: bytes, db: sqlite3.Connection) -> tuple[bool, str | None]:
    client_id = handler.headers.get("X-Loki-Client-Id", "")
    timestamp = handler.headers.get("X-Loki-Timestamp", "")
    signature = handler.headers.get("X-Loki-Signature", "")
    if not client_id or not timestamp or not signature:
        return False, None
    try:
        if abs(time.time() - int(timestamp)) > MAX_SKEW_SECONDS:
            return False, client_id
    except ValueError:
        return False, client_id

    row = db.execute("SELECT client_secret FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    if row is None:
        return False, client_id
    expected = sign(row["client_secret"], handler.command, urlparse(handler.path).path, timestamp, raw_body)
    return hmac.compare_digest(signature, expected), client_id


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


def system_stats(clients: list[dict[str, Any]]) -> dict[str, Any]:
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
    }


def dashboard_payload() -> dict[str, Any]:
    with connect() as db:
        rows = db.execute(
            """
            SELECT client_id, display_id, username, machine_name, app_version, original_ip, region, provider, status,
                   routing_mode, connections_json, total_traffic_bytes, last_seen_at, device_json,
                   auto_updates_enabled, logs_upload_enabled, update_manifest_url,
                   update_fallback_manifest_url, update_last_check_success, update_last_check_message,
                   update_active_rule_set, update_rule_sets_json, update_last_seen_at
            FROM clients
            ORDER BY last_seen_at DESC;
            """
        ).fetchall()
    clients = [client_row(row) for row in rows]
    manifest = cached_manifest()
    return {
        "system": system_stats(clients),
        "updates": {
            "channel": manifest.get("channel"),
            "version": manifest.get("version"),
            "minimumVersion": manifest.get("minimumVersion"),
            "publishedAt": manifest.get("publishedAt"),
            "installer": manifest.get("installer"),
            "watcher": manifest.get("watcher"),
            "ruleSets": dashboard_rule_sets(manifest),
            "githubRepository": GITHUB_REPOSITORY,
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
    server_version = "LokiWatcher/0.1"

    def do_OPTIONS(self) -> None:
        json_response(self, HTTPStatus.NO_CONTENT, {})

    def do_GET(self) -> None:
        init_db()
        path = urlparse(self.path).path
        if path == "/health":
            json_response(self, HTTPStatus.OK, {"status": "ok"})
            return

        if path == "/manifest.json":
            try:
                payload = cached_manifest_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload)
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
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
        init_db()
        path = urlparse(self.path).path
        if path == "/api/v1/enroll":
            self.handle_enroll()
            return

        if path == "/api/v1/telemetry/batch":
            self.handle_batch()
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

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_DELETE(self) -> None:
        init_db()
        path = urlparse(self.path).path
        if path.startswith("/api/v1/clients/"):
            self.handle_delete_client(path)
            return

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def handle_update_state(self) -> None:
        try:
            body, _ = read_json(self)
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
        now = utc_now()
        with connect() as db:
            exists = db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if exists is None:
                db.execute(
                    """
                    INSERT INTO clients (
                        client_id, display_id, client_secret, original_ip, region, provider, status,
                        total_traffic_bytes, created_at, last_seen_at
                    ) VALUES (?, ?, '', ?, ?, ?, 'unknown', 0, ?, ?)
                    """,
                    (client_id, display_id, ip, network["region"], network["provider"], now, now),
                )

            db.execute(
                """
                UPDATE clients SET
                    display_id = ?,
                    original_ip = COALESCE(NULLIF(original_ip, ''), ?),
                    region = CASE WHEN region IS NULL OR region = '' OR region IN ('unknown', 'local/private') THEN ? ELSE region END,
                    provider = CASE WHEN provider IS NULL OR provider = '' OR provider IN ('unknown', 'local/private') THEN ? ELSE provider END,
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
            rows = db.execute("SELECT client_id, display_id, last_seen_at FROM clients ORDER BY last_seen_at DESC").fetchall()
            for row in rows:
                if not is_online(row["last_seen_at"]):
                    skipped.append({"clientId": row["client_id"], "displayId": row["display_id"], "reason": "offline"})
                    continue
                command_id = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO commands (id, client_id, type, payload_json, status, created_at) VALUES (?, ?, 'check_updates', '{}', 'pending', ?)",
                    (command_id, row["client_id"], utc_now()),
                )
                queued.append({"clientId": row["client_id"], "displayId": row["display_id"], "commandId": command_id})

        json_response(self, HTTPStatus.OK, {"status": "queued", "queued": len(queued), "skipped": skipped, "failed": [], "clients": queued})

    def handle_enroll(self) -> None:
        try:
            body, _ = read_json(self)
            client_id = str(body.get("clientId", "")).strip()
            display_id = str(body.get("displayId", "")).strip()
            client_secret = str(body.get("clientSecret", "")).strip()
            device = body.get("device") if isinstance(body.get("device"), dict) else {}
            if not client_id or not display_id or not client_secret:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "missing_identity"})
                return

            ip = client_ip(self)
            network = network_info_for_ip(ip)
            now = utc_now()
            with connect() as db:
                db.execute(
                    """
                    INSERT INTO clients (
                        client_id, display_id, client_secret, username, machine_name, app_version,
                        os, windows_version, installed_at, original_ip, region, provider, device_json,
                        status, total_traffic_bytes, created_at, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disconnected', 0, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        display_id = excluded.display_id,
                        client_secret = excluded.client_secret,
                        username = excluded.username,
                        machine_name = excluded.machine_name,
                        app_version = excluded.app_version,
                        os = excluded.os,
                        windows_version = excluded.windows_version,
                        installed_at = COALESCE(clients.installed_at, excluded.installed_at),
                        original_ip = COALESCE(NULLIF(clients.original_ip, ''), excluded.original_ip),
                        region = CASE WHEN clients.region IS NULL OR clients.region = '' OR clients.region IN ('unknown', 'local/private') THEN excluded.region ELSE clients.region END,
                        provider = CASE WHEN clients.provider IS NULL OR clients.provider = '' OR clients.provider IN ('unknown', 'local/private') THEN excluded.provider ELSE clients.provider END,
                        device_json = excluded.device_json,
                        last_seen_at = excluded.last_seen_at;
                    """,
                    (
                        client_id,
                        display_id,
                        client_secret,
                        device_value(device, "userName"),
                        device_value(device, "machineName"),
                        device_value(device, "appVersion"),
                        device_value(device, "os"),
                        device_value(device, "windowsVersion"),
                        device_value(device, "installedAt"),
                        ip,
                        network["region"],
                        network["provider"],
                        json.dumps(device),
                        now,
                        now,
                    ),
                )
            json_response(self, HTTPStatus.OK, {"status": "enrolled"})
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})

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

            ip = client_ip(self)
            network = network_info_for_ip(ip)
            now = utc_now()
            status = "unknown"
            total = 0
            routing_mode = None
            connections_json = None
            for event in events:
                if not isinstance(event, dict):
                    continue
                status = str(event.get("connectionStatus") or status)
                total = max(total, int(event.get("trafficTotalBytes") or 0))
                if event.get("routingMode"):
                    routing_mode = str(event.get("routingMode"))
                if isinstance(event.get("connections"), list):
                    connections_json = json.dumps(event.get("connections"), separators=(",", ":"))
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
                        str(event.get("type") or "event"),
                        status,
                        int(event.get("trafficDeltaBytes") or 0),
                        int(event.get("trafficTotalBytes") or 0),
                        event.get("message"),
                        json.dumps(event, separators=(",", ":")),
                    ),
                )

            db.execute(
                """
                UPDATE clients SET
                    original_ip = COALESCE(NULLIF(original_ip, ''), ?),
                    region = CASE WHEN region IS NULL OR region = '' OR region IN ('unknown', 'local/private') THEN ? ELSE region END,
                    provider = CASE WHEN provider IS NULL OR provider = '' OR provider IN ('unknown', 'local/private') THEN ? ELSE provider END,
                    username = COALESCE(?, username),
                    machine_name = COALESCE(?, machine_name),
                    app_version = COALESCE(?, app_version),
                    os = COALESCE(?, os),
                    windows_version = COALESCE(?, windows_version),
                    installed_at = COALESCE(installed_at, ?),
                    device_json = ?,
                    routing_mode = COALESCE(?, routing_mode),
                    connections_json = COALESCE(?, connections_json),
                    status = ?,
                    total_traffic_bytes = MAX(total_traffic_bytes, ?),
                    last_seen_at = ?
                WHERE client_id = ?;
                """,
                (
                    ip,
                    network["region"],
                    network["provider"],
                    device_value(device, "userName"),
                    device_value(device, "machineName"),
                    device_value(device, "appVersion"),
                    device_value(device, "os"),
                    device_value(device, "windowsVersion"),
                    device_value(device, "installedAt"),
                    json.dumps(device),
                    routing_mode,
                    connections_json,
                    status,
                    total,
                    now,
                    client_id,
                ),
            )

        json_response(self, HTTPStatus.OK, {"status": "accepted", "count": len(events)})

    def handle_commands(self, path: str) -> None:
        with connect() as db:
            ok, client_id = verify_client_signature(self, b"", db)
            requested_client_id = path.rsplit("/", 1)[-1]
            if not ok or client_id != requested_client_id:
                json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                return

            db.execute("UPDATE clients SET last_seen_at = ? WHERE client_id = ?", (utc_now(), client_id))

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

    def handle_clients(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        with connect() as db:
            rows = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, app_version, original_ip, region, provider, status,
                       routing_mode, connections_json, total_traffic_bytes, last_seen_at, device_json,
                       auto_updates_enabled, logs_upload_enabled, update_manifest_url,
                       update_fallback_manifest_url, update_last_check_success, update_last_check_message,
                       update_active_rule_set, update_rule_sets_json, update_last_seen_at
                FROM clients
                ORDER BY last_seen_at DESC;
                """
            ).fetchall()
        json_response(self, HTTPStatus.OK, {"clients": [client_row(row) for row in rows]})

    def handle_client_detail(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.rsplit("/", 1)[-1]
        log_cutoff = (datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
        with connect() as db:
            client = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, app_version, os, windows_version,
                       installed_at, original_ip, region, provider, status, routing_mode, connections_json,
                       total_traffic_bytes, last_seen_at, device_json,
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
                (client_id, log_cutoff),
            ).fetchall()

        json_response(self, HTTPStatus.OK, {"client": client_row(client), "events": [dict(row) for row in events]})

    def handle_client_logs_download(self, path: str) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        client_id = path.removeprefix("/api/v1/clients/").removesuffix("/logs.zip")
        log_cutoff = (datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
        with connect() as db:
            client = db.execute("SELECT client_id, display_id FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if client is None:
                json_response(self, HTTPStatus.NOT_FOUND, {"error": "client_not_found"})
                return
            events = db.execute(
                """
                SELECT id, created_at, type, status, traffic_delta_bytes, traffic_total_bytes, message, payload_json
                FROM events
                WHERE client_id = ? AND created_at >= ?
                ORDER BY created_at DESC;
                """,
                (client_id, log_cutoff),
            ).fetchall()

        event_items = [dict(row) for row in events]
        lines = []
        for event in event_items:
            lines.append(f"{event['created_at']} [{event['type']}] {event['status']}")
            lines.append(f"traffic total: {event['traffic_total_bytes']}")
            lines.append(f"traffic delta: {event['traffic_delta_bytes']}")
            if event.get("message"):
                lines.append(str(event["message"]))
            try:
                payload = json.loads(event.get("payload_json") or "{}")
            except json.JSONDecodeError:
                payload = {}
            for log_line in payload.get("logLines") or []:
                lines.append(str(log_line))
            lines.append("")

        with io.BytesIO() as buffer:
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("logs.txt", "\n".join(lines))
                archive.writestr("events.json", json.dumps(event_items, ensure_ascii=False, indent=2))
            payload = buffer.getvalue()

        safe_display = "".join(ch for ch in str(client["display_id"]) if ch.isalnum() or ch in "-_") or "client"
        binary_response(self, HTTPStatus.OK, payload, "application/zip", f"{safe_display}-logs.zip")

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
        json_response(self, HTTPStatus.OK, {"status": "queued", "commandId": command_id})

    def handle_backup_download(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        init_db()
        with tempfile.TemporaryDirectory() as temp_dir:
            db_copy_path = os.path.join(temp_dir, "watcher.db")
            source = sqlite3.connect(DB_PATH)
            target = sqlite3.connect(db_copy_path)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()

            manifest = {
                "format": "loki-watcher-backup",
                "version": 1,
                "createdAt": utc_now(),
                "contains": ["watcher.db"],
            }
            zip_path = os.path.join(temp_dir, "loki-watcher-backup.zip")
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(db_copy_path, "watcher.db")
                archive.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")))
            with open(zip_path, "rb") as backup:
                payload = backup.read()

        file_stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        binary_response(self, HTTPStatus.OK, payload, "application/zip", f"loki-watcher-backup-{file_stamp}.zip")

    def handle_backup_upload(self) -> None:
        if not dashboard_authorized(self):
            auth_required_response(self)
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_BACKUP_BYTES:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_backup_size"})
            return

        raw = self.rfile.read(length)
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "upload.zip")
            restored_db_path = os.path.join(temp_dir, "watcher.db")
            with open(zip_path, "wb") as backup:
                backup.write(raw)

            try:
                with zipfile.ZipFile(zip_path, "r") as archive:
                    if "watcher.db" not in archive.namelist():
                        json_response(self, HTTPStatus.BAD_REQUEST, {"error": "watcher_db_missing"})
                        return
                    archive.extract("watcher.db", temp_dir)
            except zipfile.BadZipFile:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_zip"})
                return

            try:
                db = sqlite3.connect(restored_db_path)
                try:
                    required_tables = {"clients", "events", "commands"}
                    rows = db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
                    table_names = {row[0] for row in rows}
                finally:
                    db.close()
                if not required_tables.issubset(table_names):
                    json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_watcher_database"})
                    return
            except sqlite3.DatabaseError:
                json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_sqlite_database"})
                return

            db_dir = os.path.dirname(DB_PATH) or "."
            backup_name = None
            try:
                os.makedirs(db_dir, exist_ok=True)
                staged_db_path = os.path.join(db_dir, f".watcher-restore-{uuid.uuid4().hex}.db")
                shutil.copyfile(restored_db_path, staged_db_path)
                if os.path.exists(DB_PATH):
                    backup_name = f"{DB_PATH}.before-restore-{int(time.time())}"
                    os.replace(DB_PATH, backup_name)
                os.replace(staged_db_path, DB_PATH)
            except OSError:
                if backup_name and os.path.exists(backup_name):
                    os.replace(backup_name, DB_PATH)
                json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "restore_failed"})
                return

        init_db()
        json_response(self, HTTPStatus.OK, {"status": "restored"})

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
            db.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))

        json_response(self, HTTPStatus.OK, {"status": "deleted"})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")


def run_server(port: int = 8080) -> None:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", port), WatcherHandler)
    print(f"Loki watcher API listening on {port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server(int(os.environ.get("PORT", "8080")))
