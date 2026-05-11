from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import tempfile
import sqlite3
import time
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


DB_PATH = os.environ.get("LOKI_WATCHER_DB", os.path.join(os.getcwd(), "watcher.db"))
DASHBOARD_TOKEN = os.environ.get("LOKI_WATCHER_DASHBOARD_TOKEN", "")
MAX_SKEW_SECONDS = 300
ONLINE_WINDOW_SECONDS = int(os.environ.get("LOKI_WATCHER_ONLINE_WINDOW_SECONDS", "600"))
MAX_BACKUP_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_BACKUP_BYTES", str(256 * 1024 * 1024)))


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
                device_json TEXT NOT NULL DEFAULT '{}',
                routing_mode TEXT,
                connections_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'unknown',
                total_traffic_bytes INTEGER NOT NULL DEFAULT 0,
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
            "ALTER TABLE clients ADD COLUMN routing_mode TEXT",
            "ALTER TABLE clients ADD COLUMN connections_json TEXT NOT NULL DEFAULT '[]'",
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


def client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def region_for_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.is_private or address.is_loopback or address.is_link_local:
        return "local/private"
    return "unknown"


def dashboard_authorized(handler: BaseHTTPRequestHandler) -> bool:
    if not DASHBOARD_TOKEN:
        return True
    return handler.headers.get("Authorization", "") == f"Bearer {DASHBOARD_TOKEN}"


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

        if path.startswith("/api/v1/commands/"):
            self.handle_commands(path)
            return

        if path == "/api/v1/clients":
            self.handle_clients()
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
            now = utc_now()
            with connect() as db:
                db.execute(
                    """
                    INSERT INTO clients (
                        client_id, display_id, client_secret, username, machine_name, app_version,
                        os, windows_version, installed_at, original_ip, region, device_json,
                        status, total_traffic_bytes, created_at, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disconnected', 0, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        display_id = excluded.display_id,
                        client_secret = excluded.client_secret,
                        username = excluded.username,
                        machine_name = excluded.machine_name,
                        app_version = excluded.app_version,
                        os = excluded.os,
                        windows_version = excluded.windows_version,
                        installed_at = COALESCE(clients.installed_at, excluded.installed_at),
                        original_ip = excluded.original_ip,
                        region = excluded.region,
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
                        region_for_ip(ip),
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
                    original_ip = ?,
                    region = ?,
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
                    region_for_ip(ip),
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
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
            return

        with connect() as db:
            rows = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, original_ip, region, status,
                       routing_mode, connections_json, total_traffic_bytes, last_seen_at, device_json
                FROM clients
                ORDER BY last_seen_at DESC;
                """
            ).fetchall()
        json_response(self, HTTPStatus.OK, {"clients": [client_row(row) for row in rows]})

    def handle_client_detail(self, path: str) -> None:
        if not dashboard_authorized(self):
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
            return

        client_id = path.rsplit("/", 1)[-1]
        with connect() as db:
            client = db.execute(
                """
                SELECT client_id, display_id, username, machine_name, app_version, os, windows_version,
                       installed_at, original_ip, region, status, routing_mode, connections_json,
                       total_traffic_bytes, last_seen_at, device_json
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
                FROM events WHERE client_id = ? ORDER BY created_at DESC LIMIT 200;
                """,
                (client_id,),
            ).fetchall()

        json_response(self, HTTPStatus.OK, {"client": client_row(client), "events": [dict(row) for row in events]})

    def handle_collect_now(self, path: str) -> None:
        if not dashboard_authorized(self):
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
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
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
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
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
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
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
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

            os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
            if os.path.exists(DB_PATH):
                backup_name = f"{DB_PATH}.before-restore-{int(time.time())}"
                os.replace(DB_PATH, backup_name)
            os.replace(restored_db_path, DB_PATH)

        init_db()
        json_response(self, HTTPStatus.OK, {"status": "restored"})

    def handle_delete_client(self, path: str) -> None:
        if not dashboard_authorized(self):
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "dashboard_token_required"})
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
