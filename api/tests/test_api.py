import base64
import hashlib
import hmac
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import date, datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app
import common.backup_contract as backup_contract

os.environ.setdefault(
    "LOKI_WATCHER_BACKUP_ENCRYPTION_KEY",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
)


def secret() -> str:
    return base64.urlsafe_b64encode(b"0" * 32).decode("ascii").rstrip("=")


def signature(method: str, path: str, timestamp: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, timestamp, body_hash]).encode("utf-8")
    return base64.b64encode(hmac.new(b"0" * 32, canonical, hashlib.sha256).digest()).decode("ascii")


def legacy_generation_one_backup(db_path: str) -> bytes:
    key = backup_contract.decode_backup_key()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        snapshot_path = os.path.join(temp_dir, "watcher.db")
        encrypted_path = os.path.join(temp_dir, "watcher.db.enc")
        backup_contract.snapshot_database(db_path, snapshot_path)
        with app.sqlite3.connect(snapshot_path) as db:
            db.execute("DROP TABLE connection_sources")
        counts = backup_contract.database_record_counts(snapshot_path, schema_generation=1)
        nonce, tag = backup_contract.encrypt_file(snapshot_path, encrypted_path, key)
        with open(encrypted_path, "rb") as source:
            encrypted = source.read()
        readme = backup_contract.readme_text().encode("utf-8")
        manifest = {
            "format": backup_contract.FORMAT_NAME,
            "schemaVersion": backup_contract.FORMAT_VERSION,
            "databaseSchemaGeneration": 1,
            "serviceRole": "watcher-control-plane",
            "sourceVersion": "legacy-test",
            "createdAt": backup_contract.utc_now(),
            "scope": "complete",
            "restoreMode": "replace",
            "source": "legacy-test",
            "encryption": {
                "algorithm": "AES-256-GCM",
                "keyFingerprint": backup_contract.key_fingerprint(key),
                "nonce": nonce,
                "tag": tag,
                "externalKeyRequired": True,
            },
            "files": {
                backup_contract.STATE_MEMBER: {
                    "sha256": hashlib.sha256(encrypted).hexdigest(),
                    "uncompressedBytes": len(encrypted),
                    "records": sum(counts.values()),
                    "recordCounts": counts,
                    "encrypted": True,
                },
                backup_contract.README_MEMBER: {
                    "sha256": hashlib.sha256(readme).hexdigest(),
                    "uncompressedBytes": len(readme),
                    "records": 0,
                    "encrypted": False,
                },
            },
        }
        manifest["manifestHmacSha256"] = hmac.new(
            key,
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w") as archive:
            archive.writestr(backup_contract.STATE_MEMBER, encrypted)
            archive.writestr(backup_contract.README_MEMBER, readme)
            archive.writestr(
                backup_contract.MANIFEST_MEMBER,
                json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            )
        return result.getvalue()


class ApiTests(unittest.TestCase):
    def setUp(self):
        app._dashboard_auth_failures.clear()
        app._dashboard_auth_blocked_until.clear()
        app._public_initialization_attempts.clear()
        app._public_initialization_global_attempts.clear()
        app.invalidate_manifest_cache()
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        app.DB_PATH = os.path.join(self.tmp.name, "watcher.db")
        app.init_db(app.DB_PATH)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.WatcherHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        time.sleep(0.1)
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=payload, headers=headers or {})
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8") or "{}")
        finally:
            conn.close()

    def signed_request(self, method, path, body, client_id, client_secret=None, headers=None):
        payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        key = client_secret or secret()
        signed_headers = {
            "Content-Type": "application/json",
            "X-Loki-Client-Id": client_id,
            "X-Loki-Timestamp": timestamp,
            "X-Loki-Signature": signature(method, path, timestamp, payload),
            **(headers or {}),
        }
        if key != secret():
            body_hash = hashlib.sha256(payload).hexdigest()
            canonical = "\n".join([method, path, timestamp, body_hash]).encode("utf-8")
            decoded_key = base64.urlsafe_b64decode(key + "=" * ((4 - len(key) % 4) % 4))
            signed_headers["X-Loki-Signature"] = base64.b64encode(
                hmac.new(decoded_key, canonical, hashlib.sha256).digest()
            ).decode("ascii")
        return self.request(method, path, body, signed_headers)

    def raw_request(self, method, path, body=b"", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_legacy_audit_schema_is_migrated_before_backfill(self):
        legacy_path = os.path.join(self.tmp.name, "legacy.db")
        db = app.sqlite3.connect(legacy_path)
        try:
            db.execute(
                """
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    actor TEXT,
                    message TEXT,
                    context_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            db.execute(
                "INSERT INTO audit_events (created_at, status, action, target, actor, message, context_json) VALUES (?, ?, ?, ?, ?, ?, '{}')",
                (app.utc_now(), "success", "legacy.action", "legacy", "operator", "legacy row"),
            )
            db.commit()
        finally:
            db.close()

        app.init_db(legacy_path)
        with app.connect(legacy_path) as migrated:
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(audit_events)")}
            row = migrated.execute("SELECT event_id, severity FROM audit_events WHERE action = 'legacy.action'").fetchone()
        self.assertTrue({"event_id", "severity", "target_type", "actor_type", "request_id", "transport_method", "error_json"}.issubset(columns))
        self.assertRegex(row["event_id"], r"^[0-9a-f]{32}$")
        self.assertEqual("info", row["severity"])

    def test_enroll_batch_clients_and_command(self):
        client_id = "client-1"
        with app.connect(app.DB_PATH) as db:
            db.execute(
                "UPDATE register_entries SET value = '75' WHERE key = 'clients.heartbeat_interval_seconds'"
            )
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "X8Q3L7M2Z9K5R1PA",
                "clientSecret": secret(),
                "device": {"platform": "windows", "deviceType": "desktop-windows", "userName": "tester"},
            },
            client_id,
            headers={"X-Forwarded-For": "10.2.3.4"},
        )
        self.assertEqual(200, status, body)
        self.assertEqual(75, body["clientConfig"]["heartbeatIntervalSeconds"])
        update_policy = body["clientConfig"]["updatePolicy"]
        self.assertEqual("psewdon1m-loki/client", update_policy["repository"])
        self.assertEqual(
            "https://github.com/psewdon1m-loki/client/releases/latest/download/manifest.json",
            update_policy["manifestUrl"],
        )
        self.assertTrue(update_policy["fallbackManifestUrl"].endswith("/manifest.json"))

        batch = {
            "clientId": client_id,
            "displayId": "X8Q3L7M2Z9K5R1PA",
            "device": {
                "platform": "windows",
                "deviceType": "desktop-windows",
                "userName": "tester-current",
                "machineName": "cake-pc",
                "appVersion": "0.1.68",
            },
            "events": [{
                "type": "heartbeat",
                "connectionStatus": "connected",
                "routingMode": "russia-smart",
                "connections": [{"name": "secure ru", "host": "example.com", "port": 443}],
                "trafficTotalBytes": 1234,
                "trafficMeteringMode": "device-network-while-connected",
                "logsUploadEnabled": False,
                "autoUpdatesEnabled": True,
            }],
        }
        raw = json.dumps(batch, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        status, body = self.request(
            "POST",
            "/api/v1/telemetry/batch",
            batch,
            {
                "Content-Type": "application/json",
                "X-Loki-Client-Id": client_id,
                "X-Loki-Timestamp": timestamp,
                "X-Loki-Signature": signature("POST", "/api/v1/telemetry/batch", timestamp, raw),
                "X-Forwarded-For": "10.9.8.7",
            },
        )
        self.assertEqual(200, status, body)
        self.assertEqual(75, body["clientConfig"]["heartbeatIntervalSeconds"])
        self.assertEqual("psewdon1m-loki/client", body["clientConfig"]["updatePolicy"]["repository"])

        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertEqual("connected", body["clients"][0]["status"])
        self.assertEqual("russia-smart", body["clients"][0]["routing_mode"])
        self.assertEqual(1234, body["clients"][0]["total_traffic_bytes"])
        self.assertEqual("windows", body["clients"][0]["platform"])

        status, body = self.request("GET", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)
        self.assertEqual("X8Q3L7M2Z9K5R1PA", body["client"]["display_id"])
        self.assertEqual("tester-current", body["client"]["username"])
        self.assertEqual("10.2.3.4", body["client"]["original_ip"])
        self.assertEqual("10.9.8.7", body["client"]["last_ip"])
        self.assertEqual("local/private", body["client"]["region"])
        self.assertEqual("local/private", body["client"]["provider"])
        self.assertFalse(body["client"]["logs_upload_enabled"])
        self.assertTrue(body["client"]["auto_updates_enabled"])
        self.assertEqual("device-network-while-connected", body["client"]["traffic_metering_mode"])
        self.assertEqual("example.com", body["client"]["connections"][0]["host"])

        status, headers, logs_zip = self.raw_request("GET", f"/api/v1/clients/{client_id}/logs.zip")
        self.assertEqual(200, status)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(logs_zip)) as archive:
            self.assertEqual(
                {"manifest.json", "events.jsonl", "logs.txt", "README.txt"},
                set(archive.namelist()),
            )
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual("vpn-enus-client-log-export", manifest["format"])
            self.assertEqual(1, manifest["files"]["events.jsonl"]["records"])

        status, body = self.request("POST", f"/api/v1/commands/{client_id}/collect-now")
        self.assertEqual(200, status, body)

        timestamp = str(int(time.time()))
        status, body = self.request(
            "GET",
            f"/api/v1/commands/{client_id}",
            headers={
                "X-Loki-Client-Id": client_id,
                "X-Loki-Timestamp": timestamp,
                "X-Loki-Signature": signature("GET", f"/api/v1/commands/{client_id}", timestamp, b""),
            },
        )
        self.assertEqual(200, status, body)
        self.assertEqual("collect_now", body["commands"][0]["type"])

        status, body = self.request("DELETE", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)

        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertEqual([], body["clients"])

    def test_android_platform_is_reported_on_client_card(self):
        client_id = "client-android"
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "ANDROIDCLIENT01",
                "clientSecret": secret(),
                "device": {
                    "platform": "android",
                    "deviceType": "mobile-android",
                    "machineName": "Pixel",
                    "appVersion": "1.0.0",
                },
            },
            client_id,
        )
        self.assertEqual(200, status, body)

        status, body = self.request("GET", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)
        self.assertEqual("android", body["client"]["platform"])

    def test_online_window_tracks_register_heartbeat_interval(self):
        client_id = "client-long-heartbeat"
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "LONGHEARTBEAT01",
                "clientSecret": secret(),
                "device": {"platform": "windows"},
            },
            client_id,
        )
        self.assertEqual(200, status, body)

        with app.connect(app.DB_PATH) as db:
            db.execute(
                "UPDATE register_entries SET value = '3600' WHERE key = 'clients.heartbeat_interval_seconds'"
            )
            db.execute(
                "UPDATE clients SET last_seen_at = ? WHERE client_id = ?",
                ((datetime.now(timezone.utc) - timedelta(minutes=90)).isoformat(), client_id),
            )

        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertTrue(body["clients"][0]["online"])

        status, body = self.request("GET", "/api/v1/dashboard")
        self.assertEqual(200, status, body)
        self.assertEqual(3600, body["system"]["heartbeatIntervalSeconds"])
        self.assertEqual(7200, body["system"]["onlineWindowSeconds"])

        with app.connect(app.DB_PATH) as db:
            db.execute(
                "UPDATE clients SET last_seen_at = ? WHERE client_id = ?",
                ((datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(), client_id),
            )
        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertFalse(body["clients"][0]["online"])

    def test_backup_download_and_restore(self):
        client_id = "client-backup"
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "B8Q3L7M2Z9K5R1PA",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            client_id,
        )
        self.assertEqual(200, status, body)

        status, headers, backup = self.raw_request("GET", "/api/v1/backups/download")
        self.assertEqual(200, status)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(backup)) as archive:
            self.assertEqual(
                {"manifest.json", "data/watcher.db.enc", "README.txt"},
                set(archive.namelist()),
            )
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual("vpn-enus-watcher-backup", manifest["format"])
            self.assertEqual("AES-256-GCM", manifest["encryption"]["algorithm"])
            self.assertEqual("replace", manifest["restoreMode"])
            self.assertRegex(manifest["files"]["data/watcher.db.enc"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(secret().encode("ascii"), backup)

        status, body = self.request("DELETE", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)

        status, raw_headers, raw_body = self.raw_request(
            "POST",
            "/api/v1/backups/upload",
            backup,
            {"Content-Type": "application/zip"},
        )
        self.assertEqual(200, status, raw_body)

        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertEqual(client_id, body["clients"][0]["client_id"])

    def test_generation_one_backup_restores_and_migrates_connection_sources(self):
        status, body = self.request(
            "POST",
            "/api/v1/connections",
            {
                "id": "legacy-connection",
                "telegramId": "123456",
                "subscriptionUrl": "https://legacy.example/sub/token",
                "status": "active",
                "configurations": ["vless://legacy@example.test:443#legacy"],
            },
        )
        self.assertEqual(201, status, body)
        with app.connect(app.DB_PATH) as db:
            db.execute(
                "UPDATE issued_connections SET subscription_url = ? WHERE id = ?",
                ("https://legacy.example/sub/token", "legacy-connection"),
            )
        legacy_backup = legacy_generation_one_backup(app.DB_PATH)

        status, body = self.request("DELETE", "/api/v1/connections/legacy-connection")
        self.assertEqual(200, status, body)
        status, _, response = self.raw_request(
            "POST",
            "/api/v1/backups/upload",
            legacy_backup,
            {"Content-Type": "application/zip"},
        )
        self.assertEqual(200, status, response)

        with app.connect(app.DB_PATH) as db:
            source = db.execute(
                "SELECT provider, subscription_url FROM connection_sources WHERE connection_id = ?",
                ("legacy-connection",),
            ).fetchone()
        self.assertIsNotNone(source)
        self.assertEqual("manual", source["provider"])
        self.assertEqual("https://legacy.example/sub/token", source["subscription_url"])

    def test_corrupt_backup_is_rejected_before_live_mutation(self):
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": "backup-integrity-client",
                "displayId": "BACKUP-INTEGRITY",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            "backup-integrity-client",
        )
        self.assertEqual(200, status, body)
        status, _, backup = self.raw_request("GET", "/api/v1/backups/download")
        self.assertEqual(200, status)

        source = zipfile.ZipFile(io.BytesIO(backup))
        corrupt_buffer = io.BytesIO()
        with source, zipfile.ZipFile(corrupt_buffer, "w") as corrupt:
            for name in source.namelist():
                payload = source.read(name)
                if name == "data/watcher.db.enc":
                    payload = bytes([payload[0] ^ 1]) + payload[1:]
                corrupt.writestr(name, payload)
        status, _, response = self.raw_request(
            "POST",
            "/api/v1/backups/upload",
            corrupt_buffer.getvalue(),
            {"Content-Type": "application/zip"},
        )
        self.assertEqual(400, status, response)
        status, clients = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, clients)
        self.assertEqual("backup-integrity-client", clients["clients"][0]["client_id"])

    def test_backup_rejects_unsafe_archive_shapes_before_live_mutation(self):
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": "backup-shape-client",
                "displayId": "BACKUP-SHAPE",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            "backup-shape-client",
        )
        self.assertEqual(200, status, body)
        status, _, backup = self.raw_request("GET", "/api/v1/backups/download")
        self.assertEqual(200, status)

        variants = {}
        with zipfile.ZipFile(io.BytesIO(backup)) as source:
            missing = io.BytesIO()
            with zipfile.ZipFile(missing, "w") as target:
                for name in source.namelist():
                    if name != "README.txt":
                        target.writestr(name, source.read(name))
            variants["missing"] = missing.getvalue()

            traversal = io.BytesIO()
            with zipfile.ZipFile(traversal, "w") as target:
                for name in source.namelist():
                    target.writestr(name, source.read(name))
                target.writestr("../escape", b"forbidden")
            variants["traversal"] = traversal.getvalue()

            link = io.BytesIO()
            with zipfile.ZipFile(link, "w") as target:
                for name in source.namelist():
                    if name == "README.txt":
                        info = zipfile.ZipInfo("README.txt")
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                        target.writestr(info, b"manifest.json")
                    else:
                        target.writestr(name, source.read(name))
            variants["link"] = link.getvalue()

        for name, payload in variants.items():
            with self.subTest(name=name):
                status, _, response = self.raw_request(
                    "POST",
                    "/api/v1/backups/upload",
                    payload,
                    {"Content-Type": "application/zip"},
                )
                self.assertEqual(400, status, response)

        status, clients = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, clients)
        self.assertEqual("backup-shape-client", clients["clients"][0]["client_id"])

    def test_failed_post_apply_invariant_restores_pre_restore_snapshot(self):
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": "archive-state-client",
                "displayId": "ARCHIVE-STATE",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            "archive-state-client",
        )
        self.assertEqual(200, status, body)
        status, _, backup = self.raw_request("GET", "/api/v1/backups/download")
        self.assertEqual(200, status)
        status, _ = self.request("DELETE", "/api/v1/clients/archive-state-client")
        self.assertEqual(200, status)
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": "pre-restore-client",
                "displayId": "PRE-RESTORE",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            "pre-restore-client",
        )
        self.assertEqual(200, status, body)

        original_init_db = app.init_db
        calls = 0

        def fail_first_post_apply_check(path=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise app.BackupContractError("forced_post_apply_failure")
            return original_init_db(path)

        try:
            app.init_db = fail_first_post_apply_check
            status, _, response = self.raw_request(
                "POST",
                "/api/v1/backups/upload",
                backup,
                {"Content-Type": "application/zip"},
            )
            self.assertEqual(400, status, response)
        finally:
            app.init_db = original_init_db

        status, clients = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, clients)
        self.assertEqual(["pre-restore-client"], [item["client_id"] for item in clients["clients"]])

    def test_enrollment_requires_signature_and_cannot_replace_secret(self):
        client_id = "client-enrollment"
        enrollment = {
            "clientId": client_id,
            "displayId": "ENROLLMENT",
            "clientSecret": secret(),
            "device": {"deviceType": "desktop-windows"},
        }

        status, body = self.request("POST", "/api/v1/enroll", enrollment)
        self.assertEqual(401, status, body)

        status, body = self.signed_request("POST", "/api/v1/enroll", enrollment, client_id)
        self.assertEqual(200, status, body)

        replacement_secret = base64.urlsafe_b64encode(b"1" * 32).decode("ascii").rstrip("=")
        replacement = {**enrollment, "clientSecret": replacement_secret}
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            replacement,
            client_id,
            client_secret=replacement_secret,
        )
        self.assertEqual(409, status, body)

        with app.connect(app.DB_PATH) as db:
            stored = db.execute(
                "SELECT client_secret FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        self.assertEqual(secret(), stored["client_secret"])

    def test_analytics_batch_is_idempotent_and_excludes_heartbeat(self):
        client_id = "client-analytics"
        enrollment = {
            "clientId": client_id,
            "displayId": "ANALYTICSCLIENT01",
            "clientSecret": secret(),
            "device": {"deviceType": "desktop-windows", "machineName": "qa-pc"},
        }
        status, body = self.signed_request("POST", "/api/v1/enroll", enrollment, client_id)
        self.assertEqual(200, status, body)

        report = {
            "reportId": "report-fail-0001",
            "type": "fail_analytics",
            "occurredAt": "2026-08-21T02:00:00+00:00",
            "schemaVersion": "1.0",
            "engineVersion": "client-0.1.67",
            "status": "FAIL",
            "summary": {"reasonCode": "AUTHENTICATED_E2E_FAILED"},
            "payload": {
                "status": "FAIL",
                "reasonCode": "AUTHENTICATED_E2E_FAILED",
                "clientSecret": "must-not-be-stored",
            },
        }
        batch = {"clientId": client_id, "reports": [report]}
        for _ in range(2):
            status, body = self.signed_request(
                "POST", "/api/v1/analytics/batch", batch, client_id
            )
            self.assertEqual(200, status, body)
            self.assertEqual([report["reportId"]], body["acceptedReportIds"])

        heartbeat = {
            "clientId": client_id,
            "events": [{"type": "heartbeat", "connectionStatus": "connected"}],
        }
        status, body = self.signed_request(
            "POST", "/api/v1/telemetry/batch", heartbeat, client_id
        )
        self.assertEqual(200, status, body)

        status, body = self.request("GET", "/api/v1/analytics")
        self.assertEqual(200, status, body)
        self.assertEqual(1, len(body["reports"]))
        self.assertEqual("fail_analytics", body["reports"][0]["report_type"])
        self.assertNotIn("payload", body["reports"][0])

        status, body = self.request(
            "GET", f"/api/v1/analytics/{report['reportId']}"
        )
        self.assertEqual(200, status, body)
        self.assertEqual("[REDACTED]", body["report"]["payload"]["clientSecret"])
        with app.connect(app.DB_PATH) as db:
            self.assertEqual(1, db.execute("SELECT COUNT(*) FROM analytics_reports").fetchone()[0])

    def test_analytics_rejects_unknown_type(self):
        client_id = "client-analytics-invalid"
        enrollment = {
            "clientId": client_id,
            "displayId": "ANALYTICSINVALID",
            "clientSecret": secret(),
            "device": {},
        }
        status, body = self.signed_request("POST", "/api/v1/enroll", enrollment, client_id)
        self.assertEqual(200, status, body)
        status, body = self.signed_request(
            "POST",
            "/api/v1/analytics/batch",
            {
                "clientId": client_id,
                "reports": [{
                    "reportId": "report-invalid-01",
                    "type": "heartbeat",
                    "occurredAt": "2026-08-21T02:00:00Z",
                    "payload": {},
                }],
            },
            client_id,
        )
        self.assertEqual(400, status, body)
        self.assertEqual("invalid_analytics_report_type", body["error"])

    def test_dashboard_basic_auth(self):
        old_username = app.DASHBOARD_USERNAME
        old_password = app.DASHBOARD_PASSWORD
        try:
            app.DASHBOARD_USERNAME = "admin"
            app.DASHBOARD_PASSWORD = "secret"

            status, body = self.request("GET", "/api/v1/clients")
            self.assertEqual(401, status, body)

            status, body = self.request(
                "GET",
                "/api/v1/clients",
                headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
            )
            self.assertEqual(200, status, body)
        finally:
            app.DASHBOARD_USERNAME = old_username
            app.DASHBOARD_PASSWORD = old_password

    def test_dashboard_auth_is_rate_limited(self):
        old_username = app.DASHBOARD_USERNAME
        old_password = app.DASHBOARD_PASSWORD
        try:
            app.DASHBOARD_USERNAME = "admin"
            app.DASHBOARD_PASSWORD = "secret"
            for _ in range(app.DASHBOARD_AUTH_MAX_FAILURES - 1):
                status, _ = self.request("GET", "/api/v1/clients")
                self.assertEqual(401, status)
            status, body = self.request("GET", "/api/v1/clients")
            self.assertEqual(429, status, body)
            self.assertEqual("dashboard_auth_rate_limited", body["error"])
            status, body = self.request(
                "GET",
                "/api/v1/clients",
                headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
            )
            self.assertEqual(429, status, body)
        finally:
            app.DASHBOARD_USERNAME = old_username
            app.DASHBOARD_PASSWORD = old_password

    def test_subscription_fetch_rejects_insecure_and_private_origins(self):
        with self.assertRaisesRegex(ValueError, "subscription_https_required"):
            app.validate_subscription_url("http://example.com/subscription")
        with self.assertRaisesRegex(ValueError, "subscription_private_address_denied"):
            app.validate_subscription_url("https://127.0.0.1/subscription")
        app.validate_subscription_url(
            "http://127.0.0.1/subscription",
            trusted_origin="http://127.0.0.1",
        )

    def test_dashboard_does_not_wait_for_github(self):
        old_request_json = app.request_json
        old_cache = app._manifest_cache_body
        try:
            app._manifest_cache_body = None
            app.request_json = lambda url, timeout=30: self.fail("dashboard must not call GitHub")
            status, body = self.request("GET", "/api/v1/dashboard")
            self.assertEqual(200, status, body)
            self.assertIn("issuedConnections", body["system"])
        finally:
            app.request_json = old_request_json
            app._manifest_cache_body = old_cache

    def test_update_state_is_stored_on_client(self):
        client_id = "client-update"
        status, body = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "UPD123",
                "clientSecret": secret(),
                "device": {"appVersion": "0.1.57"},
            },
            client_id,
        )
        self.assertEqual(200, status, body)

        status, body = self.request(
            "POST",
            "/api/v1/update-state",
            {"clientId": client_id, "displayId": "UPD123"},
        )
        self.assertEqual(401, status, body)

        status, body = self.signed_request(
            "POST",
            "/api/v1/update-state",
            {
                "clientId": client_id,
                "displayId": "UPD123",
                "appVersion": "0.1.57",
                "routingMode": "russia-smart",
                "activeRuleSet": "russia-smart",
                "autoUpdatesEnabled": True,
                "logsUploadEnabled": False,
                "updateManifestUrl": "https://watcher.example.test/manifest.json",
                "lastCheckSuccess": True,
                "lastCheckMessage": "ok",
                "ruleSets": [{"id": "russia-smart", "sha256": "abc"}],
            },
            client_id,
        )
        self.assertEqual(200, status, body)

        status, body = self.request("GET", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)
        self.assertTrue(body["client"]["auto_updates_enabled"])
        self.assertFalse(body["client"]["logs_upload_enabled"])
        self.assertEqual("reported", body["client"]["update_report_status"])
        self.assertEqual("https://watcher.example.test/manifest.json", body["client"]["update_manifest_url"])

    def test_connections_register_settings_and_audit_endpoints(self):
        connection = {
            "id": "connection-test",
            "status": "active",
            "configurations": [
                "vless://first@example.test:443?security=reality#first",
                "vless://second@example.test:443?security=reality#second",
            ],
        }
        status, created = self.request("POST", "/api/v1/connections", connection)
        self.assertEqual(201, status)
        self.assertEqual(connection["configurations"], created["connection"]["configurations"])
        self.assertEqual(date.today().isoformat(), created["connection"]["subscription_renewal_date"])
        self.assertTrue(created["connection"]["track_subscription"])
        created_at = created["connection"]["created_at"]

        connection["status"] = "disabled"
        connection["subscriptionRenewalDate"] = "2026-09-27"
        connection["trackSubscription"] = False
        status, updated = self.request("PUT", "/api/v1/connections/connection-test", connection)
        self.assertEqual(200, status)
        self.assertEqual("disabled", updated["connection"]["status"])
        self.assertEqual("2026-09-27", updated["connection"]["subscription_renewal_date"])
        self.assertFalse(updated["connection"]["track_subscription"])
        self.assertEqual(created_at, updated["connection"]["created_at"])

        rejected = {**connection, "status": "revoked"}
        status, invalid = self.request("PUT", "/api/v1/connections/connection-test", rejected)
        self.assertEqual(400, status)
        self.assertEqual("invalid_connection_status", invalid["error"])

        old_fetch_subscription = app.fetch_subscription
        try:
            app.fetch_subscription = lambda url, verify_tls, **kwargs: [
                f"vless://id@server-{index}.example:443#server-{index}" for index in range(1, 6)
            ]
            status, scanned = self.request("POST", "/api/v1/connections/connection-test/scan")
            self.assertEqual(200, status)
            self.assertEqual(2, scanned["count"])
        finally:
            app.fetch_subscription = old_fetch_subscription

        status, listed = self.request("GET", "/api/v1/connections")
        self.assertEqual(200, status)
        self.assertIsNone(listed["connections"][0]["telegram_id"])
        self.assertEqual("direct", listed["connections"][0]["sources"][0]["provider"])

        status, created_register = self.request(
            "POST",
            "/api/v1/register",
            {"key": "panel.public_url", "value": "https://panel.example", "description": "Panel URL"},
        )
        self.assertEqual(201, status)
        self.assertEqual("panel.public_url", created_register["entry"]["key"])

        status, register = self.request("GET", "/api/v1/register")
        self.assertEqual(200, status)
        self.assertIn("panel.public_url", [item["key"] for item in register["entries"]])
        defaults = {item["key"]: item for item in register["entries"]}
        for obsolete_key in app.OBSOLETE_REGISTER_KEYS:
            self.assertNotIn(obsolete_key, defaults)
        self.assertEqual("psewdon1m-loki/client", defaults["github.repository"]["value"])
        self.assertEqual("60", defaults["clients.heartbeat_interval_seconds"]["value"])
        self.assertEqual("", defaults["updates.manifest_public_key_pem"]["value"])
        self.assertTrue(defaults["pasarguard.api_key"]["secret"])
        self.assertEqual("", defaults["pasarguard.api_key"]["value"])

        status, api_key_update = self.request(
            "PUT",
            "/api/v1/register/pasarguard.api_key",
            {
                "key": "pasarguard.api_key",
                "value": "registered-pasarguard-key",
                "description": defaults["pasarguard.api_key"]["description"],
            },
        )
        self.assertEqual(200, status, api_key_update)
        self.assertTrue(api_key_update["entry"]["configured"])
        self.assertEqual("", api_key_update["entry"]["value"])
        status, preserved_api_key = self.request(
            "PUT",
            "/api/v1/register/pasarguard.api_key",
            {
                "key": "pasarguard.api_key",
                "value": "",
                "description": "Updated masked secret description",
                "preserveSecret": True,
            },
        )
        self.assertEqual(200, status, preserved_api_key)
        self.assertTrue(preserved_api_key["entry"]["configured"])
        with app.connect(app.DB_PATH) as db:
            stored_api_key = db.execute(
                "SELECT value FROM register_entries WHERE key = 'pasarguard.api_key'"
            ).fetchone()["value"]
        self.assertEqual("registered-pasarguard-key", stored_api_key)

        status, invalid_heartbeat = self.request(
            "PUT",
            "/api/v1/register/clients.heartbeat_interval_seconds",
            {
                "key": "clients.heartbeat_interval_seconds",
                "value": "5",
                "description": defaults["clients.heartbeat_interval_seconds"]["description"],
            },
        )
        self.assertEqual(400, status, invalid_heartbeat)
        self.assertEqual("invalid_client_heartbeat_interval", invalid_heartbeat["error"])

        status, repository_update = self.request(
            "PUT",
            "/api/v1/register/github.repository",
            {
                "key": "github.repository",
                "value": "owner/client",
                "description": defaults["github.repository"]["description"],
            },
        )
        self.assertEqual(200, status, repository_update)
        self.assertEqual("https://api.github.com/repos/owner/client/releases/latest", app.github_api_url())
        with app.connect(app.DB_PATH) as db:
            update_policy = app.client_update_policy(db)
        self.assertEqual("owner/client", update_policy["repository"])
        self.assertEqual(
            "https://github.com/owner/client/releases/latest/download/manifest.json",
            update_policy["manifestUrl"],
        )

        status, invalid_signing_key_update = self.request(
            "PUT",
            "/api/v1/register/updates.manifest_public_key_pem",
            {
                "key": "updates.manifest_public_key_pem",
                "value": "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
                "description": defaults["updates.manifest_public_key_pem"]["description"],
            },
        )
        self.assertEqual(400, status, invalid_signing_key_update)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        status, signing_key_update = self.request(
            "PUT",
            "/api/v1/register/updates.manifest_public_key_pem",
            {
                "key": "updates.manifest_public_key_pem",
                "value": public_key_pem,
                "description": defaults["updates.manifest_public_key_pem"]["description"],
            },
        )
        self.assertEqual(200, status, signing_key_update)
        with app.connect(app.DB_PATH) as db:
            signed_update_policy = app.client_update_policy(db)
        self.assertTrue(signed_update_policy["requireManifestSignature"])
        self.assertIn("BEGIN PUBLIC KEY", signed_update_policy["manifestPublicKeyPem"])

        status, sni_update = self.request(
            "PUT",
            "/api/v1/register/watcher.public_sni",
            {
                "key": "watcher.public_sni",
                "value": "subscriptions.example",
                "description": defaults["watcher.public_sni"]["description"],
            },
        )
        self.assertEqual(200, status, sni_update)

        status, settings = self.request("GET", "/api/v1/settings")
        self.assertEqual(200, status)
        self.assertEqual(30, settings["retention"]["telemetryDays"])
        self.assertEqual(15, settings["connections"]["scanIntervalMinutes"])
        self.assertEqual(60, settings["clients"]["heartbeatIntervalSeconds"])
        self.assertTrue(settings["connections"]["pasarguard"]["apiKeyConfigured"])
        self.assertEqual("owner/client", settings["updates"]["clientRepository"])
        self.assertEqual("https://subscriptions.example", settings["updates"]["publicUrl"])

        status, connection_settings = self.request(
            "PUT",
            "/api/v1/settings/connections",
            {"scanIntervalMinutes": 15},
        )
        self.assertEqual(200, status)
        self.assertEqual(15, connection_settings["scanIntervalMinutes"])

        status, audit = self.request("GET", "/api/v1/audit?limit=20")
        self.assertEqual(200, status)
        self.assertIn("connection.create", [item["action"] for item in audit["events"]])
        self.assertIn("register.create", [item["action"] for item in audit["events"]])

        status, headers, payload = self.raw_request("GET", "/api/v1/logs/download")
        self.assertEqual(200, status)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            self.assertEqual(
                {"events.jsonl", "errors.json", "manifest.json", "README.txt"},
                set(archive.namelist()),
            )
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual("vpn-enus-log-export", manifest["format"])
            self.assertFalse(manifest["exportAuditEventIncluded"])
            streams = {
                json.loads(line)["stream"]
                for line in archive.read("events.jsonl").decode("utf-8").splitlines()
            }
            self.assertEqual({"audit"}, streams)

        status, _ = self.request("DELETE", "/api/v1/connections/connection-test")
        self.assertEqual(200, status)
        status, _ = self.request("DELETE", "/api/v1/register/panel.public_url")
        self.assertEqual(200, status)

    def test_pasarguard_provision_reset_and_stable_watcher_subscription(self):
        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE register_entries SET value = 'subscriptions.example' WHERE key = 'watcher.public_sni'")
        status, created = self.request(
            "POST",
            "/api/v1/connections",
            {
                "id": "permanent-id",
                "status": "active",
                "configurations": [],
            },
        )
        self.assertEqual(201, status, created)
        self.assertEqual("permanent-id", created["connection"]["id"])
        self.assertEqual("draft", created["connection"]["provisioning_state"])
        stable_url = created["connection"]["public_subscription_url"]

        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE register_entries SET value = 'https://pasarguard.example' WHERE key = 'pasarguard.base_url'")
            db.execute("UPDATE register_entries SET value = '17' WHERE key = 'pasarguard.user_template_id'")
            db.execute("UPDATE register_entries SET value = 'pg_key_test' WHERE key = 'pasarguard.api_key'")
        self.assertEqual(
            ("https://pasarguard.example", "pg_key_test"),
            app.pasarguard_client_settings(),
        )

        old_request = app.pasarguard_request
        old_fetch = app.fetch_subscription
        calls = []
        remote = {
            "id": 71,
            "username": "permanent-id",
            "note": "managed-by=vpnenus-watcher; connection=permanent-id",
            "subscription_url": "/sub/old-token",
            "proxy_settings": {"vless": {"id": "old-credential"}},
        }

        def fake_pasarguard_request(method, path, body=None):
            calls.append((method, path, body))
            if method == "GET" and path == "/api/user_template/17":
                return {"id": 17, "username_prefix": None, "username_suffix": None}
            if method == "GET" and path.endswith("/by-username/permanent-id"):
                raise app.PasarGuardError(404, "pasarguard_http_404", "not found")
            if method == "GET" and path.endswith("/by-id/71"):
                return dict(remote)
            if method == "POST" and path == "/api/user/from_template":
                self.assertEqual("permanent-id", body["username"])
                self.assertEqual(17, body["user_template_id"])
                return dict(remote)
            if method == "POST" and path.endswith("/by-id/71/revoke_sub"):
                remote["subscription_url"] = "/sub/new-token"
                remote["proxy_settings"] = {"vless": {"id": "new-credential"}}
                return dict(remote)
            self.fail(f"Unexpected PasarGuard call: {method} {path}")

        def fake_fetch(url, verify_tls, **kwargs):
            self.assertTrue(verify_tls)
            credential = "new-credential" if "new-token" in url else "old-credential"
            return [f"vless://{credential}@node.example:443?security=reality#node"]

        app.pasarguard_request = fake_pasarguard_request
        app.fetch_subscription = fake_fetch
        try:
            status, provisioned = self.request(
                "POST", "/api/v1/connections/permanent-id/pasarguard/provision"
            )
            self.assertEqual(200, status, provisioned)
            connection = provisioned["connection"]
            self.assertEqual("permanent-id", connection["id"])
            pasar_source = next(source for source in connection["sources"] if source["provider"] == "pasarguard")
            self.assertEqual("permanent-id", pasar_source["external_username"])
            self.assertEqual("", connection["telegram_username"])
            self.assertEqual(stable_url, connection["public_subscription_url"])
            self.assertTrue(stable_url.startswith("https://subscriptions.example/sub/"))
            self.assertEqual("https://pasarguard.example/sub/old-token", connection["subscription_url"])
            self.assertIn("old-credential", connection["configurations"][0])

            public_path = app.urlparse(stable_url).path
            status, raw_headers, raw = self.raw_request("GET", f"{public_path}?format=raw")
            self.assertEqual(200, status)
            self.assertIn(b"old-credential", raw)
            self.assertIn("ETag", raw_headers)
            status, cached_headers, cached = self.raw_request(
                "GET", f"{public_path}?format=raw", headers={"If-None-Match": raw_headers["ETag"]}
            )
            self.assertEqual(304, status)
            self.assertEqual(b"", cached)
            self.assertEqual(raw_headers["ETag"], cached_headers["ETag"])
            status, _, encoded = self.raw_request("GET", public_path)
            self.assertEqual(200, status)
            self.assertIn(b"old-credential", base64.b64decode(encoded))
            status, _, managed_payload = self.raw_request("GET", f"{public_path}?format=json")
            self.assertEqual(200, status)
            managed = json.loads(managed_payload)
            self.assertEqual("loki-managed-subscription", managed["type"])
            self.assertEqual("permanent-id", managed["connectionId"])
            self.assertTrue(managed["trackSubscription"])
            self.assertEqual(date.today().isoformat(), managed["subscriptionRenewalDate"])
            self.assertIn("old-credential", managed["configurations"][0])

            status, reset = self.request(
                "POST", "/api/v1/connections/permanent-id/pasarguard/reset"
            )
            self.assertEqual(200, status, reset)
            connection = reset["connection"]
            self.assertEqual("permanent-id", connection["id"])
            pasar_source = next(source for source in connection["sources"] if source["provider"] == "pasarguard")
            self.assertEqual("permanent-id", pasar_source["external_username"])
            self.assertEqual("", connection["telegram_username"])
            self.assertEqual(stable_url, connection["public_subscription_url"])
            self.assertIn("new-token", connection["subscription_url"])
            self.assertIn("new-credential", connection["configurations"][0])
            self.assertIn(("POST", "/api/user/by-id/71/revoke_sub", None), calls)
        finally:
            app.pasarguard_request = old_request
            app.fetch_subscription = old_fetch

    def test_client_initialization_is_signed_idempotent_and_returns_stable_link(self):
        client_id = "managed-client"
        status, enrolled = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "MANAGED-CLIENT",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            client_id,
        )
        self.assertEqual(200, status, enrolled)

        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE register_entries SET value = 'subscriptions.example' WHERE key = 'watcher.public_sni'")
            db.execute("UPDATE register_entries SET value = 'https://pasarguard.example' WHERE key = 'pasarguard.base_url'")
            db.execute("UPDATE register_entries SET value = '17' WHERE key = 'pasarguard.user_template_id'")
            db.execute("UPDATE register_entries SET value = 'pg_key_test' WHERE key = 'pasarguard.api_key'")

        old_request = app.pasarguard_request
        old_fetch = app.fetch_subscription
        created_users = []
        remote = {}

        def fake_pasarguard_request(method, path, body=None):
            if method == "GET" and path == "/api/user_template/17":
                return {"id": 17, "username_prefix": None, "username_suffix": None}
            if method == "GET" and "/by-username/" in path:
                raise app.PasarGuardError(404, "pasarguard_http_404", "not found")
            if method == "POST" and path == "/api/user/from_template":
                created_users.append(body["username"])
                remote.update({
                    "id": 91,
                    "username": body["username"],
                    "note": f"managed-by=vpnenus-watcher; connection={body['username']}",
                    "subscription_url": "/sub/client-token",
                    "proxy_settings": {"vless": {"id": "client-credential"}},
                })
                return dict(remote)
            if method == "GET" and path == "/api/user/by-id/91":
                return dict(remote)
            self.fail(f"Unexpected PasarGuard call: {method} {path}")

        app.pasarguard_request = fake_pasarguard_request
        app.fetch_subscription = lambda url, verify_tls, **kwargs: [
            "vless://client-credential@node.example:443?security=reality#managed"
        ]
        try:
            payload = {"clientId": client_id, "displayId": "MANAGED-CLIENT"}
            status, first = self.signed_request(
                "POST", "/api/v1/client/connections/initialize", payload, client_id
            )
            self.assertEqual(201, status, first)
            self.assertTrue(first["created"])
            self.assertEqual(1, first["count"])
            self.assertTrue(first["subscriptionUrl"].startswith("https://subscriptions.example/sub/"))
            self.assertTrue(first["createdAt"])

            status, second = self.signed_request(
                "POST", "/api/v1/client/connections/initialize", payload, client_id
            )
            self.assertEqual(200, status, second)
            self.assertFalse(second["created"])
            self.assertEqual(first["connectionId"], second["connectionId"])
            self.assertEqual(first["subscriptionUrl"], second["subscriptionUrl"])
            self.assertEqual(1, len(created_users))

            replacement_client_id = "managed-client-after-reset"
            replacement_secret = base64.urlsafe_b64encode(b"replacement-client-secret-32byt"[:32]).decode("ascii").rstrip("=")
            status, replacement_enrollment = self.signed_request(
                "POST",
                "/api/v1/enroll",
                {
                    "clientId": replacement_client_id,
                    "displayId": "RESET-CLIENT",
                    "clientSecret": replacement_secret,
                    "device": {"deviceType": "desktop-windows"},
                },
                replacement_client_id,
                client_secret=replacement_secret,
            )
            self.assertEqual(200, status, replacement_enrollment)
            status, replacement = self.signed_request(
                "POST",
                "/api/v1/client/connections/initialize",
                {"clientId": replacement_client_id, "displayId": "RESET-CLIENT"},
                replacement_client_id,
                client_secret=replacement_secret,
            )
            self.assertEqual(201, status, replacement)
            self.assertTrue(replacement["created"])
            self.assertNotEqual(first["connectionId"], replacement["connectionId"])
            self.assertNotEqual(first["subscriptionUrl"], replacement["subscriptionUrl"])
            self.assertEqual(2, len(created_users))

            with app.connect(app.DB_PATH) as db:
                bound_id = db.execute(
                    "SELECT connection_id FROM clients WHERE client_id = ?", (client_id,)
                ).fetchone()["connection_id"]
            self.assertEqual(first["connectionId"], bound_id)
        finally:
            app.pasarguard_request = old_request
            app.fetch_subscription = old_fetch

    def test_client_initialization_returns_existing_direct_connection_without_pasarguard(self):
        client_id = "direct-managed-client"
        status, enrolled = self.signed_request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "DIRECT-MANAGED-CLIENT",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            client_id,
        )
        self.assertEqual(200, status, enrolled)

        connection_id = "client-existing-direct"
        status, created = self.request(
            "POST",
            "/api/v1/connections",
            {
                "id": connection_id,
                "status": "active",
                "configurations": ["vless://direct@node.example:443?security=reality#direct"],
            },
        )
        self.assertEqual(201, status, created)
        stable_url = created["connection"]["public_subscription_url"]
        with app.connect(app.DB_PATH) as db:
            db.execute(
                "UPDATE clients SET connection_id = ? WHERE client_id = ?",
                (connection_id, client_id),
            )

        old_provision = app.provision_pasarguard_connection

        def unexpected_provision(*args, **kwargs):
            self.fail("A usable direct connection must not trigger PasarGuard provisioning.")

        app.provision_pasarguard_connection = unexpected_provision
        try:
            status, initialized = self.signed_request(
                "POST",
                "/api/v1/client/connections/initialize",
                {"clientId": client_id, "displayId": "DIRECT-MANAGED-CLIENT"},
                client_id,
            )
        finally:
            app.provision_pasarguard_connection = old_provision

        self.assertEqual(200, status, initialized)
        self.assertFalse(initialized["created"])
        self.assertEqual(connection_id, initialized["connectionId"])
        self.assertEqual(stable_url, initialized["subscriptionUrl"])
        self.assertEqual(1, initialized["count"])

    def test_public_initialization_is_idempotent_imports_pasarguard_and_returns_only_vless(self):
        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE register_entries SET value = 'https://pasarguard.example' WHERE key = 'pasarguard.base_url'")
            db.execute("UPDATE register_entries SET value = '17' WHERE key = 'pasarguard.user_template_id'")
            db.execute("UPDATE register_entries SET value = 'pg_key_test' WHERE key = 'pasarguard.api_key'")

        old_request = app.pasarguard_request
        old_fetch = app.fetch_subscription
        old_limit = app.PUBLIC_INITIALIZATION_MAX_PER_HOUR
        created_users = []
        remote = {}

        def fake_pasarguard_request(method, path, body=None):
            if method == "GET" and path == "/api/user_template/17":
                return {"id": 17, "username_prefix": None, "username_suffix": None}
            if method == "GET" and "/by-username/" in path:
                raise app.PasarGuardError(404, "pasarguard_http_404", "not found")
            if method == "POST" and path == "/api/user/from_template":
                created_users.append(body["username"])
                remote.update({
                    "id": 121,
                    "username": body["username"],
                    "note": f"managed-by=vpnenus-watcher; connection={body['username']}",
                    "subscription_url": "/sub/public-token",
                    "proxy_settings": {"vless": {"id": "public-credential"}},
                })
                return dict(remote)
            if method == "GET" and path == "/api/user/by-id/121":
                return dict(remote)
            self.fail(f"Unexpected PasarGuard call: {method} {path}")

        app.pasarguard_request = fake_pasarguard_request
        app.fetch_subscription = lambda url, verify_tls, **kwargs: [
            "vless://public-credential@node.example:443?security=reality#public",
            "trojan://public-credential@node.example:443#not-copied",
        ]
        app.PUBLIC_INITIALIZATION_MAX_PER_HOUR = 1
        try:
            payload = {"requestId": "a" * 32}
            json_headers = {"Content-Type": "application/json"}
            status, first = self.request(
                "POST", "/api/v1/public/connections/initialize", payload, json_headers
            )
            self.assertEqual(201, status, first)
            self.assertTrue(first["created"])
            self.assertEqual(1, first["count"])
            self.assertEqual(
                ["vless://public-credential@node.example:443?security=reality#public"],
                first["vlessLinks"],
            )
            self.assertNotIn("subscriptionUrl", first)
            self.assertTrue(first["connectionId"].startswith("web-"))
            self.assertEqual([first["connectionId"]], created_users)

            stored = app.load_issued_connection(first["connectionId"])
            self.assertEqual(2, len(stored["configurations"]))
            self.assertTrue(any(value.startswith("trojan://") for value in stored["configurations"]))

            status, second = self.request(
                "POST", "/api/v1/public/connections/initialize", payload, json_headers
            )
            self.assertEqual(200, status, second)
            self.assertFalse(second["created"])
            self.assertEqual(first["connectionId"], second["connectionId"])
            self.assertEqual(first["vlessLinks"], second["vlessLinks"])
            self.assertEqual(1, len(created_users))

            status, limited = self.request(
                "POST",
                "/api/v1/public/connections/initialize",
                {"requestId": "b" * 32},
                json_headers,
            )
            self.assertEqual(429, status, limited)
            self.assertEqual("public_initialization_rate_limited", limited["error"])

            status, invalid = self.request(
                "POST",
                "/api/v1/public/connections/initialize",
                {"requestId": "not-a-secure-request-id"},
                json_headers,
            )
            self.assertEqual(400, status, invalid)
            self.assertEqual("invalid_initialization_request_id", invalid["error"])

            status, unsupported = self.request(
                "POST",
                "/api/v1/public/connections/initialize",
                {"requestId": "c" * 32},
                {"Content-Type": "text/plain"},
            )
            self.assertEqual(415, status, unsupported)
            self.assertEqual("json_content_type_required", unsupported["error"])
        finally:
            app.PUBLIC_INITIALIZATION_MAX_PER_HOUR = old_limit
            app.pasarguard_request = old_request
            app.fetch_subscription = old_fetch

    def test_pasarguard_template_affixes_are_rejected_before_user_creation(self):
        old_request = app.pasarguard_request
        calls = []

        def fake_pasarguard_request(method, path, body=None):
            calls.append((method, path, body))
            return {"id": 21, "username_prefix": "vpn-", "username_suffix": None}

        app.pasarguard_request = fake_pasarguard_request
        try:
            with self.assertRaises(app.PasarGuardError) as raised:
                app.validate_pasarguard_template_for_permanent_id(21)
            self.assertEqual("pasarguard_template_changes_username", raised.exception.code)
            self.assertEqual([("GET", "/api/user_template/21", None)], calls)
        finally:
            app.pasarguard_request = old_request

    def test_updater_policy_and_version_only_bridge(self):
        old_control_token = app.LOCAL_CONTROL_TOKEN
        old_bridge = app.updater_socket_request
        app.LOCAL_CONTROL_TOKEN = "test-updater-control-token-abcdefghijklmnopqrstuvwxyz"
        calls = []

        def fake_bridge(method, path, *, body=None, mutation=False, timeout=10.0):
            calls.append({"method": method, "path": path, "body": body, "mutation": mutation})
            if method == "POST":
                self.assertEqual({"requestId", "version"}, set(body))
                return 202, {
                    "accepted": True,
                    "idempotent": False,
                    "job": {"jobId": body["requestId"], "requestedVersion": body["version"], "state": "REQUESTED"},
                }
            return 200, {
                "availableRelease": {"version": "1.2.3"},
                "installed": {"version": "1.2.2"},
                "updateAvailable": True,
            }

        try:
            status, body = self.request("GET", "/api/v1/updater/policy")
            self.assertEqual(403, status, body)
            status, body = self.request(
                "GET",
                "/api/v1/updater/policy",
                headers={"X-Watcher-Control-Token": app.LOCAL_CONTROL_TOKEN},
            )
            self.assertEqual(200, status, body)
            self.assertEqual("psewdon1m-loki/watcher", body["repositories"]["server"])
            self.assertEqual(body["repositories"]["server"], body["repositories"]["updater"])
            supplied_checksum = body.pop("checksumSha256")
            expected_checksum = hashlib.sha256(
                json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.assertEqual(expected_checksum, supplied_checksum)

            app.updater_socket_request = fake_bridge
            status, body = self.request("GET", "/api/v1/server-updates/check")
            self.assertEqual(200, status, body)
            self.assertTrue(body["updateAvailable"])
            status, body = self.request(
                "POST",
                "/api/v1/server-updates/jobs",
                {"version": "1.2.3", "requestId": "web-update-test-123"},
            )
            self.assertEqual(202, status, body)
            self.assertEqual("REQUESTED", body["job"]["state"])
            self.assertTrue(calls[-1]["mutation"])
            self.assertEqual({"requestId", "version"}, set(calls[-1]["body"]))
            status, body = self.request(
                "POST",
                "/api/v1/server-updates/jobs",
                {"version": "1.2.3", "requestId": "web-update-test-456", "command": "docker system prune"},
            )
            self.assertEqual(400, status, body)
            self.assertEqual("invalid_update_request", body["error"])
            with app.connect(app.DB_PATH) as db:
                audit = db.execute(
                    "SELECT status, action, target FROM audit_events WHERE action = 'server.update.request' ORDER BY id DESC LIMIT 1"
                ).fetchone()
            self.assertEqual("success", audit["status"])
            self.assertEqual("1.2.3", audit["target"])
        finally:
            app.LOCAL_CONTROL_TOKEN = old_control_token
            app.updater_socket_request = old_bridge

    def test_server_release_check_falls_back_to_informational_discovery(self):
        old_bridge = app.updater_socket_request
        old_discovery = app.discover_server_release_without_updater

        def unavailable_bridge(*args, **kwargs):
            raise app.UpdaterBridgeError(503, "updater_unavailable", "no local daemon")

        try:
            app.updater_socket_request = unavailable_bridge
            app.discover_server_release_without_updater = lambda: {
                "serviceId": "watcher",
                "installed": {"version": "1.0.0", "images": {}},
                "availableRelease": {"version": "1.1.0"},
                "updateAvailable": True,
                "policy": {"source": "live-register", "repository": "owner/watcher"},
                "informationalOnly": True,
            }
            status, body = self.request("GET", "/api/v1/server-updates/check")
            self.assertEqual(200, status, body)
            self.assertTrue(body["informationalOnly"])
            self.assertTrue(body["updateAvailable"])
        finally:
            app.updater_socket_request = old_bridge
            app.discover_server_release_without_updater = old_discovery

    def test_server_release_check_falls_back_when_daemon_check_fails(self):
        old_bridge = app.updater_socket_request
        old_discovery = app.discover_server_release_without_updater

        try:
            app.updater_socket_request = lambda *args, **kwargs: (
                500,
                {"error": "updater_internal_error", "message": "UpdateError"},
            )
            app.discover_server_release_without_updater = lambda: {
                "serviceId": "watcher",
                "installed": {"version": "1.0.0", "images": {}},
                "availableRelease": {"version": "1.0.0"},
                "updateAvailable": False,
                "policy": {"source": "live-register", "repository": "owner/watcher"},
                "informationalOnly": True,
            }
            status, body = self.request("GET", "/api/v1/server-updates/check")
            self.assertEqual(200, status, body)
            self.assertTrue(body["informationalOnly"])
            self.assertEqual("updater_internal_error", body["daemonWarning"]["error"])
        finally:
            app.updater_socket_request = old_bridge
            app.discover_server_release_without_updater = old_discovery

    def test_informational_server_discovery_validates_release_contract(self):
        old_policy = app.updater_policy_document
        old_github = app.github_json_bounded
        old_version = app.WATCHER_VERSION
        manifest = {
            "schemaVersion": 1,
            "databaseSchemaGeneration": app.DATABASE_SCHEMA_GENERATION,
            "componentRole": "watcher-control-plane",
            "version": "1.2.0",
            "channel": "stable",
            "minimumUpdaterVersion": "1.1.0",
            "images": {
                role: f"ghcr.io/owner/watcher-{role}@sha256:" + (str(index) * 64)
                for index, role in enumerate(("api", "web", "worker"), start=1)
            },
        }
        try:
            app.WATCHER_VERSION = "1.1.0"
            app.updater_policy_document = lambda: {
                "revision": "revision-1",
                "repositories": {"server": "owner/watcher", "updater": "owner/watcher"},
            }
            requested_urls = []

            def fake_github(url, **kwargs):
                requested_urls.append(url)
                return manifest

            app.github_json_bounded = fake_github
            result = app.discover_server_release_without_updater()
            self.assertTrue(result["updateAvailable"])
            self.assertEqual("owner/watcher", result["policy"]["repository"])
            self.assertEqual(1, len(requested_urls))
            self.assertIn("/releases/latest/download/", requested_urls[0])

            manifest["images"]["api"] = "ghcr.io/owner/watcher-api:latest"
            with self.assertRaises(app.UpdaterBridgeError):
                app.discover_server_release_without_updater()
        finally:
            app.updater_policy_document = old_policy
            app.github_json_bounded = old_github
            app.WATCHER_VERSION = old_version

    def test_scheduled_connection_scan_refreshes_due_active_rows(self):
        status, body = self.request(
            "POST",
            "/api/v1/connections",
            {
                "id": "scheduled-connection",
                "status": "active",
                "configurations": ["vless://id@scheduled.example:443?security=reality#scheduled"],
            },
        )
        self.assertEqual(201, status, body)
        old_fetch_subscription = app.fetch_subscription
        try:
            app.fetch_subscription = lambda url, verify_tls, **kwargs: [
                "vless://id@scheduled.example:443?security=reality#scheduled"
            ]
            self.assertEqual(1, app.scan_due_connections())
            self.assertEqual(0, app.scan_due_connections())
        finally:
            app.fetch_subscription = old_fetch_subscription

        status, listed = self.request("GET", "/api/v1/connections")
        self.assertEqual(200, status, listed)
        connection = listed["connections"][0]
        self.assertEqual("success", connection["last_scan_status"])
        self.assertEqual(1, len(connection["configurations"]))

        status, result = self.request(
            "PUT",
            "/api/v1/settings/connections",
            {"scanIntervalMinutes": 0},
        )
        self.assertEqual(400, status, result)
        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE issued_connections SET last_scan_at = NULL")
        self.assertEqual(1, app.scan_due_connections())

    def test_operator_can_change_password(self):
        old_username = app.DASHBOARD_USERNAME
        old_password = app.DASHBOARD_PASSWORD
        app.DASHBOARD_USERNAME = "operator"
        app.DASHBOARD_PASSWORD = "OldPassword_123!"
        old_auth = base64.b64encode(b"operator:OldPassword_123!").decode("ascii")
        new_auth = base64.b64encode(b"operator:NewPassword_456!").decode("ascii")
        try:
            status, body = self.request(
                "POST",
                "/api/v1/settings/password",
                {
                    "currentPassword": "OldPassword_123!",
                    "newPassword": "NewPassword_456!",
                    "repeatPassword": "NewPassword_456!",
                },
                {"Authorization": f"Basic {old_auth}"},
            )
            self.assertEqual(200, status, body)

            status, _ = self.request(
                "GET",
                "/api/v1/settings",
                headers={"Authorization": f"Basic {old_auth}"},
            )
            self.assertEqual(401, status)
            status, _ = self.request(
                "GET",
                "/api/v1/settings",
                headers={"Authorization": f"Basic {new_auth}"},
            )
            self.assertEqual(200, status)
        finally:
            app.DASHBOARD_USERNAME = old_username
            app.DASHBOARD_PASSWORD = old_password

    def test_subscription_parser_returns_all_base64_connections(self):
        connections = [
            f"vless://client@server-{index}.example:443?security=reality#server-{index}"
            for index in range(1, 6)
        ]
        payload = base64.b64encode("\n".join(connections).encode("utf-8"))
        self.assertEqual(connections, app.parse_subscription_payload(payload))

    def test_audit_redaction_and_cursor_pagination(self):
        redacted = app.redact_for_logging(
            {
                "password": "never-export-me",
                "nested": {"Authorization": "Bearer secret-token"},
                "subscription": "https://panel.example/sub/private-token",
                "connection": "vless://identity@example.test:443#private",
            }
        )
        self.assertEqual("[REDACTED]", redacted["password"])
        self.assertEqual("[REDACTED]", redacted["nested"]["Authorization"])
        self.assertNotIn("private-token", redacted["subscription"])
        self.assertEqual("[REDACTED_CONNECTION_URI]", redacted["connection"])

        with app.connect(app.DB_PATH) as db:
            for index in range(3):
                app.write_audit(db, "success", f"test.action.{index}", "target", "tester", "ok")
        status, first = self.request("GET", "/api/v1/audit?limit=2")
        self.assertEqual(200, status, first)
        self.assertEqual(2, len(first["events"]))
        self.assertTrue(first["hasMore"])
        self.assertIsNotNone(first["nextBeforeId"])
        status, second = self.request("GET", f"/api/v1/audit?limit=2&beforeId={first['nextBeforeId']}")
        self.assertEqual(200, status, second)
        self.assertEqual(1, len(second["events"]))

    def test_request_data_queues_online_update_checks(self):
        online_id = "client-online"
        offline_id = "client-offline"
        for client_id in (online_id, offline_id):
            status, body = self.signed_request(
                "POST",
                "/api/v1/enroll",
                {
                    "clientId": client_id,
                    "displayId": client_id,
                    "clientSecret": secret(),
                    "device": {"appVersion": "0.1.57"},
                },
                client_id,
            )
            self.assertEqual(200, status, body)

        with app.connect(app.DB_PATH) as db:
            db.execute("UPDATE clients SET last_seen_at = ? WHERE client_id = ?", ("2020-01-01T00:00:00+00:00", offline_id))

        status, body = self.request("POST", "/api/v1/request-data")
        self.assertEqual(200, status, body)
        self.assertEqual(1, body["queued"])
        self.assertEqual(1, len(body["skipped"]))

        timestamp = str(int(time.time()))
        status, body = self.request(
            "GET",
            f"/api/v1/commands/{online_id}",
            headers={
                "X-Loki-Client-Id": online_id,
                "X-Loki-Timestamp": timestamp,
                "X-Loki-Signature": signature("GET", f"/api/v1/commands/{online_id}", timestamp, b""),
            },
        )
        self.assertEqual(200, status, body)
        self.assertEqual("check_updates", body["commands"][0]["type"])

    def test_manifest_can_be_built_from_release_bundle(self):
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps({
                "channel": "preview",
                "version": "0.1.57",
                "installer": None,
                "ruleSets": [{"id": "custom", "url": "https://unsupported.test/custom.zip"}],
                "watcher": None,
            }))
            archive.writestr("LokiClientSetup-0.1.57-win-x64.exe", b"installer")
            archive.writestr("russia-smart.zip", b"rule")

        release = {
            "tag_name": "v0.1.57",
            "published_at": "2026-05-13T08:00:00Z",
            "assets": [{
                "name": "LokiClientRelease-0.1.57-win-x64.zip",
                "browser_download_url": "https://github.test/bundle.zip",
            }],
        }

        old_request_json = app.request_json
        old_request_bytes = app.request_bytes
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: bundle.getvalue()
            with app.connect(app.DB_PATH) as db:
                db.execute("UPDATE register_entries SET value = 'watcher.example.test' WHERE key = 'watcher.public_sni'")

            manifest = app.build_manifest()

            self.assertEqual("stable", manifest["channel"])
            self.assertEqual("0.1.57", manifest["version"])
            self.assertEqual("https://watcher.example.test/assets/LokiClientSetup-0.1.57-win-x64.exe", manifest["installer"]["url"])
            self.assertEqual(hashlib.sha256(b"installer").hexdigest(), manifest["installer"]["sha256"])
            self.assertEqual("psewdon1m-loki/client", manifest["repository"])
            self.assertEqual(
                "https://github.com/psewdon1m-loki/client/releases/latest/download/manifest.json",
                manifest["fallbackManifestUrl"],
            )
            self.assertEqual("russia-smart", manifest["ruleSets"][0]["id"])
            self.assertEqual(["russia-smart"], [item["id"] for item in manifest["ruleSets"]])
            self.assertEqual("https://watcher.example.test/assets/russia-smart.zip", manifest["ruleSets"][0]["url"])
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes

    def test_manifest_rewrites_separate_release_assets_to_watcher_urls(self):
        release = {
            "tag_name": "v0.1.60",
            "published_at": "2026-05-13T08:00:00Z",
            "assets": [
                {
                    "name": "manifest.json",
                    "browser_download_url": "https://github.test/manifest.json",
                },
                {
                    "name": "LokiClientSetup-0.1.60-win-x64.exe",
                    "browser_download_url": "https://github.test/LokiClientSetup-0.1.60-win-x64.exe",
                },
                {
                    "name": "russia-smart.zip",
                    "browser_download_url": "https://github.test/russia-smart.zip",
                },
            ],
        }
        upstream_manifest = json.dumps({
            "channel": "stable",
            "version": "0.1.60",
            "installer": {
                "url": "https://github.test/LokiClientSetup-0.1.60-win-x64.exe",
                "sha256": "old",
                "mandatory": False,
            },
            "ruleSets": [{
                "id": "russia-smart",
                "version": "0.1.60",
                "url": "https://github.test/russia-smart.zip",
                "sha256": "old",
            }],
            "watcher": None,
        }).encode("utf-8")
        payloads = {
            "https://github.test/manifest.json": upstream_manifest,
            "https://github.test/LokiClientSetup-0.1.60-win-x64.exe": b"installer",
            "https://github.test/russia-smart.zip": b"rule",
        }

        old_request_json = app.request_json
        old_request_bytes = app.request_bytes
        old_sha256_url = app.sha256_url
        old_rule_set_ids = app.RULE_SET_IDS
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: payloads[url]
            app.sha256_url = lambda url: hashlib.sha256(payloads[url]).hexdigest()
            with app.connect(app.DB_PATH) as db:
                db.execute("UPDATE register_entries SET value = 'watcher.example.test' WHERE key = 'watcher.public_sni'")
            app.RULE_SET_IDS = ["russia-smart"]

            manifest = app.build_manifest()

            self.assertEqual(
                "https://watcher.example.test/assets/LokiClientSetup-0.1.60-win-x64.exe",
                manifest["installer"]["url"],
            )
            self.assertEqual(
                "https://github.test/LokiClientSetup-0.1.60-win-x64.exe",
                manifest["installer"]["fallbackUrl"],
            )
            self.assertEqual(hashlib.sha256(b"installer").hexdigest(), manifest["installer"]["sha256"])
            self.assertEqual("https://watcher.example.test/assets/russia-smart.zip", manifest["ruleSets"][0]["url"])
            self.assertEqual("https://github.test/russia-smart.zip", manifest["ruleSets"][0]["fallbackUrl"])
            self.assertEqual(hashlib.sha256(b"rule").hexdigest(), manifest["ruleSets"][0]["sha256"])
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes
            app.sha256_url = old_sha256_url
            app.RULE_SET_IDS = old_rule_set_ids

    def test_signed_manifest_fallback_preserves_exact_payload_and_signature(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        manifest = b'{"schemaVersion":2,"productRole":"vpn-enus-windows-client","version":"0.1.68"}\n'
        signature = base64.b64encode(
            private_key.sign(manifest, padding.PKCS1v15(), hashes.SHA256())
        ) + b"\n"
        release = {
            "tag_name": "v0.1.68",
            "assets": [
                {"name": "manifest.json", "browser_download_url": "https://github.test/manifest.json"},
                {"name": "manifest.json.sig", "browser_download_url": "https://github.test/manifest.json.sig"},
            ],
        }
        payloads = {
            "https://github.test/manifest.json": manifest,
            "https://github.test/manifest.json.sig": signature,
        }
        old_request_json = app.request_json
        old_request_bytes = app.request_bytes
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: payloads[url]
            with app.connect(app.DB_PATH) as db:
                db.execute(
                    "UPDATE register_entries SET value = ? WHERE key = 'updates.manifest_public_key_pem'",
                    (public_key,),
                )
            app.invalidate_manifest_cache()

            status, _, body = self.raw_request("GET", "/manifest.json")
            signature_status, _, signature_body = self.raw_request("GET", "/manifest.json.sig")

            self.assertEqual(200, status)
            self.assertEqual(manifest, body)
            self.assertEqual(200, signature_status)
            self.assertEqual(signature, signature_body)
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes
            app.invalidate_manifest_cache()

    def test_assets_endpoint_serves_separate_release_asset(self):
        release = {
            "tag_name": "v0.1.60",
            "assets": [{
                "name": "russia-smart.zip",
                "browser_download_url": "https://github.test/russia-smart.zip",
            }],
        }
        old_request_json = app.request_json
        old_request_bytes = app.request_bytes
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: b"rule"

            status, headers, payload = self.raw_request("GET", "/assets/russia-smart.zip")

            self.assertEqual(200, status)
            self.assertEqual(b"rule", payload)
            self.assertIn("attachment", headers.get("Content-Disposition", ""))
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes


if __name__ == "__main__":
    unittest.main()
