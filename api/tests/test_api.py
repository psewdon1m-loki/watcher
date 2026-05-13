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
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app


def secret() -> str:
    return base64.urlsafe_b64encode(b"0" * 32).decode("ascii").rstrip("=")


def signature(method: str, path: str, timestamp: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, timestamp, body_hash]).encode("utf-8")
    return base64.b64encode(hmac.new(b"0" * 32, canonical, hashlib.sha256).digest()).decode("ascii")


class ApiTests(unittest.TestCase):
    def setUp(self):
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

    def raw_request(self, method, path, body=b"", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_enroll_batch_clients_and_command(self):
        client_id = "client-1"
        status, body = self.request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "X8Q3L7M2Z9K5R1PA",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            {"Content-Type": "application/json"},
        )
        self.assertEqual(200, status, body)

        batch = {
            "clientId": client_id,
            "displayId": "X8Q3L7M2Z9K5R1PA",
            "events": [{
                "type": "heartbeat",
                "connectionStatus": "connected",
                "routingMode": "russia-smart",
                "connections": [{"name": "secure ru", "host": "example.com", "port": 443}],
                "trafficTotalBytes": 1234,
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
            },
        )
        self.assertEqual(200, status, body)

        status, body = self.request("GET", "/api/v1/clients")
        self.assertEqual(200, status, body)
        self.assertEqual("connected", body["clients"][0]["status"])
        self.assertEqual("russia-smart", body["clients"][0]["routing_mode"])
        self.assertEqual(1234, body["clients"][0]["total_traffic_bytes"])

        status, body = self.request("GET", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)
        self.assertEqual("example.com", body["client"]["connections"][0]["host"])

        status, headers, logs_zip = self.raw_request("GET", f"/api/v1/clients/{client_id}/logs.zip")
        self.assertEqual(200, status)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(logs_zip)) as archive:
            self.assertIn("logs.txt", archive.namelist())
            self.assertIn("events.json", archive.namelist())

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

    def test_backup_download_and_restore(self):
        client_id = "client-backup"
        status, body = self.request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "B8Q3L7M2Z9K5R1PA",
                "clientSecret": secret(),
                "device": {"deviceType": "desktop-windows"},
            },
            {"Content-Type": "application/json"},
        )
        self.assertEqual(200, status, body)

        status, headers, backup = self.raw_request("GET", "/api/v1/backups/download")
        self.assertEqual(200, status)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(backup)) as archive:
            self.assertIn("watcher.db", archive.namelist())
            self.assertIn("manifest.json", archive.namelist())

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

    def test_update_state_is_stored_on_client(self):
        client_id = "client-update"
        status, body = self.request(
            "POST",
            "/api/v1/enroll",
            {
                "clientId": client_id,
                "displayId": "UPD123",
                "clientSecret": secret(),
                "device": {"appVersion": "0.1.57"},
            },
            {"Content-Type": "application/json"},
        )
        self.assertEqual(200, status, body)

        status, body = self.request(
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
            {"Content-Type": "application/json"},
        )
        self.assertEqual(200, status, body)

        status, body = self.request("GET", f"/api/v1/clients/{client_id}")
        self.assertEqual(200, status, body)
        self.assertTrue(body["client"]["auto_updates_enabled"])
        self.assertFalse(body["client"]["logs_upload_enabled"])
        self.assertEqual("reported", body["client"]["update_report_status"])
        self.assertEqual("https://watcher.example.test/manifest.json", body["client"]["update_manifest_url"])

    def test_request_data_queues_online_update_checks(self):
        online_id = "client-online"
        offline_id = "client-offline"
        for client_id in (online_id, offline_id):
            status, body = self.request(
                "POST",
                "/api/v1/enroll",
                {
                    "clientId": client_id,
                    "displayId": client_id,
                    "clientSecret": secret(),
                    "device": {"appVersion": "0.1.57"},
                },
                {"Content-Type": "application/json"},
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
                "channel": "stable",
                "version": "0.1.57",
                "installer": None,
                "ruleSets": [],
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
        old_public_url = app.WATCHER_PUBLIC_URL
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: bundle.getvalue()
            app.WATCHER_PUBLIC_URL = "https://watcher.example.test"

            manifest = app.build_manifest()

            self.assertEqual("0.1.57", manifest["version"])
            self.assertEqual("https://watcher.example.test/assets/LokiClientSetup-0.1.57-win-x64.exe", manifest["installer"]["url"])
            self.assertEqual(hashlib.sha256(b"installer").hexdigest(), manifest["installer"]["sha256"])
            self.assertEqual("russia-smart", manifest["ruleSets"][0]["id"])
            self.assertEqual("https://watcher.example.test/assets/russia-smart.zip", manifest["ruleSets"][0]["url"])
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes
            app.WATCHER_PUBLIC_URL = old_public_url

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
        old_public_url = app.WATCHER_PUBLIC_URL
        old_rule_set_ids = app.RULE_SET_IDS
        try:
            app.request_json = lambda url: release
            app.request_bytes = lambda url, timeout=30: payloads[url]
            app.sha256_url = lambda url: hashlib.sha256(payloads[url]).hexdigest()
            app.WATCHER_PUBLIC_URL = "https://watcher.example.test"
            app.RULE_SET_IDS = ["russia-smart"]

            manifest = app.build_manifest()

            self.assertEqual(
                "https://watcher.example.test/assets/LokiClientSetup-0.1.60-win-x64.exe",
                manifest["installer"]["url"],
            )
            self.assertEqual(hashlib.sha256(b"installer").hexdigest(), manifest["installer"]["sha256"])
            self.assertEqual("https://watcher.example.test/assets/russia-smart.zip", manifest["ruleSets"][0]["url"])
            self.assertEqual(hashlib.sha256(b"rule").hexdigest(), manifest["ruleSets"][0]["sha256"])
        finally:
            app.request_json = old_request_json
            app.request_bytes = old_request_bytes
            app.sha256_url = old_sha256_url
            app.WATCHER_PUBLIC_URL = old_public_url
            app.RULE_SET_IDS = old_rule_set_ids

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
