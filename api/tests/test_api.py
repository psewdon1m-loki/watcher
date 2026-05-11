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


if __name__ == "__main__":
    unittest.main()
