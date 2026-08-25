from __future__ import annotations

import contextlib
import io
import os
import socketserver
import sys
import tempfile
import threading
import unittest


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import recovery_tool


class BackupHandler(socketserver.StreamRequestHandler):
    payload = b"PK\x03\x04bounded-encrypted-backup"

    def handle(self) -> None:
        request = self.rfile.readline()
        headers: dict[str, str] = {}
        while True:
            line = self.rfile.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
            name, value = line.decode("ascii").split(":", 1)
            headers[name.lower()] = value.strip()
        if request.startswith(b"GET /api/v1/backups/download ") and len(headers.get("x-watcher-control-token", "")) >= 32:
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: "
                + str(len(self.payload)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + self.payload
            )
            return
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


class RecoveryToolTests(unittest.TestCase):
    def test_backup_is_private_atomic_and_refuses_overwrite(self) -> None:
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), BackupHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        values = {
            "LOKI_WATCHER_API_PORT": str(server.server_address[1]),
            "LOKI_WATCHER_LOCAL_CONTROL_TOKEN": "test-control-token-abcdefghijklmnopqrstuvwxyz",
        }
        try:
            with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
                recovery_tool.backup(values, directory)
                created = [os.path.join(directory, name) for name in os.listdir(directory)]
                self.assertEqual(1, len(created))
                with open(created[0], "rb") as backup_file:
                    self.assertEqual(BackupHandler.payload, backup_file.read())
                if os.name == "posix":
                    self.assertEqual(0, os.stat(created[0]).st_mode & 0o077)
                with self.assertRaisesRegex(recovery_tool.RecoveryError, "refusing to overwrite"):
                    recovery_tool.backup(values, created[0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
