import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone

import worker


class RetentionWorkerTests(unittest.TestCase):
    def test_cleanup_removes_telemetry_and_inactive_clients_after_retention(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = os.path.join(temp_dir, "watcher.db")
            self._create_database(database_path)
            now = datetime.now(timezone.utc)
            old = (now - timedelta(days=31)).isoformat()
            recent = (now - timedelta(days=1)).isoformat()

            with closing(sqlite3.connect(database_path)) as db, db:
                db.executemany(
                    "INSERT INTO clients (client_id, last_seen_at) VALUES (?, ?)",
                    [("inactive", old), ("active", recent)],
                )
                db.executemany(
                    "INSERT INTO events (client_id, created_at, payload_json) VALUES (?, ?, ?)",
                    [
                        ("inactive", old, json.dumps({"logLines": ["old"]})),
                        ("active", recent, json.dumps({"logLines": ["recent"]})),
                    ],
                )
                db.execute(
                    "INSERT INTO commands (id, client_id, status, delivered_at) VALUES ('old', 'inactive', 'delivered', ?)",
                    (old,),
                )
                db.executemany(
                    "INSERT INTO analytics_reports (client_id, received_at, summary_json, payload_bytes) VALUES (?, ?, '{}', ?)",
                    [("inactive", old, 100), ("active", recent, 100)],
                )

            original_path = worker.DB_PATH
            original_log_days = worker.LOG_RETENTION_DAYS
            original_telemetry_days = worker.TELEMETRY_RETENTION_DAYS
            original_command_days = worker.COMMAND_RETENTION_DAYS
            original_analytics_days = worker.ANALYTICS_RETENTION_DAYS
            original_analytics_bytes = worker.ANALYTICS_MAX_BYTES
            try:
                worker.DB_PATH = database_path
                worker.LOG_RETENTION_DAYS = 30
                worker.TELEMETRY_RETENTION_DAYS = 30
                worker.COMMAND_RETENTION_DAYS = 30
                worker.ANALYTICS_RETENTION_DAYS = 30
                worker.ANALYTICS_MAX_BYTES = 1024 * 1024
                worker.cleanup()
            finally:
                worker.DB_PATH = original_path
                worker.LOG_RETENTION_DAYS = original_log_days
                worker.TELEMETRY_RETENTION_DAYS = original_telemetry_days
                worker.COMMAND_RETENTION_DAYS = original_command_days
                worker.ANALYTICS_RETENTION_DAYS = original_analytics_days
                worker.ANALYTICS_MAX_BYTES = original_analytics_bytes

            with closing(sqlite3.connect(database_path)) as db, db:
                clients = [row[0] for row in db.execute("SELECT client_id FROM clients")]
                events = [row[0] for row in db.execute("SELECT client_id FROM events")]
                commands = db.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
                analytics = [row[0] for row in db.execute("SELECT client_id FROM analytics_reports")]

            self.assertEqual(["active"], clients)
            self.assertEqual(["active"], events)
            self.assertEqual(0, commands)
            self.assertEqual(["active"], analytics)

    def test_cleanup_keeps_newest_analytics_within_byte_cap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = os.path.join(temp_dir, "watcher.db")
            self._create_database(database_path)
            now = datetime.now(timezone.utc)
            with closing(sqlite3.connect(database_path)) as db, db:
                db.execute("INSERT INTO clients (client_id, last_seen_at) VALUES ('active', ?)", (now.isoformat(),))
                db.executemany(
                    "INSERT INTO analytics_reports (client_id, received_at, summary_json, payload_bytes) VALUES ('active', ?, '{}', ?)",
                    [((now - timedelta(minutes=2)).isoformat(), 600), ((now - timedelta(minutes=1)).isoformat(), 600)],
                )
            original = (worker.DB_PATH, worker.ANALYTICS_RETENTION_DAYS, worker.ANALYTICS_MAX_BYTES)
            try:
                worker.DB_PATH = database_path
                worker.ANALYTICS_RETENTION_DAYS = 30
                worker.ANALYTICS_MAX_BYTES = 900
                worker.cleanup()
            finally:
                worker.DB_PATH, worker.ANALYTICS_RETENTION_DAYS, worker.ANALYTICS_MAX_BYTES = original
            with closing(sqlite3.connect(database_path)) as db:
                remaining = db.execute("SELECT COUNT(*) FROM analytics_reports").fetchone()[0]
            self.assertEqual(1, remaining)

    @staticmethod
    def _create_database(path: str) -> None:
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript(
                """
                CREATE TABLE clients (
                    client_id TEXT PRIMARY KEY,
                    last_seen_at TEXT NOT NULL
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE commands (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE TABLE analytics_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL
                );
                """
            )


if __name__ == "__main__":
    unittest.main()
