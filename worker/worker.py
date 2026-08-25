import os
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

from common.database_lock import database_access


DB_PATH = os.environ.get("LOKI_WATCHER_DB", "/data/watcher.db")
LOG_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_LOG_RETENTION_DAYS", "30"))
TELEMETRY_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_TELEMETRY_RETENTION_DAYS", "30"))
ANALYTICS_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_ANALYTICS_RETENTION_DAYS", "30"))
ANALYTICS_MAX_BYTES = int(os.environ.get("LOKI_WATCHER_ANALYTICS_MAX_BYTES", str(512 * 1024 * 1024)))
COMMAND_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_COMMAND_RETENTION_DAYS", "30"))
AUDIT_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_AUDIT_RETENTION_DAYS", "30"))
AUDIT_MAX_ENTRIES = int(os.environ.get("LOKI_WATCHER_AUDIT_MAX_ENTRIES", "10000"))
AUDIT_MAX_BYTES = int(os.environ.get("LOKI_WATCHER_AUDIT_MAX_BYTES", str(64 * 1024 * 1024)))


def cleanup() -> None:
    if not os.path.exists(DB_PATH):
        return
    log_cutoff = (datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
    telemetry_cutoff = (datetime.now(timezone.utc) - timedelta(days=TELEMETRY_RETENTION_DAYS)).isoformat()
    command_cutoff = (datetime.now(timezone.utc) - timedelta(days=COMMAND_RETENTION_DAYS)).isoformat()
    audit_cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat()
    analytics_cutoff = (datetime.now(timezone.utc) - timedelta(days=ANALYTICS_RETENTION_DAYS)).isoformat()
    # sqlite3.Connection.__exit__ commits/rolls back but does not close the
    # handle. Close it explicitly so cleanup does not retain file descriptors.
    with database_access(DB_PATH), closing(sqlite3.connect(DB_PATH)) as db, db:
        rows = db.execute(
            """
            SELECT id, payload_json FROM events
            WHERE created_at < ? AND created_at >= ? AND payload_json LIKE '%logLines%'
            """,
            (log_cutoff, telemetry_cutoff),
        ).fetchall()
        cleared = 0
        for event_id, payload_json in rows:
            try:
                payload = json.loads(payload_json or "{}")
            except json.JSONDecodeError:
                continue
            if payload.get("logLines"):
                payload["logLines"] = []
                db.execute(
                    "UPDATE events SET payload_json = ? WHERE id = ?",
                    (json.dumps(payload, separators=(",", ":")), event_id),
                )
                cleared += 1

        deleted_events = db.execute("DELETE FROM events WHERE created_at < ?", (telemetry_cutoff,)).rowcount
        deleted_commands = db.execute(
            "DELETE FROM commands WHERE status = 'delivered' AND delivered_at < ?",
            (command_cutoff,),
        ).rowcount
        stale_clients = [
            row[0]
            for row in db.execute(
                "SELECT client_id FROM clients WHERE last_seen_at < ?",
                (telemetry_cutoff,),
            ).fetchall()
        ]
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        deleted_analytics = 0
        if "analytics_reports" in tables:
            analytics_before = db.execute("SELECT COUNT(*) FROM analytics_reports").fetchone()[0]
            if ANALYTICS_RETENTION_DAYS > 0:
                db.execute("DELETE FROM analytics_reports WHERE received_at < ?", (analytics_cutoff,))
            if ANALYTICS_MAX_BYTES > 0:
                db.execute(
                    """
                    WITH sized AS (
                        SELECT id,
                               SUM(payload_bytes + length(summary_json) + 256)
                               OVER (ORDER BY id DESC) AS running_bytes
                        FROM analytics_reports
                    )
                    DELETE FROM analytics_reports WHERE id IN (
                        SELECT id FROM sized WHERE running_bytes > ?
                    )
                    """,
                    (ANALYTICS_MAX_BYTES,),
                )
            deleted_analytics = analytics_before - db.execute("SELECT COUNT(*) FROM analytics_reports").fetchone()[0]
        if stale_clients:
            db.executemany("DELETE FROM commands WHERE client_id = ?", [(client_id,) for client_id in stale_clients])
            db.executemany("DELETE FROM events WHERE client_id = ?", [(client_id,) for client_id in stale_clients])
            if "analytics_reports" in tables:
                db.executemany("DELETE FROM analytics_reports WHERE client_id = ?", [(client_id,) for client_id in stale_clients])
            db.executemany("DELETE FROM clients WHERE client_id = ?", [(client_id,) for client_id in stale_clients])
        deleted_audit = 0
        if "audit_events" in tables:
            audit_before = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if AUDIT_RETENTION_DAYS > 0:
                db.execute("DELETE FROM audit_events WHERE created_at < ?", (audit_cutoff,))
            if AUDIT_MAX_ENTRIES > 0:
                db.execute(
                    "DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)",
                    (AUDIT_MAX_ENTRIES,),
                )
            if AUDIT_MAX_BYTES > 0:
                audit_columns = {row[1] for row in db.execute("PRAGMA table_info(audit_events)")}
                sized_columns = [
                    name
                    for name in (
                        "event_id", "created_at", "severity", "status", "action", "target",
                        "target_type", "actor", "actor_type", "message", "request_id",
                        "transport_method", "context_json", "error_json",
                    )
                    if name in audit_columns
                ]
                size_expression = " + ".join(f"length(COALESCE({name}, ''))" for name in sized_columns) or "0"
                db.execute(
                    f"""
                    WITH sized AS (
                        SELECT id,
                               SUM(
                                   {size_expression}
                               ) OVER (ORDER BY id DESC) AS running_bytes
                        FROM audit_events
                    )
                    DELETE FROM audit_events WHERE id IN (SELECT id FROM sized WHERE running_bytes > ?)
                    """,
                    (AUDIT_MAX_BYTES,),
                )
            deleted_audit = audit_before - db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    print(
        "cleanup complete; "
        f"log_cutoff={log_cutoff}; telemetry_cutoff={telemetry_cutoff}; "
        f"cleared_log_events={cleared}; deleted_events={deleted_events}; "
        f"deleted_commands={deleted_commands}; deleted_clients={len(stale_clients)}; "
        f"deleted_analytics={deleted_analytics}; deleted_audit={deleted_audit}",
        flush=True,
    )


if __name__ == "__main__":
    while True:
        cleanup()
        time.sleep(3600)
