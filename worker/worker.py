import os
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone


DB_PATH = os.environ.get("LOKI_WATCHER_DB", "/data/watcher.db")
LOG_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_LOG_RETENTION_DAYS", "7"))
COMMAND_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_COMMAND_RETENTION_DAYS", "30"))


def cleanup() -> None:
    if not os.path.exists(DB_PATH):
        return
    log_cutoff = (datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
    command_cutoff = (datetime.now(timezone.utc) - timedelta(days=COMMAND_RETENTION_DAYS)).isoformat()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute(
            "SELECT id, payload_json FROM events WHERE created_at < ? AND payload_json LIKE '%logLines%'",
            (log_cutoff,),
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

        db.execute("DELETE FROM commands WHERE status = 'delivered' AND delivered_at < ?", (command_cutoff,))
    print(f"cleanup complete; log_cutoff={log_cutoff}; cleared_log_events={cleared}", flush=True)


if __name__ == "__main__":
    while True:
        cleanup()
        time.sleep(3600)
