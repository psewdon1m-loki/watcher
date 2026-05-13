import json
import os
import sqlite3
import time
import zipfile
from datetime import datetime, timedelta, timezone


DB_PATH = os.environ.get("LOKI_WATCHER_DB", "/data/watcher.db")
BACKUP_DIR = os.environ.get("LOKI_WATCHER_BACKUP_DIR", "/backups")
BACKUP_INTERVAL_SECONDS = int(os.environ.get("LOKI_WATCHER_BACKUP_INTERVAL_SECONDS", "86400"))
BACKUP_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_BACKUP_RETENTION_DAYS", "30"))


def create_backup() -> str | None:
    if not os.path.exists(DB_PATH):
        print(f"backup skipped; database not found: {DB_PATH}", flush=True)
        return None

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    temp_db_path = os.path.join(BACKUP_DIR, f".watcher-{stamp}.db")
    backup_path = os.path.join(BACKUP_DIR, f"loki-watcher-backup-{stamp}.zip")

    source = sqlite3.connect(DB_PATH)
    target = sqlite3.connect(temp_db_path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()

    manifest = {
        "format": "loki-watcher-backup",
        "version": 1,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "source": "scheduled",
        "contains": ["watcher.db"],
    }
    with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(temp_db_path, "watcher.db")
        archive.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")))

    try:
        os.remove(temp_db_path)
    except OSError:
        pass

    print(f"backup created: {backup_path}", flush=True)
    return backup_path


def cleanup_old_backups() -> None:
    if BACKUP_RETENTION_DAYS <= 0 or not os.path.isdir(BACKUP_DIR):
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=BACKUP_RETENTION_DAYS)
    removed = 0
    for name in os.listdir(BACKUP_DIR):
        if not name.startswith("loki-watcher-backup-") or not name.endswith(".zip"):
            continue
        path = os.path.join(BACKUP_DIR, name)
        try:
            modified = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
        except OSError:
            continue
        if modified < cutoff:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    if removed:
        print(f"old backups removed: {removed}", flush=True)


def run() -> None:
    while True:
        try:
            create_backup()
            cleanup_old_backups()
        except Exception as exc:
            print(f"backup failed: {exc}", flush=True)
        time.sleep(max(60, BACKUP_INTERVAL_SECONDS))


if __name__ == "__main__":
    run()
