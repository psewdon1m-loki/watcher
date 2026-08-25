import os
import time
from datetime import datetime, timedelta, timezone

from common.backup_contract import BackupContractError, create_backup_archive, decode_backup_key


DB_PATH = os.environ.get("LOKI_WATCHER_DB", "/data/watcher.db")
BACKUP_DIR = os.environ.get("LOKI_WATCHER_BACKUP_DIR", "/backups")
BACKUP_INTERVAL_SECONDS = int(os.environ.get("LOKI_WATCHER_BACKUP_INTERVAL_SECONDS", "86400"))
BACKUP_RETENTION_DAYS = int(os.environ.get("LOKI_WATCHER_BACKUP_RETENTION_DAYS", "30"))
BACKUP_MAX_FILES = int(os.environ.get("LOKI_WATCHER_BACKUP_MAX_FILES", "20"))
BACKUP_MAX_TOTAL_BYTES = int(os.environ.get("LOKI_WATCHER_BACKUP_MAX_TOTAL_BYTES", str(2 * 1024 * 1024 * 1024)))


def create_backup() -> str | None:
    if not os.path.exists(DB_PATH):
        print(f"backup skipped; database not found: {DB_PATH}", flush=True)
        return None

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"loki-watcher-backup-{stamp}.zip")
    create_backup_archive(DB_PATH, backup_path, source="scheduled", key=decode_backup_key())

    print(f"backup created: {backup_path}", flush=True)
    return backup_path


def cleanup_old_backups() -> None:
    if not os.path.isdir(BACKUP_DIR):
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=BACKUP_RETENTION_DAYS)
    removed = 0
    retained: list[tuple[str, float, int]] = []
    for name in os.listdir(BACKUP_DIR):
        if not name.startswith("loki-watcher-backup-") or not name.endswith(".zip"):
            continue
        path = os.path.join(BACKUP_DIR, name)
        try:
            modified_seconds = os.path.getmtime(path)
            modified = datetime.fromtimestamp(modified_seconds, timezone.utc)
            size = os.path.getsize(path)
        except OSError:
            continue
        if BACKUP_RETENTION_DAYS > 0 and modified < cutoff:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
        else:
            retained.append((path, modified_seconds, size))

    retained.sort(key=lambda item: item[1], reverse=True)
    keep_paths = {item[0] for item in retained[:max(0, BACKUP_MAX_FILES)]} if BACKUP_MAX_FILES > 0 else {item[0] for item in retained}
    total_bytes = 0
    for path, _, size in retained:
        should_remove = path not in keep_paths
        if not should_remove and BACKUP_MAX_TOTAL_BYTES > 0:
            should_remove = total_bytes + size > BACKUP_MAX_TOTAL_BYTES
        if should_remove:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
        else:
            total_bytes += size
    if removed:
        print(f"old backups removed: {removed}", flush=True)


def run() -> None:
    while True:
        try:
            create_backup()
            cleanup_old_backups()
        except BackupContractError as exc:
            print(f"backup failed: {exc.code}", flush=True)
        except Exception as exc:
            print(f"backup failed: {type(exc).__name__}", flush=True)
        time.sleep(max(60, BACKUP_INTERVAL_SECONDS))


if __name__ == "__main__":
    run()
