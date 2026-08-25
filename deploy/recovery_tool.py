#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

from validate_env import validate


MAX_BACKUP_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class RecoveryError(Exception):
    pass


def fsync_directory(path: str) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def connection(values: dict[str, str]) -> http.client.HTTPConnection:
    return http.client.HTTPConnection("127.0.0.1", int(values["LOKI_WATCHER_API_PORT"]), timeout=120)


def response_error(response: http.client.HTTPResponse, operation: str) -> RecoveryError:
    body = response.read(64 * 1024)
    try:
        error = json.loads(body.decode("utf-8")).get("error")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        error = None
    return RecoveryError(f"{operation} failed with HTTP {response.status}: {error or 'unexpected_response'}")


def backup(values: dict[str, str], target: str) -> None:
    target = os.path.abspath(target)
    if os.path.isdir(target):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        target = os.path.join(target, f"vpn-enus-watcher-backup-{stamp}.zip")
    parent = os.path.dirname(target) or "."
    if not os.path.isdir(parent):
        raise RecoveryError(f"backup destination directory does not exist: {parent}")
    if os.path.lexists(target):
        raise RecoveryError(f"refusing to overwrite existing backup: {target}")

    client = connection(values)
    pending_path = ""
    try:
        client.request(
            "GET",
            "/api/v1/backups/download",
            headers={
                "X-Watcher-Control-Token": values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"],
                "X-Request-Id": f"recovery-backup-{uuid.uuid4().hex}",
            },
        )
        response = client.getresponse()
        if response.status != 200:
            raise response_error(response, "backup")
        declared_size = response.getheader("Content-Length")
        if declared_size is not None and (not declared_size.isdigit() or int(declared_size) > MAX_BACKUP_BYTES):
            raise RecoveryError("backup response size is invalid")
        descriptor, pending_path = tempfile.mkstemp(prefix=f".{os.path.basename(target)}.", suffix=".tmp", dir=parent)
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "wb") as output:
            while chunk := response.read(CHUNK_BYTES):
                total += len(chunk)
                if total > MAX_BACKUP_BYTES:
                    raise RecoveryError("backup response exceeded the local limit")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if total == 0:
            raise RecoveryError("backup response is empty")
        os.chmod(pending_path, 0o600)
        try:
            os.link(pending_path, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise RecoveryError(f"refusing to overwrite existing backup: {target}") from exc
        os.remove(pending_path)
        pending_path = ""
        fsync_directory(parent)
        print(json.dumps({"status": "created", "path": target, "bytes": total, "sha256": digest.hexdigest()}))
    finally:
        client.close()
        if pending_path:
            try:
                os.remove(pending_path)
            except OSError:
                pass


def restore(values: dict[str, str], source: str) -> None:
    source = os.path.abspath(source)
    try:
        size = os.path.getsize(source)
    except OSError as exc:
        raise RecoveryError(f"cannot read backup: {source}") from exc
    if size <= 0 or size > MAX_BACKUP_BYTES:
        raise RecoveryError("backup file size is invalid")

    client = connection(values)
    try:
        client.putrequest("POST", "/api/v1/backups/upload")
        client.putheader("Content-Type", "application/zip")
        client.putheader("Content-Length", str(size))
        client.putheader("X-Watcher-Control-Token", values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"])
        client.putheader("X-Request-Id", f"recovery-restore-{uuid.uuid4().hex}")
        client.endheaders()
        with open(source, "rb") as input_file:
            while chunk := input_file.read(CHUNK_BYTES):
                client.send(chunk)
        response = client.getresponse()
        if response.status != 200:
            raise response_error(response, "restore")
        body = response.read(64 * 1024)
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RecoveryError("restore returned an invalid response") from exc
        print(json.dumps(result, separators=(",", ":")))
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("target")
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("source")
    args = parser.parse_args()
    try:
        values = validate(args.env)
        if args.operation == "backup":
            backup(values, args.target)
        else:
            restore(values, args.source)
    except (OSError, ValueError, RecoveryError, http.client.HTTPException) as exc:
        print(f"recovery operation failed: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
