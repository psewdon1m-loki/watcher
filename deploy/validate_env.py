#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import re
import stat
import sys


REQUIRED = {
    "LOKI_WATCHER_DASHBOARD_USERNAME",
    "LOKI_WATCHER_DASHBOARD_PASSWORD",
    "LOKI_WATCHER_BACKUP_ENCRYPTION_KEY",
    "LOKI_WATCHER_LOCAL_CONTROL_TOKEN",
    "LOKI_WATCHER_UPDATER_GID",
    "LOKI_WATCHER_PUBLIC_SNI",
    "LOKI_WATCHER_API_PORT",
    "LOKI_WATCHER_WEB_PORT",
    "LOKI_WATCHER_VERSION",
    "LOKI_WATCHER_API_IMAGE",
    "LOKI_WATCHER_WEB_IMAGE",
    "LOKI_WATCHER_WORKER_IMAGE",
}
PLACEHOLDERS = {"", "CHANGE_ME", "CHANGE_ME_OPERATOR", "CHANGE_ME_STRONG_PASSWORD", "GENERATED_BY_PREPARE"}
IMAGE_RE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$")
SNI_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


def parse_env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as source:
        for number, raw in enumerate(source, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"invalid line {number}")
            key, value = line.split("=", 1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise ValueError(f"invalid key on line {number}")
            if key in values:
                raise ValueError(f"duplicate key: {key}")
            if "\x00" in value or "\n" in value or "\r" in value:
                raise ValueError(f"invalid value: {key}")
            values[key] = value
    return values


def validate(path: str) -> dict[str, str]:
    values = parse_env(path)
    missing = sorted(REQUIRED - values.keys())
    if missing:
        raise ValueError(f"missing required values: {', '.join(missing)}")
    for key in REQUIRED:
        if values[key] in PLACEHOLDERS or "example.invalid" in values[key]:
            raise ValueError(f"placeholder is not allowed: {key}")
    if len(values["LOKI_WATCHER_DASHBOARD_USERNAME"]) < 3:
        raise ValueError("operator username is too short")
    password = values["LOKI_WATCHER_DASHBOARD_PASSWORD"]
    if len(password) < 16 or password.lower() in {"admin", "admin/admin", "password", "changeme"}:
        raise ValueError("operator password must be at least 16 characters and non-default")
    if not SNI_RE.fullmatch(values["LOKI_WATCHER_PUBLIC_SNI"]):
        raise ValueError("public SNI is invalid")
    ports = []
    for key in ("LOKI_WATCHER_API_PORT", "LOKI_WATCHER_WEB_PORT"):
        try:
            port = int(values[key])
        except ValueError as exc:
            raise ValueError(f"invalid port: {key}") from exc
        if port < 1024 or port > 65535:
            raise ValueError(f"port is outside 1024..65535: {key}")
        ports.append(port)
    if ports[0] == ports[1]:
        raise ValueError("API and web ports must differ")
    if not VERSION_RE.fullmatch(values["LOKI_WATCHER_VERSION"]):
        raise ValueError("release version must be semantic version X.Y.Z")
    for key in ("LOKI_WATCHER_API_IMAGE", "LOKI_WATCHER_WEB_IMAGE", "LOKI_WATCHER_WORKER_IMAGE"):
        if not IMAGE_RE.fullmatch(values[key]):
            raise ValueError(f"image must be an allow-listed GHCR reference pinned by sha256 digest: {key}")
    encoded_key = values["LOKI_WATCHER_BACKUP_ENCRYPTION_KEY"]
    try:
        key = base64.urlsafe_b64decode(encoded_key + "=" * ((4 - len(encoded_key) % 4) % 4))
    except ValueError as exc:
        raise ValueError("backup encryption key is invalid") from exc
    if len(key) != 32:
        raise ValueError("backup encryption key must decode to 32 bytes")
    if len(values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"]) < 32:
        raise ValueError("local update-control token must contain at least 32 characters")
    try:
        updater_gid = int(values["LOKI_WATCHER_UPDATER_GID"])
    except ValueError as exc:
        raise ValueError("updater socket group ID is invalid") from exc
    if updater_gid <= 0 or updater_gid > 2147483647:
        raise ValueError("updater socket group ID is invalid")
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise ValueError("environment file permissions must be 0600 or stricter")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--get")
    args = parser.parse_args()
    try:
        values = validate(args.path)
    except (OSError, ValueError) as exc:
        print(f"environment validation failed: {exc}", file=sys.stderr)
        return 1
    if args.get:
        if args.get not in values:
            print(f"unknown environment key: {args.get}", file=sys.stderr)
            return 1
        print(values[args.get])
    else:
        print("environment validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
