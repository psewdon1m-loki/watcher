#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import stat
import uuid
from datetime import datetime, timezone
from typing import Any


UPDATER_VERSION = "1.1.2"
DEFAULT_SOCKET_PATH = "/run/vpnenus-updater/updater.sock"
DEFAULT_PROFILE_DIR = "/etc/vpnenus-updater/profiles.d"
DEFAULT_STATE_ROOT = "/var/lib/vpnenus-updater"
SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
VERSION_RE = re.compile(r"^(\d{1,9})\.(\d{1,9})\.(\d{1,9})$")
TERMINAL_STATES = {"COMPLETED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"}
PRE_MUTATION_STATES = {"REQUESTED", "BACKUP_VERIFIED", "ARTIFACT_VERIFIED", "PULLING"}
MUTATION_STATES = {"APPLYING", "HEALTH_CHECK", "ROLLING_BACK"}


class UpdaterProtocolError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def version_tuple(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if not match:
        raise UpdaterProtocolError("version must be an exact stable semantic version X.Y.Z")
    return tuple(map(int, match.groups()))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: str, value: dict[str, Any], mode: int = 0o600) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    pending = os.path.join(directory, f".{os.path.basename(path)}.{uuid.uuid4().hex}.tmp")
    try:
        with open(pending, "x", encoding="utf-8") as target:
            json.dump(value, target, ensure_ascii=False, separators=(",", ":"))
            target.flush()
            os.fsync(target.fileno())
        os.chmod(pending, mode)
        os.replace(pending, path)
    finally:
        try:
            os.remove(pending)
        except OSError:
            pass


def _require_private_root_file(path: str) -> None:
    if os.name != "posix":
        return
    metadata = os.stat(path, follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise UpdaterProtocolError("profile must be a regular file")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UpdaterProtocolError("profile must be root-owned with mode 0600 or stricter")


def load_profile(path: str, *, require_root_owner: bool = True) -> dict[str, Any]:
    if require_root_owner:
        _require_private_root_file(path)
    try:
        with open(path, "r", encoding="utf-8") as source:
            profile = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdaterProtocolError("profile is unreadable or invalid") from exc
    required = {"schemaVersion", "serviceId", "installDir", "apiHost", "apiPort", "controlToken"}
    if not isinstance(profile, dict) or required - profile.keys():
        raise UpdaterProtocolError("profile fields are incomplete")
    if profile.get("schemaVersion") != 1 or not SERVICE_RE.fullmatch(str(profile.get("serviceId") or "")):
        raise UpdaterProtocolError("profile identity is invalid")
    install_dir = os.path.abspath(str(profile.get("installDir") or ""))
    if install_dir in {"/", ""} or (os.name == "posix" and not install_dir.startswith("/opt/")):
        raise UpdaterProtocolError("profile install directory is outside /opt")
    if profile.get("apiHost") != "127.0.0.1":
        raise UpdaterProtocolError("profile API host must be loopback")
    try:
        api_port = int(profile.get("apiPort"))
    except (TypeError, ValueError) as exc:
        raise UpdaterProtocolError("profile API port is invalid") from exc
    if not 1024 <= api_port <= 65535:
        raise UpdaterProtocolError("profile API port is invalid")
    token = str(profile.get("controlToken") or "")
    if len(token) < 32:
        raise UpdaterProtocolError("profile control token is invalid")
    profile["installDir"] = install_dir
    profile["apiPort"] = api_port
    return profile


def validate_policy(policy: dict[str, Any], service_id: str) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise UpdaterProtocolError("policy must be an object")
    supplied_checksum = policy.get("checksumSha256")
    unsigned = {key: value for key, value in policy.items() if key != "checksumSha256"}
    expected_checksum = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if not isinstance(supplied_checksum, str) or not hmac.compare_digest(supplied_checksum, expected_checksum):
        raise UpdaterProtocolError("policy checksum is invalid")
    repositories = policy.get("repositories") if isinstance(policy.get("repositories"), dict) else {}
    if (
        policy.get("schemaVersion") != 1
        or policy.get("serviceId") != service_id
        or policy.get("channel") != "stable"
        or not str(policy.get("revision") or "")
    ):
        raise UpdaterProtocolError("policy identity or channel is invalid")
    for role in ("server", "updater"):
        if not REPOSITORY_RE.fullmatch(str(repositories.get(role) or "")):
            raise UpdaterProtocolError(f"policy repository is invalid: {role}")
    if repositories["server"] != repositories["updater"]:
        raise UpdaterProtocolError("server and updater repositories must be identical")
    return policy


def unix_request(
    socket_path: str,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    maximum_response_bytes: int = 1024 * 1024,
) -> tuple[int, dict[str, Any]]:
    if not hasattr(socket, "AF_UNIX"):
        raise UpdaterProtocolError("Unix sockets are unavailable on this host")
    payload = b"" if body is None else canonical_json(body)
    request_headers = {
        "Host": "localhost",
        "Connection": "close",
        "Accept": "application/json",
        "Content-Length": str(len(payload)),
        **(headers or {}),
    }
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    lines = [f"{method} {path} HTTP/1.1", *[f"{key}: {value}" for key, value in request_headers.items()], "", ""]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        sock.sendall("\r\n".join(lines).encode("ascii") + payload)
        response = http.client.HTTPResponse(sock)
        response.begin()
        length = response.getheader("Content-Length")
        if length is not None and int(length) > maximum_response_bytes:
            raise UpdaterProtocolError("updater response exceeded its size limit")
        raw = response.read(maximum_response_bytes + 1)
        if len(raw) > maximum_response_bytes:
            raise UpdaterProtocolError("updater response exceeded its size limit")
        try:
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdaterProtocolError("updater response is invalid JSON") from exc
        if not isinstance(value, dict):
            raise UpdaterProtocolError("updater response must be an object")
        return response.status, value
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise UpdaterProtocolError("updater socket is unavailable") from exc
    finally:
        sock.close()
