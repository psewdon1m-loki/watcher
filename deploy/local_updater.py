#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any

from validate_env import parse_env, validate
from updater_common import (
    DEFAULT_PROFILE_DIR,
    DEFAULT_STATE_ROOT,
    UPDATER_VERSION,
    UpdaterProtocolError,
    atomic_json as atomic_common_json,
    load_profile,
    validate_policy,
)


MANIFEST_ASSET = "vpn-enus-watcher-release.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_BACKUP_BYTES = 128 * 1024 * 1024
TERMINAL_STATES = {"COMPLETED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"}
PRE_MUTATION_STATES = {"REQUESTED", "BACKUP_VERIFIED", "ARTIFACT_VERIFIED", "PULLING"}
MUTATION_STATES = {"APPLYING", "HEALTH_CHECK", "ROLLING_BACK"}
VERSION_RE = re.compile(r"^(\d{1,9})\.(\d{1,9})\.(\d{1,9})$")
IMAGE_RE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
RELEASE_HOSTS = {"github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}


class UpdateError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: str, value: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    pending = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(pending, "x", encoding="utf-8") as target:
        json.dump(value, target, ensure_ascii=False, separators=(",", ":"))
        target.flush()
        os.fsync(target.fileno())
    os.chmod(pending, 0o600)
    os.replace(pending, path)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], timeout: int = 300, *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, timeout=timeout, capture_output=capture)


def version_tuple(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if not match:
        raise UpdateError("version must be an exact stable semantic version X.Y.Z")
    return tuple(map(int, match.groups()))


def validate_release_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise UpdateError("release URL is not an allow-listed credential-free HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in RELEASE_HOSTS
        or port not in {None, 443}
        or parsed.username
        or parsed.password
    ):
        raise UpdateError("release URL is not an allow-listed credential-free HTTPS URL")


def download(url: str, target: str, maximum: int) -> tuple[int, str]:
    validate_release_url(url)
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": f"vpn-enus-updater/{UPDATER_VERSION}"})
    total = 0
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=30) as response, open(target, "wb") as output:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in RELEASE_HOSTS or final.username or final.password:
                raise UpdateError("release download redirected to a non-allow-listed host")
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise UpdateError("release download exceeded its size limit")
                digest.update(chunk)
                output.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError("release download failed") from exc
    return total, digest.hexdigest()


def fetch_json(url: str, maximum: int) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(delete=False) as temporary:
        path = temporary.name
    try:
        download(url, path, maximum)
        with open(path, "r", encoding="utf-8") as source:
            value = json.load(source)
        if not isinstance(value, dict):
            raise UpdateError("release JSON must be an object")
        return value
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpdateError("release JSON is invalid") from exc
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def resolve_release(repository: str, version: str, *, enforce_minimum_updater: bool = True) -> dict[str, Any]:
    release = fetch_json(f"https://api.github.com/repos/{repository}/releases/tags/v{version}", MAX_MANIFEST_BYTES)
    if release.get("draft") or release.get("prerelease") or str(release.get("tag_name")) != f"v{version}":
        raise UpdateError("release is missing, draft, prerelease or identity-mismatched")
    asset = next((item for item in release.get("assets", []) if item.get("name") == MANIFEST_ASSET), None)
    if not isinstance(asset, dict):
        raise UpdateError("release manifest asset is missing")
    manifest = fetch_json(str(asset.get("browser_download_url") or ""), MAX_MANIFEST_BYTES)
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("componentRole") != "watcher-control-plane"
        or manifest.get("version") != version
        or manifest.get("channel") != "stable"
        or manifest.get("databaseSchemaGeneration") != 3
    ):
        raise UpdateError("release manifest identity is invalid")
    if enforce_minimum_updater and version_tuple(str(manifest.get("minimumUpdaterVersion") or "0.0.0")) > version_tuple(UPDATER_VERSION):
        raise UpdateError("release requires a newer local updater")
    images = manifest.get("images") if isinstance(manifest.get("images"), dict) else {}
    if any(not IMAGE_RE.fullmatch(str(images.get(name) or "")) for name in ("api", "web", "worker")):
        raise UpdateError("release manifest contains a mutable or non-allow-listed image")
    bundle = manifest.get("bundle") if isinstance(manifest.get("bundle"), dict) else {}
    validate_release_url(str(bundle.get("url") or ""))
    if not re.fullmatch(r"[0-9a-f]{64}", str(bundle.get("sha256") or "")):
        raise UpdateError("bundle digest is invalid")
    if not isinstance(bundle.get("bytes"), int) or bundle["bytes"] <= 0 or bundle["bytes"] > MAX_BUNDLE_BYTES:
        raise UpdateError("bundle size is invalid")
    return manifest


def api_fetch_policy(profile: dict[str, Any]) -> dict[str, Any]:
    connection = http.client.HTTPConnection(profile["apiHost"], profile["apiPort"], timeout=10)
    try:
        connection.request(
            "GET",
            "/api/v1/updater/policy",
            headers={
                "X-Watcher-Control-Token": profile["controlToken"],
                "X-Request-Id": f"updater-policy-{uuid.uuid4().hex}",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_MANIFEST_BYTES + 1)
        if response.status != 200 or len(raw) > MAX_MANIFEST_BYTES:
            raise UpdateError(f"application policy endpoint failed with status {response.status}")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise UpdateError("application policy response must be an object")
        return validate_policy(value, profile["serviceId"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, UpdaterProtocolError) as exc:
        raise UpdateError("application release policy is unavailable or invalid") from exc
    finally:
        connection.close()


def load_release_policy(profile: dict[str, Any], state_root: str) -> tuple[dict[str, Any], bool]:
    cache_path = os.path.join(state_root, "policy", f"{profile['serviceId']}.json")
    try:
        policy = api_fetch_policy(profile)
        atomic_common_json(cache_path, policy)
        return policy, False
    except UpdateError:
        try:
            with open(cache_path, "r", encoding="utf-8") as source:
                cached = json.load(source)
            return validate_policy(cached, profile["serviceId"]), True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, UpdaterProtocolError) as exc:
            raise UpdateError("release policy is unavailable and no valid last-known-good cache exists") from exc


def api_port(values: dict[str, str]) -> int:
    return int(values["LOKI_WATCHER_API_PORT"])


def api_download_backup(values: dict[str, str], target: str) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", api_port(values), timeout=60)
    headers = {"X-Watcher-Control-Token": values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"], "X-Request-Id": f"update-backup-{uuid.uuid4().hex}"}
    try:
        connection.request("GET", "/api/v1/backups/download", headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpdateError(f"application backup was rejected with status {response.status}")
        total = 0
        with open(target, "wb") as output:
            os.chmod(target, 0o600)
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BACKUP_BYTES:
                    raise UpdateError("application backup exceeded the updater limit")
                output.write(chunk)
        if total <= 0:
            raise UpdateError("application backup is empty")
    finally:
        connection.close()
    return sha256_file(target)


def api_restore_backup(values: dict[str, str], source: str) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", api_port(values), timeout=180)
    headers = {
        "Content-Type": "application/zip",
        "Content-Length": str(os.path.getsize(source)),
        "X-Watcher-Control-Token": values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"],
        "X-Request-Id": f"update-restore-{uuid.uuid4().hex}",
    }
    try:
        with open(source, "rb") as body:
            connection.request("POST", "/api/v1/backups/upload", body=body, headers=headers)
            response = connection.getresponse()
            response.read()
        if response.status != 200:
            raise UpdateError(f"rollback data restore failed with status {response.status}")
    finally:
        connection.close()


def wait_health(values: dict[str, str], timeout: int = 120) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", api_port(values), timeout=3)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            payload = response.read()
            if response.status == 200 and b'"status":"ok"' in payload:
                return True
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(2)
    return False


def write_env(source_path: str, target_path: str, replacements: dict[str, str]) -> None:
    with open(source_path, "r", encoding="utf-8") as source:
        lines = source.readlines()
    found: set[str] = set()
    output = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else None
        if key in replacements:
            output.append(f"{key}={replacements[key]}\n")
            found.add(key)
        else:
            output.append(line)
    if found != replacements.keys():
        raise UpdateError("release-lock fields are missing from the environment file")
    with open(target_path, "x", encoding="utf-8", newline="\n") as target:
        target.writelines(output)
    os.chmod(target_path, 0o600)


def safe_extract_bundle(bundle_path: str, target: str) -> None:
    allowed = {
        "docker-compose.yml", ".env.template", "install.sh", "watcherctl", "recovery_tool.py", "validate_env.py",
        "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py",
        "vpnenus-updater.service", "RELEASE.txt",
    }
    with zipfile.ZipFile(bundle_path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or set(names) != allowed or len(names) > 16:
            raise UpdateError("release bundle member list is invalid")
        if sum(item.file_size for item in infos) > MAX_BUNDLE_BYTES:
            raise UpdateError("release bundle uncompressed limit exceeded")
        os.mkdir(target, 0o700)
        for info in infos:
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or "/" in info.filename or "\\" in info.filename or stat.S_ISLNK(mode):
                raise UpdateError("release bundle contains an unsafe path")
            destination = os.path.join(target, info.filename)
            with archive.open(info) as source, open(destination, "xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            os.chmod(destination, 0o700 if info.filename in {"install.sh", "watcherctl", "recovery_tool.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py"} else 0o600)


class Job:
    def __init__(self, path: str, request_id: str, version: str):
        self.path = path
        self.value: dict[str, Any] = {"jobId": request_id, "requestedVersion": version, "state": "REQUESTED", "message": "Update request accepted.", "createdAt": utc_now(), "updatedAt": utc_now(), "history": []}
        self.transition("REQUESTED", "Update request accepted.")

    def transition(self, state: str, message: str, **fields: Any) -> None:
        self.value.update(fields)
        self.value["state"] = state
        self.value["message"] = message
        self.value["updatedAt"] = utc_now()
        self.value.setdefault("history", []).append({"state": state, "message": message, "at": self.value["updatedAt"]})
        atomic_json(self.path, self.value)


def reconcile_jobs(jobs_dir: str) -> None:
    if not os.path.isdir(jobs_dir):
        return
    for name in os.listdir(jobs_dir):
        if not name.endswith(".json"):
            continue
        path = os.path.join(jobs_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as source:
                job = json.load(source)
        except (OSError, json.JSONDecodeError):
            continue
        state = job.get("state")
        if state in TERMINAL_STATES:
            continue
        job["state"] = "FAILED" if state in PRE_MUTATION_STATES else "ROLLBACK_FAILED"
        job["message"] = "Updater restart interrupted this job. Run vpn-enus-watcher repair, verify health, then retry with a new request ID."
        job["updatedAt"] = utc_now()
        job.setdefault("history", []).append({"state": job["state"], "message": job["message"], "at": job["updatedAt"]})
        atomic_json(path, job)


def prune(directory: str, suffix: str, keep: int = 20, days: int = 30) -> None:
    if not os.path.isdir(directory):
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries = []
    for name in os.listdir(directory):
        if not name.endswith(suffix):
            continue
        path = os.path.join(directory, name)
        modified = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
        entries.append((path, modified))
    entries.sort(key=lambda item: item[1], reverse=True)
    for index, (path, modified) in enumerate(entries):
        if index >= keep or modified < cutoff:
            os.remove(path)


def prune_directories(directory: str, suffix: str, keep: int = 20, days: int = 30) -> None:
    if not os.path.isdir(directory):
        return
    base = os.path.realpath(directory)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries = []
    for name in os.listdir(base):
        if not name.endswith(suffix):
            continue
        path = os.path.join(base, name)
        resolved = os.path.realpath(path)
        if os.path.commonpath((base, resolved)) != base or os.path.islink(path) or not os.path.isdir(path):
            continue
        modified = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
        entries.append((path, modified))
    entries.sort(key=lambda item: item[1], reverse=True)
    for index, (path, modified) in enumerate(entries):
        if index >= keep or modified < cutoff:
            shutil.rmtree(path)


def compose_command(compose_path: str, env_path: str, *args: str) -> list[str]:
    return ["docker", "compose", "--env-file", env_path, "-f", compose_path, *args]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=os.path.join(DEFAULT_PROFILE_DIR, "watcher.json"))
    parser.add_argument("--install-dir", default=None)
    parser.add_argument("--version", required=True)
    parser.add_argument("--request-id", default=None)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("local updater must run as root")
    version_tuple(args.version)
    request_id = args.request_id or uuid.uuid4().hex
    if not REQUEST_RE.fullmatch(request_id):
        raise SystemExit("request ID is invalid")
    try:
        profile = load_profile(args.profile)
    except UpdaterProtocolError as exc:
        raise SystemExit(str(exc)) from exc
    install_dir = os.path.abspath(args.install_dir or profile["installDir"])
    if install_dir != profile["installDir"]:
        raise SystemExit("install directory does not match the registered service profile")
    env_path = os.path.join(install_dir, ".env")
    compose_path = os.path.join(install_dir, "docker-compose.yml")
    values = validate(env_path)
    if (
        not hmac.compare_digest(values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"], profile["controlToken"])
        or int(values["LOKI_WATCHER_API_PORT"]) != profile["apiPort"]
    ):
        raise SystemExit("runtime environment does not match the registered updater profile")
    state_root = DEFAULT_STATE_ROOT
    service_root = os.path.join(state_root, "services", profile["serviceId"])
    jobs_dir = os.path.join(service_root, "jobs")
    backups_dir = os.path.join(service_root, "backups")
    os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
    os.makedirs(backups_dir, mode=0o700, exist_ok=True)
    lock_path = "/run/vpnenus-updater/mutation.lock"
    with open(lock_path, "a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reconcile_jobs(jobs_dir)
        job_path = os.path.join(jobs_dir, f"{request_id}.json")
        if os.path.exists(job_path):
            with open(job_path, "r", encoding="utf-8") as source:
                print(json.dumps(json.load(source), ensure_ascii=False, indent=2))
            return 0
        job = Job(job_path, request_id, args.version)
        backup_path = os.path.join(backups_dir, f"{request_id}.zip")
        rollback_dir = os.path.join(backups_dir, f"{request_id}.runtime")
        mutation_started = False
        try:
            backup_digest = api_download_backup(values, backup_path)
            job.transition("BACKUP_VERIFIED", "Application backup persisted and checksum-verified.", backupPath=backup_path, backupSha256=backup_digest, operatorCopyHeld=False)
            policy, policy_offline = load_release_policy(profile, state_root)
            manifest = resolve_release(policy["repositories"]["server"], args.version)
            bundle_path = os.path.join(backups_dir, f"{request_id}.bundle.zip")
            downloaded_bytes, bundle_digest = download(manifest["bundle"]["url"], bundle_path, MAX_BUNDLE_BYTES)
            if downloaded_bytes != manifest["bundle"]["bytes"] or bundle_digest != manifest["bundle"]["sha256"]:
                raise UpdateError("release bundle size or checksum mismatch")
            with tempfile.TemporaryDirectory() as staging:
                extracted = os.path.join(staging, "bundle")
                safe_extract_bundle(bundle_path, extracted)
                replacements = {
                    "LOKI_WATCHER_VERSION": args.version,
                    "LOKI_WATCHER_API_IMAGE": manifest["images"]["api"],
                    "LOKI_WATCHER_WEB_IMAGE": manifest["images"]["web"],
                    "LOKI_WATCHER_WORKER_IMAGE": manifest["images"]["worker"],
                }
                staged_env = os.path.join(staging, ".env")
                write_env(env_path, staged_env, replacements)
                validate(staged_env)
                staged_compose = os.path.join(extracted, "docker-compose.yml")
                if sha256_file(staged_compose) != manifest.get("composeSha256"):
                    raise UpdateError("release Compose digest mismatch")
                run(compose_command(staged_compose, staged_env, "config", "--quiet"), timeout=30)
                job.transition(
                    "ARTIFACT_VERIFIED",
                    "Release identity, policy, bundle, Compose and compatibility verified.",
                    releaseManifest=manifest,
                    policyRevision=policy["revision"],
                    policySource="last-known-good" if policy_offline else "live-register",
                )
                job.transition("PULLING", "Pulling immutable images by digest.")
                for image in manifest["images"].values():
                    run(["docker", "pull", image], timeout=600)
                os.mkdir(rollback_dir, 0o700)
                shutil.copy2(env_path, os.path.join(rollback_dir, ".env"))
                for name in ("docker-compose.yml", "install.sh", "watcherctl", "recovery_tool.py", "validate_env.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py", "vpnenus-updater.service", ".env.template"):
                    source = os.path.join(install_dir, name)
                    if os.path.exists(source):
                        shutil.copy2(source, os.path.join(rollback_dir, name))
                mutation_started = True
                job.transition("APPLYING", "Atomically applying release lock and deployment files.", previousVersion=values["LOKI_WATCHER_VERSION"])
                for name in ("docker-compose.yml", "install.sh", "watcherctl", "recovery_tool.py", "validate_env.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py", "vpnenus-updater.service", ".env.template"):
                    source = os.path.join(extracted, name)
                    if os.path.exists(source):
                        pending = os.path.join(install_dir, f".{name}.{uuid.uuid4().hex}.tmp")
                        shutil.copy2(source, pending)
                        os.chmod(pending, 0o700 if name in {"install.sh", "watcherctl", "recovery_tool.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py"} else 0o600)
                        os.replace(pending, os.path.join(install_dir, name))
                os.replace(staged_env, env_path)
                values = validate(env_path)
                run(compose_command(compose_path, env_path, "up", "-d", "--no-build"), timeout=300)
                job.transition("HEALTH_CHECK", "Polling loopback health after service replacement.")
                if not wait_health(values):
                    raise UpdateError("new release failed loopback health")
            job.transition("COMPLETED", "Update completed and health passed.", installedVersion=args.version, installedImages=manifest["images"])
        except Exception as exc:
            message = str(exc) if isinstance(exc, UpdateError) else type(exc).__name__
            if not mutation_started:
                job.transition("FAILED", f"Update failed before runtime mutation: {message}")
                return 1
            try:
                job.transition("ROLLING_BACK", f"New release failed; restoring previous runtime: {message}")
                for name in os.listdir(rollback_dir):
                    source = os.path.join(rollback_dir, name)
                    pending = os.path.join(install_dir, f".{name}.{uuid.uuid4().hex}.rollback")
                    shutil.copy2(source, pending)
                    os.replace(pending, os.path.join(install_dir, name))
                values = validate(env_path)
                run(compose_command(compose_path, env_path, "up", "-d", "--no-build"), timeout=300)
                if not wait_health(values):
                    raise UpdateError("previous runtime did not recover health")
                api_restore_backup(values, backup_path)
                if not wait_health(values, timeout=30):
                    raise UpdateError("health failed after rollback data restore")
                job.transition("ROLLED_BACK", f"Previous runtime and application backup restored after: {message}")
            except Exception as rollback_error:
                job.transition("ROLLBACK_FAILED", f"Automatic rollback failed: {rollback_error}. Manual recovery is required.")
            return 1
        finally:
            prune(jobs_dir, ".json")
            prune(backups_dir, ".zip")
            prune_directories(backups_dir, ".runtime")
    print(json.dumps(job.value, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
