#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Any

from local_updater import (
    MAX_BUNDLE_BYTES,
    UpdateError,
    download,
    load_release_policy,
    prune,
    prune_directories,
    resolve_release,
    safe_extract_bundle,
)
from updater_common import (
    DEFAULT_PROFILE_DIR,
    DEFAULT_SOCKET_PATH,
    DEFAULT_STATE_ROOT,
    REQUEST_RE,
    UPDATER_VERSION,
    UpdaterProtocolError,
    atomic_json,
    load_profile,
    unix_request,
    utc_now,
    version_tuple,
)


UPDATER_ROOT = "/opt/vpnenus-updater"
UNIT_PATH = "/etc/systemd/system/vpnenus-updater.service"
UPDATER_FILES = (
    "updater_daemon.py",
    "updater_client.py",
    "updater_common.py",
    "updater_self_update.py",
    "local_updater.py",
    "validate_env.py",
)


class SelfUpdateError(Exception):
    pass


class SelfUpdateJob:
    def __init__(self, path: str, request_id: str, release_version: str, unit_name: str):
        self.path = path
        self.value: dict[str, Any] = {
            "jobId": request_id,
            "releaseVersion": release_version,
            "unitName": unit_name,
            "state": "REQUESTED",
            "message": "Updater self-update request accepted.",
            "createdAt": utc_now(),
            "updatedAt": utc_now(),
            "history": [],
        }
        self.transition("REQUESTED", "Updater self-update request accepted.")

    def transition(self, state: str, message: str, **fields: Any) -> None:
        self.value.update(fields)
        self.value["state"] = state
        self.value["message"] = message
        self.value["updatedAt"] = utc_now()
        self.value["history"].append({"state": state, "message": message, "at": self.value["updatedAt"]})
        atomic_json(self.path, self.value)


def run(command: list[str], timeout: int = 120) -> None:
    subprocess.run(command, check=True, timeout=timeout, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_daemon(timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = unix_request(DEFAULT_SOCKET_PATH, "GET", "/health", timeout=2)
            if status == 200 and body.get("status") == "ok":
                return True
        except UpdaterProtocolError:
            pass
        time.sleep(1)
    return False


def install_staged(staged: str) -> None:
    for name in UPDATER_FILES:
        source = os.path.join(staged, name)
        if not os.path.isfile(source):
            raise SelfUpdateError(f"self-update bundle is missing {name}")
        pending = os.path.join(UPDATER_ROOT, f".{name}.{uuid.uuid4().hex}.tmp")
        shutil.copy2(source, pending)
        os.chmod(pending, 0o755)
        os.replace(pending, os.path.join(UPDATER_ROOT, name))
    unit_source = os.path.join(staged, "vpnenus-updater.service")
    if not os.path.isfile(unit_source):
        raise SelfUpdateError("self-update bundle is missing the systemd unit")
    unit_pending = f"{UNIT_PATH}.{uuid.uuid4().hex}.tmp"
    shutil.copy2(unit_source, unit_pending)
    os.chmod(unit_pending, 0o644)
    os.replace(unit_pending, UNIT_PATH)


def restore_previous(previous: str) -> None:
    for name in UPDATER_FILES:
        source = os.path.join(previous, name)
        if os.path.isfile(source):
            pending = os.path.join(UPDATER_ROOT, f".{name}.{uuid.uuid4().hex}.rollback")
            shutil.copy2(source, pending)
            os.chmod(pending, 0o755)
            os.replace(pending, os.path.join(UPDATER_ROOT, name))
    unit_source = os.path.join(previous, "vpnenus-updater.service")
    if os.path.isfile(unit_source):
        pending = f"{UNIT_PATH}.{uuid.uuid4().hex}.rollback"
        shutil.copy2(unit_source, pending)
        os.chmod(pending, 0o644)
        os.replace(pending, UNIT_PATH)


def prune_self_update_state(jobs_dir: str, backups_dir: str) -> None:
    prune(jobs_dir, ".json", keep=20, days=30)
    prune_directories(backups_dir, ".previous", keep=20, days=30)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=os.path.join(DEFAULT_PROFILE_DIR, "watcher.json"))
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--unit-name", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("updater self-update must run as root")
    if not REQUEST_RE.fullmatch(args.request_id):
        raise SystemExit("request ID is invalid")
    version_tuple(args.release_version)
    profile = load_profile(args.profile)
    self_root = os.path.join(DEFAULT_STATE_ROOT, "self-update")
    jobs_dir = os.path.join(self_root, "jobs")
    backups_dir = os.path.join(self_root, "previous")
    os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
    os.makedirs(backups_dir, mode=0o700, exist_ok=True)
    job = SelfUpdateJob(os.path.join(jobs_dir, f"{args.request_id}.json"), args.request_id, args.release_version, args.unit_name)
    mutation_lock = open("/run/vpnenus-updater/mutation.lock", "a+", encoding="utf-8")
    try:
        fcntl.flock(mutation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        job.transition("FAILED", "Another host mutation already holds the updater lock.")
        mutation_lock.close()
        prune_self_update_state(jobs_dir, backups_dir)
        return 1
    previous = os.path.join(backups_dir, f"{args.request_id}.previous")
    mutation_started = False
    try:
        os.mkdir(previous, 0o700)
        policy, offline = load_release_policy(profile, DEFAULT_STATE_ROOT)
        manifest = resolve_release(policy["repositories"]["updater"], args.release_version, enforce_minimum_updater=False)
        candidate_version = str(manifest.get("updaterVersion") or "")
        if version_tuple(candidate_version) <= version_tuple(UPDATER_VERSION):
            raise SelfUpdateError("selected release does not contain a newer updater")
        with tempfile.TemporaryDirectory(dir=self_root) as staging:
            bundle_path = os.path.join(staging, "bundle.zip")
            size, digest = download(manifest["bundle"]["url"], bundle_path, MAX_BUNDLE_BYTES)
            if size != manifest["bundle"]["bytes"] or digest != manifest["bundle"]["sha256"]:
                raise SelfUpdateError("self-update bundle size or checksum mismatch")
            extracted = os.path.join(staging, "bundle")
            safe_extract_bundle(bundle_path, extracted)
            job.transition(
                "ARTIFACT_VERIFIED",
                "Updater release policy, manifest and bundle verified.",
                candidateUpdaterVersion=candidate_version,
                policyRevision=policy["revision"],
                policySource="last-known-good" if offline else "live-register",
            )
            for name in UPDATER_FILES:
                source = os.path.join(UPDATER_ROOT, name)
                if os.path.isfile(source):
                    shutil.copy2(source, os.path.join(previous, name))
            if os.path.isfile(UNIT_PATH):
                shutil.copy2(UNIT_PATH, os.path.join(previous, "vpnenus-updater.service"))
            mutation_started = True
            job.transition("APPLYING", "Installing candidate updater files atomically.", previousUpdaterVersion=UPDATER_VERSION)
            install_staged(extracted)
        job.transition("HEALTH_CHECK", "Restarting updater service and polling Unix-socket health.")
        run(["systemctl", "daemon-reload"], timeout=30)
        run(["systemctl", "restart", "vpnenus-updater.service"], timeout=30)
        if not wait_daemon():
            raise SelfUpdateError("candidate updater did not become healthy")
        job.transition("COMPLETED", "Updater self-update completed and socket health passed.", installedUpdaterVersion=candidate_version)
        prune_self_update_state(jobs_dir, backups_dir)
        mutation_lock.close()
        return 0
    except Exception as exc:
        message = str(exc) if isinstance(exc, (SelfUpdateError, UpdateError, UpdaterProtocolError)) else type(exc).__name__
        if not mutation_started:
            job.transition("FAILED", f"Updater self-update failed before mutation: {message}")
            prune_self_update_state(jobs_dir, backups_dir)
            mutation_lock.close()
            return 1
        try:
            job.transition("ROLLING_BACK", f"Candidate updater failed; restoring previous files: {message}")
            restore_previous(previous)
            run(["systemctl", "daemon-reload"], timeout=30)
            run(["systemctl", "restart", "vpnenus-updater.service"], timeout=30)
            if not wait_daemon():
                raise SelfUpdateError("previous updater did not recover socket health")
            job.transition("ROLLED_BACK", f"Previous updater restored after candidate failure: {message}")
        except Exception as rollback_error:
            job.transition("ROLLBACK_FAILED", f"Updater rollback failed: {type(rollback_error).__name__}. Manual recovery is required.")
        prune_self_update_state(jobs_dir, backups_dir)
        mutation_lock.close()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
