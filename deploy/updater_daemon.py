#!/usr/bin/env python3
from __future__ import annotations

import argparse
import grp
import hashlib
import hmac
import json
import os
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from local_updater import MAX_MANIFEST_BYTES, load_release_policy, reconcile_jobs, resolve_release
from updater_common import (
    DEFAULT_PROFILE_DIR,
    DEFAULT_SOCKET_PATH,
    DEFAULT_STATE_ROOT,
    REQUEST_RE,
    TERMINAL_STATES,
    UPDATER_VERSION,
    UpdaterProtocolError,
    atomic_json,
    load_profile,
    utc_now,
    version_tuple,
)
from validate_env import parse_env


MAX_REQUEST_BYTES = 64 * 1024
MAX_HEADER_VALUE_CHARS = 4096
GITHUB_RELEASE_HOST = "api.github.com"
_launch_lock = threading.Lock()


class DaemonError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def profile_path(profile_dir: str, service_id: str) -> str:
    if not service_id or not service_id.replace("-", "").isalnum() or service_id.lower() != service_id:
        raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_service", "Service identity is invalid.")
    path = os.path.abspath(os.path.join(profile_dir, f"{service_id}.json"))
    if os.path.commonpath((os.path.abspath(profile_dir), path)) != os.path.abspath(profile_dir):
        raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_service", "Service identity is invalid.")
    return path


def service_paths(service_id: str, state_root: str) -> tuple[str, str]:
    service_root = os.path.join(state_root, "services", service_id)
    return os.path.join(service_root, "jobs"), os.path.join(service_root, "backups")


def load_job(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DaemonError(HTTPStatus.NOT_FOUND, "job_not_found", "Update job was not found.") from exc
    if not isinstance(value, dict):
        raise DaemonError(HTTPStatus.INTERNAL_SERVER_ERROR, "job_invalid", "Stored update job is invalid.")
    return value


def list_jobs(jobs_dir: str) -> list[dict[str, Any]]:
    if not os.path.isdir(jobs_dir):
        return []
    jobs = []
    for name in os.listdir(jobs_dir):
        if not name.endswith(".json"):
            continue
        try:
            jobs.append(load_job(os.path.join(jobs_dir, name)))
        except DaemonError:
            continue
    jobs.sort(key=lambda item: str(item.get("updatedAt") or item.get("createdAt") or ""), reverse=True)
    return jobs


def latest_job_and_busy(jobs_dir: str) -> tuple[dict[str, Any] | None, bool]:
    jobs = list_jobs(jobs_dir)
    return (jobs[0] if jobs else None), any(item.get("state") not in TERMINAL_STATES for item in jobs)


def installed_identity(profile: dict[str, Any]) -> dict[str, Any]:
    env_path = os.path.join(profile["installDir"], ".env")
    try:
        values = parse_env(env_path)
    except (OSError, ValueError):
        values = {}
    return {
        "version": values.get("LOKI_WATCHER_VERSION"),
        "images": {
            "api": values.get("LOKI_WATCHER_API_IMAGE"),
            "web": values.get("LOKI_WATCHER_WEB_IMAGE"),
            "worker": values.get("LOKI_WATCHER_WORKER_IMAGE"),
        },
    }


def fetch_release_candidates(repository: str) -> list[dict[str, Any]]:
    url = f"https://{GITHUB_RELEASE_HOST}/repos/{repository}/releases?per_page=100"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": f"vpnenus-updater/{UPDATER_VERSION}"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_MANIFEST_BYTES + 1)
            final = response.geturl()
        final_url = urllib.parse.urlparse(final)
        if (
            len(raw) > MAX_MANIFEST_BYTES
            or final_url.scheme != "https"
            or final_url.hostname != GITHUB_RELEASE_HOST
            or final_url.port not in {None, 443}
            or final_url.username
            or final_url.password
        ):
            raise DaemonError(HTTPStatus.BAD_GATEWAY, "release_discovery_failed", "Release discovery response was rejected.")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
        raise DaemonError(HTTPStatus.BAD_GATEWAY, "release_discovery_failed", "Release discovery failed.") from exc
    if not isinstance(value, list):
        raise DaemonError(HTTPStatus.BAD_GATEWAY, "release_discovery_failed", "Release discovery response is invalid.")
    return [item for item in value if isinstance(item, dict)]


def discover_latest(repository: str) -> dict[str, Any]:
    candidates = []
    for release in fetch_release_candidates(repository):
        tag = str(release.get("tag_name") or "")
        if release.get("draft") or release.get("prerelease") or not tag.startswith("v"):
            continue
        try:
            semantic = version_tuple(tag[1:])
        except UpdaterProtocolError:
            continue
        if any(asset.get("name") == "vpn-enus-watcher-release.json" for asset in release.get("assets", []) if isinstance(asset, dict)):
            candidates.append((semantic, tag[1:], release))
    if not candidates:
        raise DaemonError(HTTPStatus.NOT_FOUND, "release_not_found", "No stable release-contract release was found.")
    _, version, release = sorted(candidates, key=lambda item: item[0])[-1]
    manifest = resolve_release(repository, version)
    return {
        "version": version,
        "tag": f"v{version}",
        "publishedAt": release.get("published_at"),
        "releaseNotesUrl": manifest.get("releaseNotesUrl") or release.get("html_url"),
        "images": manifest.get("images"),
        "minimumUpdaterVersion": manifest.get("minimumUpdaterVersion"),
    }


class UnixThreadingServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str, handler, profile_dir: str, state_root: str):
        self.profile_dir = profile_dir
        self.state_root = state_root
        super().__init__(socket_path, handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "VpnEnusUpdater/1.1"
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"updater request: {format % args}", flush=True)

    def json_response(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("X-Updater-Version", UPDATER_VERSION)
        self.end_headers()
        self.wfile.write(payload)

    def reject(self, error: DaemonError) -> None:
        self.json_response(error.status, {"error": error.code, "message": error.message})

    def require_local_host(self) -> None:
        host = str(self.headers.get("Host") or "")
        if len(host) > MAX_HEADER_VALUE_CHARS or host != "localhost":
            raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_host", "Local Host identity is required.")

    def service_profile(self) -> tuple[str, dict[str, Any]]:
        service_id = str(self.headers.get("X-Updater-Service") or "")
        if len(service_id) > 64:
            raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_service", "Service identity is invalid.")
        path = profile_path(self.server.profile_dir, service_id)
        try:
            return path, load_profile(path)
        except UpdaterProtocolError as exc:
            raise DaemonError(HTTPStatus.NOT_FOUND, "service_not_registered", "Service profile is unavailable.") from exc

    def require_mutation_token(self, profile: dict[str, Any]) -> None:
        supplied = str(self.headers.get("X-Updater-Control-Token") or "")
        if len(supplied) > MAX_HEADER_VALUE_CHARS or not hmac.compare_digest(supplied, profile["controlToken"]):
            raise DaemonError(HTTPStatus.FORBIDDEN, "control_token_invalid", "Update-control token is invalid.")

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_content_length", "Content-Length is invalid.") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise DaemonError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_too_large", "Request body is outside the allowed size.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise DaemonError(HTTPStatus.BAD_REQUEST, "incomplete_body", "Request body is incomplete.")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_json", "Request body is invalid JSON.") from exc
        if not isinstance(value, dict):
            raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_json", "Request body must be an object.")
        return value

    def do_GET(self) -> None:
        try:
            self.require_local_host()
            if self.path == "/health":
                self.json_response(HTTPStatus.OK, {"status": "ok", "updaterVersion": UPDATER_VERSION, "time": utc_now()})
                return
            _, profile = self.service_profile()
            jobs_dir, _ = service_paths(profile["serviceId"], self.server.state_root)
            self_jobs_dir = os.path.join(self.server.state_root, "self-update", "jobs")
            if self.path == f"/v1/services/{profile['serviceId']}/status":
                latest, busy = latest_job_and_busy(jobs_dir)
                latest_self, self_busy = latest_job_and_busy(self_jobs_dir)
                self.json_response(
                    HTTPStatus.OK,
                    {
                        "serviceId": profile["serviceId"],
                        "available": True,
                        "busy": busy or self_busy,
                        "updaterVersion": UPDATER_VERSION,
                        "installed": installed_identity(profile),
                        "latestJob": latest,
                        "latestSelfUpdateJob": latest_self,
                    },
                )
                return
            self_prefix = "/v1/updater/self-update/jobs/"
            if self.path.startswith(self_prefix):
                request_id = self.path[len(self_prefix):]
                if not REQUEST_RE.fullmatch(request_id):
                    raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request_id", "Request ID is invalid.")
                self.json_response(HTTPStatus.OK, load_job(os.path.join(self_jobs_dir, f"{request_id}.json")))
                return
            if self.path == f"/v1/services/{profile['serviceId']}/releases/check":
                policy, offline = load_release_policy(profile, self.server.state_root)
                latest = discover_latest(policy["repositories"]["server"])
                installed = installed_identity(profile)
                self.json_response(
                    HTTPStatus.OK,
                    {
                        "serviceId": profile["serviceId"],
                        "installed": installed,
                        "availableRelease": latest,
                        "updateAvailable": bool(installed.get("version") and version_tuple(latest["version"]) > version_tuple(installed["version"])),
                        "policy": {
                            "revision": policy["revision"],
                            "source": "last-known-good" if offline else "live-register",
                            "repository": policy["repositories"]["server"],
                        },
                    },
                )
                return
            prefix = f"/v1/services/{profile['serviceId']}/jobs/"
            if self.path.startswith(prefix):
                request_id = self.path[len(prefix):]
                if not REQUEST_RE.fullmatch(request_id):
                    raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request_id", "Request ID is invalid.")
                self.json_response(HTTPStatus.OK, load_job(os.path.join(jobs_dir, f"{request_id}.json")))
                return
            raise DaemonError(HTTPStatus.NOT_FOUND, "not_found", "Updater route was not found.")
        except DaemonError as exc:
            self.reject(exc)
        except (UpdaterProtocolError, ValueError) as exc:
            self.reject(DaemonError(HTTPStatus.BAD_GATEWAY, "updater_validation_failed", str(exc)))
        except Exception as exc:
            self.reject(DaemonError(HTTPStatus.INTERNAL_SERVER_ERROR, "updater_internal_error", type(exc).__name__))

    def do_POST(self) -> None:
        try:
            self.require_local_host()
            profile_path_value, profile = self.service_profile()
            self.require_mutation_token(profile)
            expected_path = f"/v1/services/{profile['serviceId']}/jobs"
            self_update_path = "/v1/updater/self-update/jobs"
            if self.path not in {expected_path, self_update_path}:
                raise DaemonError(HTTPStatus.NOT_FOUND, "not_found", "Updater route was not found.")
            body = self.read_json()
            if self.path == self_update_path:
                if set(body) != {"requestId", "releaseVersion"}:
                    raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request", "Only requestId and releaseVersion are accepted.")
                request_id = str(body.get("requestId") or "")
                release_version = str(body.get("releaseVersion") or "")
                if not REQUEST_RE.fullmatch(request_id):
                    raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request_id", "Request ID is invalid.")
                try:
                    version_tuple(release_version)
                except UpdaterProtocolError as exc:
                    raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_version", str(exc)) from exc
                jobs_dir, _ = service_paths(profile["serviceId"], self.server.state_root)
                self_jobs_dir = os.path.join(self.server.state_root, "self-update", "jobs")
                os.makedirs(self_jobs_dir, mode=0o700, exist_ok=True)
                job_path = os.path.join(self_jobs_dir, f"{request_id}.json")
                with _launch_lock:
                    if os.path.exists(job_path):
                        self.json_response(HTTPStatus.OK, {"accepted": False, "idempotent": True, "job": load_job(job_path)})
                        return
                    _, service_busy = latest_job_and_busy(jobs_dir)
                    _, self_busy = latest_job_and_busy(self_jobs_dir)
                    if service_busy or self_busy:
                        raise DaemonError(HTTPStatus.CONFLICT, "updater_busy", "Another application or updater mutation is active.")
                    unit_name = f"vpnenus-updater-self-update-{hashlib.sha256(request_id.encode('utf-8')).hexdigest()[:20]}"
                    command = [
                        "systemd-run", "--quiet", "--collect", f"--unit={unit_name}",
                        "--property=UMask=0077", "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
                        "--property=ProtectHome=yes", "--property=ProtectSystem=strict", "--property=ProtectKernelTunables=yes",
                        "--property=ProtectKernelModules=yes", "--property=ProtectKernelLogs=yes", "--property=ProtectControlGroups=yes",
                        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER",
                        "--property=ReadWritePaths=/opt/vpnenus-updater /etc/systemd/system/vpnenus-updater.service /var/lib/vpnenus-updater /run/vpnenus-updater",
                        "/usr/bin/python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "updater_self_update.py"),
                        "--profile", profile_path_value, "--release-version", release_version,
                        "--request-id", request_id, "--unit-name", unit_name,
                    ]
                    subprocess.run(command, check=True, timeout=15, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not os.path.exists(job_path):
                        time.sleep(0.05)
                    if not os.path.exists(job_path):
                        raise DaemonError(HTTPStatus.INTERNAL_SERVER_ERROR, "job_start_failed", "Self-update job did not persist its initial state.")
                    self.json_response(HTTPStatus.ACCEPTED, {"accepted": True, "idempotent": False, "job": load_job(job_path)})
                    return
            if set(body) != {"requestId", "version"}:
                raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request", "Only requestId and version are accepted.")
            request_id = str(body.get("requestId") or "")
            version = str(body.get("version") or "")
            if not REQUEST_RE.fullmatch(request_id):
                raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_request_id", "Request ID is invalid.")
            try:
                version_tuple(version)
            except UpdaterProtocolError as exc:
                raise DaemonError(HTTPStatus.BAD_REQUEST, "invalid_version", str(exc)) from exc
            jobs_dir, _ = service_paths(profile["serviceId"], self.server.state_root)
            os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
            job_path = os.path.join(jobs_dir, f"{request_id}.json")
            with _launch_lock:
                if os.path.exists(job_path):
                    self.json_response(HTTPStatus.OK, {"accepted": False, "idempotent": True, "job": load_job(job_path)})
                    return
                _, busy = latest_job_and_busy(jobs_dir)
                _, self_busy = latest_job_and_busy(os.path.join(self.server.state_root, "self-update", "jobs"))
                if busy or self_busy:
                    raise DaemonError(HTTPStatus.CONFLICT, "updater_busy", "Another update job is active.")
                command = [
                    sys.executable,
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_updater.py"),
                    "--profile",
                    profile_path_value,
                    "--version",
                    version,
                    "--request-id",
                    request_id,
                ]
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not os.path.exists(job_path) and process.poll() is None:
                    time.sleep(0.05)
                if not os.path.exists(job_path):
                    raise DaemonError(HTTPStatus.INTERNAL_SERVER_ERROR, "job_start_failed", "Updater process did not persist its initial state.")
                self.json_response(HTTPStatus.ACCEPTED, {"accepted": True, "idempotent": False, "job": load_job(job_path)})
        except DaemonError as exc:
            self.reject(exc)
        except Exception as exc:
            self.reject(DaemonError(HTTPStatus.INTERNAL_SERVER_ERROR, "updater_internal_error", type(exc).__name__))


def prepare_socket(socket_path: str) -> None:
    if not os.path.lexists(socket_path):
        return
    metadata = os.lstat(socket_path)
    if not stat.S_ISSOCK(metadata.st_mode):
        raise SystemExit("updater socket path exists and is not a socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(socket_path)
    except OSError:
        os.unlink(socket_path)
    else:
        raise SystemExit("another updater daemon is already listening")
    finally:
        probe.close()


def reconcile_registered_services(profile_dir: str, state_root: str) -> None:
    if not os.path.isdir(profile_dir):
        return
    for name in os.listdir(profile_dir):
        if not name.endswith(".json"):
            continue
        try:
            profile = load_profile(os.path.join(profile_dir, name))
        except UpdaterProtocolError:
            continue
        jobs_dir, _ = service_paths(profile["serviceId"], state_root)
        os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
        reconcile_jobs(jobs_dir)


def reconcile_self_update_jobs(state_root: str) -> None:
    jobs_dir = os.path.join(state_root, "self-update", "jobs")
    for job in list_jobs(jobs_dir):
        if job.get("state") in TERMINAL_STATES:
            continue
        unit_name = str(job.get("unitName") or "")
        active = False
        if unit_name:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "--quiet", unit_name],
                    check=False,
                    timeout=5,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                active = result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                active = False
        if active:
            continue
        state = str(job.get("state") or "")
        job_id = str(job.get("jobId") or "")
        if not REQUEST_RE.fullmatch(job_id):
            continue
        job["state"] = "FAILED" if state in {"REQUESTED", "ARTIFACT_VERIFIED"} else "ROLLBACK_FAILED"
        job["message"] = "Updater self-update was interrupted and its transient systemd unit is no longer active. Verify updater health before retrying."
        job["updatedAt"] = utc_now()
        job.setdefault("history", []).append({"state": job["state"], "message": job["message"], "at": job["updatedAt"]})
        atomic_json(os.path.join(jobs_dir, f"{job_id}.json"), job)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--profile-dir", default=DEFAULT_PROFILE_DIR)
    parser.add_argument("--state-root", default=DEFAULT_STATE_ROOT)
    parser.add_argument("--socket-group", default="vpnenus-updater")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("updater daemon must run as root")
    socket_path = os.path.abspath(args.socket)
    if not socket_path.startswith("/run/vpnenus-updater/"):
        raise SystemExit("updater socket must stay under /run/vpnenus-updater")
    socket_dir = os.path.dirname(socket_path)
    os.makedirs(socket_dir, mode=0o750, exist_ok=True)
    os.makedirs(args.profile_dir, mode=0o700, exist_ok=True)
    os.makedirs(args.state_root, mode=0o700, exist_ok=True)
    group = grp.getgrnam(args.socket_group)
    os.chown(socket_dir, 0, group.gr_gid)
    os.chmod(socket_dir, 0o750)
    prepare_socket(socket_path)
    reconcile_registered_services(args.profile_dir, args.state_root)
    reconcile_self_update_jobs(args.state_root)
    server = UnixThreadingServer(socket_path, Handler, args.profile_dir, args.state_root)
    try:
        os.chown(socket_path, 0, group.gr_gid)
        os.chmod(socket_path, 0o660)
        print(f"VPNЭНУС updater {UPDATER_VERSION} listening on {socket_path}", flush=True)
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            os.unlink(socket_path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
