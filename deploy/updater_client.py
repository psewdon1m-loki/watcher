#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

from updater_common import (
    DEFAULT_PROFILE_DIR,
    DEFAULT_SOCKET_PATH,
    REQUEST_RE,
    UpdaterProtocolError,
    load_profile,
    unix_request,
    version_tuple,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", default="watcher")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("check")
    job_parser = subparsers.add_parser("job")
    job_parser.add_argument("request_id")
    update_parser = subparsers.add_parser("update")
    update_parser.add_argument("--version", required=True)
    update_parser.add_argument("--request-id", default=None)
    self_update_parser = subparsers.add_parser("self-update")
    self_update_parser.add_argument("--release-version", required=True)
    self_update_parser.add_argument("--request-id", default=None)
    self_job_parser = subparsers.add_parser("self-update-job")
    self_job_parser.add_argument("request_id")
    args = parser.parse_args()
    try:
        profile = load_profile(os.path.join(DEFAULT_PROFILE_DIR, f"{args.service}.json"))
        headers = {"X-Updater-Service": profile["serviceId"]}
        if args.command == "status":
            method, path, body = "GET", f"/v1/services/{profile['serviceId']}/status", None
        elif args.command == "check":
            method, path, body = "GET", f"/v1/services/{profile['serviceId']}/releases/check", None
        elif args.command == "job":
            if not REQUEST_RE.fullmatch(args.request_id):
                raise UpdaterProtocolError("request ID is invalid")
            method, path, body = "GET", f"/v1/services/{profile['serviceId']}/jobs/{args.request_id}", None
        elif args.command == "self-update-job":
            if not REQUEST_RE.fullmatch(args.request_id):
                raise UpdaterProtocolError("request ID is invalid")
            method, path, body = "GET", f"/v1/updater/self-update/jobs/{args.request_id}", None
        elif args.command == "self-update":
            version_tuple(args.release_version)
            request_id = args.request_id or uuid.uuid4().hex
            if not REQUEST_RE.fullmatch(request_id):
                raise UpdaterProtocolError("request ID is invalid")
            headers["X-Updater-Control-Token"] = profile["controlToken"]
            method, path, body = "POST", "/v1/updater/self-update/jobs", {"requestId": request_id, "releaseVersion": args.release_version}
        else:
            version_tuple(args.version)
            request_id = args.request_id or uuid.uuid4().hex
            if not REQUEST_RE.fullmatch(request_id):
                raise UpdaterProtocolError("request ID is invalid")
            headers["X-Updater-Control-Token"] = profile["controlToken"]
            method, path, body = "POST", f"/v1/services/{profile['serviceId']}/jobs", {"requestId": request_id, "version": args.version}
        status, response = unix_request(args.socket, method, path, body=body, headers=headers, timeout=30)
    except UpdaterProtocolError as exc:
        print(f"updater request failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
