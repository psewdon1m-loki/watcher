#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path
import runpy


VERSION_RE = re.compile(r"^\d{1,9}\.\d{1,9}\.\d{1,9}$")
IMAGE_RE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zip_member(archive: zipfile.ZipFile, name: str, data: bytes, executable: bool = False) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = ((0o755 if executable else 0o600) & 0xFFFF) << 16
    archive.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--api-image", required=True)
    parser.add_argument("--web-image", required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not VERSION_RE.fullmatch(args.version):
        parser.error("version must be X.Y.Z")
    images = {"api": args.api_image, "web": args.web_image, "worker": args.worker_image}
    for role, image in images.items():
        if not IMAGE_RE.fullmatch(image):
            parser.error(f"{role} image must be an immutable GHCR sha256 reference")
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://github.com/"):
        parser.error("base URL must be a GitHub HTTPS release URL")

    root = Path(__file__).resolve().parent.parent
    updater_version = str(runpy.run_path(str(root / "deploy" / "updater_common.py"))["UPDATER_VERSION"])
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    compose = (root / "deploy" / "docker-compose.release.yml").read_bytes()
    template = (root / "deploy" / "env.production.template").read_text(encoding="utf-8")
    replacements = {
        "__VERSION__": args.version,
        "__API_IMAGE__": images["api"],
        "__WEB_IMAGE__": images["web"],
        "__WORKER_IMAGE__": images["worker"],
    }
    for marker, value in replacements.items():
        if template.count(marker) != 1:
            raise SystemExit(f"release template marker is invalid: {marker}")
        template = template.replace(marker, value)

    members = {
        "docker-compose.yml": compose,
        ".env.template": template.encode("utf-8"),
        "install.sh": (root / "deploy" / "install.sh").read_bytes(),
        "watcherctl": (root / "deploy" / "watcherctl").read_bytes(),
        "recovery_tool.py": (root / "deploy" / "recovery_tool.py").read_bytes(),
        "validate_env.py": (root / "deploy" / "validate_env.py").read_bytes(),
        "local_updater.py": (root / "deploy" / "local_updater.py").read_bytes(),
        "updater_daemon.py": (root / "deploy" / "updater_daemon.py").read_bytes(),
        "updater_client.py": (root / "deploy" / "updater_client.py").read_bytes(),
        "updater_common.py": (root / "deploy" / "updater_common.py").read_bytes(),
        "updater_self_update.py": (root / "deploy" / "updater_self_update.py").read_bytes(),
        "vpnenus-updater.service": (root / "deploy" / "vpnenus-updater.service").read_bytes(),
        "RELEASE.txt": (
            f"VPNЭНУС Watcher {args.version}\n"
            "This bundle is installed only after release-manifest identity and SHA-256 verification.\n"
            "Image references are immutable OCI digests.\n"
        ).encode("utf-8"),
    }
    bundle_name = f"vpn-enus-watcher-{args.version}.zip"
    bundle_path = output / bundle_name
    with zipfile.ZipFile(bundle_path, "w", allowZip64=False) as archive:
        for name in sorted(members):
            zip_member(archive, name, members[name], executable=name in {"install.sh", "watcherctl", "recovery_tool.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py"})
    bundle_bytes = bundle_path.read_bytes()
    manifest = {
        "schemaVersion": 1,
        "componentRole": "watcher-control-plane",
        "version": args.version,
        "channel": "stable",
        "minimumUpdaterVersion": updater_version,
        "updaterVersion": updater_version,
        "databaseSchemaGeneration": 3,
        "images": images,
        "bundle": {
            "url": f"{base_url}/{bundle_name}",
            "sha256": digest(bundle_bytes),
            "bytes": len(bundle_bytes),
        },
        "composeSha256": digest(compose),
        "releaseNotesUrl": f"{base_url.rsplit('/download/', 1)[0]}/tag/v{args.version}",
        "trust": {
            "manifestSigned": False,
            "checksumPurpose": "corruption-and-release-binding",
            "imageIdentity": "immutable-oci-digest",
        },
    }
    manifest_path = output / "vpn-enus-watcher-release.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    sums = [
        f"{digest(bundle_bytes)}  {bundle_name}",
        f"{digest(manifest_path.read_bytes())}  {manifest_path.name}",
    ]
    (output / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"bundle": str(bundle_path), "manifest": str(manifest_path), "sha256": manifest["bundle"]["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
