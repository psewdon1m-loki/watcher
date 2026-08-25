from __future__ import annotations

import hashlib
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from updater_common import UpdaterProtocolError, canonical_json, load_profile, unix_request, validate_policy, version_tuple

if os.name == "posix":
    import local_updater
    import updater_daemon
    import updater_self_update


class ResponseHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while self.rfile.readline() not in {b"\r\n", b"\n", b""}:
            pass
        payload = b'{"status":"ok"}'
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(payload)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + payload
        )


class UpdaterContractTests(unittest.TestCase):
    def test_policy_checksum_and_repository_allow_shape(self):
        policy = {
            "schemaVersion": 1,
            "serviceId": "watcher",
            "revision": "revision-1",
            "generatedAt": "2026-08-08T00:00:00+00:00",
            "channel": "stable",
            "repositories": {"server": "owner/watcher", "updater": "owner/watcher"},
        }
        policy["checksumSha256"] = hashlib.sha256(canonical_json(policy)).hexdigest()
        self.assertEqual(policy, validate_policy(policy, "watcher"))
        tampered = {**policy, "repositories": {"server": "evil/repository", "updater": "owner/watcher"}}
        with self.assertRaises(UpdaterProtocolError):
            validate_policy(tampered, "watcher")

    def test_profile_and_semantic_version_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "watcher.json")
            with open(path, "w", encoding="utf-8") as target:
                json.dump(
                    {
                        "schemaVersion": 1,
                        "serviceId": "watcher",
                        "installDir": "/opt/vpnenus-watcher",
                        "apiHost": "127.0.0.1",
                        "apiPort": 18080,
                        "controlToken": "control-token-abcdefghijklmnopqrstuvwxyz",
                    },
                    target,
                )
            profile = load_profile(path, require_root_owner=False)
        self.assertEqual("watcher", profile["serviceId"])
        self.assertEqual((1, 2, 3), version_tuple("1.2.3"))
        with self.assertRaises(UpdaterProtocolError):
            version_tuple("1.2.3-rc1")

    @unittest.skipUnless(hasattr(socketserver, "UnixStreamServer"), "Unix sockets are unavailable")
    def test_unix_http_client_has_bounded_json_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "updater.sock")
            server = socketserver.UnixStreamServer(socket_path, ResponseHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status, body = unix_request(socket_path, "GET", "/health")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        self.assertEqual(200, status)
        self.assertEqual("ok", body["status"])


@unittest.skipUnless(os.name == "posix", "privileged updater modules target Linux")
class LinuxUpdaterTests(unittest.TestCase):
    def test_daemon_status_is_read_only_but_mutation_requires_service_token(self):
        with tempfile.TemporaryDirectory() as directory:
            profile_dir = os.path.join(directory, "profiles")
            state_root = os.path.join(directory, "state")
            os.makedirs(profile_dir)
            os.makedirs(state_root)
            profile_path = os.path.join(profile_dir, "watcher.json")
            with open(profile_path, "w", encoding="utf-8") as target:
                json.dump(
                    {
                        "schemaVersion": 1,
                        "serviceId": "watcher",
                        "installDir": "/opt/vpnenus-watcher-test",
                        "apiHost": "127.0.0.1",
                        "apiPort": 18080,
                        "controlToken": "control-token-abcdefghijklmnopqrstuvwxyz",
                    },
                    target,
                )
            os.chmod(profile_path, 0o600)
            socket_path = os.path.join(directory, "updater.sock")
            server = updater_daemon.UnixThreadingServer(socket_path, updater_daemon.Handler, profile_dir, state_root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            profile_loader = lambda path: load_profile(path, require_root_owner=False)
            with mock.patch.object(updater_daemon, "load_profile", side_effect=profile_loader):
                thread.start()
                try:
                    status, body = unix_request(
                        socket_path,
                        "GET",
                        "/v1/services/watcher/status",
                        headers={"X-Updater-Service": "watcher"},
                    )
                    self.assertEqual(200, status, body)
                    self.assertTrue(body["available"])
                    status, body = unix_request(
                        socket_path,
                        "POST",
                        "/v1/services/watcher/jobs",
                        body={"requestId": "request-token-test", "version": "1.2.3"},
                        headers={"X-Updater-Service": "watcher", "X-Updater-Control-Token": "wrong-token"},
                    )
                    self.assertEqual(403, status, body)
                    self.assertEqual("control_token_invalid", body["error"])
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_release_resolution_binds_repository_tag_and_immutable_images(self):
        version = "1.2.3"
        release = {
            "tag_name": f"v{version}",
            "draft": False,
            "prerelease": False,
            "assets": [{"name": local_updater.MANIFEST_ASSET, "browser_download_url": "https://github.com/owner/watcher/manifest.json"}],
        }
        manifest = {
            "schemaVersion": 1,
            "componentRole": "watcher-control-plane",
            "version": version,
            "channel": "stable",
            "databaseSchemaGeneration": 3,
            "minimumUpdaterVersion": "1.1.0",
            "images": {
                role: f"ghcr.io/owner/watcher-{role}@sha256:" + (str(index) * 64)
                for index, role in enumerate(("api", "web", "worker"), start=1)
            },
            "bundle": {"url": "https://github.com/owner/watcher/bundle.zip", "sha256": "a" * 64, "bytes": 1024},
        }
        with mock.patch.object(local_updater, "fetch_json", side_effect=[release, manifest]) as fetch:
            result = local_updater.resolve_release("owner/watcher", version)
        self.assertEqual(manifest, result)
        self.assertIn("owner/watcher", fetch.call_args_list[0].args[0])
        manifest["images"]["api"] = "ghcr.io/owner/watcher-api:latest"
        with mock.patch.object(local_updater, "fetch_json", side_effect=[release, manifest]):
            with self.assertRaises(local_updater.UpdateError):
                local_updater.resolve_release("owner/watcher", version)

    def test_bundle_extraction_requires_the_exact_member_contract(self):
        allowed = {
            "docker-compose.yml", ".env.template", "install.sh", "watcherctl", "recovery_tool.py", "validate_env.py",
            "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py",
            "updater_self_update.py", "vpnenus-updater.service", "RELEASE.txt",
        }
        with tempfile.TemporaryDirectory() as directory:
            archive_path = os.path.join(directory, "bundle.zip")
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name in allowed:
                    archive.writestr(name, b"safe")
            target = os.path.join(directory, "extracted")
            local_updater.safe_extract_bundle(archive_path, target)
            self.assertEqual(allowed, set(os.listdir(target)))

            bad_path = os.path.join(directory, "bad.zip")
            with zipfile.ZipFile(bad_path, "w") as archive:
                for name in allowed | {"unexpected.sh"}:
                    archive.writestr(name, b"unsafe")
            with self.assertRaises(local_updater.UpdateError):
                local_updater.safe_extract_bundle(bad_path, os.path.join(directory, "bad"))

    def test_restart_reconciliation_never_leaves_ambiguous_jobs(self):
        with tempfile.TemporaryDirectory() as state_root:
            app_jobs = os.path.join(state_root, "services", "watcher", "jobs")
            os.makedirs(app_jobs)
            app_job_path = os.path.join(app_jobs, "request-app.json")
            with open(app_job_path, "w", encoding="utf-8") as target:
                json.dump({"jobId": "request-app", "state": "APPLYING", "history": []}, target)
            local_updater.reconcile_jobs(app_jobs)
            with open(app_job_path, "r", encoding="utf-8") as source:
                self.assertEqual("ROLLBACK_FAILED", json.load(source)["state"])

            self_jobs = os.path.join(state_root, "self-update", "jobs")
            os.makedirs(self_jobs)
            self_job_path = os.path.join(self_jobs, "request-self.json")
            with open(self_job_path, "w", encoding="utf-8") as target:
                json.dump({"jobId": "request-self", "unitName": "missing-unit", "state": "HEALTH_CHECK", "history": []}, target)
            completed = mock.Mock(returncode=3)
            with mock.patch.object(updater_daemon.subprocess, "run", return_value=completed):
                updater_daemon.reconcile_self_update_jobs(state_root)
            with open(self_job_path, "r", encoding="utf-8") as source:
                self.assertEqual("ROLLBACK_FAILED", json.load(source)["state"])

    def test_self_update_file_replacement_can_restore_previous_version(self):
        with tempfile.TemporaryDirectory() as directory:
            updater_root = os.path.join(directory, "updater")
            staged = os.path.join(directory, "staged")
            previous = os.path.join(directory, "previous")
            os.makedirs(updater_root)
            os.makedirs(staged)
            os.makedirs(previous)
            unit_path = os.path.join(directory, "vpnenus-updater.service")
            for name in updater_self_update.UPDATER_FILES:
                with open(os.path.join(updater_root, name), "wb") as target:
                    target.write(b"old")
                with open(os.path.join(staged, name), "wb") as target:
                    target.write(b"new")
                with open(os.path.join(previous, name), "wb") as target:
                    target.write(b"old")
            with open(os.path.join(staged, "vpnenus-updater.service"), "wb") as target:
                target.write(b"new-unit")
            with open(os.path.join(previous, "vpnenus-updater.service"), "wb") as target:
                target.write(b"old-unit")
            with mock.patch.object(updater_self_update, "UPDATER_ROOT", updater_root), mock.patch.object(updater_self_update, "UNIT_PATH", unit_path):
                updater_self_update.install_staged(staged)
                with open(os.path.join(updater_root, "updater_daemon.py"), "rb") as source:
                    self.assertEqual(b"new", source.read())
                updater_self_update.restore_previous(previous)
                with open(os.path.join(updater_root, "updater_daemon.py"), "rb") as source:
                    self.assertEqual(b"old", source.read())
                with open(unit_path, "rb") as source:
                    self.assertEqual(b"old-unit", source.read())


if __name__ == "__main__":
    unittest.main()
