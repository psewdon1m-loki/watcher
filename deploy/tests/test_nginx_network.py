from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class HostNginxNetworkTests(unittest.TestCase):
    def test_compose_exposes_only_loopback_application_ports(self) -> None:
        for relative in ("docker-compose.yml", "deploy/docker-compose.release.yml"):
            compose = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("\n  nginx:", compose)
            self.assertNotIn("image: nginx", compose)
            self.assertIn('"127.0.0.1:${LOKI_WATCHER_API_PORT:-18080}:8080"', compose)
            self.assertIn('"127.0.0.1:${LOKI_WATCHER_WEB_PORT:-18081}:8080"', compose)

    def test_loki_include_uses_host_loopback_and_narrow_api_prefix(self) -> None:
        config = (ROOT / "deploy/nginx-loki.locations.conf").read_text(encoding="utf-8")
        self.assertNotIn("api:8080", config)
        self.assertNotIn("web:8080", config)
        self.assertIn("location ^~ /api/v1/", config)
        self.assertNotIn("location /api/", config)
        self.assertIn("location ^~ /sub/", config)
        self.assertIn("access_log off;", config)
        self.assertIn("location = /manifest.json.sig", config)
        self.assertIn("proxy_pass http://127.0.0.1:18080;", config)
        self.assertIn("proxy_pass http://127.0.0.1:18081;", config)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertEqual(config.count("{"), config.count("}"))

    def test_deployment_removes_legacy_embedded_nginx_orphan(self) -> None:
        install = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        updater = (ROOT / "deploy/local_updater.py").read_text(encoding="utf-8")
        self.assertIn("compose up -d --no-build --remove-orphans", install)
        self.assertGreaterEqual(updater.count('"--remove-orphans"'), 2)
        self.assertFalse((ROOT / "nginx/templates/default.conf.template").exists())

    def test_bundle_contract_stays_compatible_with_existing_updater(self) -> None:
        for relative in ("scripts/build_release.py", "deploy/bootstrap.sh", "deploy/local_updater.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn('"nginx-loki.locations.conf"', source)


if __name__ == "__main__":
    unittest.main()
