from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STATUS_ROOT = REPOSITORY_ROOT / "web" / "static" / "status"


class StatusPageTests(unittest.TestCase):
    def test_public_status_page_has_local_assets_and_public_api(self):
        html = (STATUS_ROOT / "index.html").read_text(encoding="utf-8")
        script = (STATUS_ROOT / "app.js").read_text(encoding="utf-8")
        styles = (STATUS_ROOT / "styles.css").read_text(encoding="utf-8")

        self.assertIn('lang="ru"', html)
        self.assertIn('connect-src \'self\'', html)
        self.assertIn('/initialize/cake-mark.png', html)
        self.assertIn('family=Space+Grotesk', html)
        self.assertIn('/api/v1/public/status', script)
        self.assertIn('const REFRESH_INTERVAL_SECONDS = 30', script)
        self.assertIn('refreshStatus();', script)
        self.assertIn('.component-row', styles)
        self.assertIn('font-family: "Space Grotesk"', styles)

    def test_public_page_does_not_embed_connection_secrets(self):
        combined = "\n".join(
            (STATUS_ROOT / name).read_text(encoding="utf-8")
            for name in ("index.html", "app.js", "styles.css")
        )
        self.assertNotIn("vless://", combined.lower())
        self.assertNotIn("/sub/", combined.lower())

    def test_initialize_page_links_to_service_status(self):
        initialize_html = (REPOSITORY_ROOT / "web" / "static" / "initialize" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="https://statuscake.shmoza.net/"', initialize_html)
        self.assertIn('data-i18n="serviceStatus"', initialize_html)


if __name__ == "__main__":
    unittest.main()
