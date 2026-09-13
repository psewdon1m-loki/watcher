from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_JS = REPOSITORY_ROOT / "web" / "static" / "app.js"


class DashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = DASHBOARD_JS.read_text(encoding="utf-8")

    def test_server_update_downloads_operator_backup_before_job_submission(self):
        start = self.source.index("async function startServerUpdate")
        end = self.source.index("async function pollServerUpdateJob", start)
        update_flow = self.source[start:end]

        backup_download = update_flow.index("await downloadFile(")
        update_submission = update_flow.index('apiJson("/api/v1/server-updates/jobs"')
        self.assertLess(backup_download, update_submission)
        self.assertIn("if (!backupDownloaded)", update_flow)

    def test_download_helper_reports_success_and_delays_object_url_cleanup(self):
        start = self.source.index("async function downloadFile")
        end = self.source.index("async function restoreBackup", start)
        download_flow = self.source[start:end]

        self.assertIn("return true;", download_flow)
        self.assertIn("return false;", download_flow)
        self.assertIn("window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)", download_flow)


if __name__ == "__main__":
    unittest.main()
