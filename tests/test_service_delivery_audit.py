import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ServiceDeliveryAuditTest(unittest.TestCase):
    def test_full_local_delivery_and_recovery_leave_no_remote_claims(self):
        for mode in ("snapshot", "repository"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "report.json"
                result = subprocess.run([sys.executable, str(ROOT / "scripts/service-delivery-audit.py"),
                    "--local", "--workspace-mode", mode, "--output", str(output)],
                    capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = json.loads(output.read_text())
                self.assertTrue(report["passed"])
                self.assertTrue(report["cleanup_complete"])
                self.assertTrue(report["checks"]["old_token_revoked"])
                self.assertFalse(report["production_approved"])
                self.assertFalse(report["real_model_provider_tested"])
                self.assertNotIn("verification_source_readonly", report["checks"])

