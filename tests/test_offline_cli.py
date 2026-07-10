import unittest
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestOfflineCli(unittest.TestCase):
    def test_offline_modules_on_fixtures(self):
        cmd = [
            sys.executable,
            str(ROOT / "sentinel.py"),
            "--offline",
            "--no-packages",
            "--no-historical",
            "--root",
            str(ROOT / "test-fixtures"),
            "--modules",
            "ransomware-class,dns-class",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        out = proc.stdout
        self.assertIn("RW-CLASS-SHADOW-DELETE", out)
        self.assertIn("DNS-CLASS-LONG-LABEL", out)
        self.assertIn("Action", out)


if __name__ == "__main__":
    unittest.main()
