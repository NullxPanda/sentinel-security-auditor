import unittest
from pathlib import Path

from scanner.ransomware_class_scanner import scan_ransomware_class

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "ransomware"


class TestRansomwareClass(unittest.TestCase):
    def test_fixtures_fire_expected_ids(self):
        findings = scan_ransomware_class(str(FIXTURES))
        ids = {f.id for f in findings}
        self.assertIn("RW-CLASS-SHADOW-DELETE", ids)
        self.assertIn("RW-CLASS-WBADMIN-CATALOG", ids)
        self.assertIn("RW-CLASS-BCD-RECOVERY", ids)
        self.assertIn("RW-CLASS-RANSOM-NOTE", ids)
        self.assertIn("RW-CLASS-SMB-WORMISH", ids)

    def test_findings_have_blue_team_fields(self):
        findings = scan_ransomware_class(str(FIXTURES))
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f.action, msg=f"{f.id} missing action")
            self.assertTrue(f.do_not, msg=f"{f.id} missing do_not")
            self.assertEqual(f.category, "ransomware-class")
            self.assertTrue(f.evidence or f.signal)


if __name__ == "__main__":
    unittest.main()
