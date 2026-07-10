import unittest
from pathlib import Path

from scanner.dns_class_scanner import scan_dns_class

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "dns"


class TestDnsClass(unittest.TestCase):
    def test_fixtures_fire(self):
        findings = scan_dns_class(str(FIXTURES), include_system=False)
        ids = {f.id for f in findings}
        self.assertIn("DNS-CLASS-LONG-LABEL", ids)
        self.assertIn("DNS-CLASS-NXDOMAIN-FLOOD", ids)
        self.assertIn("DNS-CLASS-HIJACK-INDICATOR", ids)

    def test_actions_present(self):
        findings = scan_dns_class(str(FIXTURES), include_system=False)
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f.action)
            self.assertEqual(f.category, "dns-class")


if __name__ == "__main__":
    unittest.main()
