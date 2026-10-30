import unittest
from datetime import date

from correlator.windows_library import classify_record, match_library_to_posture


POSTURE = {
    "product": "Windows 11 Home",
    "display_version": "25H2",
    "october_release": date(2026, 10, 13),
    "october_installed": True,
}
SINCE = date(2026, 10, 13)


class TestWindowsLibrary(unittest.TestCase):
    def test_other_products_are_not_windows_findings(self):
        fortimail = {
            "id": "CVE-2026-104286",
            "status": "Analyzed",
            "published": "2026-10-20",
            "products": ["fortinet:fortimail"],
            "kev": True,
            "severity": "CRITICAL",
        }
        netscaler = {
            "id": "CVE-2026-88779",
            "status": "Analyzed",
            "published": "2026-10-20",
            "products": ["citrix:netscaler_gateway"],
            "kev": True,
            "severity": "HIGH",
        }
        self.assertEqual(classify_record(fortimail, POSTURE, SINCE), "other-product")
        self.assertEqual(classify_record(netscaler, POSTURE, SINCE), "other-product")
        self.assertEqual(match_library_to_posture([fortimail, netscaler], POSTURE), [])

    def test_rejected_windows_record_is_dropped(self):
        rejected = {
            "id": "CVE-2026-0001",
            "status": "Rejected",
            "published": "2026-10-20",
            "products": ["microsoft:windows_11_25h2"],
            "severity": "CRITICAL",
        }
        self.assertEqual(classify_record(rejected, POSTURE, SINCE), "drop")
        self.assertEqual(match_library_to_posture([rejected], POSTURE), [])

    def test_this_build_after_the_cumulative_is_a_patch_finding(self):
        record = {
            "id": "CVE-2026-100200",
            "status": "Analyzed",
            "published": "2026-10-20",
            "products": ["microsoft:windows_11_25h2"],
            "severity": "HIGH",
        }
        covered = dict(record, id="CVE-2026-100201", published="2026-10-13")
        self.assertEqual(classify_record(record, POSTURE, SINCE), "patch")
        self.assertEqual(classify_record(covered, POSTURE, SINCE), "covered")
        findings = match_library_to_posture([record, covered], POSTURE)
        self.assertEqual([f.id for f in findings], ["CVE-2026-100200"])
        self.assertEqual(findings[0].category, "windows-posture")
        self.assertIn("Do not treat a CVE ID", findings[0].do_not)


if __name__ == "__main__":
    unittest.main()
