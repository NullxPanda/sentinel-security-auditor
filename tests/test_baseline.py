"""Phase 2 — baseline allowlist suppresses known noise without killing rules."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from utils.baseline import apply_baseline, load_baseline


class TestBaseline(unittest.TestCase):
    def test_empty_rules_identity(self):
        findings = [{"id": "X", "category": "dns-class", "asset": "a.log"}]
        self.assertEqual(apply_baseline(findings, []), findings)

    def test_suppress_by_id_and_category(self):
        rules = [("dns-class", "DNS-CLASS-LONG-LABEL", "")]
        findings = [
            {"id": "DNS-CLASS-LONG-LABEL", "category": "dns-class", "asset": "dns/x.log"},
            {"id": "DNS-CLASS-HIJACK-INDICATOR", "category": "dns-class", "asset": "dns/y"},
        ]
        out = apply_baseline(findings, rules)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "DNS-CLASS-HIJACK-INDICATOR")

    def test_asset_substring(self):
        rules = [("ransomware-class", "RW-CLASS-RANSOM-NOTE", "lab/notes")]
        findings = [
            {
                "id": "RW-CLASS-RANSOM-NOTE",
                "category": "ransomware-class",
                "file": "lab/notes/demo.txt",
            },
            {
                "id": "RW-CLASS-RANSOM-NOTE",
                "category": "ransomware-class",
                "file": "test-fixtures/ransomware/ransom_note.txt",
            },
        ]
        out = apply_baseline(findings, rules)
        self.assertEqual(len(out), 1)
        self.assertIn("test-fixtures", out[0]["file"])

    def test_load_baseline_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "al.txt"
            p.write_text("# comment\n\ndns-class|DNS-CLASS-LONG-LABEL|\n")
            rules = load_baseline(str(p))
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0][1], "DNS-CLASS-LONG-LABEL")


if __name__ == "__main__":
    unittest.main()
