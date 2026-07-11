"""Shiny scanner: real fixtures still fire after Phase 2 FP tightening."""

from __future__ import annotations

import unittest
from pathlib import Path

from scanner.shiny_hunters_scanner import scan_for_shiny_hunters_vectors


class TestShinyFixture(unittest.TestCase):
    def test_guest_fixture_fires_aura_or_guest(self):
        root = Path(__file__).resolve().parent.parent / "test-fixtures" / "shiny"
        hits = scan_for_shiny_hunters_vectors(str(root))
        self.assertTrue(hits, "expected at least one shiny hit on guest_profile fixture")
        vectors = {h.get("vector") for h in hits}
        # Aura guest surface or broad guest/MFA class
        self.assertTrue(
            vectors & {"SHINY-AURA-GUEST", "SHINY-BROAD-GUEST-OR-MFA-BYPASS"},
            f"unexpected vectors only: {vectors}",
        )


if __name__ == "__main__":
    unittest.main()
