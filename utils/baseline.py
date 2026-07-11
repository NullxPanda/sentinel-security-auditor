"""
Phase 2 — baseline allowlist (fewer FPs without deleting detection).

# Why this file exists
Operators get trained to ignore CRITICAL if noise is high.
Suppress known-noise *finding keys* here; do not weaken rules silently.

Key format (one per line):
  category|id|asset_substring

Empty field = match any for that column.
Lines starting with # or blank are ignored.

Example:
  ransomware-class|RW-CLASS-RANSOM-NOTE|lab/notes/
  dns-class|DNS-CLASS-UNCOMMON-RESOLVER|
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


# (category, id, asset_substring) — empty string means wildcard
Rule = Tuple[str, str, str]


def load_baseline(path: str | None) -> List[Rule]:
    """Load allowlist rules. Missing/empty path → no rules (suppress nothing)."""
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        # Honest skip — do not fail cold path if operator mistyped path
        print(f"[baseline] file not found (no suppress): {path}")
        return []
    rules: List[Rule] = []
    for line in p.read_text(errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("|")
        # Pad to 3 fields
        while len(parts) < 3:
            parts.append("")
        cat, fid, asset = (parts[0].strip(), parts[1].strip(), parts[2].strip())
        rules.append((cat, fid, asset))
    return rules


def _rule_matches(f: Dict[str, Any], rule: Rule) -> bool:
    cat, fid, asset_sub = rule
    f_cat = str(f.get("category") or "")
    f_id = str(f.get("id") or "")
    # asset may live in asset / file / package
    f_asset = str(f.get("asset") or f.get("file") or f.get("package") or "")

    if cat and cat.lower() != f_cat.lower():
        return False
    if fid and fid.lower() != f_id.lower():
        return False
    if asset_sub and asset_sub.lower() not in f_asset.lower():
        return False
    return True


def apply_baseline(
    findings: Sequence[Dict[str, Any]],
    rules: Sequence[Rule],
) -> List[Dict[str, Any]]:
    """Drop findings that match any allowlist rule. No rules → identity."""
    if not rules:
        return list(findings)
    out: List[Dict[str, Any]] = []
    suppressed = 0
    for f in findings:
        if any(_rule_matches(f, r) for r in rules):
            suppressed += 1
            continue
        out.append(dict(f) if not isinstance(f, dict) else f)
    if suppressed:
        print(f"[baseline] suppressed {suppressed} finding(s) via allowlist")
    return out
