"""
Wireshark-style display filters for Sentinel findings.

Goal: Let you quickly categorize and slice the output the same way you
write Wireshark display filters (tcp.port==80, http, ip.src==x, !arp, etc.).

Supported simple syntax (designed to be fast to type and memorable):

  severity=CRITICAL
  severity=HIGH,CRITICAL
  id~SHINY
  id~AURA|PEOPLESOFT
  category=historical
  category=live,shiny
  vector=AURA
  tags~saas,guest
  severity!=UNKNOWN

You can combine with spaces or commas (treated as AND):

  severity=CRITICAL category=shiny
  id~SHINY severity>=HIGH

Operators:
  =     exact match (case-insensitive for most fields)
  !=    not equal
  ~     contains / substring (or regex-ish for | )
  >=    for severity ordering (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)

Special shortcuts that also work as CLI flags:
  --only-shiny
  --high-severity   (CRITICAL + HIGH)
  --live-only
  etc.

The filter is applied uniformly to live CVEs, historical (including all SHINY-*),
GHA findings, and the dedicated ShinyHunters scanner results.

This keeps the "what actually matters" philosophy while giving you the
same kind of power and speed as your Wireshark filters.
"""

from __future__ import annotations
import re
from typing import Any, Callable, Dict, List

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
    "": 0,
}

def _norm_sev(s: str) -> str:
    return (s or "").upper().strip()

def _get(f: Dict[str, Any], key: str, default="") -> str:
    # Support both flat keys and nested access for different finding shapes
    val = f.get(key, default)
    if val is None:
        val = default
    if isinstance(val, (list, tuple)):
        val = ",".join(str(x) for x in val)
    return str(val)

def _match_value(actual: str, wanted: str, op: str) -> bool:
    actual = actual.lower()
    wanted = wanted.lower()

    if op == "=":
        return actual == wanted
    if op == "!=":
        return actual != wanted
    if op == "~":
        # support | as OR inside the value, e.g. id~SHINY|AURA
        if "|" in wanted:
            return any(w in actual for w in wanted.split("|"))
        return wanted in actual
    if op == ">=":
        # severity comparison
        return SEVERITY_ORDER.get(_norm_sev(actual), 0) >= SEVERITY_ORDER.get(_norm_sev(wanted), 0)
    return False

def compile_filter(filter_str: str) -> Callable[[Dict[str, Any]], bool]:
    """
    Turn a Wireshark-like filter string into a predicate function.
    Empty string or None => always True (show everything).
    """
    if not filter_str or not filter_str.strip():
        return lambda f: True

    # Split on commas and spaces (multiple conditions ANDed together)
    tokens = re.split(r"[,\s]+", filter_str.strip())
    conditions: List[tuple] = []

    for tok in tokens:
        if not tok:
            continue
        # Parse key op value
        m = re.match(r"([a-zA-Z_]+)\s*(!=|>=|=|~)\s*(.+)", tok)
        if not m:
            # bare word, treat as category or id contains
            conditions.append(("id", "~", tok))
            continue

        key, op, value = m.groups()
        key = key.lower()
        conditions.append((key, op, value))

    def predicate(finding: Dict[str, Any]) -> bool:
        for key, op, value in conditions:
            if key in ("sev", "severity"):
                actual = _norm_sev(_get(finding, "severity"))
                if not _match_value(actual, value, op):
                    return False
            elif key in ("cat", "category"):
                actual = _get(finding, "category") or _get(finding, "type") or ""
                if not _match_value(actual, value, op):
                    return False
            elif key in ("id", "cve", "cve_id"):
                actual = _get(finding, "id") or _get(finding, "cve_id") or _get(finding, "workflow") or ""
                if not _match_value(actual, value, op):
                    return False
            elif key in ("vector", "tag", "tags"):
                # tags can be list or comma string
                actual = _get(finding, "tags") or _get(finding, "vector") or ""
                if not _match_value(actual, value, op):
                    return False
            elif key == "desc" or key == "description" or key == "title":
                actual = _get(finding, "description") or _get(finding, "title") or ""
                if not _match_value(actual, value, op):
                    return False
            else:
                # generic key lookup
                actual = _get(finding, key)
                if not _match_value(actual, value, op):
                    return False
        return True

    return predicate


def apply_filters(findings: List[Dict[str, Any]], filter_str: str = "") -> List[Dict[str, Any]]:
    """Apply a filter string to a list of findings (dicts)."""
    pred = compile_filter(filter_str)
    return [f for f in findings if pred(f)]


def add_category_and_tags(f: Dict[str, Any], category: str, tags: List[str] | None = None) -> Dict[str, Any]:
    """Helper to normalize findings for filtering."""
    f = dict(f)  # copy
    f.setdefault("category", category)
    existing = f.get("tags") or []
    if isinstance(existing, str):
        existing = [t.strip() for t in existing.split(",") if t.strip()]
    f["tags"] = sorted(set(existing + (tags or [])))
    return f


# Convenience for CLI
def get_severity_filter(severities: str) -> str:
    if not severities:
        return ""
    return "severity~=" + severities.replace(",", "|")


if __name__ == "__main__":
    # Self test
    test = [
        {"id": "SHINY-2026-AURA", "severity": "CRITICAL", "category": "shiny", "vector": "AURA"},
        {"id": "CVE-2014-6271", "severity": "CRITICAL", "category": "historical"},
        {"id": "libnfs", "severity": "HIGH", "category": "live_cve"},
        {"workflow": ".github/...", "severity": "CRITICAL", "category": "gha", "risks": ["prompt injection"]},
    ]
    print("All:", len(apply_filters(test, "")))
    print("Only shiny:", len(apply_filters(test, "category=shiny")))
    print("High or critical shiny or historical:", len(apply_filters(test, "severity>=HIGH category~shiny|historical")))
    print("SHINY id:", len(apply_filters(test, "id~SHINY")))
