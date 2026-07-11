"""
Containment-oriented reporting for Sentinel findings.

Team contract (read this if you touch output):
  Operators need five answers, not vibes:
    1. What fired
    2. Why it matters
    3. Evidence
    4. Action (≈5 minutes)
    5. Do NOT (panic moves that make IR worse)

Keep labels stable — scripts and muscle memory depend on "Action" / "Do NOT".
# comments below are for us; the printed lines are the product.
"""

from __future__ import annotations

from typing import Any, Dict, List, Union

from models.data_models import Finding


def print_findings(findings):
    """Legacy path: VulnerabilityFinding objects (package CVE list)."""
    # Older call sites; prefer print_blue_team_findings for new modules
    if not findings:
        print("\nNo vulnerabilities detected.")
        return

    print("\nVulnerability Findings (actionable only):\n")
    for finding in findings:
        print(f"[{finding.severity}] {finding.package} {finding.version} → {finding.cve_id}")


def print_blue_team_findings(
    findings: List[Union[Finding, Dict[str, Any]]],
    title: str = "Findings",
    *,
    show_chain: bool = True,
) -> None:
    """Print operator-facing blocks: what / why / evidence / action / do_not."""
    if not findings:
        return

    print(f"\n=== {title} ({len(findings)}) ===")
    for raw in findings:
        # Accept Finding or already-normalized dict (orchestrator uses both)
        f = raw.to_dict() if isinstance(raw, Finding) else dict(raw)
        sev = (f.get("severity") or "UNKNOWN").upper()
        fid = f.get("id") or "?"
        cat = f.get("category") or ""
        print(f"\n[{sev}] {fid}" + (f"  ({cat})" if cat else ""))

        # What/Why first — severity alone is not enough for triage
        if f.get("description"):
            print(f"  What/Why : {f['description']}")

        # Asset: prefer explicit asset, then file path, then package name
        asset = f.get("asset") or f.get("file") or f.get("package") or ""
        if asset:
            print(f"  Asset    : {asset}")
        if f.get("signal"):
            print(f"  Signal   : {f['signal']}")
        if f.get("evidence"):
            # Single-line evidence keeps the TTY readable
            ev = str(f["evidence"]).replace("\n", " ")
            if len(ev) > 200:
                ev = ev[:197] + "..."
            print(f"  Evidence : {ev}")

        # Optional depth for historical knowledge — compact, not a wall of text
        if show_chain and f.get("attack_chain"):
            chain = f["attack_chain"]
            if isinstance(chain, list) and chain:
                print(f"  Chain    : {' → '.join(str(s) for s in chain[:4])}")
                if len(chain) > 4:
                    print(f"             (+{len(chain) - 4} more steps in --json)")

        # Action / Do NOT are the contract — never drop these labels
        action = f.get("action") or f.get("recommendation") or ""
        if action:
            print(f"  Action   : {action}")
        if f.get("do_not"):
            print(f"  Do NOT   : {f['do_not']}")

        tags = f.get("tags") or []
        if tags:
            if isinstance(tags, list):
                print(f"  Tags     : {', '.join(str(t) for t in tags)}")
            else:
                print(f"  Tags     : {tags}")


def print_summary(findings: List[Union[Finding, Dict[str, Any]]]) -> None:
    """Severity rollup — one line, easy to screenshot for receipts."""
    counts: Dict[str, int] = {}
    for raw in findings:
        f = raw.to_dict() if isinstance(raw, Finding) else dict(raw)
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        print("\nSummary: 0 findings")
        return
    # Fixed order so CRITICAL is never buried under LOW
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    parts = [f"{s}={counts[s]}" for s in order if s in counts]
    for s, n in counts.items():
        if s not in order:
            parts.append(f"{s}={n}")
    print("\nSummary: " + ", ".join(parts) + f" (total={sum(counts.values())})")
