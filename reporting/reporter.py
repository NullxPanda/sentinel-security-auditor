"""Containment-oriented reporting for Sentinel findings."""

from __future__ import annotations

from typing import Any, Dict, List, Union

from models.data_models import Finding, VulnerabilityFinding


def print_findings(findings):
    """Legacy path: VulnerabilityFinding objects."""
    if not findings:
        print("\nNo vulnerabilities detected.")
        return

    print("\nVulnerability Findings (actionable only):\n")
    for finding in findings:
        print(f"[{finding.severity}] {finding.package} {finding.version} → {finding.cve_id}")


def print_blue_team_findings(
    findings: List[Union[Finding, Dict[str, Any]]],
    title: str = "Findings",
) -> None:
    """Print operator-facing blocks: what / why / evidence / action / do_not."""
    if not findings:
        return

    print(f"\n=== {title} ({len(findings)}) ===")
    for raw in findings:
        f = raw.to_dict() if isinstance(raw, Finding) else dict(raw)
        sev = (f.get("severity") or "UNKNOWN").upper()
        fid = f.get("id") or "?"
        cat = f.get("category") or ""
        print(f"\n[{sev}] {fid}" + (f"  ({cat})" if cat else ""))
        if f.get("description"):
            print(f"  What/Why : {f['description']}")
        asset = f.get("asset") or f.get("file") or f.get("package") or ""
        if asset:
            print(f"  Asset    : {asset}")
        if f.get("signal"):
            print(f"  Signal   : {f['signal']}")
        if f.get("evidence"):
            ev = str(f["evidence"]).replace("\n", " ")
            if len(ev) > 160:
                ev = ev[:157] + "..."
            print(f"  Evidence : {ev}")
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
    counts: Dict[str, int] = {}
    for raw in findings:
        f = raw.to_dict() if isinstance(raw, Finding) else dict(raw)
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        print("\nSummary: 0 findings")
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    parts = [f"{s}={counts[s]}" for s in order if s in counts]
    for s, n in counts.items():
        if s not in order:
            parts.append(f"{s}={n}")
    print("\nSummary: " + ", ".join(parts) + f" (total={sum(counts.values())})")
