#!/usr/bin/env python3
"""Sentinel — local-first blue-team signal reducer.

sense → match known-ugly classes → prioritize → recommend contain/patch

See BACKBONE.md for doctrine.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.data_models import Finding
from reporting.reporter import print_blue_team_findings, print_summary
from utils.filters import add_category_and_tags, apply_filters, compile_filter


def _run_go_guard(root: str = ".") -> List[Dict[str, Any]]:
    """Invoke the Go hardening layer (sentinel-guard) if built. Returns finding dicts."""
    here = Path(__file__).resolve().parent
    candidates = [
        here / "bin" / "sentinel-guard",
        here / "sentinel-guard",
    ]
    binary = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if binary is None:
        print("\n[Go guard] Binary not found. Build with:")
        print("  cd /home/ghostnode/projects/sentinel && go build -o bin/sentinel-guard ./cmd/sentinel-guard")
        return []

    print("\nRunning Go hardening layer (sentinel-guard: path-safe GHA + secrets scan)...")
    proc = subprocess.run(
        [str(binary), "-root", root, "-mode", "all", "-json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(f"[Go guard] exited {proc.returncode}: {proc.stderr.strip()}")
        return []

    try:
        findings = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print("[Go guard] invalid JSON output")
        return []

    out = []
    for f in findings:
        d = add_category_and_tags(
            {
                "id": f.get("id", "GO-GUARD"),
                "severity": f.get("severity", "UNKNOWN"),
                "description": f.get("description", ""),
                "file": f.get("file", ""),
                "asset": f.get("file", ""),
                "signal": f.get("signal", ""),
                "evidence": f.get("signal", "") or f.get("file", ""),
                "action": f.get("recommendation", ""),
                "recommendation": f.get("recommendation", ""),
                "do_not": "Do not force-push secrets; rotate if exposed.",
                "tags": f.get("tags") or ["go-guard"],
            },
            f.get("category") or "go-guard",
            f.get("tags") or ["go-guard"],
        )
        out.append(d)
    return out


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description=(
            "Sentinel — local-first blue-team signal reducer "
            "(sense → match known-ugly classes → prioritize → recommend contain/patch)"
        ),
        epilog=(
            "Examples: python3 sentinel.py --offline --modules ransomware-class,dns-class "
            "--root test-fixtures"
        ),
    )
    p.add_argument("--root", default=".", help="Scan root directory (default: .)")
    p.add_argument(
        "--offline",
        action="store_true",
        help="Skip live NVD/CVE network calls (recommended on constrained links / Phase 0 demos)",
    )
    p.add_argument(
        "--modules",
        default="all",
        metavar="LIST",
        help=(
            "Comma list: packages,historical,gha,shiny,ransomware-class,dns-class,go-guard "
            "or 'all' (default). Offline default still runs local modules."
        ),
    )
    p.add_argument("--no-packages", action="store_true", help="Skip installed package inventory")
    p.add_argument("--no-historical", action="store_true", help="Skip local historical knowledge base")
    p.add_argument("--go-guard", action="store_true", help="Also run Go hardening layer if built")
    p.add_argument(
        "--filter",
        "-f",
        default="",
        metavar="EXPR",
        help="Wireshark-like display filter",
    )
    p.add_argument("--severity", help="Shortcut severities (comma), e.g. CRITICAL,HIGH")
    p.add_argument("--category", help="Shortcut categories (comma)")
    p.add_argument("--shiny-only", action="store_true", help="Only ShinyHunters-related findings")
    p.add_argument("--high-only", action="store_true", help="Only CRITICAL and HIGH")
    p.add_argument("--list-filters", action="store_true", help="Show filter examples and exit")
    p.add_argument("--json", action="store_true", help="Emit findings as JSON array on stdout (still prints progress on stderr-ish; simple mode prints JSON last)")
    return p.parse_args(argv)


def build_filter_string(args) -> str:
    parts = []
    if args.filter:
        parts.append(args.filter)
    if args.severity:
        parts.append("severity~=" + args.severity.replace(",", "|"))
    if args.category:
        parts.append("category~=" + args.category.replace(",", "|"))
    if args.shiny_only:
        parts.append("category~shiny|historical id~SHINY")
    if args.high_only:
        parts.append("severity>=HIGH")
    return " ".join(parts)


def _wanted_modules(args) -> set:
    raw = (args.modules or "all").strip().lower()
    if raw == "all":
        mods = {
            "packages",
            "historical",
            "gha",
            "shiny",
            "ransomware-class",
            "dns-class",
        }
    else:
        mods = {m.strip() for m in raw.split(",") if m.strip()}
    if args.no_packages:
        mods.discard("packages")
    if args.no_historical:
        mods.discard("historical")
    if args.offline:
        mods.discard("packages")  # packages alone without CVE is noisy; skip inventory in offline unless forced
        # allow packages back if explicitly listed
        if args.modules and "packages" in args.modules.lower() and args.modules.lower() != "all":
            mods.add("packages")
    if args.go_guard:
        mods.add("go-guard")
    return mods


def normalize_live_cve(f) -> Dict[str, Any]:
    d = {
        "id": f.cve_id,
        "severity": f.severity,
        "package": f.package,
        "version": f.version,
        "asset": f"{f.package}@{f.version}",
        "description": f"Installed package may be affected by {f.cve_id}",
        "signal": f.cve_id,
        "evidence": f"{f.package} {f.version}",
        "action": f"Patch or upgrade {f.package}; verify fixed version; restart service if needed.",
        "do_not": "Do not ignore CRITICAL/HIGH on internet-exposed services.",
        "recommendation": f"Patch {f.package}",
    }
    return add_category_and_tags(d, "live", ["cve", "package"])


def normalize_historical(h: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(h)
    d.setdefault("id", h.get("id"))
    d.setdefault("severity", h.get("severity", "UNKNOWN"))
    d.setdefault("description", h.get("description", ""))
    d.setdefault("action", h.get("notes") or "Review attack chain; confirm you are not exposed to this class.")
    d.setdefault(
        "do_not",
        "Do not treat historical knowledge as a live compromise by itself — validate against your assets.",
    )
    d.setdefault("evidence", h.get("example_payload") or h.get("description", "")[:120])
    d.setdefault("signal", d.get("id", ""))
    tags = ["classic"]
    if str(h.get("id", "")).startswith("AI-GHA"):
        tags.append("ai-gha")
    if str(h.get("id", "")).startswith("SHINY"):
        tags.extend(["shiny", "saas"])
    return add_category_and_tags(d, "historical", tags)


def normalize_gha(f: Dict[str, Any]) -> Dict[str, Any]:
    risks = f.get("risks") or []
    d = {
        "id": f.get("workflow") or "GHA",
        "severity": f.get("severity", "HIGH"),
        "description": " | ".join(risks) if risks else "GitHub Actions AI/supply-chain risk",
        "asset": f.get("workflow", ""),
        "file": f.get("workflow", ""),
        "signal": "github-actions",
        "evidence": " | ".join(risks),
        "action": f.get("recommendation")
        or "Pin actions; restrict triggers; never feed raw issue bodies into agents with write tokens.",
        "do_not": "Do not grant contents:write to untrusted-trigger AI workflows.",
        "recommendation": f.get("recommendation", ""),
    }
    return add_category_and_tags(d, "gha", ["github-actions", "prompt-injection", "supply-chain"])


def normalize_shiny(f: Dict[str, Any]) -> Dict[str, Any]:
    d = {
        "id": f.get("vector") or "SHINY",
        "severity": f.get("severity", "HIGH"),
        "file": f.get("file", ""),
        "asset": f.get("file", ""),
        "signal": f.get("signal", ""),
        "evidence": f.get("snippet") or f.get("signal", ""),
        "description": f.get("recommendation") or f.get("signal") or "ShinyHunters-class exposure surface",
        "action": f.get("recommendation") or "Harden guest/unauth surfaces; force MFA; review SaaS sharing.",
        "do_not": "Do not leave guest/profile public read on high-value SaaS objects.",
        "recommendation": f.get("recommendation", ""),
    }
    tags = ["shiny", "saas"]
    if "AURA" in str(d["id"]):
        tags.append("guest-access")
    if "PEOPLESOFT" in str(d["id"]):
        tags.append("erp")
    if "MFA" in str(d["id"]) or "VISH" in str(d["id"]):
        tags.append("social-engineering")
    return add_category_and_tags(d, "shiny", tags)


def finding_to_filter_dict(f: Finding) -> Dict[str, Any]:
    return add_category_and_tags(f.to_dict(), f.category, f.tags)


def main(argv=None):
    args = parse_args(argv)

    if args.list_filters:
        print(
            """Wireshark-style filters (use with --filter / -f):

  --filter 'severity=CRITICAL'
  --filter 'category=ransomware-class'
  --filter 'category~dns-class|gha severity>=HIGH'
  --filter 'id~RW-CLASS|DNS-CLASS'
  --shiny-only   --high-only

Offline demo:
  python3 sentinel.py --offline --modules ransomware-class,dns-class --root test-fixtures
"""
        )
        return 0

    root = args.root
    mods = _wanted_modules(args)
    filt_str = build_filter_string(args)
    all_findings: List[Dict[str, Any]] = []

    print("sentinel :: boot")
    print("product: local-first blue-team signal reducer")
    print(f"root: {root}")
    print(f"modules: {', '.join(sorted(mods)) or '(none)'}")
    print(f"mode: {'offline' if args.offline else 'online-capable'}")
    print("-" * 40)

    # --- packages + live CVE ---
    if "packages" in mods and not args.offline:
        from scanner.package_scanner import get_installed_packages
        from vulnerability.cve_client import fetch_recent_cves
        from correlator.matcher import match_packages_to_cves

        print("Scanning system packages...")
        packages = get_installed_packages()
        print("Packages discovered:", len(packages))
        print("Downloading CVE intelligence (live recent)...")
        cves = fetch_recent_cves(50)
        print("CVE records retrieved:", len(cves))
        raw_live = match_packages_to_cves(packages, cves)
        live = apply_filters([normalize_live_cve(f) for f in raw_live], filt_str)
        if live:
            print_blue_team_findings(live, "Live package / CVE findings")
            all_findings.extend(live)
        else:
            print("No live CVE matches after filter (or none actionable).")
    elif "packages" in mods and args.offline:
        print("Skipping live package/CVE correlation (--offline).")

    # --- historical ---
    if "historical" in mods:
        from vulnerability.historical import get_historical_cves

        print("\nLoading local historical attack knowledge base...")
        historical_raw = get_historical_cves(50)
        hist = apply_filters([normalize_historical(h) for h in historical_raw], filt_str)
        # Keep output bounded
        if hist:
            # prefer mix: non-shiny first few + shiny
            non_shiny = [h for h in hist if not str(h.get("id", "")).startswith("SHINY-")][:6]
            shiny_ones = [h for h in hist if str(h.get("id", "")).startswith("SHINY-")][:8]
            bounded = non_shiny + shiny_ones
            print_blue_team_findings(bounded, "Historical / classic knowledge (local)")
            all_findings.extend(bounded)
        else:
            print("(historical section empty or filtered)")

    # --- GHA ---
    if "gha" in mods:
        from scanner.github_actions_scanner import get_github_action_findings

        print("\nScanning GitHub Actions workflows for AI agent / prompt-injection risks...")
        gha_raw = get_github_action_findings(root)
        gha = apply_filters([normalize_gha(f) for f in gha_raw], filt_str)
        if gha:
            print_blue_team_findings(gha, "GitHub Actions / AI risk findings")
            all_findings.extend(gha)
        else:
            print("No GHA / AI agent findings after filter (or none).")

    # --- Shiny ---
    if "shiny" in mods:
        from scanner.shiny_hunters_scanner import get_shiny_hunters_findings

        print("\nScanning for ShinyHunters-class exposure surfaces...")
        shiny_raw = get_shiny_hunters_findings(root)
        shiny = apply_filters([normalize_shiny(f) for f in shiny_raw], filt_str)
        if shiny:
            print_blue_team_findings(shiny, "ShinyHunters strategy vector findings")
            all_findings.extend(shiny)
        else:
            print("No ShinyHunters-class local misconfig signals (or filtered).")

    # --- ransomware-class ---
    if "ransomware-class" in mods:
        from scanner.ransomware_class_scanner import scan_ransomware_class

        print("\nScanning for ransomware-CLASS behavior patterns (safe text rules)...")
        rw = [finding_to_filter_dict(f) for f in scan_ransomware_class(root)]
        rw = apply_filters(rw, filt_str)
        if rw:
            print_blue_team_findings(rw, "Ransomware-class findings")
            all_findings.extend(rw)
        else:
            print("No ransomware-class patterns in scan root.")

    # --- dns-class ---
    if "dns-class" in mods:
        from scanner.dns_class_scanner import scan_dns_class

        print("\nScanning for DNS-CLASS abuse / misconfig patterns...")
        dns = [finding_to_filter_dict(f) for f in scan_dns_class(root, include_system=False)]
        dns = apply_filters(dns, filt_str)
        if dns:
            print_blue_team_findings(dns, "DNS-class findings")
            all_findings.extend(dns)
        else:
            print("No DNS-class patterns in scan root.")

    # --- go guard ---
    if "go-guard" in mods:
        gof = apply_filters(_run_go_guard(root), filt_str)
        if gof:
            print_blue_team_findings(gof, "Go guard findings")
            all_findings.extend(gof)

    print_summary(all_findings)
    print("\nsentinel :: done")

    if args.json:
        print(json.dumps(all_findings, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
