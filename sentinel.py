#!/usr/bin/env python3
"""
Sentinel — local-first blue-team signal reducer.

  sense → match known-ugly classes → prioritize → recommend contain/patch

This file is the ORCHESTRATOR only.
  - Detection logic lives in scanner/*
  - Shape translation lives in correlator/normalize.py
  - Operator output lives in reporting/reporter.py
  - Doctrine lives in BACKBONE.md

We build this together — if you change module order or flags, leave a # comment
so the other half of the duo knows why.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Shared normalizers (single dialect for every module).
# Do NOT invent a third shape in this file — convert in correlator/normalize.py.
# ---------------------------------------------------------------------------
from correlator.normalize import (
    finding_to_filter_dict,
    normalize_gha,
    normalize_go_guard,
    normalize_historical,
    normalize_live_cve,
    normalize_shiny,
)
from reporting.reporter import print_blue_team_findings, print_summary
from utils.filters import apply_filters


def _run_go_guard(root: str = ".") -> List[Dict[str, Any]]:
    """
    Optional Go hardening layer (path-safe GHA + secrets).

    Binary is gitignored under bin/ — build when you want this path:
      go build -o bin/sentinel-guard ./cmd/sentinel-guard

    Missing binary is NOT a failure; we stay Python-first on the Surface.
    """
    here = Path(__file__).resolve().parent
    # Prefer bin/ (gitignored) then a repo-root binary leftover from experiments
    candidates = [
        here / "bin" / "sentinel-guard",
        here / "sentinel-guard",
    ]
    binary = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if binary is None:
        # Team-readable skip: offline demos should not look "broken"
        print("\n[Go guard] skipped — binary not built yet (optional Phase 0 path).")
        print("  build: go build -o bin/sentinel-guard ./cmd/sentinel-guard")
        print("  then:  python3 sentinel.py --modules go-guard --root .")
        return []

    print("\nRunning Go hardening layer (sentinel-guard)...")
    # -json keeps stdout machine-parseable; stderr is human noise on failure
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
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print("[Go guard] invalid JSON output")
        return []

    # Same Action/Do NOT boxes as Python modules (normalize, don't reprint raw)
    return [normalize_go_guard(f) for f in raw]


def parse_args(argv=None):
    # CLI surface is part of the product — keep --demo stranger-proof.
    p = argparse.ArgumentParser(
        description=(
            "Sentinel — local-first blue-team signal reducer "
            "(sense → match known-ugly classes → prioritize → recommend contain/patch)"
        ),
        epilog=(
            "Together-mode demo: "
            "python3 sentinel.py --offline --modules ransomware-class,dns-class,gha "
            "--root test-fixtures"
        ),
    )
    p.add_argument("--root", default=".", help="Scan root directory (default: .)")
    p.add_argument(
        "--offline",
        action="store_true",
        # Phase 0/1 default for demos: no NVD, no "is the network up?" drama
        help="Skip live NVD/CVE network calls (Phase 0/1 default for demos)",
    )
    p.add_argument(
        "--modules",
        default="all",
        metavar="LIST",
        help=(
            "Comma list: packages,historical,gha,shiny,ransomware-class,dns-class,go-guard "
            "or 'all'"
        ),
    )
    # Legacy flags kept so old muscle memory / scripts still work
    p.add_argument("--no-packages", action="store_true", help="Skip package inventory")
    p.add_argument("--no-historical", action="store_true", help="Skip historical knowledge base")
    p.add_argument(
        "--go-guard",
        action="store_true",
        help="Include go-guard module (same as --modules ... go-guard)",
    )
    p.add_argument("--filter", "-f", default="", metavar="EXPR", help="Wireshark-like filter")
    p.add_argument("--severity", help="Shortcut severities, e.g. CRITICAL,HIGH")
    p.add_argument("--category", help="Shortcut categories")
    p.add_argument("--shiny-only", action="store_true")
    p.add_argument("--high-only", action="store_true")
    p.add_argument("--list-filters", action="store_true")
    p.add_argument(
        "--json",
        action="store_true",
        # Human report always prints; --json is extra for piping / receipts
        help="Also dump full findings JSON after human report (for piping)",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        # One command a teammate can run without reading our brains
        help="Stranger-proof offline demo (fixtures + class modules). Ignores network.",
    )
    return p.parse_args(argv)


def build_filter_string(args) -> str:
    # Compose one filter expr from flags; utils.filters owns the grammar.
    parts = []
    if args.filter:
        parts.append(args.filter)
    if args.severity:
        # Comma → OR via regex-ish ~= (see utils.filters)
        parts.append("severity~=" + args.severity.replace(",", "|"))
    if args.category:
        parts.append("category~=" + args.category.replace(",", "|"))
    if args.shiny_only:
        parts.append("category~shiny|historical id~SHINY")
    if args.high_only:
        parts.append("severity>=HIGH")
    return " ".join(parts)


def _wanted_modules(args) -> set:
    """
    Resolve which modules run.

    Offline + all → drop live packages (needs NVD). Explicit packages in --modules
    still allowed if someone is testing inventory only later.
    """
    raw = (args.modules or "all").strip().lower()
    if raw == "all":
        # Default Phase 0→1 set: offline-capable modules first
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

    # Explicit opt-outs win over "all"
    if args.no_packages:
        mods.discard("packages")
    if args.no_historical:
        mods.discard("historical")

    if args.offline or args.demo:
        # Live CVE path needs network — keep offline honest
        if raw == "all" or args.demo:
            mods.discard("packages")
        elif "packages" not in raw:
            # Explicit module list that omitted packages: stay offline-clean
            mods.discard("packages")

    if args.go_guard:
        # Flag is additive (same as listing go-guard in --modules)
        mods.add("go-guard")
    return mods


def main(argv=None):
    args = parse_args(argv)

    # --demo = one command a teammate can run without reading our brains
    if args.demo:
        args.offline = True
        here = Path(__file__).resolve().parent
        # Class rules need fixtures; historical is always local (no net)
        args.root = str(here / "test-fixtures")
        # Include risky workflow fixture parent for GHA? fixtures dir has ransomware+dns;
        # also scan repo root workflows by adding gha with root=.
        # Split: class modules on fixtures, gha on repo root — for simplicity demo
        # scans fixtures for class rules AND repo for gha if present.
        # Demo set is intentionally small + deterministic (no shiny noise on fixtures).
        args.modules = "ransomware-class,dns-class,historical"

    if args.list_filters:
        print(
            """Wireshark-style filters (use with --filter / -f):

  --filter 'severity=CRITICAL'
  --filter 'category=ransomware-class'
  --filter 'category~dns-class|gha severity>=HIGH'
  --filter 'id~RW-CLASS|DNS-CLASS|GHA-RISK|SHINY'

Offline / together demos:
  python3 sentinel.py --demo
  python3 scripts/demo_cold.sh
  python3 sentinel.py --offline --modules ransomware-class,dns-class,gha --root test-fixtures
"""
        )
        return 0

    root = args.root
    mods = _wanted_modules(args)
    filt_str = build_filter_string(args)
    # Accumulators are dicts (filter layer + reporter both accept dicts)
    all_findings: List[Dict[str, Any]] = []

    # Boot banner: boring, greppable, good for session receipts
    print("sentinel :: boot")
    print("product : local-first blue-team signal reducer")
    print("doctrine: BACKBONE.md (we build this together)")
    print(f"root    : {root}")
    print(f"modules : {', '.join(sorted(mods)) or '(none)'}")
    print(f"mode    : {'offline' if (args.offline or args.demo) else 'online-capable'}")
    print("-" * 40)

    # -----------------------------------------------------------------------
    # Module order matters for human reading (online first if present, then
    # offline gold, then class detectors). Change order only with a reason.
    # -----------------------------------------------------------------------

    # --- packages + live CVE (online only) ---
    if "packages" in mods and not args.offline and not args.demo:
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
        # Always normalize before filter/report so Action/Do NOT exist
        live = apply_filters([normalize_live_cve(f) for f in raw_live], filt_str)
        if live:
            print_blue_team_findings(live, "Live package / CVE findings")
            all_findings.extend(live)
        else:
            print("No live CVE matches after filter (or none actionable).")
    elif "packages" in mods:
        print("Skipping live package/CVE correlation (offline/demo mode).")

    # --- historical knowledge (offline gold) ---
    if "historical" in mods:
        from vulnerability.historical import get_historical_cves

        print("\nLoading local historical attack knowledge base...")
        historical_raw = get_historical_cves(50)
        hist = apply_filters([normalize_historical(h) for h in historical_raw], filt_str)
        if hist:
            # Bound noise: classics first, then campaign vectors
            # (full list is still available via --json or higher limits later)
            non_shiny = [h for h in hist if not str(h.get("id", "")).startswith("SHINY-")][:6]
            shiny_ones = [h for h in hist if str(h.get("id", "")).startswith("SHINY-")][:8]
            bounded = non_shiny + shiny_ones
            print_blue_team_findings(bounded, "Historical / classic knowledge (local)")
            all_findings.extend(bounded)
        else:
            print("(historical section empty or filtered)")

    # --- GitHub Actions ---
    if "gha" in mods:
        from scanner.github_actions_scanner import get_github_action_findings

        print("\nScanning GitHub Actions for AI agent / prompt-injection risks...")
        # For --demo we still want the risky workflow under repo .github if root is fixtures.
        # So: if demo, also scan package root once.
        gha_roots = [root]
        if args.demo:
            # Fixtures root alone misses .github/workflows in the real repo
            gha_roots.append(str(Path(__file__).resolve().parent))
        gha_acc: List[Dict[str, Any]] = []
        seen_wf = set()
        for gr in gha_roots:
            for raw in get_github_action_findings(gr):
                key = raw.get("workflow") or raw.get("file")
                if key in seen_wf:
                    continue  # de-dupe when demo scans fixtures + repo
                seen_wf.add(key)
                gha_acc.append(normalize_gha(raw))
        gha = apply_filters(gha_acc, filt_str)
        if gha:
            print_blue_team_findings(gha, "GitHub Actions / AI risk findings")
            all_findings.extend(gha)
        else:
            print("No GHA / AI agent findings after filter (or none).")

    # --- ShinyHunters-class surface ---
    if "shiny" in mods:
        from scanner.shiny_hunters_scanner import get_shiny_hunters_findings

        print("\nScanning for ShinyHunters-class exposure surfaces...")
        shiny = apply_filters(
            [normalize_shiny(f) for f in get_shiny_hunters_findings(root)],
            filt_str,
        )
        if shiny:
            print_blue_team_findings(shiny, "ShinyHunters strategy vector findings")
            all_findings.extend(shiny)
        else:
            print("No ShinyHunters-class local misconfig signals (or filtered).")

    # --- ransomware-class ---
    if "ransomware-class" in mods:
        from scanner.ransomware_class_scanner import scan_ransomware_class

        print("\nScanning for ransomware-CLASS patterns (safe text rules)...")
        # Class scanners already return Finding; finding_to_filter_dict for filters
        rw = apply_filters(
            [finding_to_filter_dict(f) for f in scan_ransomware_class(root)],
            filt_str,
        )
        if rw:
            print_blue_team_findings(rw, "Ransomware-class findings")
            all_findings.extend(rw)
        else:
            print("No ransomware-class patterns in scan root.")

    # --- dns-class ---
    if "dns-class" in mods:
        from scanner.dns_class_scanner import scan_dns_class

        print("\nScanning for DNS-CLASS abuse / misconfig patterns...")
        # include_system=False: demos stay deterministic on any machine
        dns = apply_filters(
            [finding_to_filter_dict(f) for f in scan_dns_class(root, include_system=False)],
            filt_str,
        )
        if dns:
            print_blue_team_findings(dns, "DNS-class findings")
            all_findings.extend(dns)
        else:
            print("No DNS-class patterns in scan root.")

    # --- go guard (optional) ---
    if "go-guard" in mods:
        gof = apply_filters(_run_go_guard(root), filt_str)
        if gof:
            print_blue_team_findings(gof, "Go guard findings")
            all_findings.extend(gof)

    # Summary always last (screenshot-friendly for CHALLENGE receipts)
    print_summary(all_findings)
    print("\nsentinel :: done  (see BACKBONE.md if you're new here)")

    if args.json:
        print(json.dumps(all_findings, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
