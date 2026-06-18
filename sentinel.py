import argparse
import sys

from scanner.package_scanner import get_installed_packages
from scanner.github_actions_scanner import get_github_action_findings
from scanner.shiny_hunters_scanner import get_shiny_hunters_findings
from vulnerability.cve_client import fetch_recent_cves
from vulnerability.historical import get_historical_cves, print_historical_findings
from correlator.matcher import match_packages_to_cves
from reporting.reporter import print_findings
from utils.filters import compile_filter, apply_filters, add_category_and_tags


def _run_go_guard(root: str = ".") -> None:
    """Invoke the Go hardening layer (sentinel-guard) if built."""
    import json
    import os
    import subprocess
    from pathlib import Path

    here = Path(__file__).resolve().parent
    candidates = [
        here / "bin" / "sentinel-guard",
        here / "sentinel-guard",
    ]
    binary = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if binary is None:
        print("\n[Go guard] Binary not found. Build with:")
        print("  cd projects/sentinel && go build -o bin/sentinel-guard ./cmd/sentinel-guard")
        return

    print("\nRunning Go hardening layer (sentinel-guard: path-safe GHA + secrets scan)...")
    proc = subprocess.run(
        [str(binary), "-root", root, "-mode", "all", "-json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(f"[Go guard] exited {proc.returncode}: {proc.stderr.strip()}")
        return

    try:
        findings = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print("[Go guard] invalid JSON output")
        return

    if not findings:
        print("Go guard: no additional hardening findings (clean).")
        return

    print(f"\n=== Go Guard Findings ({len(findings)} — path-hardened, YAML-aware) ===")
    for f in findings:
        print(f"\n[{f.get('severity', 'UNKNOWN')}] {f.get('id', '')} ({f.get('category', '')})")
        if f.get("file"):
            print(f"  File: {f['file']}")
        if f.get("signal"):
            print(f"  Signal: {f['signal']}")
        print(f"  {f.get('description', '')}")
        if f.get("recommendation"):
            print(f"  Recommendation: {f['recommendation']}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="sentinel - local security auditor (what actually matters)",
        epilog="Wireshark-style filters: --filter 'severity=CRITICAL category~shiny|historical'  "
               "or  --filter 'id~SHINY'  or  --filter 'severity>=HIGH'"
    )
    p.add_argument("--go-guard", action="store_true",
                   help="Also run the Go hardening layer (sentinel-guard): path-safe scans + secrets")
    p.add_argument("--filter", "-f", default="", metavar="EXPR",
                   help="Wireshark-like display filter. Examples: "
                        "'severity=CRITICAL', 'id~SHINY', 'category~shiny|historical severity>=HIGH', "
                        "'vector=AURA tags~saas'")
    p.add_argument("--severity", help="Shortcut: only show these severities (comma separated, e.g. CRITICAL,HIGH)")
    p.add_argument("--category", help="Shortcut: only these categories (comma separated: live,historical,gha,shiny)")
    p.add_argument("--shiny-only", action="store_true", help="Only show ShinyHunters related findings (historical + scanner)")
    p.add_argument("--high-only", action="store_true", help="Only CRITICAL and HIGH severity items")
    p.add_argument("--list-filters", action="store_true", help="Show example Wireshark-style filters and exit")
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


def normalize_live_cve(f):
    d = {"id": f.cve_id, "severity": f.severity, "package": f.package, "version": f.version}
    return add_category_and_tags(d, "live", ["cve", "package"])


def normalize_historical(h):
    d = dict(h)
    d.setdefault("id", h.get("id"))
    d.setdefault("severity", h.get("severity", "UNKNOWN"))
    d.setdefault("description", h.get("description", ""))
    tags = ["classic"]
    if h.get("id", "").startswith("AI-GHA"):
        tags.append("ai-gha")
    if h.get("id", "").startswith("SHINY"):
        tags.append("shiny")
        tags.append("saas")  # most of them are
    return add_category_and_tags(d, "historical", tags)


def normalize_gha(f):
    d = {
        "id": f.get("workflow", ""),
        "severity": f.get("severity", "HIGH"),
        "description": " | ".join(f.get("risks", [])),
        "recommendation": f.get("recommendation", ""),
    }
    return add_category_and_tags(d, "gha", ["github-actions", "prompt-injection", "supply-chain"])


def normalize_shiny(f):
    d = {
        "id": f.get("vector", ""),
        "severity": f.get("severity", "HIGH"),
        "file": f.get("file", ""),
        "signal": f.get("signal", ""),
        "description": f.get("recommendation", ""),
    }
    tags = ["shiny", "saas"]
    if "AURA" in d["id"]:
        tags.append("guest-access")
    if "PEOPLESOFT" in d["id"]:
        tags.append("erp")
    if "MFA" in d["id"] or "VISH" in d["id"]:
        tags.append("social-engineering")
    return add_category_and_tags(d, "shiny", tags)


def main(argv=None):
    args = parse_args(argv)

    if args.list_filters:
        print("""Wireshark-style filters for sentinel (use with --filter or -f):

  Basic:
    --filter 'severity=CRITICAL'
    --filter 'severity=HIGH,CRITICAL'
    --filter 'id~SHINY'
    --filter 'category=shiny'
    --filter 'category~shiny|historical'

  Combined (AND):
    --filter 'severity>=HIGH category~shiny|historical'
    --filter 'id~AURA|PEOPLESOFT severity=CRITICAL'

  Other useful ones:
    --filter 'tags~saas,guest'
    --filter 'vector=AURA'
    --shiny-only                 (shorthand for shiny-related)
    --high-only                  (CRITICAL + HIGH)
    --severity CRITICAL,HIGH

  You can also combine CLI flags:
    sentinel.py --shiny-only --severity CRITICAL

  The filter is applied to live CVEs, historical (classics + AI-GHA + SHINY-*), GHA, and the Shiny scanner results.
  Sections with zero matches after filtering are omitted.
""")
        return

    filt_str = build_filter_string(args)
    pred = compile_filter(filt_str)

    print("Scanning system packages...")

    packages = get_installed_packages()
    print("Packages discovered:", len(packages))

    print("\nDownloading CVE intelligence (live recent, last ~3 years)...")
    cves = fetch_recent_cves(50)
    print("CVE records retrieved:", len(cves))

    print("\nRunning vulnerability correlation (live)...")
    raw_live = match_packages_to_cves(packages, cves)
    live_findings = [normalize_live_cve(f) for f in raw_live]
    live_findings = apply_filters(live_findings, filt_str)

    if live_findings:
        # Convert back to dataclass shape for the existing reporter (or just print simply)
        print("\nVulnerability Findings (actionable only):")
        for f in live_findings:
            print(f"[{f['severity']}] {f.get('package')} {f.get('version')} → {f['id']}")
        if len(raw_live) > len(live_findings):
            print(f"  ({len(raw_live) - len(live_findings)} items filtered by --filter / flags)")
    else:
        if filt_str:
            print("No live CVE matches after applying filter.")
        else:
            print("No live CVE matches with usable severity on installed packages (good).")

    # === Historical (classics + AI + ShinyHunters vectors) ===
    print("\nLoading local historical/classic attack knowledge base...")
    historical_raw = get_historical_cves(50)
    hist_norm = [normalize_historical(h) for h in historical_raw]
    hist_filtered_norm = apply_filters(hist_norm, filt_str)

    if hist_filtered_norm:
        # Map back to the original rich dicts (they have attack_chain, notes, etc.)
        kept_ids = {h["id"] for h in hist_filtered_norm}
        kept_historical = [h for h in historical_raw if h.get("id") in kept_ids]
        # Keep a nice mix but limited
        non_shiny = [h for h in kept_historical if not str(h.get("id","")).startswith("SHINY-")][:6]
        shiny_ones = [h for h in kept_historical if str(h.get("id","")).startswith("SHINY-")]
        print_historical_findings(non_shiny + shiny_ones)
    else:
        if filt_str:
            print("(historical section fully filtered by --filter)")

    # === GitHub Actions ===
    print("\nScanning local GitHub Actions workflows for AI agent / prompt injection risks...")
    gha_raw = get_github_action_findings(".")
    gha_norm = [normalize_gha(f) for f in gha_raw]
    gha_filtered_norm = apply_filters(gha_norm, filt_str)
    kept_gha = [g for g in gha_raw if any(n["id"] == g.get("workflow") for n in gha_filtered_norm)]

    if kept_gha:
        print("\n=== GitHub Actions / AI Risk Findings (prompt injection & supply chain vectors) ===")
        for orig in kept_gha:
            print(f"\n[{orig.get('severity','HIGH')}] {orig.get('workflow')}")
            for r in orig.get("risks", []):
                print(f"  - {r}")
            print(f"  Recommendation: {orig.get('recommendation','')}")
    else:
        if filt_str or gha_raw:
            print("No GitHub Actions / AI agent findings after filter.")
        else:
            print("No risky GitHub Actions / AI agent workflows detected in this tree.")

    # === ShinyHunters dedicated scanner ===
    print("\nScanning for ShinyHunters strategy attack vectors (Aura/guest, PeopleSoft, MFA-bypass, SaaS exposure, supply)...")
    shiny_raw = get_shiny_hunters_findings(".")
    shiny_norm = [normalize_shiny(f) for f in shiny_raw]
    shiny_filtered_norm = apply_filters(shiny_norm, filt_str)
    kept_shiny = [s for s in shiny_raw if any(n["id"] == s.get("vector") for n in shiny_filtered_norm)]

    if kept_shiny:
        print("\n=== ShinyHunters Strategy Attack Vector Findings (local misconfig / exposure surface) ===")
        for orig in kept_shiny:
            print(f"\n[{orig.get('severity')}] {orig.get('vector')} @ {orig.get('file')}")
            print(f"  Signal: {orig.get('signal')}")
            if orig.get("snippet"):
                print(f"  Context: ...{orig.get('snippet')}...")
            print(f"  Recommendation: {orig.get('recommendation')}")
        print("\n[Sentinel note] These are the exact patterns ShinyHunters are actively exploiting right now (2026 campaigns). "
              "Prioritize hardening any hits before they mass-scan you.")
    else:
        if filt_str:
            print("(ShinyHunters scanner section filtered out by --filter)")
        elif shiny_raw:
            print("No obvious ShinyHunters targetable misconfigs (Aura guest, PeopleSoft, broad guest/MFA exceptions, high-value SaaS) detected in this tree. Good posture signal.")
        else:
            print("No obvious ShinyHunters targetable misconfigs ... Good posture signal.")

    if args.go_guard:
        _run_go_guard(".")


if __name__ == "__main__":
    main()
