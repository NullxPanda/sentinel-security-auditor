from scanner.package_scanner import get_installed_packages
from scanner.github_actions_scanner import get_github_action_findings
from vulnerability.cve_client import fetch_recent_cves
from vulnerability.historical import get_historical_cves, print_historical_findings
from correlator.matcher import match_packages_to_cves
from reporting.reporter import print_findings


def main():

    print("Scanning system packages...")

    packages = get_installed_packages()

    print("Packages discovered:", len(packages))


    print("\nDownloading CVE intelligence (live recent)...")

    cves = fetch_recent_cves(50)

    print("CVE records retrieved:", len(cves))


    print("\nRunning vulnerability correlation (live)...")

    findings = match_packages_to_cves(packages, cves)

    print_findings(findings)


    # === New: also surface classic/old CVEs with real attack chains + payloads ===
    # These live in vulnerability/historical.py and are always available offline.
    # Perfect for the "old-cve with chained attack methods + wicked payload" cases.
    print("\nLoading local historical/classic attack knowledge base...")
    historical = get_historical_cves(20)
    # For demo we just pretty-print the enriched historical ones.
    # In a real run you could merge them into the findings list or run a separate correlator.
    print_historical_findings(historical[:5])

    # === GitHub Actions / AI Agent risk scan (new in 2026) ===
    # Defends against the Claude Code GitHub Action prompt injection / repo hijack class of flaws
    # (malicious issue -> untrusted trigger -> prompt injection -> token exfil -> write access / supply chain poison).
    # See https://thehackernews.com/2026/06/claude-code-github-action-flaw-let-one.html
    # and historical patterns AI-GHA-2026-*
    print("\nScanning local GitHub Actions workflows for AI agent / prompt injection risks...")
    gha_findings = get_github_action_findings(".")
    if gha_findings:
        print("\n=== GitHub Actions / AI Risk Findings (prompt injection & supply chain vectors) ===")
        for f in gha_findings:
            print(f"\n[{f['severity']}] {f['workflow']}")
            for r in f['risks']:
                print(f"  - {r}")
            print(f"  Recommendation: {f['recommendation']}")
    else:
        print("No risky GitHub Actions / AI agent workflows detected in this tree.")


if __name__ == "__main__":
    main()
