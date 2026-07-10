"""
ShinyHunters Strategy Attack Vector Scanner for Sentinel.

Implements detection of local indicators that map directly to ShinyHunters
(UNC6040/Bling Libra) observed tactics:
- Public SaaS / Experience Cloud / Aura exposure (guest profile abuse)
- References to Oracle PeopleSoft or similar legacy portals
- Broad/guest/unauthenticated access patterns in config, IaC, docs, workflows
- Third-party vendor / supply chain hooks that have been used in their campaigns
- MFA / SSO / "no MFA" comments or risky patterns in local code

This is the "strategy attack vector" addition requested during device scan
while a Brave window was open on "ShinyHunters Exploits Oracle PeopleSoft Zero-Day..."

Design: fast (stdlib glob + Path + substring on lower text), readable,
actionable recommendations that mirror the mitigations from threat intel.
No new runtime dependencies. Complements the historical.py SHINY-* entries
and the GitHub Actions scanner (supply chain angle).

Run via get_shiny_hunters_findings(".") from the main sentinel flow.
"""

from pathlib import Path
from typing import List, Dict, Any
import glob


# High-signal keywords for their primary current vectors.
# Kept minimal to reduce noise while catching real exposure surface.
AURA_SALESFORCE_SIGNS = [
    "sfsites/aura",
    "/s/sfsites",
    "aura inspector",
    "experience cloud",
    "guest user",
    "guest profile",
    "public read",
    "without sharing",
    "unauthenticated",
    "allow guest",
    "salesforce aura",
]

PEOPLESOFT_SIGNS = [
    "peoplesoft",
    "oracle peoplesoft",
    "psft",
    "cve-2026-35273",  # the one referenced in the research tab
]

BROAD_ACCESS_SIGNS = [
    'guest":',
    '"public": "read',
    "read:*",
    "unauth",
    "no auth",
    "bypass mfa",
    "mfa exception",
    "device enrollment",
    "breakglass",
]

VENDOR_SUPPLY_SIGNS = [
    "context.ai",
    "anodot",
    "snowflake",
    "mixpanel",
    "instructure",
    "canvas lms",
]

MFA_SSO_DOC_SIGNS = [
    "mfa required",
    "phishing resistant",
    "number matching",
    "webauthn",
    "passkey",
    "no-mfa",
    "mfa disabled for",
    "sso exception",
]


def _scan_files(root: Path, patterns: List[str], exts: List[str]) -> List[Dict[str, Any]]:
    """Fast scan: glob + lower content contains. Returns list of hits with context snippet."""
    hits: List[Dict[str, Any]] = []
    for ext in exts:
        for p in root.rglob(f"*{ext}"):
            # Skip obvious noise (node_modules, .git, venv, __pycache__, target, etc.)
            if any(skip in p.parts for skip in (".git", "node_modules", "__pycache__", "venv", ".venv", "target", "dist", "build")):
                continue
            # Do not self-flag the sentinel project's own docs/README when they describe the vectors (educational content only)
            sp = str(p).lower()
            if "sentinel" in sp and any(x in sp for x in ("readme", "historical", "shiny")):
                continue
            try:
                text = p.read_text(errors="ignore").lower()
            except Exception:
                continue
            for sig in patterns:
                if sig in text:
                    # tiny context
                    idx = text.find(sig)
                    snippet = text[max(0, idx - 30): idx + 80].replace("\n", " ").strip()
                    hits.append({
                        "file": str(p),
                        "signal": sig,
                        "snippet": snippet[:200],
                    })
                    break  # one hit per file is enough for this scanner
    return hits


def scan_for_shiny_hunters_vectors(root: str = ".") -> List[Dict[str, Any]]:
    """
    Main scanner. Returns structured findings with severity + concrete recs.
    Each finding is one local file exhibiting a pattern that ShinyHunters love to hunt.
    """
    rootp = Path(root).resolve()
    findings: List[Dict[str, Any]] = []

    # 1. Salesforce Aura / Experience Cloud guest exposure surface
    aura_hits = _scan_files(rootp, AURA_SALESFORCE_SIGNS, [".yml", ".yaml", ".json", ".xml", ".md", ".txt", ".js", ".ts"])
    for h in aura_hits:
        findings.append({
            "vector": "SHINY-AURA-GUEST",
            "severity": "CRITICAL",
            "file": h["file"],
            "signal": h["signal"],
            "snippet": h["snippet"],
            "recommendation": "Harden or remove guest user profiles on any public Experience Cloud sites. Audit /s/sfsites/aura exposure. Enforce auth for all sensitive objects. See historical SHINY-2026-AURA.",
        })

    # 2. PeopleSoft / Oracle ERP portals (current 0-day campaign vector)
    ps_hits = _scan_files(rootp, PEOPLESOFT_SIGNS, [".yml", ".yaml", ".json", ".md", ".txt", ".properties", ".xml"])
    for h in ps_hits:
        findings.append({
            "vector": "SHINY-PEOPLESOFT",
            "severity": "CRITICAL",
            "file": h["file"],
            "signal": h["signal"],
            "snippet": h["snippet"],
            "recommendation": "Treat any PeopleSoft/Oracle ERP references as high-risk. Accelerate patches (watch CVE-2026-35273 chain), segment access, add WAF/behavioral monitoring. Assume public portals are being mass-scanned. See SHINY-2026-PEOPLESOFT.",
        })

    # 3. Broad guest / unauth / MFA-bypass patterns in any config or docs
    broad_hits = _scan_files(rootp, BROAD_ACCESS_SIGNS, [".yml", ".yaml", ".json", ".md", ".txt", ".conf", ".ini"])
    for h in broad_hits:
        findings.append({
            "vector": "SHINY-BROAD-GUEST-OR-MFA-BYPASS",
            "severity": "HIGH",
            "file": h["file"],
            "signal": h["signal"],
            "snippet": h["snippet"],
            "recommendation": "Remove 'guest read', 'public:*', 'no auth', 'mfa exception', or 'breakglass' patterns. Enforce least privilege + phishing-resistant MFA (number matching / passkeys) everywhere. Document required MFA in IaC.",
        })

    # 4. High-value SaaS vendors + supply chain hooks they have used (Snowflake, Instructure, etc.)
    vendor_hits = _scan_files(rootp, VENDOR_SUPPLY_SIGNS, [".json", ".yml", ".yaml", ".toml", ".md", "requirements*.txt", "package*.json"])
    for h in vendor_hits:
        findings.append({
            "vector": "SHINY-VENDOR-SUPPLY",
            "severity": "HIGH",
            "file": h["file"],
            "signal": h["signal"],
            "snippet": h["snippet"],
            "recommendation": "For any Snowflake/SaaS/Instructure/Canvas etc. integration: enforce MFA + short sessions + anomaly alerts + no long-lived tokens in code. Review 3rd-party vendor risk (they have used supply chain like context.ai). See SHINY-2026-NO-MFA-SAAS + SHINY-2026-MFA-VISH.",
        })

    # 5. Docs/comments around MFA/SSO that indicate weak posture (inverse of good signals)
    mfa_hits = _scan_files(rootp, MFA_SSO_DOC_SIGNS, [".md", ".txt", ".yml", ".yaml", ".rst"])
    for h in mfa_hits:
        # Only flag the risky ones (the "bypass" / "exception" / "no-mfa" ones already caught above; here we catch positive "mfa required" as info but skip to avoid noise)
        if any(bad in h["signal"] for bad in ["bypass", "exception", "no-mfa", "disabled"]):
            findings.append({
                "vector": "SHINY-WEAK-MFA-DOC",
                "severity": "HIGH",
                "file": h["file"],
                "signal": h["signal"],
                "snippet": h["snippet"],
                "recommendation": "Update docs/config to require phishing-resistant MFA. Remove any 'MFA disabled' or exception language. Align with the vishing defense guidance from Mandiant/Google 2026 reports.",
            })

    return findings


def get_shiny_hunters_findings(root: str = ".") -> List[Dict[str, Any]]:
    """Public entry point used by sentinel main."""
    return scan_for_shiny_hunters_vectors(root)
