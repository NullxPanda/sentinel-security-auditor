"""
normalize.py — SHARED translation layer (we build this together).

Why this file exists
--------------------
Every scanner used to speak a slightly different dialect (workflow vs vector vs
cve_id). Operators need ONE shape:

  id / category / severity / description / asset / signal / evidence /
  action / do_not / tags

If you add a new scanner, convert here (or return Finding directly from the
scanner). Do not invent a third shape in sentinel.py — that is how mess returns.

Team note: leave # comments when you change rules. Future-us is part of the duo.
Operator-facing Action / Do NOT strings live in the maps below — not as code
noise inside scanners' detection needles.
"""

from __future__ import annotations

from typing import Any, Dict, List

from models.data_models import Finding
from utils.filters import add_category_and_tags

# ---------------------------------------------------------------------------
# Historical knowledge → blue-team actions
# Map campaign / classic IDs to concrete 5-minute moves + anti-patterns.
# These are *ours* — curated, not AI-dumped. Edit when intel updates.
#
# Keys must match vulnerability/historical.py "id" fields.
# When you add a HISTORICAL_ATTACKS row, add a playbook entry here too
# (or the defaults below kick in — fine, but less useful for operators).
# ---------------------------------------------------------------------------
_HISTORICAL_ACTIONS: Dict[str, Dict[str, str]] = {
    # A-audit: older classics need playbooks too (defaults are honest but thin)
    "CVE-1999-0095": {
        "action": "Confirm no internet-facing sendmail/debug SMTP; upgrade MTA; block port 25/465/587 from untrusted nets if unused.",
        "do_not": "Do not leave 'debug' or old sendmail on edge hosts for nostalgia.",
    },
    "CVE-2014-6271": {
        "action": "Patch bash; inventory CGI/SSH ForceCommand surfaces; block untrusted env injection paths.",
        "do_not": "Do not leave CGI + old bash on internet edges 'because it still works'.",
    },
    "CVE-2014-0160": {
        "action": "Confirm OpenSSL/service patch level; rotate keys/certs that could have been leaked; reissue long-lived tokens.",
        "do_not": "Do not only patch without key rotation if the host was exposed during the vulnerable window.",
    },
    "CVE-2017-5638": {
        "action": "Patch Struts; put WAF rules on Content-Type abuse; remove unused upload endpoints.",
        "do_not": "Do not leave debug error pages returning stack/OGNL detail to the internet.",
    },
    "CVE-2021-44228": {
        "action": "Upgrade Log4j; set log4j2.formatMsgNoLookups where applicable; block outbound LDAP/RMI from app tiers.",
        "do_not": "Do not assume 'we don't log User-Agent' — any logged user string can be a vector.",
    },
    "AI-GHA-2026-001": {
        "action": "Pin claude-code-action >=1.0.94; require human/write-access actors; never pipe raw issue bodies into agents with write tokens.",
        "do_not": "Do not allow [bot] wildcards or issues: write on untrusted triggers.",
    },
    "AI-GHA-2026-002": {
        "action": "Remove allowed_non_write_users: '*'; least-privilege GITHUB_TOKEN; trusted-only AI triage.",
        "do_not": "Do not copy-paste AI workflow examples without threat-modeling triggers.",
    },
    "SHINY-2026-AURA": {
        "action": "Lock down Experience Cloud guest profiles; remove object perms from guest; monitor /s/sfsites/aura anonymously.",
        "do_not": "Do not grant guest 'view all' / broad object read for convenience.",
    },
    "SHINY-2026-PEOPLESOFT": {
        "action": "Patch PeopleSoft ASAP; segment HR portals; put WAF + auth in front; assume exposure until verified.",
        "do_not": "Do not leave PeopleSoft on the open internet without compensating controls.",
    },
    "SHINY-2026-MFA-VISH": {
        "action": "Enforce number-matching / phishing-resistant MFA; train on vishing; alert on new device enrollment.",
        "do_not": "Do not approve unexpected MFA pushes or enroll 'IT audit' devices on a phone call.",
    },
    "SHINY-2026-NO-MFA-SAAS": {
        "action": "Force MFA on all SaaS (Snowflake etc.); kill long-lived passwords; review sessions after stealer alerts.",
        "do_not": "Do not leave service accounts or human users without MFA on data warehouses.",
    },
}

# Safe defaults when an intel row has no explicit playbook yet
_DEFAULT_HIST_ACTION = (
    "Validate whether this class touches your assets; patch or segment if exposed; document residual risk."
)
_DEFAULT_HIST_DO_NOT = (
    "Do not treat a knowledge-base hit as proof of live compromise — correlate to YOUR systems."
)


def finding_to_filter_dict(f: Finding) -> Dict[str, Any]:
    """Finding → dict the Wireshark-style filter layer already understands."""
    # add_category_and_tags ensures category/tags are filterable even if empty
    return add_category_and_tags(f.to_dict(), f.category, list(f.tags or []))


def normalize_live_cve(f) -> Dict[str, Any]:
    """Package×CVE hit from correlator.matcher → operator block."""
    # f is VulnerabilityFinding-like (attributes, not dict)
    d = {
        "id": f.cve_id,
        "severity": f.severity,
        "package": f.package,
        "version": f.version,
        "asset": f"{f.package}@{f.version}",
        "description": f"Installed package may be affected by {f.cve_id}",
        "signal": f.cve_id,
        "evidence": f"{f.package} {f.version}",
        # Generic playbook — live CVEs don't get per-id essays here
        "action": f"Patch or upgrade {f.package}; verify fixed version; restart service if needed.",
        "do_not": "Do not ignore CRITICAL/HIGH on internet-exposed services.",
        "recommendation": f"Patch {f.package}",
    }
    return add_category_and_tags(d, "live", ["cve", "package"])


def normalize_historical(h: Dict[str, Any]) -> Dict[str, Any]:
    """
    Local knowledge row → blue-team Finding dict.

    We keep attack_chain for humans who want depth, but the PRIMARY fields
    operators see first are action / do_not / evidence (via reporter).
    """
    hid = str(h.get("id") or "HIST")
    playbook = _HISTORICAL_ACTIONS.get(hid, {})

    # Prefer explicit fields on the row (so we can edit intel in historical.py)
    # then our map, then safe defaults.
    action = h.get("action") or playbook.get("action") or _DEFAULT_HIST_ACTION
    do_not = h.get("do_not") or playbook.get("do_not") or _DEFAULT_HIST_DO_NOT

    # Compact chain for evidence; full chain still on the dict for --json
    chain = h.get("attack_chain") or []
    chain_one_liner = " → ".join(chain[:4]) if chain else ""

    evidence_bits = []
    if h.get("example_payload"):
        evidence_bits.append(f"pattern: {h['example_payload']}")
    if chain_one_liner:
        evidence_bits.append(f"chain: {chain_one_liner}")
    # Truncate description fallback so the terminal stays readable
    evidence = " | ".join(evidence_bits) or (h.get("description") or "")[:160]

    products = h.get("affected_products") or []
    asset = ", ".join(products) if isinstance(products, list) else str(products)

    # Tag prefixes drive filters like --shiny-only / category~shiny
    tags = ["classic", "knowledge-base"]
    if hid.startswith("AI-GHA"):
        tags.append("ai-gha")
    if hid.startswith("SHINY"):
        tags.extend(["shiny", "saas"])

    d = {
        "id": hid,
        "severity": h.get("severity", "UNKNOWN"),
        "description": h.get("description", ""),
        "asset": asset or "knowledge-base",
        "signal": hid,
        "evidence": evidence,
        "action": action,
        "do_not": do_not,
        "recommendation": action,  # legacy field alias; reporter prefers action
        # Keep raw chain for --json consumers / future UI (reporter may ignore)
        "attack_chain": chain,
        "notes": h.get("notes", ""),
    }
    return add_category_and_tags(d, "historical", tags)


def normalize_gha(f: Dict[str, Any]) -> Dict[str, Any]:
    """GitHub Actions scanner raw dict → operator block."""
    risks = f.get("risks") or []
    workflow = f.get("workflow") or f.get("file") or "GHA"
    # Scanner may already set action/do_not (GHA_ACTION constants); keep fallbacks
    action = f.get("action") or f.get("recommendation") or (
        "Pin AI actions; restrict triggers to trusted actors; least-privilege tokens; "
        "never feed raw issue/PR bodies into agents with write access."
    )
    do_not = f.get("do_not") or (
        "Do not grant contents:write / issues:write to workflows that fire on untrusted issues "
        "or allow [bot]/* bypasses."
    )
    d = {
        "id": workflow if not str(workflow).endswith((".yml", ".yaml")) else f"GHA:{workflow}",
        "severity": f.get("severity", "HIGH"),
        # risks list is the "what fired" story for operators
        "description": " | ".join(risks) if risks else "GitHub Actions AI / supply-chain risk",
        "asset": workflow,
        "file": workflow,
        "signal": "github-actions-ai",
        "evidence": " | ".join(risks) if risks else workflow,
        "action": action,
        "do_not": do_not,
        "recommendation": action,
    }
    # Prefer a stable id for filters when workflow is a path
    d["id"] = f.get("id") or f"GHA-RISK:{workflow}"
    return add_category_and_tags(d, "gha", ["github-actions", "prompt-injection", "supply-chain"])


def normalize_shiny(f: Dict[str, Any]) -> Dict[str, Any]:
    """ShinyHunters-class local surface hit → operator block."""
    # Scanner uses "vector"; accept "id" too so we can evolve without thrash
    vid = f.get("vector") or f.get("id") or "SHINY"
    rec = f.get("recommendation") or f.get("action") or (
        "Harden guest/unauth surfaces; enforce MFA; review high-value SaaS sharing."
    )
    d = {
        "id": vid,
        "severity": f.get("severity", "HIGH"),
        "file": f.get("file", ""),
        "asset": f.get("file") or f.get("asset") or "",
        "signal": f.get("signal", ""),
        # snippet is local text evidence — not a payload to run
        "evidence": f.get("snippet") or f.get("evidence") or f.get("signal", ""),
        "description": f.get("description")
        or f.get("signal")
        or "ShinyHunters-class exposure surface in local tree",
        "action": rec,
        "do_not": f.get("do_not")
        or "Do not leave guest/public-read on CRM/ERP objects or skip MFA on data SaaS.",
        "recommendation": rec,
    }
    # Sub-tags help --filter without inventing new categories
    tags = ["shiny", "saas"]
    sid = str(d["id"]).upper()
    if "AURA" in sid:
        tags.append("guest-access")
    if "PEOPLESOFT" in sid:
        tags.append("erp")
    if "MFA" in sid or "VISH" in sid:
        tags.append("social-engineering")
    return add_category_and_tags(d, "shiny", tags)


def normalize_go_guard(f: Dict[str, Any]) -> Dict[str, Any]:
    """Go sentinel-guard JSON object → same operator block as Python modules."""
    rec = f.get("recommendation") or f.get("action") or "Review file; rotate if secret; fix workflow path."
    d = {
        "id": f.get("id", "GO-GUARD"),
        "severity": f.get("severity", "UNKNOWN"),
        "description": f.get("description", ""),
        "file": f.get("file", ""),
        "asset": f.get("file") or f.get("asset") or "",
        "signal": f.get("signal", ""),
        "evidence": f.get("evidence") or f.get("signal") or f.get("file") or "",
        "action": rec,
        "do_not": f.get("do_not")
        or "Do not force-push secrets out of history without rotation; assume leak until rotated.",
        "recommendation": rec,
        "tags": f.get("tags") or ["go-guard"],
    }
    # Category may already be set by Go; default keeps filters simple
    return add_category_and_tags(d, f.get("category") or "go-guard", d.get("tags") or ["go-guard"])


def require_blue_team_fields(d: Dict[str, Any]) -> List[str]:
    """
    Validation helper for tests (and for us when reviewing PRs together).
    Returns list of missing required keys.
    """
    # These five (+ category) are the BACKBONE output contract
    required = ["id", "category", "severity", "description", "action", "do_not"]
    return [k for k in required if not d.get(k)]
