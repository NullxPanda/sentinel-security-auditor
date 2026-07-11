"""Core data models for Sentinel.

Finding is the stable shape every scanner must produce (Python + compatible with Go guard JSON).
Blue-team contract: what / why / evidence / action / do_not.

Team: if you add a field, update correlator/normalize.py AND tests/test_finding_model.py
so we do not drift into a third dialect.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List


@dataclass
class Package:
    # Inventory unit from package_scanner (live path only)
    name: str
    version: str
    source: str


@dataclass
class Vulnerability:
    # NVD-ish record shape used by cve_client / matcher
    cve_id: str
    description: str
    severity: str
    affected_package: str
    affected_version: str


@dataclass
class VulnerabilityFinding:
    # Match result: package × CVE (pre-normalize_live_cve)
    package: str
    version: str
    cve_id: str
    severity: str


@dataclass
class GitHubActionFinding:
    """Legacy GHA finding shape (still produced by github_actions_scanner)."""

    # Prefer dicts with action/do_not now; this type remains for older imports
    workflow: str
    risks: List[str]
    severity: str
    recommendation: str


@dataclass
class Finding:
    """Stable blue-team finding.

    Fields map to operator questions:
      id/category/severity/description → what + why
      asset/signal/evidence/file → where + proof
      action / do_not → 5-minute contain path + anti-patterns
    """

    id: str
    category: str
    severity: str
    description: str
    signal: str = ""
    asset: str = ""
    evidence: str = ""
    action: str = ""
    do_not: str = ""
    # recommendation is a legacy alias; to_dict copies action → recommendation if empty
    recommendation: str = ""
    file: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Keep both fields filled so old printers / Go JSON consumers stay happy
        if not d.get("recommendation") and d.get("action"):
            d["recommendation"] = d["action"]
        return d

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Finding":
        # Drop unknown keys so extra JSON from Go guard does not explode
        known = {f.name for f in fields(cls)}
        data = {k: v for k, v in raw.items() if k in known}
        # Tolerant defaults for partial payloads
        data.setdefault("id", raw.get("id") or raw.get("cve_id") or raw.get("workflow") or "UNKNOWN")
        data.setdefault("category", raw.get("category") or "unknown")
        data.setdefault("severity", raw.get("severity") or "UNKNOWN")
        data.setdefault("description", raw.get("description") or raw.get("signal") or "")
        tags = data.get("tags") or []
        if isinstance(tags, str):
            # Comma-separated tags from shell / CSV exports
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        data["tags"] = list(tags)
        return cls(**data)


def findings_to_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in findings]
