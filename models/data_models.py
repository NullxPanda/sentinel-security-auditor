"""Core data models for Sentinel.

Finding is the stable shape every scanner must produce (Python + compatible with Go guard JSON).
Blue-team contract: what / why / evidence / action / do_not.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List


@dataclass
class Package:
    name: str
    version: str
    source: str


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    affected_package: str
    affected_version: str


@dataclass
class VulnerabilityFinding:
    package: str
    version: str
    cve_id: str
    severity: str


@dataclass
class GitHubActionFinding:
    """Legacy GHA finding shape (still produced by github_actions_scanner)."""

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
    recommendation: str = ""
    file: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not d.get("recommendation") and d.get("action"):
            d["recommendation"] = d["action"]
        return d

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Finding":
        known = {f.name for f in fields(cls)}
        data = {k: v for k, v in raw.items() if k in known}
        data.setdefault("id", raw.get("id") or raw.get("cve_id") or raw.get("workflow") or "UNKNOWN")
        data.setdefault("category", raw.get("category") or "unknown")
        data.setdefault("severity", raw.get("severity") or "UNKNOWN")
        data.setdefault("description", raw.get("description") or raw.get("signal") or "")
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        data["tags"] = list(tags)
        return cls(**data)


def findings_to_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in findings]
