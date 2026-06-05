from dataclasses import dataclass 



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
    """Finding from .github/workflows scan for prompt injection / AI agent repo hijack risks (2026 Claude Code GitHub Action class of flaws)."""
    workflow: str
    risks: list
    severity: str
    recommendation: str
