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
    status: str = "unknown"
    confidence: str = "unconfirmed"
