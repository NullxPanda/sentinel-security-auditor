"""
NPM Supply Chain Scanner for Sentinel.

Purpose: Turn raw 'npm audit' output into structured findings with urgency signals.
Threat model (2026): Attackers compromise transitive deps or publish malicious
versions that pass initial audits. Cached + native audit for speed + low noise.
"""

import subprocess
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any

from diskcache import Cache


class NpmScanner:
    """Cached wrapper around npm audit. Fast path for local node projects."""

    def __init__(self, cache_dir: str = ".sentinel_cache"):
        self.cache = Cache(cache_dir)
        self.timeout = 30  # Never let a scan hang the tool.

    def _project_hash(self, target_dir: Path) -> str:
        """Stable cache key from lockfile or package.json bytes."""
        lock_path = target_dir / "package-lock.json"
        pkg_path = target_dir / "package.json"

        if lock_path.exists():
            content = lock_path.read_bytes()
        elif pkg_path.exists():
            content = pkg_path.read_bytes()
        else:
            return "no-node-project"

        return hashlib.sha256(content).hexdigest()[:16]

    def scan(self, target_dir: str) -> List[Dict[str, Any]]:
        """Main entry: cached, fast, returns [] for non-npm dirs."""
        path = Path(target_dir).resolve()

        if not (path / "package.json").exists():
            return []

        cache_key = f"npm_scan:{self._project_hash(path)}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        findings = self._run_npm_audit(path)
        self.cache[cache_key] = findings
        return findings

    def _run_npm_audit(self, path: Path) -> List[Dict]:
        """Run native npm audit --json and extract usable vulns. Silent fallback."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0 and not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            vulnerabilities = data.get("vulnerabilities", {})

            findings: List[Dict] = []
            for pkg_name, details in vulnerabilities.items():
                for vuln in details.get("via", []):
                    if isinstance(vuln, str):  # version string only, skip
                        continue
                    findings.append({
                        "type": "npm",
                        "package": pkg_name,
                        "version": details.get("version"),
                        "severity": vuln.get("severity", "unknown"),
                        "title": vuln.get("title"),
                        "url": vuln.get("url"),
                        "raw": vuln,
                    })
            return findings

        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []


# Quick manual test
if __name__ == "__main__":
    scanner = NpmScanner()
    findings = scanner.scan(".")
    print(f"Found {len(findings)} npm vulnerabilities")
    for f in findings[:3]:
        print(f)
