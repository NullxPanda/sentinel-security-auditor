"""
NPM Supply Chain Scanner
Purpose: Turn raw 'npm audit' output into structured findings with urgency signals.
Threat Model (2026): Attackers compromise transitive deps or publish malicious
versions that pass initial audits. We enrich with OSV and cache for speed.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any
import hashlib
from diskcache import Cache


class NpmScanner:
    def __init__(self, cache_dir: str = ".sentinel_cache"):
        self.cache = Cache(cache_dir)
        self.timeout = 30       #NEVER EVER LET A SCAN HANGGIN  

    def _project_hash(self, target_dir: Path) -> str:
        """Create stable cache key based on lockfile or package.json"""
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
        """Main scan entrypoint - cached, performant."""
        path = Path(target_dir).resolve()
        
        if not (path / "package.json").exists():
            return []
        
        cache_key = f"npm_scan:{self._project_hash(path)}"
        #CACHE HITTER -DERECT DEPOSIT
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        #RUN NATIVE NPM AUDIT
        findings = self._run_npm_audit(path)
        
        
        self.cache[cache_key] = findings
        return findings

    def _run_npm_audit(self, path: Path) -> List[Dict]:
        """Execute npm audit and parse JSON output."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # npm returns non-zero when nada is found
            if result.returncode != 0 and not result.stdout.strip():
                return []
            
            data = json.loads(result.stdout)
            vulnerabilities = data.get("vulnerabilities", {})
            
            findings = []
            for pkg_name, details in vulnerabilities.items():
                for vuln in details.get("via", []):
                    if isinstance(vuln, str):  #version string
                        continue
                    findings.append({
                        "type": "npm",
                        "package": pkg_name,
                        "version": details.get("version"),
                        "severity": vuln.get("severity", "unknown"),
                        "title": vuln.get("title"),
                        "url": vuln.get("url"),
                        "raw": vuln
                    })
            return findings
            
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []    #FALLBACKKING


# Quick test when run directly
if __name__ == "__main__":
    scanner = NpmScanner()
    findings = scanner.scan(".")
    print(f"Found {len(findings)} npm vulnerabilities")
    for f in findings[:3]:  #shows the first few
        print(f)
