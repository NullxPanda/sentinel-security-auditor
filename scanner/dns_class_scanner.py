"""DNS-CLASS detector (misconfig + abuse patterns from text/logs).

Catches defender-relevant DNS ugliness without being a full resolver SOC:
  - suspicious long / high-entropy-looking labels in logs
  - sudden use of odd resolvers documented in configs
  - DNS tunneling-ish query patterns in sample logs
  - hosts/resolv risks

Offline fixtures under test-fixtures/dns/ are the primary reliable path.
Live reads of /etc/resolv.conf are optional and best-effort.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Iterable, List, Optional

from models.data_models import Finding

_SKIP_DIRS = {".git", "__pycache__", ".sentinel_cache", "node_modules", "venv", ".venv", "bin"}

# domain-ish tokens
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)
_QUERY_LINE_RE = re.compile(r"(query|nxdomain|servfail|dns|named|unbound|systemd-resolved)", re.I)

# Resolvers that are fine / common — everything else in resolv.conf is a signal, not always bad
_COMMON_RESOLVERS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "127.0.0.1",
    "127.0.0.53",
    "::1",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter

    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _iter_dns_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        name = p.name.lower()
        if p.stat().st_size > 2_000_000:
            continue
        if (
            "dns" in name
            or name.endswith((".log", ".txt", ".conf", ".hosts"))
            or "resolv" in name
            or p.suffix.lower() in {".pcap.txt", ".sample"}
        ):
            yield p
        elif "dns" in str(p.parent).lower():
            yield p


def _findings_from_text(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    lower = text.lower()

    # Tunneling-ish: very long labels
    for m in _DOMAIN_RE.finditer(text):
        dom = m.group(0)
        labels = dom.split(".")
        long_labels = [lb for lb in labels if len(lb) >= 40]
        high_ent = [lb for lb in labels if len(lb) >= 20 and _entropy(lb.lower()) >= 3.5]
        if long_labels or high_ent:
            evidence = dom[:200]
            out.append(
                Finding(
                    id="DNS-CLASS-LONG-LABEL",
                    category="dns-class",
                    severity="HIGH",
                    description="Very long or high-entropy DNS label — possible tunneling or C2 beaconing pattern in logs/config.",
                    signal="long-or-high-entropy-label",
                    asset=rel,
                    file=rel,
                    evidence=evidence,
                    action="Identify process generating queries; sinkhole/block domain at resolver if confirmed malicious; capture pcap; check for data exfil.",
                    do_not="Do not ignore as 'random CDN' without checking process and volume; do not flush all DNS caches before noting query source.",
                    recommendation="Identify process; block/sinkhole if hostile; capture evidence.",
                    tags=["dns-class", "tunneling", "T1071.004"],
                )
            )
            break  # one finding per file for this class is enough

    # NXDOMAIN flood hint
    nx = lower.count("nxdomain")
    if nx >= 15:
        out.append(
            Finding(
                id="DNS-CLASS-NXDOMAIN-FLOOD",
                category="dns-class",
                severity="MEDIUM",
                description=f"High NXDOMAIN count in log ({nx}) — brute DGA, misconfig, or reconnaissance noise.",
                signal=f"nxdomain_count={nx}",
                asset=rel,
                file=rel,
                evidence=f"nxdomain occurrences: {nx}",
                action="Baseline normal NXDOMAIN rate; identify top queriers; rate-limit or investigate hosts with spikes.",
                do_not="Do not blanket-block all recursive DNS without a roll-out plan — you will break the network.",
                recommendation="Investigate top queriers; baseline NXDOMAIN rates.",
                tags=["dns-class", "dga", "recon"],
            )
        )

    # Explicit evil resolver docs
    for bad in ("0.0.0.0", "attacker-dns", "malicious-resolver", "dns-hijack"):
        if bad in lower:
            out.append(
                Finding(
                    id="DNS-CLASS-HIJACK-INDICATOR",
                    category="dns-class",
                    severity="CRITICAL",
                    description="Config/log language indicating DNS hijack or malicious resolver.",
                    signal=bad,
                    asset=rel,
                    file=rel,
                    evidence=bad,
                    action="Verify authoritative resolver settings on hosts/routers; restore known-good DNS; rotate creds if portal hijack suspected.",
                    do_not="Do not keep using the suspicious resolver 'temporarily'.",
                    recommendation="Restore known-good resolvers; verify DHCP/DNS options.",
                    tags=["dns-class", "hijack", "T1557"],
                )
            )
            break

    # nameserver lines that look odd in project configs
    for line in text.splitlines():
        if line.strip().lower().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in _COMMON_RESOLVERS and not parts[1].startswith("192.168."):
                # private 10/172 still ok-ish; flag uncommon public-looking
                ip = parts[1]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "192.168.")):
                    if ip not in _COMMON_RESOLVERS:
                        out.append(
                            Finding(
                                id="DNS-CLASS-UNCOMMON-RESOLVER",
                                category="dns-class",
                                severity="LOW",
                                description=f"Uncommon public resolver configured: {ip}",
                                signal=f"nameserver {ip}",
                                asset=rel,
                                file=rel,
                                evidence=line.strip()[:200],
                                action="Confirm resolver is organizationally approved; prefer DNSSEC-capable known resolvers.",
                                do_not="Do not mass-change resolvers during an incident without documenting prior state.",
                                recommendation="Confirm resolver is approved.",
                                tags=["dns-class", "config"],
                            )
                        )
    return out


def _scan_system_resolv() -> List[Finding]:
    path = Path("/etc/resolv.conf")
    if not path.is_file():
        return []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    findings = _findings_from_text("/etc/resolv.conf", text)
    # demote live system uncommon resolver noise: keep only hijack-class
    return [f for f in findings if f.id == "DNS-CLASS-HIJACK-INDICATOR"]


def scan_dns_class(root: str = ".", include_system: bool = False) -> List[Finding]:
    rootp = Path(root).resolve()
    findings: List[Finding] = []
    seen = set()

    for path in _iter_dns_files(rootp):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(rootp)) if path.is_relative_to(rootp) else str(path)
        for f in _findings_from_text(rel, text):
            key = (f.id, f.file, f.evidence[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

    if include_system:
        for f in _scan_system_resolv():
            findings.append(f)

    return findings


def get_dns_class_findings(root: str = ".", include_system: bool = False) -> List[Finding]:
    return scan_dns_class(root, include_system=include_system)
