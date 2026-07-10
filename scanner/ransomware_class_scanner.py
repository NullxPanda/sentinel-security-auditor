"""Ransomware-CLASS detector (behavior / prep patterns — not live malware).

Detects scripts, docs, and configs that match known WannaCry-adjacent and
generic ransomware *operator* patterns:
  - volume shadow copy / backup destruction
  - recovery disable
  - mass encrypt / extension ransom notes
  - wormish SMB lateral hints in automation

Safe by design: text pattern matching on a root tree + optional fixture dir.
Never executes samples. Never downloads malware.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Tuple

from models.data_models import Finding

# (rule_id, severity, substrings_all_lower, description, action, do_not, tags)
RULES: List[Tuple] = [
    (
        "RW-CLASS-SHADOW-DELETE",
        "CRITICAL",
        ["vssadmin", "delete", "shadows"],
        "Script/config references deleting Volume Shadow Copies — classic ransomware prep to block recovery.",
        "Quarantine the file host process; snapshot/isolate the machine; verify backup immutability; do not power-cycle if memory forensics needed.",
        "Do not wipe the disk or delete the suspicious scripts before copying evidence off-box.",
        ["ransomware-class", "backup-destruction", "T1490"],
    ),
    (
        "RW-CLASS-WBADMIN-CATALOG",
        "CRITICAL",
        ["wbadmin", "delete", "catalog"],
        "Windows backup catalog delete pattern — common ransomware anti-recovery step.",
        "Isolate host; restore from offline backup; rotate creds used on host; review scheduled tasks.",
        "Do not run the same script 'to see what it does' on a production box.",
        ["ransomware-class", "backup-destruction", "T1490"],
    ),
    (
        "RW-CLASS-BCD-RECOVERY",
        "HIGH",
        ["bcdedit", "recoveryenabled"],
        "Boot configuration recovery disable — often paired with ransomware deployment.",
        "Preserve disk image if possible; re-enable recovery only after clean rebuild plan; check for other RW-CLASS hits.",
        "Do not assume 'it failed' means safe — partial runs still leave persistence.",
        ["ransomware-class", "defense-evasion", "T1490"],
    ),
    (
        "RW-CLASS-RANSOM-NOTE",
        "HIGH",
        ["your files have been encrypted"],
        "Ransom note language present in tree — may be fixture, doc, or real incident artifact.",
        "If unexpected on a live system: disconnect network, preserve evidence, engage IR. If fixture/test: ensure path is lab-only.",
        "Do not pay ransom or run decryptor tools from untrusted sites.",
        ["ransomware-class", "impact", "T1486"],
    ),
    (
        "RW-CLASS-MASS-EXTENSION",
        "MEDIUM",
        [".encrypted", "rename"],
        "Hints of mass rename / .encrypted extension automation — encryptor-class behavior in scripts.",
        "Review script ownership and scheduled execution; block write to bulk data dirs if active.",
        "Do not bulk-delete 'encrypted' files without recovery plan — may be the only remaining data.",
        ["ransomware-class", "impact", "T1486"],
    ),
    (
        "RW-CLASS-SMB-WORMISH",
        "HIGH",
        ["smb", "eternal"],
        "SMB/Eternal-class lateral movement language — WannaCry-like worm narrative in tooling/docs.",
        "Ensure SMBv1 disabled; patch OS; segment networks; scan for exposed 445.",
        "Do not enable SMBv1 'for compatibility' on internet-facing hosts.",
        ["ransomware-class", "lateral", "wannacry-class", "T1210"],
    ),
]

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".sentinel_cache",
    "node_modules",
    "venv",
    ".venv",
    "bin",
    "vendor",
}

_TEXT_SUFFIXES = {
    ".py",
    ".sh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
    ".txt",
    ".md",
    ".yml",
    ".yaml",
    ".json",
    ".conf",
    ".cfg",
    ".log",
    ".sample",
}


def _iter_text_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in _TEXT_SUFFIXES and p.name not in {
            "Dockerfile",
            "Makefile",
            "Vagrantfile",
        }:
            # allow extensionless notes named like ransom
            if "ransom" not in p.name.lower() and "encrypt" not in p.name.lower():
                continue
        if p.stat().st_size > 1_500_000:
            continue
        yield p


def scan_ransomware_class(root: str = ".") -> List[Finding]:
    rootp = Path(root).resolve()
    findings: List[Finding] = []
    seen = set()

    for path in _iter_text_files(rootp):
        try:
            text = path.read_text(errors="ignore").lower()
        except OSError:
            continue
        rel = str(path.relative_to(rootp)) if path.is_relative_to(rootp) else str(path)

        for rule_id, sev, needles, desc, action, do_not, tags in RULES:
            if all(n in text for n in needles):
                key = (rule_id, rel)
                if key in seen:
                    continue
                seen.add(key)
                # evidence snippet
                idx = text.find(needles[0])
                snippet = text[max(0, idx - 40) : idx + 80].replace("\n", " ")
                findings.append(
                    Finding(
                        id=rule_id,
                        category="ransomware-class",
                        severity=sev,
                        description=desc,
                        signal="+".join(needles),
                        asset=rel,
                        file=rel,
                        evidence=snippet.strip() or needles[0],
                        action=action,
                        do_not=do_not,
                        recommendation=action,
                        tags=list(tags),
                    )
                )
    return findings


def get_ransomware_class_findings(root: str = ".") -> List[Finding]:
    return scan_ransomware_class(root)
