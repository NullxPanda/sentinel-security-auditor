"""Match the local CVE library to this PC.

A Microsoft Windows product string for this build can become a patch finding.
FortiMail, NetScaler, and every other product stay off that list.
Rejected records are dropped. A match is still not proof this PC is exploited.
"""

from __future__ import annotations

from datetime import timedelta

from models.data_models import Finding


def _products(record):
    return [str(p).lower() for p in (record.get("products") or [])]


def _rejected(record):
    return (record.get("status") or "").lower() == "rejected"


def windows_token(posture):
    """CPE-style token for this client build, such as microsoft:windows_11_25h2."""
    name = (posture.get("product") or "").lower()
    display = (posture.get("display_version") or "").lower()
    if "server" in name or not display:
        return ""
    family = "windows_10" if "windows 10" in name else "windows_11"
    return f"microsoft:{family}_{display}"


def since_date(posture):
    """Date the installed cumulative covers. A missing cumulative covers nothing."""
    release = posture.get("october_release")
    if release is None:
        return None
    if posture.get("october_installed"):
        return release
    return release - timedelta(days=1)


def classify_record(record, posture, since):
    """Return drop, patch, covered, undated, or other-product."""
    cve_id = record.get("id") or ""
    if _rejected(record) or not cve_id.startswith("CVE-"):
        return "drop"

    token = windows_token(posture)
    on_this_pc = bool(token) and any(token in product for product in _products(record))
    if not on_this_pc:
        return "other-product"

    published = (record.get("published") or "")[:10]
    if not published:
        return "undated"
    if since and published <= since.isoformat():
        return "covered"
    return "patch"


def to_finding(record) -> Finding:
    products = ", ".join(record.get("products") or [])
    return Finding(
        id=record["id"],
        category="windows-posture",
        severity=record.get("severity") or "UNKNOWN",
        description=(
            f"{record['id']} names this PC's Windows build and was published "
            "after the installed cumulative."
        ),
        asset="windows",
        signal=record["id"],
        evidence=f"published {record.get('published') or 'undated'}; products {products}",
        action=(
            "Install the next Windows cumulative when it posts. "
            "Confirm the fixed build before treating this ID as exposed."
        ),
        do_not="Do not treat a CVE ID as proof this PC is exploited.",
        tags=["windows", "cve", "unconfirmed-impact"],
    )


def match_library_to_posture(records, posture):
    since = since_date(posture)
    findings = []
    for record in records:
        if classify_record(record, posture, since) != "patch":
            continue
        findings.append(to_finding(record))
    return findings
