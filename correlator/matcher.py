import re

from models.data_models import VulnerabilityFinding
from utils.severity_utils import extract_severity


def _status(cve_data):
    return cve_data.get("vulnStatus", "")


def _description(cve_data):
    descriptions = cve_data.get("descriptions") or []
    if not descriptions:
        return ""
    return descriptions[0].get("value", "")


def match_packages_to_cves(packages, cves):
    findings = []

    for pkg in packages:
        name = pkg.name.lower().strip()
        if len(name) < 4:
            continue
        pattern = re.compile(rf"\b{re.escape(name)}\b")

        for cve in cves:
            cve_data = cve["cve"]
            if _status(cve_data) == "Rejected":
                continue

            description_text = _description(cve_data)
            if not pattern.search(description_text.lower()):
                continue

            findings.append(
                VulnerabilityFinding(
                    package=pkg.name,
                    version=pkg.version,
                    cve_id=cve_data["id"],
                    severity=extract_severity(cve_data),
                    status=_status(cve_data),
                    confidence="name-only",
                )
            )

    return findings


def _microsoft_windows_cpe(cve_data):
    for conf in cve_data.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") and ":microsoft:windows" in match.get("criteria", ""):
                    return True
    return False


def windows_cves_since(cves, since):
    """Real NVD records published after the installed cumulative.

    A Microsoft Windows CPE means the record names Windows itself.
    Anything else only mentions Windows and is a different product.
    Neither result proves the bug is present on this PC.
    """
    rows = []
    for cve in cves:
        cve_data = cve["cve"]
        if _status(cve_data) == "Rejected":
            continue
        published = (cve_data.get("published") or "")[:10]
        if since and published <= since.isoformat():
            continue
        microsoft = _microsoft_windows_cpe(cve_data)
        text = _description(cve_data).lower()
        if not microsoft and "microsoft windows" not in text and "windows" not in text:
            continue
        if microsoft:
            kind = "microsoft-windows"
        elif "microsoft windows" in text:
            kind = "mentioned-microsoft-windows"
        else:
            kind = "other-product"
        rows.append(
            {
                "cve_id": cve_data["id"],
                "published": published,
                "status": _status(cve_data),
                "severity": extract_severity(cve_data),
                "kind": kind,
            }
        )
    return rows
