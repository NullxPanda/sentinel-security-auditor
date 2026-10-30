import re
from models.data_models import Package, VulnerabilityFinding
from utils.version_utils import (
    is_version_vulnerable,
    is_vulnerable_in_cpe,
    extract_product_from_cpe,
)
from utils.severity_utils import extract_severity


def match_packages_to_cves(packages, cves):
    """Match installed packages against CVE records.

    Primary signal: NVD 'configurations' / CPE data (product + version ranges).
    Secondary / fallback: word-boundary match in the first English description
    (much stricter than naive substring to kill 1999-era noise like "ed" or "file").
    Only records with usable severity (not UNKNOWN) are kept for the live section.
    """
    findings = []
    pkg_names = [p.name.lower() for p in packages]
    pkg_map = {p.name.lower(): p for p in packages}

    for cve in cves:
        cve_data = cve["cve"]
        cve_id = cve_data.get("id")
        severity = extract_severity(cve_data)

        # Skip ancient noise with no modern severity vector early
        if severity == "UNKNOWN":
            continue

        matched_pkg = None

        # === PRIMARY: structured CPE matching ===
        for cfg in cve_data.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    product = extract_product_from_cpe(cm.get("criteria", ""))
                    if not product:
                        continue
                    for p_name in pkg_names:
                        if product in p_name or p_name in product:
                            pkg = pkg_map[p_name]
                            if is_vulnerable_in_cpe(pkg.version, cm):
                                matched_pkg = pkg
                                break
                    if matched_pkg:
                        break
                if matched_pkg:
                    break
            if matched_pkg:
                break

        if not matched_pkg:
            # === FALLBACK: strict word-boundary in description (cuts "ed", "sed", "pass" spam) ===
            descriptions = cve_data.get("descriptions", [])
            if descriptions:
                description_text = descriptions[0].get("value", "").lower()
                for p_name in pkg_names:
                    if re.search(r"\b" + re.escape(p_name) + r"\b", description_text):
                        matched_pkg = pkg_map[p_name]
                        break

        if matched_pkg:
            findings.append(
                VulnerabilityFinding(
                    package=matched_pkg.name,
                    version=matched_pkg.version,
                    cve_id=cve_id,
                    severity=severity,
                )
            )

    # De-dupe (same pkg + cve can appear from multiple CPE nodes)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.package, f.cve_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def _status(cve_data):
    return cve_data.get("vulnStatus", "")


def _description(cve_data):
    descriptions = cve_data.get("descriptions") or []
    if not descriptions:
        return ""
    return descriptions[0].get("value", "")


def _microsoft_windows_cpe(cve_data):
    for conf in cve_data.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") and ":microsoft:windows" in match.get("criteria", ""):
                    return True
    return False


def windows_cves_since(cves, since):
    """Live NVD records published after the installed cumulative.

    A Microsoft Windows CPE means the record names Windows itself.
    A description mention stays a different product.
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
