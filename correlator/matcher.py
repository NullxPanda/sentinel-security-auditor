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
    Secondary / fallback: substring of the first English description (old behavior).
    """
    findings = []

    for pkg in packages:
        pkg_name = pkg.name.lower()
        pkg_version = pkg.version

        for cve in cves:
            cve_data = cve["cve"]
            cve_id = cve_data.get("id")
            severity = extract_severity(cve_data)

            matched = False

            # === PRIMARY: structured configurations / CPE matching ===
            for cfg in cve_data.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cm in node.get("cpeMatch", []):
                        product = extract_product_from_cpe(cm.get("criteria", ""))
                        if product and (pkg_name in product or product in pkg_name):
                            if is_vulnerable_in_cpe(pkg_version, cm):
                                findings.append(
                                    VulnerabilityFinding(
                                        package=pkg.name,
                                        version=pkg_version,
                                        cve_id=cve_id,
                                        severity=severity,
                                    )
                                )
                                matched = True
                                break
                    if matched:
                        break
                if matched:
                    break

            if matched:
                continue

            # === FALLBACK: old naive description substring (kept for coverage) ===
            descriptions = cve_data.get("descriptions", [])
            if descriptions:
                description_text = descriptions[0].get("value", "").lower()
                if pkg_name in description_text:
                    findings.append(
                        VulnerabilityFinding(
                            package=pkg.name,
                            version=pkg_version,
                            cve_id=cve_id,
                            severity=severity,
                        )
                    )

    return findings
