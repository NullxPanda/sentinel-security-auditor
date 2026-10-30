def extract_severity(cve: dict) -> str:
    """
    Extract baseSeverity from available CVSS metrics.
    Prefers v3.1 > v3.0 > v2 (where present). Falls back to UNKNOWN for ancient records.
    This cuts a lot of the 1999-era noise that lacks modern CVSS vectors.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            try:
                entry = metrics[key][0]
                # v3+ uses cvssData.baseSeverity ; v2 often has it too in modern NVD responses
                data = entry.get("cvssData", entry)
                sev = data.get("baseSeverity") or data.get("severity")
                if sev:
                    return sev.upper()
            except (KeyError, IndexError, TypeError):
                continue
    return "UNKNOWN"
