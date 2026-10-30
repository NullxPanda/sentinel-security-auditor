def extract_severity(cve):

    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")

    return "UNKNOWN"
