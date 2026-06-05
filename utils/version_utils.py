import re


def normalize_version(version):
    """Turn a version string into a list of ints for comparison.
    Strips epochs (e.g. '1:2.3' -> '2.3'), and splits on any non-digit runs.
    Much more robust for real distro versions like "1:9.6p1-3ubuntu13.16" or "3.0.13-0ubuntu3.9".
    """
    if not version or not isinstance(version, str):
        return [0]
    # strip epoch
    if ":" in version:
        version = version.split(":", 1)[1]
    # split on anything that is not a digit, collect the numeric groups
    tokens = re.split(r"[^0-9]+", version)
    parts = [int(t) for t in tokens if t.isdigit()]
    return parts or [0]


def _compare(v1, v2):
    """Return negative if v1 < v2, 0 if equal, positive if v1 > v2."""
    for a, b in zip(v1, v2):
        if a != b:
            return a - b
    return len(v1) - len(v2)


def is_version_vulnerable(installed, affected):
    """Legacy simple check: is installed older than the 'affected' version?"""
    i = normalize_version(installed)
    a = normalize_version(affected)
    length = max(len(i), len(a))
    i += [0] * (length - len(i))
    a += [0] * (length - len(a))
    return _compare(i, a) < 0


def is_vulnerable_in_cpe(installed_version, cpe_match):
    """Return True if this installed_version is vulnerable according to the NVD cpeMatch dict.

    Handles versionStartIncluding, versionEndExcluding, versionStartExcluding, versionEndIncluding.
    Falls back to True for the product if no version constraints are present (common on old CVEs).
    """
    if not cpe_match or not cpe_match.get("vulnerable", True):
        return False

    start_inc = cpe_match.get("versionStartIncluding")
    end_exc = cpe_match.get("versionEndExcluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")

    inst = normalize_version(installed_version)

    if start_inc:
        if _compare(inst, normalize_version(start_inc)) < 0:
            return False
    if start_exc:
        if _compare(inst, normalize_version(start_exc)) <= 0:
            return False
    if end_exc:
        if _compare(inst, normalize_version(end_exc)) >= 0:
            return False
    if end_inc:
        if _compare(inst, normalize_version(end_inc)) > 0:
            return False

    # No constraining ranges present -> the CPE entry indicates this product is vulnerable
    # (many older records encode the vulnerable version directly in the CPE criteria)
    return True


def extract_product_from_cpe(criteria):
    """From a CPE string like cpe:2.3:a:vendor:product:version:... return the product part."""
    if not criteria or not isinstance(criteria, str):
        return ""
    try:
        parts = criteria.split(":")
        if len(parts) > 4:
            return parts[4].lower()
    except Exception:
        pass
    return ""
