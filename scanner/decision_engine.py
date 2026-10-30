from typing import List, Dict

RUNTIME_WEIGHT = 2
EXPOSURE_WEIGHT = 3
EXPLOIT_WEIGHT = 2
CRITICAL_WEIGHT = 2
MITIGATION_WEIGHT = -3


def is_running(vuln: Dict) -> bool:
    return bool(vuln.get("running", False))


def is_exposed(vuln: Dict) -> bool:
    return bool(vuln.get("exposed", False))


def has_known_exploit(vuln: Dict) -> bool:
    return bool(vuln.get("exploit", False))


def is_critical(service: str) -> bool:
    return service.lower() in ["ssh", "nginx", "apache", "openssl"]


def is_mitigated(service: str) -> bool:
    return False


def calculate_urgency(vuln: Dict) -> int:
    score = vuln.get("cvss", 0)

    if is_running(vuln):
        score += RUNTIME_WEIGHT

    if is_exposed(vuln):
        score += EXPOSURE_WEIGHT

    if has_known_exploit(vuln):
        score += EXPLOIT_WEIGHT

    if is_critical(vuln["service"]):
        score += CRITICAL_WEIGHT

    if is_mitigated(vuln["service"]):
        score += MITIGATION_WEIGHT

    return score


def classify_priority(score: int) -> str:
    if score >= 12:
        return "IMMEDIATE"
    elif score >= 8:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"


def generate_action(vuln: Dict) -> str:
    return f"Patch {vuln['service']}"


def estimate_impact(vuln: Dict) -> Dict:
    return {
        "downtime": "~2-5s",
        "restart_required": True,
        "risk_reduction": "high"
    }


def build_decision(vuln: Dict) -> Dict:
    score = calculate_urgency(vuln)
    priority = classify_priority(score)

    return {
        "service": vuln["service"],
        "cve_id": vuln["cve_id"],
        "score": score,
        "priority": priority,
        "action": generate_action(vuln),
        "why": [reason for reason in [
            f"CVE: {vuln['cve_id']}",
            "service running" if is_running(vuln) else "",
            "network exposed" if is_exposed(vuln) else "",
            "known exploited" if has_known_exploit(vuln) else "",
        ] if reason],
        "impact": estimate_impact(vuln)
    }


def process_vulnerabilities(vulns: List[Dict]) -> List[Dict]:
    decisions = [build_decision(v) for v in vulns]
    return sorted(decisions, key=lambda x: x["score"], reverse=True)


