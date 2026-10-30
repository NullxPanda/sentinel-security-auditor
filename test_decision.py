from scanner.decision_engine import process_vulnerabilities

sample = [
    {"service": "openssl", "cve_id": "CVE-2024-1234", "cvss": 9.8, "running": True, "exposed": True},
    {"service": "nginx", "cve_id": "CVE-2023-9999", "cvss": 7.5, "running": True, "exposed": True}
]

results = process_vulnerabilities(sample)

for r in results:
    print("\n---")
    print(f"[{r['priority']}] {r['action']}")
    print("Why:", r["why"])
    print("Impact:", r["impact"])
