import platform
from datetime import date, timedelta

from correlator.matcher import match_packages_to_cves, windows_cves_since
from reporting.reporter import print_findings
from scanner.decision_engine import process_vulnerabilities
from scanner.package_scanner import get_installed_packages
from scanner.windows_posture import collect_windows_posture, print_posture
from vulnerability.cve_client import fetch_recent_cves
from vulnerability.library import load_library, summarize


def _nvd_stamp(day, end=False):
    clock = "23:59:59.999" if end else "00:00:00.000"
    return f"{day.isoformat()}T{clock}"


def main():
    posture = None
    if platform.system() == "Windows":
        posture = collect_windows_posture()
        print_posture(posture)
        library = load_library()
        if library is None:
            print("\nCVE library is missing. Run: python -m vulnerability.update_library")
        else:
            info = summarize(library)
            print("\nCVE library")
            print("-----------")
            print(f"Updated: {info['updated']}")
            print(f"Records kept: {info['count']}")
            print(f"Rejected or empty dropped: {info['dropped']}")
            print(f"Known-exploited flags added in October: {info['kev']}")
            print(f"Records naming a vulnerable Microsoft Windows product: {info['windows_product']}")
            print(f"Window: {library.get('window')}")
        print()

    today = date.today()
    if posture is not None:
        start = posture["october_release"] + timedelta(days=1)
    else:
        start = today - timedelta(days=21)
    print(f"Downloading CVE intelligence ({start.isoformat()} to {today.isoformat()})...")
    keyword = "Windows" if posture is not None else None
    cves = fetch_recent_cves(
        50,
        published_after=_nvd_stamp(start),
        published_before=_nvd_stamp(today, end=True),
        keyword=keyword,
    )
    print("Validated CVE records:", len(cves))
    print("Rejected and empty records were dropped. A validated ID is a real NVD entry.")

    if posture is not None:
        newer = windows_cves_since(cves, posture["october_release"])
        microsoft = [row for row in newer if row["kind"] == "microsoft-windows"]
        mentioned = [row for row in newer if row["kind"] == "mentioned-microsoft-windows"]
        other = [row for row in newer if row["kind"] == "other-product"]
        print(f"\nRecords published after {posture['october_release'].isoformat()}: {len(newer)}")
        print(f"Microsoft Windows CPE: {len(microsoft)}")
        print(f"Description names Microsoft Windows, CPE not assigned: {len(mentioned)}")
        print(f"Other products that only run on Windows: {len(other)}")
        print("These IDs are real NVD records. None are confirmed present on this PC.")
        for row in (microsoft + mentioned)[:15]:
            print(
                f"[{row['severity']}] {row['cve_id']} "
                f"{row['published']} {row['status']} {row['kind']}"
            )
        if not microsoft and not mentioned:
            print("No Microsoft Windows OS record in this page.")
        print(
            "\nAction: this PC already has the October 13 cumulative. "
            "Take the November Patch Tuesday cumulative when it posts. "
            "Do not treat a CVE title as proof this machine is exposed."
        )
        return

    print("\nScanning system packages...")
    packages = get_installed_packages()
    print("Packages discovered:", len(packages))
    print("\nRunning vulnerability correlation...")
    findings = match_packages_to_cves(packages, cves)
    print_findings(findings)

    if findings:
        print("\nDecision Engine Output:\n")
        decisions = process_vulnerabilities([
            {
                "service": f.package,
                "cve_id": f.cve_id,
                "cvss": 9.0 if f.severity == "CRITICAL" else 7.0 if f.severity == "HIGH" else 5.0,
            }
            for f in findings
        ])
        for d in decisions[:3]:
            print(f"[{d['priority']}] {d['action']}")
            print("Why:", d["why"])
            print("Impact:", d["impact"])
            print("---")
    else:
        print("\nNo actionable vulnerabilities for decision engine.")


if __name__ == "__main__":
    main()
