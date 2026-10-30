import json
import platform
import subprocess
from datetime import date, timedelta


# October 13, 2026 Patch Tuesday for Windows 11 25H2.
OCTOBER_KB = "KB5127648"
OCTOBER_BUILD = 9711
OCTOBER_RELEASE = date(2026, 10, 13)


def second_tuesday(year, month):
    day = date(year, month, 1)
    tuesdays = 0
    while True:
        if day.weekday() == 1:
            tuesdays += 1
            if tuesdays == 2:
                return day
        day += timedelta(days=1)


def next_patch_tuesday(today):
    this_month = second_tuesday(today.year, today.month)
    if today <= this_month:
        return this_month
    year = today.year + (1 if today.month == 12 else 0)
    month = 1 if today.month == 12 else today.month + 1
    return second_tuesday(year, month)


def _powershell(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    if not text:
        return None
    return json.loads(text)


def collect_windows_posture():
    if platform.system() != "Windows":
        return None

    build = _powershell(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
        "| Select-Object ProductName, DisplayVersion, CurrentBuild, UBR, EditionID "
        "| ConvertTo-Json"
    ) or {}

    hotfixes = _powershell(
        "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
    ) or []
    if isinstance(hotfixes, dict):
        hotfixes = [hotfixes]

    defender = _powershell(
        "Get-MpComputerStatus | Select-Object AntivirusSignatureVersion, "
        "@{N='AntivirusSignatureLastUpdated';E={$_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')}}, "
        "DefenderSignaturesOutOfDate, RealTimeProtectionEnabled, QuickScanAge, "
        "FullScanAge, NISEnabled, AMServiceEnabled | ConvertTo-Json"
    ) or {}

    ubr = int(build.get("UBR") or 0)
    installed = {item.get("HotFixID", "").upper() for item in hotfixes}
    october_installed = OCTOBER_KB in installed and ubr >= OCTOBER_BUILD

    return {
        "product": build.get("ProductName"),
        "display_version": build.get("DisplayVersion"),
        "edition": build.get("EditionID"),
        "build": f"{build.get('CurrentBuild')}.{ubr}",
        "ubr": ubr,
        "october_kb": OCTOBER_KB,
        "october_installed": october_installed,
        "hotfixes": hotfixes,
        "defender": defender,
        "next_patch_tuesday": next_patch_tuesday(date.today()),
        "october_release": OCTOBER_RELEASE,
    }


def print_posture(posture):
    print("Local patch posture")
    print("-------------------")
    name = posture["product"] or "Windows"
    if str(posture.get("display_version", "")).endswith("H2"):
        name = f"Windows 11 {posture['display_version']}"
    print(f"{name} ({posture['edition']}) build {posture['build']}")
    state = "installed" if posture["october_installed"] else "MISSING"
    print(f"October cumulative {posture['october_kb']}: {state}")
    defender = posture["defender"]
    print(
        "Defender signatures: "
        f"{defender.get('AntivirusSignatureVersion')} "
        f"updated {defender.get('AntivirusSignatureLastUpdated')} "
        f"out_of_date={defender.get('DefenderSignaturesOutOfDate')}"
    )
    print(f"Real-time protection: {defender.get('RealTimeProtectionEnabled')}")
    print(f"Next Patch Tuesday: {posture['next_patch_tuesday'].isoformat()}")
    print(
        "November updates are not published before that date. "
        "Install the cumulative the day it appears."
    )
