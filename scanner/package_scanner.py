import platform
import subprocess
from typing import List

from models.data_models import Package


def get_installed_packages() -> List[Package]:
    """Return list of installed packages for this platform (dpkg on Linux for now)."""
    system = platform.system()

    if system == "Linux":
        return scan_dpkg()
    elif system == "Windows":
        return []
    else:
        print(f"Unsupported OS: {system}")
        return []


def scan_dpkg() -> List[Package]:
    """Parse dpkg -l output into Package dataclasses. Fast and dependency-free."""
    packages: List[Package] = []
    result = subprocess.run(
        ["dpkg", "-l"],
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("ii"):
            parts = line.split()
            if len(parts) >= 3:
                packages.append(
                    Package(
                        name=parts[1],
                        version=parts[2],
                        source="dpkg",
                    )
                )
    return packages

