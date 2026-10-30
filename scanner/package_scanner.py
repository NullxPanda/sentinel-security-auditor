import platform
import subprocess

from models.data_models import Package


def get_installed_packages():

    system = platform.system()

    if system == "Linux":
        return scan_dpkg()

    elif system == "Windows":
        return []

    else:
        print(f"Unsupported OS: {system}")
        return []


def scan_dpkg():

    packages = []

    result = subprocess.run(
        ["dpkg", "-l"],
        capture_output=True,
        text=True
    )

    lines = result.stdout.split("\n")

    for line in lines:

        if line.startswith("ii"):

            parts = line.split()

            name = parts[1]
            version = parts[2]

            pkg = Package(
                name=name,
                version=version,
                source="dpkg"
            )

            packages.append(pkg)

    return packages

