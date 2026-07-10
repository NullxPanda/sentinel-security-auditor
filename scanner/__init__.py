# Lazy imports to avoid pulling in optional/heavy deps (diskcache, playwright, etc.) on light machines
# until the specific scanner is actually used.
# Updated during device prefs + ShinyHunters vector work for cleanliness.

def get_installed_packages(*a, **k):
    from .package_scanner import get_installed_packages as _f
    return _f(*a, **k)

def get_npm_findings(*a, **k):
    # NpmScanner class API (preferred); kept old name for back-compat surface.
    from .npm_scanner import NpmScanner
    return NpmScanner().scan(*a, **k)

def scan_github_workflows(*a, **k):
    from .github_actions_scanner import scan_github_workflows as _f
    return _f(*a, **k)

def get_github_action_findings(*a, **k):
    from .github_actions_scanner import get_github_action_findings as _f
    return _f(*a, **k)

def get_shiny_hunters_findings(*a, **k):
    from .shiny_hunters_scanner import get_shiny_hunters_findings as _f
    return _f(*a, **k)


def get_ransomware_class_findings(*a, **k):
    from .ransomware_class_scanner import get_ransomware_class_findings as _f
    return _f(*a, **k)


def get_dns_class_findings(*a, **k):
    from .dns_class_scanner import get_dns_class_findings as _f
    return _f(*a, **k)


__all__ = [
    "get_installed_packages",
    "get_npm_findings",
    "scan_github_workflows",
    "get_github_action_findings",
    "get_shiny_hunters_findings",
    "get_ransomware_class_findings",
    "get_dns_class_findings",
]
