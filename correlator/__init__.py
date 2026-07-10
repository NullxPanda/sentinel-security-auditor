"""
Correlator package for Sentinel.

Currently provides the live CVE matcher (matcher.py).
Kept minimal / lazy to support the fast "what actually matters" workflow.
"""

from .matcher import match_packages_to_cves  # re-export for convenience

__all__ = ["match_packages_to_cves"]
