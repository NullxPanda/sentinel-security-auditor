"""
Reporting package for Sentinel.

Basic print helpers today (reporter.py). Expand here for JSON, files, or
rich output when needed. Kept tiny so core scans stay fast and readable.
"""

from .reporter import print_findings

__all__ = ["print_findings"]
