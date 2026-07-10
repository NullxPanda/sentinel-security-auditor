"""Scanner module contract.

Every detection module:
  - accepts a root path (and optional options)
  - returns list[Finding] (or list[dict] convertible via Finding.from_dict)

No network required for class scanners. Keep deps stdlib when possible.
"""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from models.data_models import Finding


@runtime_checkable
class Scanner(Protocol):
    """Scanner in → list[Finding] out."""

    name: str

    def scan(self, root: str = ".") -> List[Finding]:
        ...


def ensure_findings(items) -> List[Finding]:
    """Normalize mixed Finding / dict lists."""
    out: List[Finding] = []
    for item in items or []:
        if isinstance(item, Finding):
            out.append(item)
        elif isinstance(item, dict):
            out.append(Finding.from_dict(item))
        else:
            continue
    return out
