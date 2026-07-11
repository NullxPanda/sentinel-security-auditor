#!/usr/bin/env bash
# demo_cold.sh — stranger-proof / teammate-proof offline demo
#
# Why this exists (team note):
#   Cold path must work without NVD, without Go binary, without tribal knowledge.
#   If this script fails, Phase 1 is not done.
#
# Usage (from repo root OR anywhere):
#   bash scripts/demo_cold.sh
#   # or: python3 sentinel.py --demo

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Sentinel cold demo (offline, fixtures, together-mode)"
echo "    root: $ROOT"
echo

# stdlib tests first — trust before demo theater
python3 -m unittest discover -s tests -v

echo
echo "==> Operator-facing demo output"
python3 sentinel.py --demo

echo
echo "==> Class modules only (fixtures)"
python3 sentinel.py --offline \
  --modules ransomware-class,dns-class \
  --root test-fixtures

echo
echo "OK — cold path green. Doctrine: BACKBONE.md"
