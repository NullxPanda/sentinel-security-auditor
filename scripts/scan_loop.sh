#!/usr/bin/env bash
# scan_loop.sh — Phase 2 continuous offline class scan
#
# Why: re-run without re-learning CLI. Ctrl+C exits clean (no zombie party).
# Not a service manager — just a boring loop for lab / Surface sessions.
#
# Usage (from anywhere):
#   bash scripts/scan_loop.sh
#   bash scripts/scan_loop.sh --interval 30
#   bash scripts/scan_loop.sh --root test-fixtures --modules ransomware-class,dns-class
#   bash scripts/scan_loop.sh --baseline config/baseline_allowlist.txt

set -euo pipefail

ROOT_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_REPO"

INTERVAL=60
SCAN_ROOT="test-fixtures"
MODULES="ransomware-class,dns-class"
BASELINE=""
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval)
      INTERVAL="${2:?}"
      shift 2
      ;;
    --root)
      SCAN_ROOT="${2:?}"
      shift 2
      ;;
    --modules)
      MODULES="${2:?}"
      shift 2
      ;;
    --baseline)
      BASELINE="${2:?}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      EXTRA+=("$1")
      shift
      ;;
  esac
done

echo "sentinel :: scan_loop (Phase 2 continuous)"
echo "  repo    : $ROOT_REPO"
echo "  root    : $SCAN_ROOT"
echo "  modules : $MODULES"
echo "  interval: ${INTERVAL}s"
echo "  baseline: ${BASELINE:-'(none)'}"
echo "  stop    : Ctrl+C"
echo

PASS=0
while true; do
  PASS=$((PASS + 1))
  echo "======== pass $PASS @ $(date -Iseconds) ========"
  CMD=(python3 sentinel.py --offline --modules "$MODULES" --root "$SCAN_ROOT")
  if [[ -n "$BASELINE" ]]; then
    CMD+=(--baseline "$BASELINE")
  fi
  # shellcheck disable=SC2206
  if [[ ${#EXTRA[@]} -gt 0 ]]; then
    CMD+=("${EXTRA[@]}")
  fi
  "${CMD[@]}" || echo "[scan_loop] scan exited non-zero (continuing)"
  echo
  echo "(sleep ${INTERVAL}s — Ctrl+C to stop)"
  sleep "$INTERVAL"
done
