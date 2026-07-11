# Lab — real practice, safe by design

**Phase 2.** This directory is for **notes, scenarios, and safe samples** while learning Sentinel.

## Rules

1. **No live malware binaries.** Text fixtures and decoy configs only.  
2. Prefer `test-fixtures/` for automated tests; use `lab/` for human practice notes.  
3. If you copy a finding path into the baseline allowlist, document *why* in a note here.  
4. Canonical product code stays in repo root — lab is not a second product.  
5. Offline first: practice with  
   `python3 sentinel.py --offline --modules ransomware-class,dns-class --root test-fixtures`

## Suggested first drills

| Drill | Command / action |
|-------|------------------|
| Cold trust | `bash scripts/demo_cold.sh` |
| Class only | `python3 sentinel.py --offline --modules ransomware-class,dns-class --root test-fixtures` |
| Loop watch | `bash scripts/scan_loop.sh --interval 30` (Ctrl+C to stop) |
| Baseline dry | add a lab note, suppress one known path via `config/baseline_allowlist.txt` |

## Notes

Drop short markdown notes as `lab/notes/YYYY-MM-DD-topic.md` when you learn something.
Keep them boring and searchable.
