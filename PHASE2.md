# Phase 2 — continuous · fewer FPs · real lab

**Status:** OPEN (Session 3, after A∪B∪C green)  
**Canonical:** `/home/ghostnode/projects/sentinel`  
**Doctrine parent:** BACKBONE.md (Phase 2 row)

## Why Phase 2 exists

Phase 0–1 proved: one tree, Finding chassis, class detectors, cold demo, Action/Do NOT.

Phase 2 makes that **usable day-to-day**:
1. **Continuous scans** — re-run without re-learning the CLI  
2. **Fewer FPs** — baseline / allowlist so noise does not train you to ignore CRITICAL  
3. **Real lab** — a place for notes + safe fixtures that is not production chaos  

Still **not** EDR. Still offline-first. AI still does not kill.

## Working slices (order)

| Slice | Deliverable | Done when | Status |
|-------|-------------|-----------|--------|
| P2.1 | `scripts/scan_loop.sh` (+ README note) | loop runs class modules offline, Ctrl+C exits clean | **done** Session 3 |
| P2.2 | `config/baseline_allowlist.txt` + `--baseline` | known finding keys suppressible; test covers suppress | **done** Session 3 |
| P2.3 | `lab/README.md` + lab rules | lab path documented; no malware policy restated | **done** Session 3 |
| P2.4 | Shiny FP pass | one noisy pattern narrowed + fixture still proves real hits | **done** Session 3 |
| P2.5 | Receipts | CHALLENGE Session N lists ships | **done** Session 3 |

Remaining polish (still Phase 2, not closed until boring day-to-day use): more lab notes, schedule-friendly exit codes, optional more baselines from real runs.

## Commands (target)

```bash
# cold still sacred
bash scripts/demo_cold.sh

# continuous class scan (offline)
bash scripts/scan_loop.sh --interval 60

# with baseline (skip known noise)
python3 sentinel.py --offline --modules ransomware-class,dns-class \
  --root test-fixtures --baseline config/baseline_allowlist.txt
```

## FP key format

Allowlist lines are `#` comments or keys:

```text
# category|id|asset_substring
ransomware-class|RW-CLASS-RANSOM-NOTE|lab/known_note.txt
```

Empty file = no suppress. Missing file = no suppress.

## Exit criteria to call Phase 2 “usable”

Cold green + loop works + allowlist works + lab doc exists + at least one FP reduction with test.

Then Phase 3 talk only if we still care (AI rank/explain — never auto-kill).
