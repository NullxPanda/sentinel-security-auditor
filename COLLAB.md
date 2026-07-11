# We build this together

Not a solo AI dump. Not a vibe tool.

## Rules of the duo

1. **Leave comments** when you change detection rules, thresholds, or module order — future-us is in the room.
2. **Talk in the receipt** (`CHALLENGE.md` session notes) after each push session.
3. **One dialect:** every path ends in Action / Do NOT via `correlator/normalize.py` + `reporting/reporter.py`.
4. **No force-push lifestyle.** Fix forward.
5. **Fixtures before fantasy.** New class rule = new fixture + test.

## Where comments matter most

| File | Why |
|------|-----|
| `scanner/*_class_scanner.py` | Detection brain |
| `correlator/normalize.py` | Playbook actions |
| `vulnerability/historical.py` | Intel rows |
| `sentinel.py` | Module orchestration |
| `BACKBONE.md` | Doctrine memory |

## Cold trust check

```bash
bash scripts/demo_cold.sh
# or
python3 sentinel.py --demo
```

If that fails, stop feature-hunting and fix the chassis.

## Phase 2 extras

```bash
bash scripts/scan_loop.sh --interval 60
python3 sentinel.py --offline --modules ransomware-class,dns-class \
  --root test-fixtures --baseline config/baseline_allowlist.txt
```

Lab notes: `lab/README.md`. Allowlist format: `category|id|asset_substring`.
