# Challenge: Phase 0 → 1 weekend push

**Accepted:** A + B + C + D  
**Window:** Friday night + 2 days  
**Flagship:** Sentinel @ `/home/ghostnode/projects/sentinel`

## Definition of Done (Phase 0)

- [x] Canonical root declared (BACKBONE + AGENTS)
- [x] Stable `Finding` model used by new modules
- [x] Scanner interface documented in code (`scanner/base.py`)
- [x] Ransomware-**class** module + fixtures + tests
- [x] DNS-**class** module + fixtures + tests
- [x] Unified reporter: what / why / evidence / action / do_not
- [x] `--offline` path works without NVD
- [x] `python3 -m unittest discover -s tests` green (7 tests)
- [x] README: product sentence, install, limitations, what we don't detect
- [x] Git: small commits, no force-push (`335b650` on feature/phase2-supplychain — no force)

## Phase 1 stretch (weekend → Session 2)

- [x] Demo receipt script / one-liner in README proven on cold shell (`scripts/demo_cold.sh`, `python3 sentinel.py --demo`)
- [x] Tighten GHA + shiny normalizers fully onto Finding fields everywhere (`correlator/normalize.py`)
- [x] Historical section: less wall-of-text, more action boxes (reporter + `_HISTORICAL_ACTIONS`)
- [x] Optional: go-guard wired in default CI-less test skip if binary missing
- [x] Duo comments pass (`#` why-notes on orchestrator / scanners / normalize) + COLLAB.md

## Rules of engagement

1. One WIP: Sentinel  
2. Commit messages explain *why*  
3. Stuck 25m → write failure + evidence, then ask  
4. No new feature if install/tests broken  
5. Receipts: short list of what shipped each session  

## Session 1 receipt (2026-07-10)

Shipped:

- BACKBONE.md / AGENTS.md / CHALLENGE.md as system memory  
- Finding model + blue-team reporter  
- ransomware-class + dns-class scanners + safe fixtures  
- offline CLI (`--offline --modules --root`)  
- 7 unittest cases green  
- Canonical vs TrippyD3v pointer clarified  

## Session 2 receipt (2026-07-10)

Shipped (Phase 1 chassis + duo working style):

- `correlator/normalize.py` — one dialect for historical / GHA / shiny / live / go-guard  
- `sentinel.py` orchestrator: `--demo`, offline module set, normalize-before-filter  
- Operator blocks: Action / Do NOT stable in `reporting/reporter.py`  
- `scripts/demo_cold.sh` + README cold path + COLLAB.md  
- `#` comments on detection/orchestration files (for us; not in operator text)  
- Tests: 11 green (`test_normalize` + class fixtures + offline CLI)  

Next session → Challenge **A ∪ B ∪ C** focus (see end of this file).

## Challenge A ∪ B ∪ C (next plan)

| Letter | Meaning (BACKBONE) | Next concrete work |
|--------|--------------------|--------------------|
| **A** | Session work — audit, cold-run, first green path | Re-run cold demo after clean checkout; fix any red; session receipt only when green |
| **B** | Written protocol in-repo | Keep CHALLENGE / BACKBONE / COLLAB honest; no tribal knowledge outside the tree |
| **C** | Flagship is Sentinel | No side toys; every hour goes into this root until Phase 1 feels boring-solid |

Optional Phase 1+ after A∪B∪C is green: fewer FPs on shiny, more fixtures, lab notes — not Phase 2 theater.

## Respect metric

Not vibes. Cold clone → signal → tests → history a teammate can follow.
