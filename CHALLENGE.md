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
- [ ] Git: small commits, no force-push (in progress)

## Phase 1 stretch (remaining weekend)

- [ ] Demo receipt script / one-liner in README proven on cold shell
- [ ] Tighten GHA + shiny normalizers fully onto Finding fields everywhere
- [ ] Historical section: less wall-of-text, more action boxes
- [ ] Optional: go-guard wired in default CI-less test skip if binary missing

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

## Respect metric

Not vibes. Cold clone → signal → tests → history a teammate can follow.
