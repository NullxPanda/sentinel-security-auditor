# SENTINEL BACKBONE (SYSTEM MEMORY)

**Status:** Living doctrine — Phase 0/1 closed; Phase 2 open (2026-07-10).  
**Canonical root:** `/home/ghostnode/projects/sentinel` (only truth).  
**Pointer stub:** `~/TrippyD3v/projects/sentinel` is not source.

Any agent (Grok, Claude, human) working this repo **must** follow this file.

---

## Product sentence (non-negotiable)

> **Sentinel = local-first blue-team signal reducer: sense → match known-ugly classes → prioritize → recommend contain/patch.**

If a feature cannot defend that sentence, it does not ship.

---

## Mythos (direction, not a clone)

- **Not:** “clone Claude Mythos / dump AI-generated mega-tool.”
- **Yes:** handmade defensive software that approaches **mythos-class speed of insight** for operators:
  - catch **classes** of WannaCry-like behavior (not every 0-day),
  - surface DNS / exposure / misconfig **before** full compromise,
  - give **actionable** contain/patch paths,
  - stay **offline-first / API-optional**.

AI may later **rank/explain**. AI never owns detection or auto-kill.

Surface 4GB / solo / learning Go+Python was **Phase 0**, not a life sentence.  
Ladder: clean core → class modules + fixtures → lab → hardware only when it hurts → optional AI last.

---

## Engineering maturity (always)

| Need | Rule |
|------|------|
| One repo, one truth | Canonical path only; no duplicate trees as “main” |
| Tests + fixtures | Detection without fixtures is fanfic |
| Stable Finding model | `id, category, severity, asset, signal, evidence, description, action, do_not, tags` |
| Module interface | Scanner in → `list[Finding]` out |
| Git discipline | Small commits; **no force-push lifestyle** |
| Boring docs | Cold clone → install → one command → useful output |

---

## Build now / do not build yet

**Built (Phase 0→1 — closed):**  
Finding model, reporters, package/CVE + GHA + path/secrets (cleaned), ransomware-class, DNS-class, normalize dialect, cold demo, containment output, fixtures + tests.

**Build now (Phase 2):**  
Continuous / loop scans, baseline allowlist (fewer FPs), real `lab/` notes, FP reduction with fixtures. See **PHASE2.md**.

**Do not build yet:**  
Full EDR, kernel drivers, live malware zoo, AI block/kill, enterprise DNS sinkhole product, multi-host console.

---

## Blue-team output contract

Every finding should answer:

1. **What** fired  
2. **Why** it matters  
3. **Evidence**  
4. **Action (≤5 min)**  
5. **Do not** (panic wipe, destroy forensics, etc.)

---

## Challenge mode (A∪B∪C∪D)

- **A:** Session work — audit, cold-run, first green path  
- **B:** Written protocol in-repo (`CHALLENGE.md`, this file)  
- **C:** Flagship is **Sentinel** (not a side toy)  
- **D:** Full ladder doctrine above (lab, skills, hardware ROI, scope kill-switch)

**Session 3:** A∪B∪C green (see CHALLENGE.md receipt). Respect currency still applies.

---

## Phases

| Phase | Goal | Status |
|-------|------|--------|
| 0 | Clean core, one tree, tests, install path | **Closed** |
| 1 | 2–3 detection classes + actions, cold demo | **Closed** |
| 2 | Continuous scans, fewer FPs, real lab | **Open** → PHASE2.md |
| 3 | Optional AI rank/explain; multi-host | Not yet |

Phase 3 without Phase 0–1 is theater. Phase 2 without cold green is theater.
