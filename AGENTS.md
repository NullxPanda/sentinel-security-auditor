# AGENTS.md — Sentinel

Read **BACKBONE.md** first. It is system memory for this project.

## Canonical root

`/home/ghostnode/projects/sentinel` only.  
Do not treat `~/TrippyD3v/projects/sentinel` as source (pointer/docs only).

## Product

Sentinel = local-first blue-team signal reducer: sense → match known-ugly classes → prioritize → recommend contain/patch.

## Non-negotiables

- Defensive only — no exploit payloads, no malware samples as live binaries.
- Offline-first; network (NVD) is optional.
- Finding model is stable; scanners return `Finding` / dicts with the same keys.
- Tests + fixtures for every detection class.
- No force-push as workflow. Fix forward.
- Scope kill-switch: no EDR/kernel/AI-auto-kill until Phase 0–1 core is green.

## Layout

- `sentinel.py` — CLI entry
- `models/` — Finding + legacy package/CVE types
- `scanner/` — modules (packages, GHA, shiny, ransomware-class, dns-class, …)
- `reporting/` — containment-oriented printer
- `test-fixtures/` — golden inputs (safe)
- `tests/` — unittest (stdlib)
- `cmd/sentinel-guard` — optional Go hardening layer
- `BACKBONE.md` / `CHALLENGE.md` — doctrine

## Run (cold)

```bash
cd /home/ghostnode/projects/sentinel
python3 -m pip install -r requirements-core.txt --user   # light deps
python3 sentinel.py --offline --help
python3 -m unittest discover -s tests -v
```

## When stuck

Reproduce → isolate → smallest fix → test → commit. No delete/reclone thrash.
