# Sentinel

**Canonical path:** `/home/ghostnode/projects/sentinel`  
**Doctrine:** [BACKBONE.md](./BACKBONE.md) · [CHALLENGE.md](./CHALLENGE.md) · [AGENTS.md](./AGENTS.md)

## Product sentence

> **Sentinel = local-first blue-team signal reducer: sense → match known-ugly classes → prioritize → recommend contain/patch.**

Not an EDR. Not Mythos-clone theater. Handmade defensive signal tooling for operators who need **what matters now** plus **what to do in five minutes**.

## Mode

- local / offline-first analysis  
- defensive focus only  
- **no exploitation**, no live malware samples  

## Quick start (cold) — stranger / teammate proof

```bash
cd /home/ghostnode/projects/sentinel

# light deps only if you need live CVE later (offline demo needs none beyond stdlib)
python3 -m pip install -r requirements-core.txt --user   # optional for --offline/--demo

# one command (tests + operator demo)
bash scripts/demo_cold.sh

# or just the operator view
python3 sentinel.py --demo

# class fixtures only
python3 sentinel.py --offline --modules ransomware-class,dns-class --root test-fixtures
```

Doctrine we share: [BACKBONE.md](./BACKBONE.md) · [COLLAB.md](./COLLAB.md) · [PHASE2.md](./PHASE2.md) · [CHALLENGE.md](./CHALLENGE.md)

### Phase 2 — continuous + fewer FPs + lab

```bash
# continuous offline class scan (Ctrl+C to stop)
bash scripts/scan_loop.sh --interval 60

# baseline allowlist (category|id|asset_substring) — default file has no active rules
python3 sentinel.py --offline --modules ransomware-class,dns-class \
  --root test-fixtures --baseline config/baseline_allowlist.txt

# lab practice notes (safe fixtures only)
ls lab/
```

Optional full network path (packages + NVD):

```bash
python3 sentinel.py --high-only
# optional: export NVD_API_KEY=...
```

Optional Go guard:

```bash
go build -o bin/sentinel-guard ./cmd/sentinel-guard
python3 sentinel.py --offline --modules gha --go-guard --root .
```

## Modules (Phase 0→2)

| Module | What it does |
|--------|----------------|
| `packages` | Installed packages + live CVE correlate (needs network) |
| `historical` | Local classic / campaign knowledge base |
| `gha` | GitHub Actions AI prompt-injection / supply-chain patterns |
| `shiny` | ShinyHunters-class SaaS/misconfig surface |
| `ransomware-class` | Safe text rules for shadow-copy wipe, ransom notes, SMB worm narrative |
| `dns-class` | Long-label / NXDOMAIN flood / hijack indicators in logs & configs |
| `go-guard` | Optional path-safe GHA + secrets (Go binary) |

## Finding shape (stable)

`id, category, severity, description, asset, signal, evidence, action, do_not, tags`

Every finding aims to answer: **what / why / evidence / action / do not**.

## Filters

```bash
python3 sentinel.py --offline --root test-fixtures \
  --modules ransomware-class,dns-class \
  --filter 'severity>=HIGH'

python3 sentinel.py --list-filters
```

## What we detect / what we don’t

**Do (classes, fixtures, configs, workflows):**  
ransomware *prep* language, DNS abuse *patterns*, GHA AI risks, known misconfig surfaces, optional CVE×package.

**Don’t (yet):**  
kernel EDR, live worm capture, auto-isolate, AI that kills processes, enterprise DNS sinkhole product, every 0-day.

Backups still matter. Sentinel helps you **see earlier** and **limit blast radius** — it does not replace IR or immutable backups.

## Lab rule

Use `test-fixtures/` only. No random malware downloads on the Surface.

## Identity

GitHub history may show `TrippyD3v` / `TrippyDev` renames. **One product name: Sentinel.** One code root (this directory).

## CVE data

Live CVE via NVD API when not `--offline`. Optional `NVD_API_KEY` for rate limits — never commit keys.
