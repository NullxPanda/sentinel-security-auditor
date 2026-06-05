# SentinelOps

**Repo:** https://github.com/TrippyDev/sentinel (renamed from TrippyD3v/sentinel-security-auditor)

Sentinel is a learning-driven system focused on backend + security thinking.

Now includes GitHub Actions scanner for AI coding agent prompt injection risks (Claude Code GitHub Action style flaws from 2026). Scans local workflows for dangerous triggers, broad perms, bot allowlists, and raw untrusted input to AI — exactly the vectors that let one malicious issue hijack repos or poison supply chains. See historical AI-GHA-2026-* patterns and the main run output.

Core question:
What actually matters on a system right now?

---

## Signal

Most tools produce noise.
Sentinel reduces that into what requires action.

---

## Mode

* local system analysis
* defensive focus
* no exploitation

---

## System View

```
sentinel_ops :: boot
[ sentinel security auditor ]
----------------------------------------
> read.system()
> parse.signal()
> reduce.noise()
----------------------------------------
sentinel :: active
purpose:
find what actually matters
method:
installed -> running -> exposed -> actionable
----------------------------------------
signal:
CVE-XXXX
urgency: immediate
> service: running
> exposure: network
action: patch
----------------------------------------
status: in_progress
mode: learning
----------------------------------------
:: sentinel_ops ::

   .----.   @   @
  / .-"-.`.  \v/
  | | '\ \ \_/ )
 ,-\ `-.' /.'  /
 '---`----'----'

> system read complete
> signal clean

h3llo!
```

---

## CVE Data Source

CVE intelligence is fetched from the NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`).

**Optional but recommended:** For much higher rate limits, get a free API key at https://nvd.nist.gov/developers/request-an-api-key and set the environment variable `NVD_API_KEY` before running Sentinel. The key is only read from your environment at runtime — it is never stored in this repository or any file created by this project.
