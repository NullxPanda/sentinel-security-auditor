"""
GitHub Actions / AI-agent risk scanner.

Built together for the 2026 Claude Code GitHub Action class of flaws:
  - untrusted triggers (issues / PR target / discussion)
  - bot allowlist bypasses
  - raw issue body → AI prompt
  - broad write perms + AI

# comments are intentional — this file is how we teach ourselves detection eng.
If you tune a rule, note WHY in a # comment so we don't thrash later.
Operator Action/Do NOT live in GHA_ACTION / GHA_DO_NOT (not mixed into needles).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


def _read_lower(p: Path) -> str:
    # Case-fold once; all rules match on lower text
    try:
        return p.read_text(errors="ignore").lower()
    except OSError:
        return ""


def _has_any(text: str, *subs: str) -> bool:
    return any(s in text for s in subs)


def _has_actor_guard(text: str) -> bool:
    # Human / collab association checks reduce drive-by issue abuse
    return "author_association" in text and _has_any(text, "owner", "member", "collaborator")


def _has_pinned_claude_action(text: str) -> bool:
    # Patched line in the 2026 writeups — keep list updated as pins move
    # Substring match is intentional (covers uses: lines with full org path)
    return _has_any(
        text,
        "claude-code-action@v1.0.9",
        "claude-code-action@v1.0.10",
        "claude-code-action@v1.0.94",
        "claude-code-action@1.0.94",
    )


def _uses_claude_action(text: str) -> bool:
    return _has_any(text, "claude-code-action", "anthropics/claude-code-action")


def _has_untrusted_trigger(text: str) -> bool:
    # These fire on content attackers can write without repo write access
    return _has_any(text, "issues:", "issue_comment:", "pull_request_target:", "discussion:")


def _has_raw_prompt_passthrough(text: str) -> bool:
    """True when untrusted event body is fed toward an agent without a safety marker."""
    if not _has_any(text, "github.event.issue.body", "github.event.pull_request.body"):
        return False
    # Escape hatches we recognize as "someone thought about this"
    if _has_any(text, "safe_body", "do not execute commands"):
        return False
    # Common copy-paste patterns from vulnerable examples
    return "| claude" in text or (
        "processing:" in text and "github.event.issue.body" in text
    )


# Shared playbook text — one place so normalize_gha and scanner stay aligned
# (operator-facing; not detection needles)
GHA_ACTION = (
    "Update claude-code-action to >=1.0.94 (or current patched pin). "
    "Require github.event.sender.type == 'User' and write-access checks. "
    "Least-privilege permissions. Never feed raw untrusted text to AI with write tokens."
)
GHA_DO_NOT = (
    "Do not use allowed_non_write_users: '*' or [bot] allowlists that any GitHub App can spoof. "
    "Do not grant contents:write on untrusted issue triggers."
)


def scan_github_workflows(root: str = ".") -> List[Dict[str, Any]]:
    """
    Fast string scan (no extra deps) over .github/workflows/*.yml|yaml.

    Returns legacy-friendly dicts; sentinel.main runs them through
    correlator.normalize.normalize_gha so operators always see Action / Do NOT.
    """
    findings: List[Dict[str, Any]] = []
    rootp = Path(root)
    # Only workflow files (not whole .github — actions/ is a different story later)
    workflow_files = list(rootp.glob(".github/workflows/*.yml")) + list(
        rootp.glob(".github/workflows/*.yaml")
    )

    for wf_path in workflow_files:
        content = _read_lower(wf_path)
        if not content:
            continue

        risks: List[str] = []

        # Unpinned / old claude-code-action (patched >=1.0.94 class)
        if _uses_claude_action(content) and not _has_pinned_claude_action(content):
            risks.append(
                "claude-code-action not pinned to a known-patched release — prompt-injection bypass class."
            )

        # Untrusted triggers without author guard
        if "on:" in content and _has_untrusted_trigger(content) and not _has_actor_guard(content):
            risks.append(
                "Workflow triggers on issues/PRs/discussions without author_association guard."
            )

        # Broad write + AI on the same workflow = high blast radius
        if _has_any(content, "contents: write", "issues: write") and _has_any(
            content, "claude", "anthropic"
        ):
            risks.append(
                "Broad write permissions (contents/issues) granted in a workflow that invokes AI "
                "on potentially untrusted content."
            )

        # Classic * bypass (Anthropic already warned; many repos still copy it)
        if "allowed_non_write_users" in content and "*" in content:
            risks.append(
                'allowed_non_write_users: "*" or equivalent — allows untrusted users to feed content to AI.'
            )

        # Bot allowlist bypass (core 2026 flaw narrative)
        if "[bot]" in content or ("endswith" in content and "bot" in content):
            risks.append(
                "Custom [bot] allowlist detected — spoofable via GitHub App issues (2026 Claude Code class)."
            )

        # Direct pipe of untrusted body into agent
        if _has_raw_prompt_passthrough(content):
            risks.append(
                "Raw issue/PR body piped into AI prompt — classic indirect prompt injection vector."
            )

        if not risks:
            continue

        # Severity: anything that smells like the known bypass class → CRITICAL
        critical = any(
            key in r.lower()
            for r in risks
            for key in ("piped", "[bot]", "not pinned", "allowed_non_write")
        )
        rel = str(wf_path)
        findings.append(
            {
                "id": f"GHA-RISK:{rel}",
                "workflow": rel,
                "file": rel,
                "risks": risks,
                "severity": "CRITICAL" if critical else "HIGH",
                "recommendation": GHA_ACTION,
                "action": GHA_ACTION,
                "do_not": GHA_DO_NOT,
            }
        )

    return findings


def get_github_action_findings(root: str = ".") -> List[Dict[str, Any]]:
    """Public entry used by sentinel.py / scanner package."""
    return scan_github_workflows(root)
