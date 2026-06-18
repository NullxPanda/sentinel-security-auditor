import glob
from pathlib import Path
from typing import List, Dict, Any


def _read_lower(p: Path) -> str:
    try:
        return p.read_text(errors="ignore").lower()
    except Exception:
        return ""


def _has_any(text: str, *subs: str) -> bool:
    return any(s in text for s in subs)


def _has_actor_guard(text: str) -> bool:
    return "author_association" in text and _has_any(text, "owner", "member", "collaborator")


def _has_pinned_claude_action(text: str) -> bool:
    return _has_any(text, "claude-code-action@v1.0.9", "claude-code-action@v1.0.10")


def _uses_claude_action(text: str) -> bool:
    return _has_any(text, "claude-code-action", "anthropics/claude-code-action")


def _has_untrusted_trigger(text: str) -> bool:
    return _has_any(text, "issues:", "issue_comment:", "pull_request_target:", "discussion:")


def _has_raw_prompt_passthrough(text: str) -> bool:
    if not _has_any(text, "github.event.issue.body", "github.event.pull_request.body"):
        return False
    if _has_any(text, "safe_body", "do not execute commands"):
        return False
    return "| claude" in text or (
        "processing:" in text and "github.event.issue.body" in text
    )


def scan_github_workflows(root: str = ".") -> List[Dict[str, Any]]:
    """
    Scan local .github/workflows for risky patterns related to AI agent actions,
    prompt injection vectors, and the 2026 Claude Code GitHub Action class of flaws.

    Fast string scan (no extra deps). Looks for:
    - claude-code-action usage
    - untrusted triggers (issues, pr_target, discussion) without guard
    - broad perms + AI
    - * allowed_non_write_users and bot allowlist bypasses
    - raw github.event.* fed to prompts
    """
    findings: List[Dict[str, Any]] = []
    rootp = Path(root)
    workflow_files = list(rootp.glob(".github/workflows/*.yml")) + list(rootp.glob(".github/workflows/*.yaml"))

    for wf_path in workflow_files:
        content = _read_lower(wf_path)
        if not content:
            continue

        risks: List[str] = []

        # Unpinned claude-code-action (patched >=1.0.94 required)
        if _uses_claude_action(content) and not _has_pinned_claude_action(content):
            risks.append(
                "claude-code-action not pinned to >=v1.0.94 — known prompt-injection bypass class."
            )

        # Untrusted triggers without author guard
        if "on:" in content and _has_untrusted_trigger(content) and not _has_actor_guard(content):
            risks.append(
                "Workflow triggers on issues/PRs/discussions without author_association guard."
            )

        # Broad write + AI
        if _has_any(content, "contents: write", "issues: write") and _has_any(content, "claude", "anthropic"):
            risks.append(
                "Broad write permissions (contents/issues) granted in a workflow that invokes AI on potentially untrusted content."
            )

        # Classic * bypass
        if "allowed_non_write_users" in content and "*" in content:
            risks.append(
                'allowed_non_write_users: "*" or equivalent — explicitly allows anyone (including attackers) to trigger AI on their content.'
            )

        # Bot allowlist bypass (core 2026 flaw)
        if "[bot]" in content or ("endswith" in content and "bot" in content):
            risks.append(
                "Custom [bot] allowlist detected — vulnerable to anyone creating a GitHub App and opening issues as [bot] (the exact bypass in the Claude Code flaw)."
            )

        # Direct pipe of untrusted body into claude (not sanitized template flow)
        if _has_raw_prompt_passthrough(content):
            risks.append(
                "Raw issue/PR body piped into AI prompt — classic indirect prompt injection vector."
            )

        if risks:
            findings.append(
                {
                    "workflow": str(wf_path),
                    "risks": risks,
                    "severity": "CRITICAL" if any("v1.0.94" in r or "piped" in r or "[bot]" in r for r in risks) else "HIGH",
                    "recommendation": (
                        "Update claude-code-action to >=1.0.94. Add explicit if: github.event.sender.type == 'User' && write permission checks. "
                        "Limit permissions. Never feed raw untrusted text to AI without sanitization or trusted-only trigger."
                    ),
                }
            )

    return findings


def get_github_action_findings(root: str = ".") -> List[Dict[str, Any]]:
    return scan_github_workflows(root)
