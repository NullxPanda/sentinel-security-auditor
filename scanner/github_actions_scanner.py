import os
import glob
from typing import List, Dict, Any

from models.data_models import GitHubActionFinding  # we'll add this dataclass


def scan_github_workflows(root: str = ".") -> List[Dict[str, Any]]:
    """
    Scan local .github/workflows for risky patterns related to AI agent actions,
    prompt injection vectors, and the 2026 Claude Code GitHub Action class of flaws.

    Looks for:
    - Use of claude-code-action or similar (version if detectable)
    - Triggers on issues / pull_request / discussion without strict write checks
    - Broad permissions (contents: write etc.) combined with untrusted inputs
    - allowed_non_write_users or bot allowlists that are too loose
    - Direct use of github.event.*.body/title in steps that feed AI
    - Public workflow summaries that could leak
    """
    findings: List[Dict[str, Any]] = []
    workflow_files = glob.glob(os.path.join(root, ".github", "workflows", "*.yml")) + \
                     glob.glob(os.path.join(root, ".github", "workflows", "*.yaml"))

    for wf_path in workflow_files:
        try:
            with open(wf_path, "r", errors="ignore") as f:
                content = f.read().lower()
                lines = content.splitlines()

            risks = []

            # Detect AI agent actions
            if "claude-code-action" in content or "anthropics/claude-code-action" in content:
                risks.append("Uses claude-code-action (or fork) — high risk for prompt injection if not pinned to >=1.0.94 and properly gated.")

            # Loose triggers on untrusted events
            if "on:" in content and ("issues:" in content or "issue_comment:" in content or "pull_request_target:" in content or "discussion:" in content):
                if "if:" not in content or "github.event.issue" in content:  # rough
                    risks.append("Workflow triggers on issues/PRs/discussions (common prompt injection entrypoint) without obvious actor/write permission guard.")

            # Broad permissions + AI
            if ("permissions:" in content or "contents: write" in content or "issues: write" in content) and ("claude" in content or "anthropic" in content):
                risks.append("Broad write permissions (contents/issues) granted in a workflow that invokes AI on potentially untrusted content.")

            # The classic bad example
            if "allowed_non_write_users" in content and "*" in content:
                risks.append("allowed_non_write_users: \"*\" or equivalent — explicitly allows anyone (including attackers) to trigger AI on their content.")

            # Bot allowlist bypass risk (the core of the 2026 flaw)
            if "[bot]" in content or "endswith" in content and "bot" in content:
                risks.append("Custom [bot] allowlist detected — vulnerable to anyone creating a GitHub App and opening issues as [bot] (the exact bypass in the Claude Code flaw).")

            # Feeding raw event data to AI without comment
            if ("github.event.issue.body" in content or "github.event.issue.title" in content or "github.event.pull_request.body" in content) and ("anthropic" in content or "claude" in content or "prompt" in content):
                risks.append("Raw issue/PR body/title passed into AI prompt step — classic vector for indirect prompt injection leading to secret exfil or command execution.")

            if risks:
                findings.append({
                    "workflow": wf_path,
                    "risks": risks,
                    "severity": "CRITICAL" if "claude-code-action" in content else "HIGH",
                    "recommendation": "Update claude-code-action to >=1.0.94. Add explicit if: github.event.sender.type == 'User' && write permission checks. Limit permissions. Never feed raw untrusted text to AI without sanitization or trusted-only trigger.",
                })
        except Exception:
            pass

    return findings


def get_github_action_findings(root: str = ".") -> List[Dict[str, Any]]:
    return scan_github_workflows(root)
