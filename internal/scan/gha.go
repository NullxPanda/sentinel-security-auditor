package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TrippyDev/sentinel/guard/internal/models"
	"github.com/TrippyDev/sentinel/guard/internal/pathguard"
	"gopkg.in/yaml.v3"
)

func hasActorGuard(content string) bool {
	return strings.Contains(content, "author_association") &&
		(strings.Contains(content, "owner") ||
			strings.Contains(content, "member") ||
			strings.Contains(content, "collaborator"))
}

func hasPinnedClaudeAction(content string) bool {
	return strings.Contains(content, "claude-code-action@v1.0.9") ||
		strings.Contains(content, "claude-code-action@v1.0.10")
}

func usesClaudeAction(content string) bool {
	return strings.Contains(content, "claude-code-action") ||
		strings.Contains(content, "anthropics/claude-code-action")
}

func hasUntrustedTrigger(content string, doc map[string]any) bool {
	on, ok := doc["on"]
	if !ok {
		return strings.Contains(content, "issues:") ||
			strings.Contains(content, "pull_request_target:")
	}
	onStr := strings.ToLower(fmt.Sprint(on))
	return strings.Contains(onStr, "issues") ||
		strings.Contains(onStr, "issue_comment") ||
		strings.Contains(onStr, "pull_request_target") ||
		strings.Contains(onStr, "discussion")
}

func hasRawPromptPassthrough(content string) bool {
	if !strings.Contains(content, "github.event.issue.body") &&
		!strings.Contains(content, "github.event.pull_request.body") {
		return false
	}
	// Hardened workflows sanitize and use a fixed template.
	if strings.Contains(content, "safe_body") || strings.Contains(content, "do not execute commands") {
		return false
	}
	return strings.Contains(content, "| claude") ||
		(strings.Contains(content, "processing:") && strings.Contains(content, "github.event.issue.body"))
}

// riskPatterns flag real attack chains, not every mention of Claude.
var riskPatterns = []struct {
	name     string
	check    func(content string, doc map[string]any) bool
	severity string
	desc     string
}{
	{
		name: "unpinned-claude-code-action",
		check: func(content string, _ map[string]any) bool {
			return usesClaudeAction(content) && !hasPinnedClaudeAction(content)
		},
		severity: "CRITICAL",
		desc:     "claude-code-action not pinned to >=v1.0.94 — known prompt-injection bypass class.",
	},
	{
		name: "untrusted-trigger",
		check: func(content string, doc map[string]any) bool {
			return hasUntrustedTrigger(content, doc) && !hasActorGuard(content)
		},
		severity: "HIGH",
		desc:     "Untrusted trigger (issues/PR/discussion) without author_association guard.",
	},
	{
		name: "broad-write-ai",
		check: func(content string, _ map[string]any) bool {
			hasWrite := strings.Contains(content, "contents: write") ||
				strings.Contains(content, "issues: write")
			hasAI := strings.Contains(content, "claude") || strings.Contains(content, "anthropic")
			return hasWrite && hasAI
		},
		severity: "HIGH",
		desc:     "Broad write permissions combined with AI on potentially untrusted content.",
	},
	{
		name: "bot-allowlist-bypass",
		check: func(content string, _ map[string]any) bool {
			return strings.Contains(content, "[bot]") ||
				(strings.Contains(content, "endswith") && strings.Contains(content, "bot"))
		},
		severity: "CRITICAL",
		desc:     "[bot] allowlist pattern — attackers can register GitHub Apps named *bot.",
	},
	{
		name: "raw-prompt-injection",
		check: func(content string, _ map[string]any) bool {
			return hasRawPromptPassthrough(content)
		},
		severity: "CRITICAL",
		desc:     "Raw issue/PR body piped into AI prompt — indirect prompt injection vector.",
	},
}

const ghaRecommendation = "Update claude-code-action to >=1.0.94. Add if: github.event.sender.type == 'User' " +
	"with write checks. Limit permissions. Never pass raw untrusted text to AI."

// GitHubActions scans .github/workflows with path hardening + YAML validation.
func GitHubActions(root string) ([]models.Finding, error) {
	absRoot, err := pathguard.ResolveRoot(root)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding
	wfDir := filepath.Join(absRoot, ".github", "workflows")

	entries, err := os.ReadDir(wfDir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, nil
		}
		return nil, fmt.Errorf("read workflows dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		rel := filepath.Join(".github", "workflows", name)
		data, err := pathguard.ReadBounded(absRoot, rel)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		var doc map[string]any
		_ = yaml.Unmarshal(data, &doc) // partial parse is fine; string checks still apply

		var risks []string
		maxSev := "HIGH"
		for _, pat := range riskPatterns {
			if pat.check(content, doc) {
				risks = append(risks, pat.desc)
				if pat.severity == "CRITICAL" {
					maxSev = "CRITICAL"
				}
			}
		}

		if len(risks) == 0 {
			continue
		}

		findings = append(findings, models.Finding{
			ID:             rel,
			Category:       "gha",
			Severity:       maxSev,
			File:           rel,
			Signal:         strings.Join(risks, " | "),
			Description:    strings.Join(risks, "; "),
			Recommendation: ghaRecommendation,
			Tags:           []string{"github-actions", "prompt-injection", "supply-chain", "go-guard"},
		})
	}

	return findings, nil
}