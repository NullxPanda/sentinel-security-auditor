package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TrippyDev/sentinel/guard/internal/models"
	"github.com/TrippyDev/sentinel/guard/internal/pathguard"
)

// secretRules are high-signal patterns — we flag, never exfiltrate.
var secretRules = []struct {
	name     string
	pattern  *regexp.Regexp
	severity string
}{
	{
		name:     "aws-access-key",
		pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		severity: "CRITICAL",
	},
	{
		name:     "github-pat",
		pattern:  regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
		severity: "CRITICAL",
	},
	{
		name:     "anthropic-key",
		pattern:  regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{20,}`),
		severity: "CRITICAL",
	},
	{
		name:     "private-key-block",
		pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		severity: "CRITICAL",
	},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	".sentinel_cache": true, "vendor": true,
}

var skipExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".zip": true, ".gz": true, ".pack": true, ".idx": true,
}

// Secrets walks the tree under root and looks for leaked credential patterns.
func Secrets(root string, maxFiles int) ([]models.Finding, error) {
	absRoot, err := pathguard.ResolveRoot(root)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding
	scanned := 0

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable paths, keep walking
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if scanned >= maxFiles {
			return filepath.SkipAll
		}

		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return nil
		}
		if skipExtensions[filepath.Ext(rel)] {
			return nil
		}

		data, err := pathguard.ReadBounded(absRoot, rel)
		if err != nil {
			return nil
		}
		scanned++

		content := string(data)
		for _, rule := range secretRules {
			if rule.pattern.MatchString(content) {
				findings = append(findings, models.Finding{
					ID:             rule.name + "@" + rel,
					Category:       "secrets",
					Severity:       rule.severity,
					File:           rel,
					Signal:         rule.name,
					Description:    "Possible leaked secret pattern: " + rule.name,
					Recommendation: "Rotate the credential immediately. Remove from git history. Use env vars / secret managers.",
					Tags:           []string{"secrets", "credential-leak", "go-guard"},
				})
				break // one finding per file is enough
			}
		}

		// Also catch hardcoded API keys in workflow env (common GHA mistake)
		if strings.Contains(rel, ".github/workflows") && strings.Contains(content, "ANTHROPIC_API_KEY:") {
			if strings.Contains(content, "sk-ant-") || strings.Contains(content, "api_key:") {
				findings = append(findings, models.Finding{
					ID:             "hardcoded-workflow-secret@" + rel,
					Category:       "secrets",
					Severity:       "HIGH",
					File:           rel,
					Signal:         "workflow-hardcoded-secret",
					Description:    "Workflow may contain hardcoded API key instead of ${{ secrets.* }}",
					Recommendation: "Use GitHub encrypted secrets. Never commit keys in workflow YAML.",
					Tags:           []string{"github-actions", "secrets", "go-guard"},
				})
			}
		}

		return nil
	})

	return findings, err
}