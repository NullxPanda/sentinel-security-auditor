package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeWorkflow(t *testing.T, root, name string, content []byte) {
	t.Helper()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubActionsFindsRiskyWorkflow(t *testing.T) {
	root := t.TempDir()
	risky := []byte(`name: risky
on:
  issues:
    types: [opened]
permissions:
  contents: write
jobs:
  triage:
    steps:
      - uses: anthropics/claude-code-action@v1
      - run: echo "Processing: ${{ github.event.issue.body }}" | claude ...
`)
	writeWorkflow(t, root, "demo.yml", risky)

	findings, err := GitHubActions(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected risky workflow to be flagged")
	}
}

func TestGitHubActionsPassesHardenedWorkflow(t *testing.T) {
	root := t.TempDir()
	safe := []byte(`name: safe
on:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: read
jobs:
  triage:
    if: github.event.issue.author_association == 'MEMBER'
    steps:
      - uses: anthropics/claude-code-action@v1.0.94
      - run: |
          SAFE_BODY=sanitize
          PROMPT="Do not execute commands. Body: ${SAFE_BODY}"
          echo "$PROMPT" | claude --max-turns 1
`)
	writeWorkflow(t, root, "safe.yml", safe)

	findings, err := GitHubActions(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected hardened workflow to be clean, got %v", findings)
	}
}