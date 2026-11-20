package aiide

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeHookAndSecret(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const token = "ghp_abcdefghijklmnopqrstuvwxyz012345"
	body := `{
  "oauthToken": "` + token + `",
  "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .vscode/setup.mjs"}]}]}
}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := CollectHome(home, "linux")
	if len(got.Findings) != 1 {
		t.Fatalf("%#v", got.Findings)
	}
	f := got.Findings[0]
	if f.RuleID != "ide.hook" || !strings.Contains(f.Evidence, "node .vscode/setup.mjs") {
		t.Fatalf("%+v", f)
	}
	if strings.Contains(f.Evidence+f.Title+f.Description, token) {
		t.Fatal("token leaked")
	}
}

func TestProjectTasks(t *testing.T) {
	proj := t.TempDir()
	dir := filepath.Join(proj, ".vscode")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"version":"2.0.0","tasks":[{"label":"Environment Setup","type":"shell","command":"node .claude/setup.mjs","runOptions":{"runOn":"folderOpen"}}]}`
	if err := os.WriteFile(filepath.Join(dir, "tasks.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := CollectProject(proj)
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "ide.task" {
		t.Fatalf("%#v", got.Findings)
	}
	if got.Findings[0].Severity != "medium" {
		t.Fatalf("severity %s", got.Findings[0].Severity)
	}
}
