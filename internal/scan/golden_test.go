package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/report"
)

// TestDemoFixtureGolden compares rendered reports to testdata/golden.
//
// Identity and fingerprint hash the finding key, and that key contains the
// absolute path. Replacing the path text in the rendered file does not change
// those hashes, so a checkout in another directory (or on Windows, where the
// same path uses backslashes) cannot match a golden built elsewhere.
// The test rewrites scan roots to fixed placeholders, uses slash paths, and
// recomputes the hashes before rendering. The golden is therefore a function
// of the fixture, not of the machine, the OS, or the Go version.
func TestDemoFixtureGolden(t *testing.T) {
	root := moduleRoot(t)
	home := filepath.Join(root, "demo", "fixtures", "home")
	sys := filepath.Join(root, "demo", "fixtures", "system")
	temp := filepath.Join(root, "demo", "fixtures", "temp")
	// The fixture npm token is a normal private config. Git does not store
	// 0600, so pin the mode before comparing goldens.
	if err := os.Chmod(filepath.Join(home, ".npmrc"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		Home: home, SystemRoot: sys, TempDir: temp,
		GOOS: "linux", Username: "dev", Now: fixedNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	const token = "npm_DemoTokenValueShouldNeverPrint0001"
	rules := map[string]bool{}
	for _, f := range rep.Findings {
		rules[f.RuleID] = true
		if strings.Contains(f.Evidence+f.Title+f.Description, token) {
			t.Fatal("demo token leaked")
		}
	}
	for _, id := range []string{
		"cursor-claude-ext-ssh-key",
		"cursor-claude-ext-smt-files",
		"cursor-claude-ext-launchagent",
		"cursor-claude-ext-startup-sysmon",
		"cursor-claude-ext-task-sysmon",
		"cursor-claude-ext-stk-temp",
		"cursor-claude-ext-cron-smt",
		"shai-hulud-claude-hook",
		"shai-hulud-vscode-task",
		"shai-hulud-setup-mjs",
		"ssh.command",
		"pkg.token",
		"shell.suspicious",
		"git.hooksPath",
	} {
		if !rules[id] {
			t.Errorf("missing %s", id)
		}
	}
	rep = canonicalize(rep, []rootSub{
		{home, "/home/dev"},
		{sys, "/system"},
		{temp, "/temp"},
	})
	for _, format := range []string{"text", "json", "markdown", "sarif"} {
		buf, err := report.Render(format, rep)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.ReplaceAll(string(buf), "\r\n", "\n")
		if strings.Contains(got, token) {
			t.Fatalf("%s leaked token", format)
		}
		if strings.Contains(got, home) || strings.Contains(got, sys) || strings.Contains(got, temp) {
			t.Fatalf("%s still contains a machine path", format)
		}
		ext := format
		if format == "markdown" {
			ext = "md"
		}
		path := filepath.Join(root, "testdata", "golden", "demo."+ext)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		wantBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s: %v (set UPDATE_GOLDEN=1 to create)", path, err)
		}
		want := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")
		if got != want {
			t.Fatalf("%s golden mismatch\n--- got ---\n%s", format, got)
		}
	}
}

// TestCanonicalizeIsStableAcrossPathSpellings checks the rewrite used by the
// golden test: a Windows absolute path and a POSIX absolute path for the same
// fixture produce the same identity.
func TestCanonicalizeIsStableAcrossPathSpellings(t *testing.T) {
	posix := model.Finalize(model.Finding{
		RuleID: "ioc.example", Collector: "ioc", Severity: model.Critical,
		Title: "example", Path: "/work/home/.ssh/authorized_keys",
		Evidence: "path exists", Key: "ioc.example:/work/home/.ssh/authorized_keys",
	})
	win := model.Finalize(model.Finding{
		RuleID: "ioc.example", Collector: "ioc", Severity: model.Critical,
		Title: "example", Path: `C:\work\home\.ssh\authorized_keys`,
		Evidence: "path exists", Key: `ioc.example:C:\work\home\.ssh\authorized_keys`,
	})
	a := canonicalize(model.Report{Home: "/work/home", Findings: []model.Finding{posix}}, []rootSub{{"/work/home", "/home/dev"}})
	b := canonicalize(model.Report{Home: `C:\work\home`, Findings: []model.Finding{win}}, []rootSub{{`C:\work\home`, "/home/dev"}})
	if a.Findings[0].Identity != b.Findings[0].Identity || a.Findings[0].Fingerprint != b.Findings[0].Fingerprint {
		t.Fatalf("posix %s %s\nwindows %s %s", a.Findings[0].Identity, a.Findings[0].Fingerprint, b.Findings[0].Identity, b.Findings[0].Fingerprint)
	}
	if a.Findings[0].Path != "/home/dev/.ssh/authorized_keys" || b.Findings[0].Path != a.Findings[0].Path {
		t.Fatalf("paths %q %q", a.Findings[0].Path, b.Findings[0].Path)
	}
}

type rootSub struct {
	from string
	to   string
}

func canonicalize(rep model.Report, subs []rootSub) model.Report {
	ordered := append([]rootSub(nil), subs...)
	// Longer roots first so "/home/dev" cannot be partially eaten by a shorter prefix.
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if len(ordered[j].from) > len(ordered[i].from) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	rep.Home = canonPath(rep.Home, ordered)
	rep.Project = canonPath(rep.Project, ordered)
	for i, f := range rep.Findings {
		f.Path = canonPath(f.Path, ordered)
		f.Key = substRoots(f.Key, ordered)
		f.Key = strings.ReplaceAll(f.Key, `\`, "/")
		f.Evidence = substRoots(f.Evidence, ordered)
		f.Identity = ""
		f.Fingerprint = ""
		rep.Findings[i] = model.Finalize(f)
	}
	for i, d := range rep.Diagnostics {
		d.Path = canonPath(d.Path, ordered)
		d.Message = substRoots(d.Message, ordered)
		rep.Diagnostics[i] = d
	}
	return rep
}

func canonPath(p string, subs []rootSub) string {
	if p == "" {
		return ""
	}
	// filepath.ToSlash only rewrites the host separator, so a Windows path
	// checked on Linux would keep its backslashes. Always use '/'.
	return strings.ReplaceAll(substRoots(p, subs), `\`, "/")
}

func substRoots(s string, subs []rootSub) string {
	for _, sub := range subs {
		if sub.from == "" {
			continue
		}
		s = strings.ReplaceAll(s, sub.from, sub.to)
		slash := filepath.ToSlash(sub.from)
		if slash != sub.from {
			s = strings.ReplaceAll(s, slash, sub.to)
		}
	}
	return s
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
