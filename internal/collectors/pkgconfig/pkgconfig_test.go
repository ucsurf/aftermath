package pkgconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNpmrcTokenNotPrinted(t *testing.T) {
	home := t.TempDir()
	const token = "npm_DemoTokenValueShouldNeverPrint0001"
	body := "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=" + token + "\n"
	path := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Collect(home, "linux")
	if len(got.Findings) != 1 {
		t.Fatalf("%#v", got.Findings)
	}
	f := got.Findings[0]
	if f.Severity != "medium" || f.RuleID != "pkg.token" {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Description, "should be rotated") {
		t.Fatalf("missing rotate note: %s", f.Description)
	}
	if strings.Contains(f.Evidence, token) || strings.Contains(f.Title, token) {
		t.Fatalf("token leaked: %+v", f)
	}
}

func TestNpmrcTokenHighWhenUnusual(t *testing.T) {
	home := t.TempDir()
	const token = "npm_DemoTokenValueShouldNeverPrint0001"
	path := filepath.Join(home, ".npmrc")
	body := "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=" + token + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home, "linux")
	// Windows file modes have no other-read bit, so the world-readable case is Unix only.
	if runtime.GOOS != "windows" {
		if len(got.Findings) != 1 || got.Findings[0].Severity != "high" || !strings.Contains(got.Findings[0].Title, "world-readable") {
			t.Fatalf("world-readable: %#v", got.Findings)
		}
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Evidence, token) {
			t.Fatal("token leaked")
		}
	}

	body = "registry=https://npm.example.test/\n//npm.example.test/:_authToken=" + token + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got = Collect(home, "linux")
	var tokenSev, sawRegistry string
	for _, f := range got.Findings {
		if strings.Contains(f.Evidence+f.Title, token) {
			t.Fatal("token leaked")
		}
		if f.RuleID == "pkg.token" {
			tokenSev = string(f.Severity)
		}
		if f.RuleID == "pkg.registry" {
			sawRegistry = string(f.Severity)
		}
	}
	if tokenSev != "high" || sawRegistry != "medium" {
		t.Fatalf("token %s registry %s findings %#v", tokenSev, sawRegistry, got.Findings)
	}
}

func TestPypircAndGradle(t *testing.T) {
	home := t.TempDir()
	const pw = "super-secret-pypi-password"
	if err := os.WriteFile(filepath.Join(home, ".pypirc"), []byte("[pypi]\npassword = "+pw+"\nrepository = https://upload.example/legacy/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".gradle", "init.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.gradle"), []byte("println 'hi'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home, "linux")
	var tokenSev, registry, init bool
	for _, f := range got.Findings {
		blob := f.Title + f.Evidence + f.Description
		if strings.Contains(blob, pw) {
			t.Fatalf("password leaked: %+v", f)
		}
		switch f.RuleID {
		case "pkg.token":
			tokenSev = f.Severity == "high"
		case "pkg.registry":
			registry = true
		case "pkg.init-script":
			init = f.Severity == "medium"
		}
	}
	if !tokenSev || !registry || !init {
		t.Fatalf("tokenHigh %v registry %v init %v findings %#v", tokenSev, registry, init, got.Findings)
	}
}
