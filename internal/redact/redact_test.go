package redact

import (
	"strings"
	"testing"
)

func TestTextRemovesKnownShapes(t *testing.T) {
	in := strings.Join([]string{
		`_authToken=npm_DemoTokenValueShouldNeverPrint0001`,
		`password = super-secret-pypi-password`,
		`https://user:super-secret-pypi-password@example.com/a`,
		`ghp_abcdefghijklmnopqrstuvwxyz012345`,
		`AKIAIOSFODNN7EXAMPLE`,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
		"AAAA" + strings.Repeat("A", 90),
	}, "\n")
	out := Text(in)
	for _, secret := range []string{
		"npm_DemoTokenValueShouldNeverPrint0001",
		"super-secret-pypi-password",
		"ghp_abcdefghijklmnopqrstuvwxyz012345",
		"AKIAIOSFODNN7EXAMPLE",
		"BEGIN OPENSSH PRIVATE KEY",
		strings.Repeat("A", 90),
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q still present in %q", secret, out)
		}
	}
	if !strings.Contains(out, Mark) {
		t.Fatalf("expected redaction mark, got %q", out)
	}
	if Text(out) != out {
		t.Fatal("redaction is not idempotent")
	}
}

func TestAssignmentDoesNotReturnValue(t *testing.T) {
	if !Assignment("_authToken", "npm_secret") {
		t.Fatal("expected token key")
	}
	if Assignment("registry", "https://registry.npmjs.org/") {
		t.Fatal("registry is not a secret field")
	}
	if Assignment("password", "  ") {
		t.Fatal("empty password")
	}
}

func FuzzText(f *testing.F) {
	f.Add("password=hunter2")
	f.Add("nothing to see")
	f.Fuzz(func(t *testing.T, s string) {
		out := Text(s)
		if strings.Contains(s, "hunter2") && strings.Contains(out, "hunter2") && strings.Contains(strings.ToLower(s), "password") {
			t.Fatalf("password survived: %q", out)
		}
	})
}
