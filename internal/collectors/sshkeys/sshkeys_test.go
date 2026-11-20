package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectKeysAndCommand(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "ssh-ed25519 AAAA dev-laptop\n" +
		"command=\"echo hi\",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry\n"
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Collect(home)
	if len(got.Findings) != 2 {
		t.Fatalf("%d findings", len(got.Findings))
	}
	var info, high int
	for _, f := range got.Findings {
		if strings.Contains(f.Evidence, "AAAAC3Nza") {
			t.Fatalf("key material leaked: %s", f.Evidence)
		}
		switch f.Severity {
		case "info":
			info++
		case "high":
			high++
			if f.RuleID != "ssh.command" {
				t.Fatal(f.RuleID)
			}
			if !strings.Contains(f.Evidence, "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk") {
				t.Fatal(f.Evidence)
			}
		}
	}
	if info != 1 || high != 1 {
		t.Fatalf("info %d high %d", info, high)
	}
}

func TestSymlinkEscape(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("UNIQUE-SECRET-OUTSIDE-ROOT-9f3a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	got := Collect(home)
	blob := ""
	for _, f := range got.Findings {
		blob += f.Evidence + f.Title
		if f.RuleID != "ssh.symlink-escape" {
			t.Fatalf("rule %s", f.RuleID)
		}
	}
	if strings.Contains(blob, "UNIQUE-SECRET-OUTSIDE-ROOT-9f3a") {
		t.Fatal("leaked symlink target")
	}
}
