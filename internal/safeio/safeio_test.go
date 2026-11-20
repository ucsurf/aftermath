package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("UNIQUE-SECRET-OUTSIDE-ROOT-9f3a"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	_, err := Read(link, NewRoots(root), 1024)
	if err != ErrEscape {
		t.Fatalf("err %v", err)
	}
	_, err = ContainsAny(link, NewRoots(root), []string{"UNIQUE"}, 1024)
	if err != ErrEscape {
		t.Fatalf("contains %v", err)
	}
}

func TestReadInsideAndTruncate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	body := []byte(strings.Repeat("A", 100))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path, NewRoots(root), 10)
	if err != nil || !f.Truncated || len(f.Data) != 10 {
		t.Fatalf("%v %+v", err, f)
	}
}

func TestFIFONotOpened(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Read(path, NewRoots(root), 32)
		done <- err
	}()
	select {
	case err := <-done:
		if err != ErrNotRegular {
			t.Fatalf("err %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read blocked on fifo")
	}
}

func TestContainsNeedle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("hello svc-telemetry world"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ContainsAny(path, NewRoots(root), []string{"missing", "svc-telemetry"}, 1024)
	if err != nil || got != "svc-telemetry" {
		t.Fatalf("%v %q", err, got)
	}
}
