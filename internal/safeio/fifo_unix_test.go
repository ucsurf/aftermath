//go:build !windows

package safeio

import (
	"syscall"
	"testing"
)

func makeFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
