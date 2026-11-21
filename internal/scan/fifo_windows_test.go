//go:build windows

package scan

import "testing"

func makeFIFO(t *testing.T, path string) {
	t.Helper()
	t.Skip("named pipes are not created on Windows")
}
