package depcheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleDepsDoNotImportNetOrExec(t *testing.T) {
	root := moduleRoot(t)
	forbidden := map[string]bool{"net": true, "net/http": true, "os/exec": true}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/...", "./internal/...")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s/%s: %v\n%s", goos, goarch, err, out)
			}
			seenScanner := false
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line == "github.com/ucsurf/aftermath/internal/scan" {
					seenScanner = true
				}
				if forbidden[line] || strings.HasPrefix(line, "net/http/") {
					t.Errorf("%s/%s imports %s", goos, goarch, line)
				}
			}
			if !seenScanner {
				t.Fatalf("%s/%s did not list the scanner", goos, goarch)
			}
		}
	}
}

func TestReadOnlyPackagesDoNotWriteOrExec(t *testing.T) {
	root := moduleRoot(t)
	readonly := []string{
		"internal/collectors",
		"internal/parse",
		"internal/ioc",
		"internal/safeio",
		"internal/scan",
		"internal/redact",
		"internal/model",
		"internal/report",
	}
	bannedSel := map[string]bool{
		"Create": true, "WriteFile": true, "Remove": true, "RemoveAll": true,
		"Rename": true, "Truncate": true, "Chmod": true, "Mkdir": true, "MkdirAll": true,
		"Chtimes": true, "OpenFile": true, "StartProcess": true,
		"Exec": true, "ForkExec": true,
	}
	fset := token.NewFileSet()
	for _, rel := range readonly {
		err := filepath.Walk(filepath.Join(root, rel), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p == "net" || p == "net/http" || p == "os/exec" || strings.HasPrefix(p, "net/http/") {
					t.Errorf("%s imports %s", path, p)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !bannedSel[sel.Sel.Name] {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if id.Name == "os" || id.Name == "syscall" || id.Name == "unix" {
					t.Errorf("%s calls %s.%s", path, id.Name, sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
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
