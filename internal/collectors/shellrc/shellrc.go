// Package shellrc reads shell and PowerShell startup files.
package shellrc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Collect scans shell startup files under home for suspicious lines.
func Collect(home, goos string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(home)
	for _, path := range files(home, goos) {
		f, err := safeio.Read(path, roots, safeio.MaxRead)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if errors.Is(err, safeio.ErrEscape) {
				out.Findings = append(out.Findings, model.Finalize(model.Finding{
					RuleID:    "shell.symlink-escape",
					Collector: "shell",
					Severity:  model.High,
					Title:     "shell startup file symlink points outside the home directory",
					Path:      path,
					Evidence:  "target not read",
					Key:       "escape:" + path,
				}))
				continue
			}
			if errors.Is(err, safeio.ErrNotRegular) {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not a regular file"})
				continue
			}
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
			continue
		}
		if f.Truncated {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "truncated at 1MiB"})
		}
		hits, truncated := parse.ScanShell(string(f.Data), home)
		if truncated {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "shell scan truncated"})
		}
		for _, h := range hits {
			rule := "shell.suspicious"
			if strings.HasPrefix(h.Reason, "PATH") {
				rule = "shell.path"
			}
			out.Findings = append(out.Findings, model.Finalize(model.Finding{
				RuleID:      rule,
				Collector:   "shell",
				Severity:    h.Severity,
				Title:       h.Reason,
				Description: "Matched a shell startup line. Common toolchain PATH prefixes are not reported.",
				Path:        path,
				Line:        h.Line,
				Evidence:    h.Text,
				Key:         path + "\n" + h.Reason + "\n" + h.Text,
			}))
		}
	}
	return out
}

func files(home, goos string) []string {
	rels := []string{
		".bashrc", ".bash_profile", ".bash_login", ".profile",
		".zshrc", ".zprofile", ".zlogin", ".zshenv",
		filepath.Join(".config", "fish", "config.fish"),
	}
	if goos == "windows" {
		rels = append(rels,
			filepath.Join("Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join("Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join("Documents", "PowerShell", "Profile.ps1"),
		)
	} else {
		rels = append(rels, filepath.Join(".config", "powershell", "profile.ps1"))
	}
	var out []string
	for _, rel := range rels {
		out = append(out, filepath.Join(home, rel))
	}
	confd := filepath.Join(home, ".config", "fish", "conf.d")
	entries, err := os.ReadDir(confd)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".fish") {
			out = append(out, filepath.Join(confd, e.Name()))
		}
	}
	return out
}
