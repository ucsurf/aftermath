// Package sshkeys reads SSH authorized_keys files. It never uses the keys.
package sshkeys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Collect reads authorized_keys and authorized_keys2 under home.
func Collect(home string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(home)
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		path := filepath.Join(home, ".ssh", name)
		fi, target, err := safeio.LstatInside(path, roots)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if errors.Is(err, safeio.ErrEscape) {
				out.Findings = append(out.Findings, model.Finalize(model.Finding{
					RuleID:      "ssh.symlink-escape",
					Collector:   "ssh",
					Severity:    model.High,
					Title:       "authorized_keys symlink points outside the home directory",
					Description: "The link was not followed.",
					Path:        path,
					Evidence:    "target=" + target,
					Key:         "escape:" + path,
				}))
				continue
			}
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular() {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not a regular file"})
			continue
		}
		f, err := safeio.Read(path, roots, safeio.MaxRead)
		if err != nil {
			if errors.Is(err, safeio.ErrEscape) {
				out.Findings = append(out.Findings, model.Finalize(model.Finding{
					RuleID:    "ssh.symlink-escape",
					Collector: "ssh",
					Severity:  model.High,
					Title:     "authorized_keys symlink points outside the home directory",
					Path:      path,
					Evidence:  "target not read",
					Key:       "escape:" + path,
				}))
				continue
			}
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
			continue
		}
		if f.Truncated {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "truncated at 1MiB"})
		}
		keys, truncated := parse.ParseAuthorizedKeys(string(f.Data))
		if truncated {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "authorized_keys parse truncated"})
		}
		for _, k := range keys {
			out.Findings = append(out.Findings, keyFinding(path, k))
		}
	}
	return out
}

func keyFinding(path string, k parse.AuthKey) model.Finding {
	sev := model.Info
	rule := "ssh.key"
	title := "SSH authorized key"
	switch {
	case k.Malformed:
		sev = model.Low
		rule = "ssh.malformed"
		title = "malformed authorized_keys line"
	case parse.HasOptionPrefix(k.Options, "command="):
		sev = model.High
		rule = "ssh.command"
		title = "SSH authorized key forces a command"
	case parse.HasOption(k.Options, "cert-authority"):
		sev = model.Medium
		rule = "ssh.cert-authority"
		title = "SSH authorized key is a certificate authority"
	case parse.HasOptionPrefix(k.Options, "environment="):
		sev = model.Medium
		rule = "ssh.environment"
		title = "SSH authorized key sets an environment variable"
	}
	opts := "none"
	if len(k.Options) > 0 {
		opts = strings.Join(k.Options, ",")
	}
	ev := k.Type + " " + k.Fingerprint
	if k.Comment != "" {
		ev += " comment=" + k.Comment
	}
	ev += " options=" + opts
	key := "fp:" + k.Fingerprint
	if k.Malformed || k.Fingerprint == "" || k.Fingerprint == "invalid" {
		key = path + "#malformed#" + ev
	}
	return model.Finalize(model.Finding{
		RuleID:      rule,
		Collector:   "ssh",
		Severity:    sev,
		Title:       title,
		Description: "Public key material is not included. The fingerprint is SHA256 of the key blob.",
		Path:        path,
		Line:        k.Line,
		Evidence:    ev,
		Key:         key,
	})
}
