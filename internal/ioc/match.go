package ioc

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Scope is where indicators are applied.
type Scope struct {
	Home    string
	Project string
	System  string
	Temp    string
}

// Apply matches packs against the scope. It does not print file contents.
func Apply(packs []Pack, scope Scope) model.CollectorResult {
	var out model.CollectorResult
	for _, p := range packs {
		for _, ind := range p.Indicators {
			out.Add(matchOne(ind, scope))
		}
	}
	return out
}

func matchOne(ind Indicator, scope Scope) model.CollectorResult {
	if ind.Match.Scope == "temp" {
		return matchTemp(ind, scope.Temp)
	}
	var out model.CollectorResult
	bases := ind.Match.Bases
	if len(bases) == 0 {
		bases = []string{"home"}
	}
	for _, baseName := range bases {
		base := scopeBase(scope, baseName)
		if base == "" {
			continue
		}
		roots := safeio.NewRoots(base)
		for _, rel := range ind.Match.Paths {
			full := filepath.Join(base, filepath.FromSlash(rel))
			out.Add(matchPath(ind, full, roots))
		}
		for _, rel := range ind.Match.ListRoots {
			dir := filepath.Join(base, filepath.FromSlash(rel))
			out.Add(matchList(ind, dir, roots))
		}
	}
	return out
}

func scopeBase(scope Scope, name string) string {
	switch name {
	case "home":
		return scope.Home
	case "project":
		return scope.Project
	case "system":
		return scope.System
	default:
		return ""
	}
}

func matchPath(ind Indicator, full string, roots safeio.Roots) model.CollectorResult {
	var out model.CollectorResult
	fi, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: full, Message: "not read"})
		return out
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if _, _, err := safeio.LstatInside(full, roots); errors.Is(err, safeio.ErrEscape) {
			out.Findings = append(out.Findings, hit(ind, full, "symlink exists; target not read"))
			return out
		}
	}
	if !fi.Mode().IsRegular() && fi.Mode()&os.ModeSymlink == 0 {
		return out
	}
	if len(ind.Match.ContentAny) == 0 && len(ind.Match.SHA256) == 0 {
		out.Findings = append(out.Findings, hit(ind, full, "path exists; contents not displayed"))
		return out
	}
	if len(ind.Match.ContentAny) > 0 {
		needle, err := safeio.ContainsAny(full, roots, ind.Match.ContentAny, safeio.MaxStream)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: full, Message: "not scanned"})
			}
			return out
		}
		if needle != "" {
			out.Findings = append(out.Findings, hit(ind, full, needleEvidence(needle)))
		}
	}
	if len(ind.Match.SHA256) > 0 {
		sum, tooBig, err := safeio.HashSHA256(full, roots, safeio.MaxStream)
		if err != nil || tooBig || sum == nil {
			return out
		}
		got := hex.EncodeToString(sum)
		for _, want := range ind.Match.SHA256 {
			if strings.EqualFold(got, want) {
				out.Findings = append(out.Findings, hit(ind, full, "sha256 "+strings.ToLower(want)))
				break
			}
		}
	}
	return out
}

func matchList(ind Indicator, dir string, roots safeio.Roots) model.CollectorResult {
	var out model.CollectorResult
	n := 0
	var walk func(string, int)
	walk = func(d string, depth int) {
		if depth > 4 || n > 2000 {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if n > 2000 {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "ioc directory walk truncated"})
				return
			}
			n++
			p := filepath.Join(d, e.Name())
			rel, _ := filepath.Rel(dir, p)
			rel = filepath.ToSlash(rel)
			if e.IsDir() {
				if nameMatch(ind, e.Name(), rel) && len(ind.Match.ContentAny) == 0 && len(ind.Match.SHA256) == 0 {
					out.Findings = append(out.Findings, hit(ind, p, "path name matched; contents not displayed"))
				}
				if !safeio.SkipHeavyDir(e.Name()) {
					walk(p, depth+1)
				}
				continue
			}
			if !nameMatch(ind, e.Name(), rel) && len(ind.Match.ContentAny) == 0 && len(ind.Match.SHA256) == 0 {
				continue
			}
			if len(ind.Match.ContentAny) == 0 && len(ind.Match.SHA256) == 0 {
				if nameMatch(ind, e.Name(), rel) {
					out.Findings = append(out.Findings, hit(ind, p, "path name matched; contents not displayed"))
				}
				continue
			}
			// Content or hash match on files under the root. Name filters apply when set.
			if (len(ind.Match.Basenames) > 0 || len(ind.Match.PathContains) > 0) && !nameMatch(ind, e.Name(), rel) {
				continue
			}
			out.Add(matchPath(ind, p, roots))
		}
	}
	walk(dir, 0)
	return out
}

func nameMatch(ind Indicator, base, rel string) bool {
	if len(ind.Match.Basenames) == 0 && len(ind.Match.PathContains) == 0 {
		return false
	}
	for _, b := range ind.Match.Basenames {
		if base == b {
			return true
		}
	}
	for _, c := range ind.Match.PathContains {
		if strings.Contains(rel, c) || strings.Contains(base, c) {
			return true
		}
	}
	return false
}

func matchTemp(ind Indicator, temp string) model.CollectorResult {
	var out model.CollectorResult
	if temp == "" {
		return out
	}
	entries, err := os.ReadDir(temp)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: temp, Message: "temp dir not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, ind.Match.NamePrefix) {
			continue
		}
		rest := name[len(ind.Match.NamePrefix):]
		if len(rest) != ind.Match.NameHexLength || !isHex(rest) {
			continue
		}
		out.Findings = append(out.Findings, hit(ind, filepath.Join(temp, name), "temp file name matched; contents not read"))
	}
	return out
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func hit(ind Indicator, path, evidence string) model.Finding {
	sev, _ := model.ParseSeverity(ind.Severity)
	return model.Finalize(model.Finding{
		RuleID:      ind.ID,
		Collector:   "ioc",
		Severity:    sev,
		Title:       ind.Title,
		Description: strings.Join(strings.Fields(ind.Description), " "),
		Path:        path,
		Evidence:    evidence,
		Source:      ind.Source,
		Key:         ind.ID + ":" + path,
	})
}

func needleEvidence(needle string) string {
	if len(needle) > 40 {
		return "matched published indicator material"
	}
	return "matched " + strconvQuote(needle)
}

func strconvQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
}
