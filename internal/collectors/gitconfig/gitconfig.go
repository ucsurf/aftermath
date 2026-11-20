// Package gitconfig reads global git config files without running git.
package gitconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Collect reads ~/.gitconfig, ~/.config/git/config, and include files under home.
func Collect(home string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(home)
	start := []string{
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".config", "git", "config"),
	}
	seen := map[string]bool{}
	seenHelper := map[string]bool{}
	var queue []string
	for _, p := range start {
		queue = append(queue, p)
	}
	files := 0
	for len(queue) > 0 && files < 10 {
		path := queue[0]
		queue = queue[1:]
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		f, err := safeio.Read(path, roots, safeio.MaxRead)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if errors.Is(err, safeio.ErrEscape) {
				out.Findings = append(out.Findings, escapeFinding(path))
				continue
			}
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
			continue
		}
		files++
		entries, truncated := parse.ParseGitConfig(string(f.Data))
		if truncated || f.Truncated {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "git config truncated"})
		}
		for _, e := range entries {
			if e.Section == "credential" && e.Key == "helper" {
				norm := normalizeHelper(e.Value)
				if norm == "" || seenHelper[norm] {
					continue
				}
				seenHelper[norm] = true
			}
			if (e.Section == "include" || e.Section == "includeif") && e.Key == "path" {
				inc, ok := resolveInclude(home, path, e.Value)
				if !ok {
					out.Findings = append(out.Findings, model.Finalize(model.Finding{
						RuleID:      "git.include",
						Collector:   "git",
						Severity:    model.Medium,
						Title:       "git include path is outside the home directory",
						Description: "The included file was not read.",
						Path:        path,
						Line:        e.Line,
						Evidence:    "path=" + e.Value,
						Key:         "include:" + e.Value,
					}))
					continue
				}
				queue = append(queue, inc)
				continue
			}
			if finding, ok := interpret(path, e); ok {
				out.Findings = append(out.Findings, finding)
			}
		}
		out.Add(hooksFor(home, roots, path, entries))
	}
	return out
}

func escapeFinding(path string) model.Finding {
	return model.Finalize(model.Finding{
		RuleID:      "git.symlink-escape",
		Collector:   "git",
		Severity:    model.High,
		Title:       "git config symlink points outside the home directory",
		Description: "The link was not followed.",
		Path:        path,
		Key:         "escape:" + path,
	})
}

func resolveInclude(home, file, value string) (string, bool) {
	v := strings.TrimSpace(value)
	if v == "" || strings.Contains(v, "..") {
		return "", false
	}
	if strings.HasPrefix(v, "~/") {
		v = filepath.Join(home, v[2:])
	} else if !filepath.IsAbs(v) {
		v = filepath.Join(filepath.Dir(file), v)
	}
	v = filepath.Clean(v)
	rel, err := filepath.Rel(home, v)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return v, true
}

func interpret(path string, e parse.GitEntry) (model.Finding, bool) {
	switch {
	case e.Section == "core" && e.Key == "hookspath":
		if strings.TrimSpace(e.Value) == "" {
			return model.Finding{}, false
		}
		return model.Finalize(model.Finding{
			RuleID:      "git.hooksPath",
			Collector:   "git",
			Severity:    model.High,
			Title:       "core.hooksPath is set",
			Description: "Git runs hooks from this directory on every repository command that uses hooks.",
			Path:        path,
			Line:        e.Line,
			Evidence:    "core.hooksPath=" + e.Value,
			Key:         "hooksPath",
		}), true
	case e.Section == "init" && e.Key == "templatedir":
		if strings.TrimSpace(e.Value) == "" {
			return model.Finding{}, false
		}
		return model.Finalize(model.Finding{
			RuleID:      "git.templateDir",
			Collector:   "git",
			Severity:    model.Medium,
			Title:       "init.templateDir is set",
			Description: "New repositories copy this template, including any hooks directory.",
			Path:        path,
			Line:        e.Line,
			Evidence:    "init.templateDir=" + e.Value,
			Key:         "templateDir",
		}), true
	case e.Section == "core" && e.Key == "fsmonitor":
		sev, title := fsmonitorSeverity(e.Value)
		if title == "" {
			return model.Finding{}, false
		}
		return model.Finalize(model.Finding{
			RuleID:    "git.fsmonitor",
			Collector: "git",
			Severity:  sev,
			Title:     title,
			Path:      path,
			Line:      e.Line,
			Evidence:  "core.fsmonitor=" + e.Value,
			Key:       "fsmonitor",
		}), true
	case e.Section == "credential" && e.Key == "helper":
		sev, title := helperSeverity(e.Value)
		if title == "" {
			return model.Finding{}, false
		}
		return model.Finalize(model.Finding{
			RuleID:    "git.credential",
			Collector: "git",
			Severity:  sev,
			Title:     title,
			Path:      path,
			Line:      e.Line,
			Evidence:  "credential.helper=" + e.Value,
			Key:       "helper:" + normalizeHelper(e.Value),
		}), true
	case e.Section == "url" && e.Key == "insteadof":
		sev, title := insteadSeverity(e.Sub)
		return model.Finalize(model.Finding{
			RuleID:      "git.insteadOf",
			Collector:   "git",
			Severity:    sev,
			Title:       title,
			Description: "Git rewrites URLs that start with the insteadOf prefix so they start with the section URL.",
			Path:        path,
			Line:        e.Line,
			Evidence:    "base=" + e.Sub + " insteadOf=" + e.Value,
			Key:         "insteadOf:" + e.Sub + ":" + e.Value,
		}), true
	default:
		return model.Finding{}, false
	}
}

func helperSeverity(v string) (model.Severity, string) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", ""
	}
	if sev, reason, ok := parse.ClassifyCommand(raw); ok && sev.Rank() >= model.High.Rank() {
		return model.High, "credential helper " + reason
	}
	body := strings.TrimPrefix(raw, "!")
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return "", ""
	}
	if oddHelperPath(fields[0]) {
		return model.High, "credential helper runs from a temp directory"
	}
	base := helperBase(fields[0])
	if isShellBin(base) {
		low := strings.ToLower(raw)
		if strings.Contains(low, "curl") || strings.Contains(low, "wget") || strings.Contains(low, "base64") {
			return model.High, "credential helper shell command downloads or decodes"
		}
		return model.Medium, "credential helper is a shell command"
	}
	if knownHelper(base, fields[1:]) {
		return model.Info, "credential helper"
	}
	if strings.HasPrefix(raw, "!") || strings.ContainsAny(fields[0], `/\`) {
		return model.Medium, "unrecognized credential helper command"
	}
	return model.Medium, "unrecognized credential helper"
}

func normalizeHelper(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "!")
	return strings.Join(strings.Fields(v), " ")
}

func helperBase(token string) string {
	token = strings.TrimPrefix(token, "!")
	token = strings.Trim(token, `"'`)
	token = strings.ReplaceAll(token, `\`, "/")
	if i := strings.LastIndex(token, "/"); i >= 0 {
		token = token[i+1:]
	}
	return strings.ToLower(token)
}

func knownHelper(base string, args []string) bool {
	switch base {
	case "cache", "store", "osxkeychain", "wincred", "manager", "manager-core",
		"gnome-keyring", "libsecret",
		"git-credential-manager", "git-credential-manager-core", "git-credential-manager.exe",
		"git-credential-osxkeychain", "git-credential-libsecret",
		"git-credential-wincred", "git-credential-gnome-keyring",
		"git-credential-store", "git-credential-cache":
		return true
	case "gh", "gh.exe":
		if len(args) == 0 {
			return true
		}
		joined := strings.ToLower(strings.Join(args, " "))
		return joined == "auth git-credential" || strings.HasPrefix(joined, "auth git-credential ")
	default:
		return false
	}
}

func isShellBin(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "fish", "ksh", "pwsh", "powershell", "powershell.exe", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

func oddHelperPath(token string) bool {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(token, "!"), `\`, "/"))
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/run/user"} {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.Contains(p, "/../")
}

func fsmonitorSeverity(v string) (model.Severity, string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	if v == "true" {
		return model.Info, "core.fsmonitor uses the built-in daemon"
	}
	if sev, reason, ok := parse.ClassifyCommand(v); ok && sev.Rank() >= model.High.Rank() {
		return model.High, "core.fsmonitor " + reason
	}
	if oddHelperPath(v) {
		return model.High, "core.fsmonitor runs from a temp directory"
	}
	if standardTool(v) {
		return model.Info, "core.fsmonitor uses a standard tool"
	}
	return model.Medium, "core.fsmonitor runs a command"
}

func standardTool(v string) bool {
	p := strings.ToLower(strings.ReplaceAll(v, `\`, "/"))
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	switch base {
	case "watchman", "query-watchman", "fsmonitor-watchman", "watchman.exe":
		return true
	}
	for _, dir := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", "/opt/local/bin/"} {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}

func insteadSeverity(base string) (model.Severity, string) {
	if hasUserinfo(base) {
		return model.High, "git URL rewrite contains credentials"
	}
	b := strings.ToLower(base)
	known := []string{
		"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht",
		"ssh.github.com", "gist.github.com",
	}
	for _, h := range known {
		if strings.Contains(b, h) {
			return model.Low, "git URL rewrite to a known host"
		}
	}
	return model.Medium, "git URL rewrite to a host outside the built-in list"
}

func hasUserinfo(u string) bool {
	i := strings.Index(u, "://")
	if i < 0 {
		return false
	}
	rest := u[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return false
	}
	return strings.Contains(rest[:at], ":")
}

func hooksFor(home string, roots safeio.Roots, cfg string, entries []parse.GitEntry) model.CollectorResult {
	var out model.CollectorResult
	for _, e := range entries {
		var dir string
		switch {
		case e.Section == "core" && e.Key == "hookspath":
			dir = resolveConfigured(home, e.Value)
		case e.Section == "init" && e.Key == "templatedir":
			d := resolveConfigured(home, e.Value)
			if d != "" {
				dir = filepath.Join(d, "hooks")
			}
		}
		if dir == "" {
			continue
		}
		rel, err := filepath.Rel(home, dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "hooks directory not read"})
			}
			continue
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			p := filepath.Join(dir, ent.Name())
			f, err := safeio.Read(p, roots, safeio.MaxRead)
			sev := model.Info
			reason := "hook file present"
			ev := ent.Name()
			if err == nil {
				if s, why, ok := firstSuspicious(string(f.Data)); ok {
					sev = s
					reason = why
					ev = ent.Name() + ": " + why
				}
			}
			out.Findings = append(out.Findings, model.Finalize(model.Finding{
				RuleID:      "git.hook-file",
				Collector:   "git",
				Severity:    sev,
				Title:       "git hook file: " + reason,
				Description: "The hook was not executed. Source config: " + cfg,
				Path:        p,
				Evidence:    ev,
				Key:         "hookfile:" + p,
			}))
		}
	}
	return out
}

func resolveConfigured(home, value string) string {
	v := strings.TrimSpace(value)
	if v == "" || strings.Contains(v, "..") {
		return ""
	}
	if strings.HasPrefix(v, "~/") {
		return filepath.Join(home, v[2:])
	}
	if filepath.IsAbs(v) {
		return v
	}
	return ""
}

func firstSuspicious(content string) (model.Severity, string, bool) {
	lines, _ := parse.Lines(content)
	var best model.Severity
	why := ""
	okAny := false
	for _, line := range lines {
		sev, reason, ok := parse.ClassifyCommand(line)
		if !ok {
			continue
		}
		if !okAny || sev.Rank() > best.Rank() {
			best = sev
			why = reason
			okAny = true
		}
	}
	return best, why, okAny
}
