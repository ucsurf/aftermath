// Package pkgconfig reads user-level package manager config.
// Token and password values are never copied into findings.
package pkgconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/redact"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Collect scans package-manager config under home.
func Collect(home, goos string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(home)
	for _, path := range files(home, goos) {
		if strings.HasSuffix(path, string(filepath.Separator)) {
			continue
		}
		out.Add(readFile(home, goos, roots, path))
	}
	out.Add(gradle(home, roots))
	return out
}

func files(home, goos string) []string {
	list := []string{
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".yarnrc"),
		filepath.Join(home, ".yarnrc.yml"),
		filepath.Join(home, ".pypirc"),
		filepath.Join(home, ".pip", "pip.conf"),
		filepath.Join(home, ".config", "pip", "pip.conf"),
		filepath.Join(home, ".cargo", "config.toml"),
		filepath.Join(home, ".cargo", "config"),
		filepath.Join(home, ".m2", "settings.xml"),
	}
	switch goos {
	case "darwin":
		list = append(list, filepath.Join(home, "Library", "Application Support", "pip", "pip.conf"))
	case "windows":
		list = append(list,
			filepath.Join(home, "pip", "pip.ini"),
			filepath.Join(home, "AppData", "Roaming", "pip", "pip.ini"),
		)
	}
	return list
}

func readFile(home, goos string, roots safeio.Roots, path string) model.CollectorResult {
	var out model.CollectorResult
	f, err := safeio.Read(path, roots, safeio.MaxRead)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		if errors.Is(err, safeio.ErrEscape) {
			out.Findings = append(out.Findings, model.Finalize(model.Finding{
				RuleID: "pkg.symlink-escape", Collector: "pkg", Severity: model.High,
				Title: "package config symlink points outside the home directory",
				Path:  path, Evidence: "target not read", Key: "escape:" + path,
			}))
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
		return out
	}
	world := worldReadable(path, goos)
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case ".npmrc":
		out.Add(npmrc(path, string(f.Data), world))
	case ".yarnrc":
		out.Add(yarnrc(path, string(f.Data), world))
	case ".yarnrc.yml":
		out.Add(yarnyml(path, string(f.Data), world))
	case ".pypirc":
		out.Add(pypirc(path, string(f.Data), world))
	case "pip.conf", "pip.ini":
		out.Add(pipconf(path, string(f.Data)))
	case "config.toml", "config":
		out.Add(cargo(path, string(f.Data), world))
	case "settings.xml":
		out.Add(maven(path, f.Data, world))
	}
	return out
}

func worldReadable(path, goos string) bool {
	// Windows reports a fake Unix mode, so the other-read bit is not meaningful there.
	if goos == "windows" || runtime.GOOS == "windows" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Perm()&0o004 != 0
}

const tokenRotateNote = "Tokens on a machine involved in an incident should be rotated."

func npmrc(path, content string, world bool) model.CollectorResult {
	var out model.CollectorResult
	props, _ := parse.ParseProps(content)
	unusualHost := ""
	var tokens []parse.Prop
	for _, p := range props {
		key := p.Key
		lk := strings.ToLower(key)
		switch {
		case redact.Assignment(key, p.Value) || strings.Contains(lk, "_authtoken") || strings.HasSuffix(lk, ":_auth"):
			tokens = append(tokens, p)
		case lk == "registry" || strings.HasSuffix(lk, ":registry"):
			if h := hostOf(p.Value); h != "" && !knownNPM(h) {
				if unusualHost == "" {
					unusualHost = h
				}
				out.Findings = append(out.Findings, presence(path, p.Line, "pkg.registry", model.Medium, "npm registry is not the public npm registry", "host="+h, "registry:"+key+":"+h))
			}
		case lk == "script-shell":
			out.Findings = append(out.Findings, presence(path, p.Line, "pkg.lifecycle", model.High, "npm script-shell is set", "script-shell is set", "script-shell"))
		}
	}
	for _, p := range tokens {
		host := registryHostFromKey(p.Key)
		out.Findings = append(out.Findings, tokenFinding(path, p.Line, "npm auth token is present", "key="+leaf(p.Key)+" host="+host, "token:"+p.Key, world, unusualHost != ""))
	}
	return out
}

func yarnrc(path, content string, world bool) model.CollectorResult {
	var out model.CollectorResult
	props, _ := parse.ParseProps(content)
	unusual := false
	var hasToken bool
	var tokenLine int
	var tokenKey string
	for _, p := range props {
		lk := strings.ToLower(p.Key)
		if (strings.Contains(lk, "token") || strings.Contains(lk, "_auth")) && strings.TrimSpace(p.Value) != "" {
			hasToken = true
			tokenLine = p.Line
			tokenKey = p.Key
		}
		if lk == "registry" {
			if h := hostOf(p.Value); h != "" && !knownNPM(h) && !strings.Contains(h, "yarnpkg.com") {
				unusual = true
				out.Findings = append(out.Findings, presence(path, p.Line, "pkg.registry", model.Medium, "yarn registry is not a public default", "host="+h, "yarn-registry:"+h))
			}
		}
	}
	if hasToken {
		out.Findings = append(out.Findings, tokenFinding(path, tokenLine, "yarn auth token is present", "token present", "yarn-token:"+tokenKey, world, unusual))
	}
	return out
}

func yarnyml(path, content string, world bool) model.CollectorResult {
	var out model.CollectorResult
	lines, _ := parse.Lines(content)
	unusual := false
	tokenLine := 0
	for i, line := range lines {
		trim := strings.TrimSpace(parse.StripComment(line))
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		low := strings.ToLower(trim)
		if strings.Contains(low, "npmauthtoken") || strings.Contains(low, "npmauthident") {
			if strings.Contains(trim, ":") {
				val := strings.TrimSpace(trim[strings.Index(trim, ":")+1:])
				if val != "" && val != `""` && val != "''" && val != "~" && val != "null" {
					tokenLine = i + 1
				}
			}
		}
		if strings.Contains(low, "npmregistryserver") {
			val := valueAfterColon(trim)
			if h := hostOf(val); h != "" && !knownNPM(h) && !strings.Contains(h, "yarnpkg.com") {
				unusual = true
				out.Findings = append(out.Findings, presence(path, i+1, "pkg.registry", model.Medium, "yarn npmRegistryServer is not a public default", "host="+h, "yarnyml-registry:"+h))
			}
		}
	}
	if tokenLine > 0 {
		out.Findings = append(out.Findings, tokenFinding(path, tokenLine, "yarn auth token is present", "token present", "yarnyml-token:"+strconv.Itoa(tokenLine), world, unusual))
	}
	return out
}

func pypirc(path, content string, world bool) model.CollectorResult {
	var out model.CollectorResult
	props, _ := parse.ParseProps(content)
	lines, _ := parse.Lines(content)
	secAt := map[int]string{}
	cur := ""
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			cur = strings.ToLower(strings.Trim(trim[1:strings.Index(trim, "]")], " "))
		}
		secAt[i+1] = cur
	}
	unusual := false
	var secretLine int
	var secretSec string
	for _, p := range props {
		lk := strings.ToLower(p.Key)
		if (lk == "password" || lk == "token") && strings.TrimSpace(p.Value) != "" {
			secretLine = p.Line
			secretSec = secAt[p.Line]
		}
		if lk == "repository" || lk == "repository_url" {
			if h := hostOf(p.Value); h != "" && !knownPyPI(h) {
				unusual = true
				out.Findings = append(out.Findings, presence(path, p.Line, "pkg.registry", model.Medium, "PyPI repository is not the public index", "host="+h, "pypi-repo:"+h))
			}
		}
	}
	if secretLine > 0 {
		out.Findings = append(out.Findings, tokenFinding(path, secretLine, "PyPI password or token is present", "secret present in "+secretSec, "pypi-secret:"+secretSec, world, unusual))
	}
	return out
}

func pipconf(path, content string) model.CollectorResult {
	var out model.CollectorResult
	props, _ := parse.ParseProps(content)
	for _, p := range props {
		lk := strings.ToLower(p.Key)
		switch lk {
		case "index-url", "extra-index-url":
			if h := hostOf(p.Value); h != "" && !knownPyPI(h) {
				title := "pip index is not the public index"
				out.Findings = append(out.Findings, presence(path, p.Line, "pkg.registry", model.Medium, title, lk+" host="+h, lk+":"+h))
			}
		case "trusted-host":
			out.Findings = append(out.Findings, presence(path, p.Line, "pkg.registry", model.Low, "pip trusted-host is set", "trusted-host="+p.Value, "trusted:"+p.Value))
		}
	}
	return out
}

func cargo(path, content string, world bool) model.CollectorResult {
	var out model.CollectorResult
	lines, _ := parse.Lines(content)
	section := ""
	unusual := false
	tokenLine := 0
	tokenSection := ""
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			section = strings.ToLower(trim[1:strings.Index(trim, "]")])
			continue
		}
		key, val, ok := splitLoose(trim)
		if !ok {
			continue
		}
		lk := strings.ToLower(key)
		if lk == "token" && strings.TrimSpace(val) != "" && val != `""` {
			tokenLine = i + 1
			tokenSection = section
		}
		if lk == "replace-with" && strings.TrimSpace(val) != "" {
			unusual = true
			out.Findings = append(out.Findings, presence(path, i+1, "pkg.registry", model.Medium, "cargo source replace-with is set", "section="+section, "cargo-replace:"+section+":"+val))
		}
	}
	if tokenLine > 0 {
		out.Findings = append(out.Findings, tokenFinding(path, tokenLine, "cargo registry token is present", "token present in ["+tokenSection+"]", "cargo-token:"+tokenSection, world, unusual))
	}
	return out
}

func maven(path string, data []byte, world bool) model.CollectorResult {
	var out model.CollectorResult
	text := string(parse.AsUTF8(data))
	low := strings.ToLower(text)
	unusual := false
	if strings.Contains(low, "<url>") {
		for _, u := range allBetween(low, "<url>", "</url>") {
			h := hostOf(u)
			if h == "" || strings.Contains(h, "repo.maven.apache.org") || strings.Contains(h, "repo1.maven.org") {
				continue
			}
			unusual = true
			out.Findings = append(out.Findings, presence(path, 0, "pkg.mirror", model.Medium, "Maven settings.xml uses a non-central repository URL", "host="+h, "maven-url:"+h))
		}
	}
	if strings.Contains(low, "<password>") {
		inner := between(low, "<password>", "</password>")
		if strings.TrimSpace(inner) != "" {
			out.Findings = append(out.Findings, tokenFinding(path, 0, "Maven settings.xml password is present", "password element is non-empty", "maven-password", world, unusual))
		}
	}
	return out
}

func gradle(home string, roots safeio.Roots) model.CollectorResult {
	var out model.CollectorResult
	dir := filepath.Join(home, ".gradle", "init.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".gradle") && !strings.HasSuffix(name, ".gradle.kts") {
			continue
		}
		p := filepath.Join(dir, name)
		f, err := safeio.Read(p, roots, safeio.MaxRead)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: p, Message: "not read"})
			continue
		}
		sev := model.Medium
		title := "Gradle init script runs on every Gradle invocation"
		ev := name
		if s, why, ok := suspiciousText(string(f.Data)); ok {
			sev = s
			title = "Gradle init script: " + why
			ev = name + ": " + why
		}
		out.Findings = append(out.Findings, model.Finalize(model.Finding{
			RuleID: "pkg.init-script", Collector: "pkg", Severity: sev, Title: title,
			Description: "Files in ~/.gradle/init.d are applied to Gradle builds. The script was not executed.",
			Path:        p, Evidence: ev, Key: "gradle:" + name,
		}))
	}
	return out
}

func suspiciousText(s string) (model.Severity, string, bool) {
	lines, _ := parse.Lines(s)
	var best model.Severity
	why := ""
	found := false
	for _, line := range lines {
		if sev, reason, ok := parse.ClassifyCommand(line); ok {
			if !found || sev.Rank() > best.Rank() {
				best, why, found = sev, reason, true
			}
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "getruntime()") || strings.Contains(low, "runtime.exec") {
			if !found || model.High.Rank() > best.Rank() {
				best, why, found = model.High, "Gradle script starts a process", true
			}
		}
	}
	return best, why, found
}

func tokenFinding(path string, line int, title, evidence, key string, world, unusual bool) model.Finding {
	sev := model.Medium
	evidence += "; rotate if this machine was involved in an incident"
	switch {
	case world && unusual:
		sev = model.High
		title += " (world-readable file, non-default registry)"
		evidence += " world-readable non-default-registry"
	case world:
		sev = model.High
		title += " (file is world-readable)"
		evidence += " world-readable"
	case unusual:
		sev = model.High
		title += " (non-default registry)"
		evidence += " non-default-registry"
	}
	return model.Finalize(model.Finding{
		RuleID: "pkg.token", Collector: "pkg", Severity: sev, Title: title,
		Description: tokenRotateNote,
		Path:        path, Line: line, Evidence: evidence, Key: key,
	})
}

func presence(path string, line int, rule string, sev model.Severity, title, evidence, key string) model.Finding {
	return model.Finalize(model.Finding{
		RuleID: rule, Collector: "pkg", Severity: sev, Title: title,
		Description: "Secret values are not printed.",
		Path:        path, Line: line, Evidence: evidence, Key: key,
	})
}

func knownNPM(host string) bool {
	h := strings.ToLower(host)
	return h == "registry.npmjs.org" || h == "registry.npmjs.com"
}

func knownPyPI(host string) bool {
	h := strings.ToLower(host)
	switch h {
	case "pypi.org", "upload.pypi.org", "files.pythonhosted.org", "pypi.python.org", "test.pypi.org":
		return true
	default:
		return strings.HasSuffix(h, ".pypi.org")
	}
}

func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"'`)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func registryHostFromKey(key string) string {
	// //registry.npmjs.org/:_authToken
	k := strings.TrimPrefix(key, "//")
	if i := strings.Index(k, "/"); i >= 0 {
		k = k[:i]
	}
	return hostOf(k)
}

func leaf(key string) string {
	if i := strings.LastIndex(key, ":"); i >= 0 {
		return key[i+1:]
	}
	return key
}

func valueAfterColon(trim string) string {
	i := strings.Index(trim, ":")
	if i < 0 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(trim[i+1:]), `"'`)
}

func splitLoose(trim string) (string, string, bool) {
	i := strings.Index(trim, "=")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(trim[:i]), strings.Trim(strings.TrimSpace(trim[i+1:]), `"'`), true
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	rest := s[i+len(a):]
	j := strings.Index(rest, b)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func allBetween(s, a, b string) []string {
	var out []string
	for {
		i := strings.Index(s, a)
		if i < 0 {
			return out
		}
		rest := s[i+len(a):]
		j := strings.Index(rest, b)
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		s = rest[j+len(b):]
	}
}
