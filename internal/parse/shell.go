package parse

import (
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
)

// ShellHit is one suspicious shell startup line.
type ShellHit struct {
	Line     int
	Severity model.Severity
	Reason   string
	Text     string
}

// ScanShell classifies suspicious lines in a shell rc or PowerShell profile.
// home, when set, is used only to recognize toolchain PATH prefixes.
func ScanShell(content, home string) (hits []ShellHit, truncated bool) {
	lines, truncated := Lines(content)
	for i, line := range lines {
		sev, reason, ok := classifyShellLine(line, home)
		if !ok {
			continue
		}
		hits = append(hits, ShellHit{Line: i + 1, Severity: sev, Reason: reason, Text: line})
	}
	return hits, truncated
}

func classifyShellLine(line, home string) (model.Severity, string, bool) {
	if sev, reason, ok := ClassifyCommand(line); ok {
		return sev, reason, true
	}
	return classifyPath(line, home)
}

func classifyPath(line, home string) (model.Severity, string, bool) {
	body := strings.TrimSpace(StripComment(line))
	if body == "" {
		return "", "", false
	}
	rhs, ok := pathRHS(body)
	if !ok {
		return "", "", false
	}
	rhs = strings.TrimSpace(rhs)
	rhs = trimMatchingQuotes(rhs)
	parts := splitPathList(rhs)
	best := model.Severity("")
	reason := ""
	saw := false
	for _, p := range parts {
		p = strings.TrimSpace(trimMatchingQuotes(p))
		if p == "" || isPathRef(p) {
			continue
		}
		saw = true
		sev, why := classifyPathComponent(p, home)
		if sev == "" {
			continue
		}
		if !okSev(best) || sev.Rank() > best.Rank() {
			best = sev
			reason = why
		}
	}
	if !saw || best == "" {
		return "", "", false
	}
	return best, reason, true
}

func okSev(s model.Severity) bool { return s != "" }

func pathRHS(body string) (string, bool) {
	low := strings.ToLower(body)
	if strings.Contains(low, "fish_add_path") {
		i := strings.Index(low, "fish_add_path")
		return strings.TrimSpace(body[i+len("fish_add_path"):]), true
	}
	if i := strings.Index(low, "$env:path"); i >= 0 {
		rest := body[i+len("$env:path"):]
		if j := strings.Index(rest, "="); j >= 0 {
			return rest[j+1:], true
		}
	}
	// export PATH=... or PATH=... or set PATH ...
	fields := strings.Fields(body)
	for i, f := range fields {
		fl := strings.TrimLeft(f, "(")
		if strings.HasPrefix(strings.ToUpper(fl), "PATH=") {
			return fl[len("PATH="):] + joinTail(fields[i+1:]), true
		}
		if strings.EqualFold(fl, "PATH") && i+1 < len(fields) && (strings.EqualFold(fields[0], "set") || strings.Contains(low, "set ")) {
			return strings.Join(fields[i+1:], " "), true
		}
	}
	return "", false
}

func joinTail(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return " " + strings.Join(fields, " ")
}

func trimMatchingQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func splitPathList(rhs string) []string {
	if strings.Contains(rhs, ";") && !strings.Contains(rhs, ":") {
		return strings.Split(rhs, ";")
	}
	return strings.Split(rhs, ":")
}

func isPathRef(p string) bool {
	switch strings.TrimSpace(p) {
	case "$PATH", "${PATH}", "%PATH%", "$env:PATH", "$Env:PATH":
		return true
	default:
		return false
	}
}

func classifyPathComponent(p, home string) (model.Severity, string) {
	if strings.Contains(p, "..") {
		return model.High, "PATH prepend contains .."
	}
	if suspiciousTemp(p) {
		return model.High, "PATH prepends a temp directory"
	}
	if p == "." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, ".\\") {
		return model.Medium, "PATH prepends a relative directory"
	}
	if allowedPath(p, home) {
		return "", ""
	}
	norm := strings.ReplaceAll(p, "${HOME}", "$HOME")
	norm = strings.ReplaceAll(norm, "${home}", "$HOME")
	if strings.HasPrefix(norm, "$HOME/") || strings.HasPrefix(norm, "~/") || (home != "" && strings.HasPrefix(p, home)) {
		return model.Medium, "PATH prepends a directory outside the toolchain allowlist"
	}
	if strings.Contains(p, "$") || strings.Contains(p, "%") {
		return model.Low, "PATH prepends an unknown variable"
	}
	return model.Medium, "PATH prepends a directory outside the toolchain allowlist"
}

func suspiciousTemp(p string) bool {
	lc := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, pre := range []string{"/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "c:/temp", "c:/windows/temp", "$tmpdir", "%temp%", "%tmp%"} {
		if lc == pre || strings.HasPrefix(lc, pre+"/") {
			return true
		}
	}
	return false
}

func allowedPath(p, home string) bool {
	c := strings.ReplaceAll(p, "\\", "/")
	c = strings.ReplaceAll(c, "${HOME}", "$HOME")
	c = strings.ReplaceAll(c, "${home}", "$HOME")
	if strings.HasPrefix(c, "~/") {
		c = "$HOME/" + c[2:]
	}
	if home != "" {
		h := strings.ReplaceAll(home, "\\", "/")
		if strings.HasPrefix(c, h+"/") || c == h {
			c = "$HOME" + c[len(h):]
		}
	}
	for _, a := range allowedPATH {
		if c == a || strings.HasPrefix(c, a+"/") {
			return true
		}
	}
	return false
}

var allowedPATH = []string{
	"$HOME/.local/bin",
	"$HOME/bin",
	"$HOME/.cargo/bin",
	"$HOME/.npm-global/bin",
	"$HOME/go/bin",
	"$HOME/.go/bin",
	"$HOME/.bun/bin",
	"$HOME/.deno/bin",
	"$HOME/.nvm",
	"$HOME/.pyenv",
	"$HOME/.rbenv",
	"$HOME/.volta",
	"$HOME/.fnm",
	"$HOME/.asdf",
	"$HOME/.local/share/pnpm",
	"$HOME/.sdkman",
	"$HOME/.jenv",
	"$HOME/.nix-profile",
	"$HOME/.composer/vendor/bin",
	"$HOME/.pub-cache/bin",
	"$HOME/.dotnet",
	"$HOME/.krew/bin",
	"$HOME/.yarn/bin",
	"$HOME/Library/pnpm",
	"/usr/local/bin",
	"/usr/bin",
	"/bin",
	"/usr/sbin",
	"/opt/homebrew/bin",
	"/opt/homebrew/sbin",
	"/snap/bin",
}
