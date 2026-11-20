// Package aiide reads user-level AI assistant and editor autoruns.
// It lists commands. It does not run them.
package aiide

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// CollectHome scans AI and editor config under the user home.
func CollectHome(home, goos string) model.CollectorResult {
	var out model.CollectorResult
	out.Add(scanTree(filepath.Join(home, ".claude"), "claude", home))
	out.Add(scanFile(filepath.Join(home, ".claude.json"), "claude", home))
	out.Add(scanTree(filepath.Join(home, ".cursor"), "cursor", home))
	out.Add(scanTree(filepath.Join(home, ".vscode"), "vscode", home))
	out.Add(scanTree(filepath.Join(home, ".gemini"), "gemini", home))
	out.Add(scanTree(filepath.Join(home, ".codex"), "codex", home))
	if dir := codeUserDir(home, goos); dir != "" {
		out.Add(scanKnown(dir, "code-user", home))
	}
	if dir := cursorUserDir(home, goos); dir != "" {
		out.Add(scanKnown(dir, "cursor-user", home))
	}
	return out
}

// CollectProject scans a project's .claude, .vscode, and .cursor directories.
func CollectProject(project string) model.CollectorResult {
	var out model.CollectorResult
	out.Add(scanTree(filepath.Join(project, ".claude"), "claude", project))
	out.Add(scanTree(filepath.Join(project, ".vscode"), "vscode", project))
	out.Add(scanTree(filepath.Join(project, ".cursor"), "cursor", project))
	return out
}

func codeUserDir(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Code", "User")
	default:
		return filepath.Join(home, ".config", "Code", "User")
	}
}

func cursorUserDir(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Cursor", "User")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Cursor", "User")
	default:
		return filepath.Join(home, ".config", "Cursor", "User")
	}
}

func scanKnown(dir, kind, root string) model.CollectorResult {
	var out model.CollectorResult
	for _, name := range []string{"settings.json", "tasks.json"} {
		out.Add(scanFile(filepath.Join(dir, name), kind, root))
	}
	return out
}

func scanTree(dir, kind, root string) model.CollectorResult {
	var out model.CollectorResult
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	roots := safeio.NewRoots(root)
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(dir)
		if err != nil || !roots.Contains(target) {
			out.Findings = append(out.Findings, escape(dir))
			return out
		}
	}
	out.Add(extensions(filepath.Join(dir, "extensions"), kind))
	out.Add(plugins(filepath.Join(dir, "plugins"), kind))
	n := 0
	var walk func(string, int)
	walk = func(d string, depth int) {
		if depth > 6 || n > 1500 {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: d, Message: "not read"})
			return
		}
		for _, e := range entries {
			if n > 1500 {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "file walk truncated"})
				return
			}
			name := e.Name()
			if name == "extensions" || name == "plugins" || safeio.SkipHeavyDir(name) {
				continue
			}
			p := filepath.Join(d, name)
			n++
			if e.IsDir() {
				walk(p, depth+1)
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				if _, _, err := safeio.LstatInside(p, roots); errors.Is(err, safeio.ErrEscape) {
					out.Findings = append(out.Findings, escape(p))
					continue
				}
			}
			if !interesting(name) {
				continue
			}
			if safeio.SensitiveName(name) {
				out.Findings = append(out.Findings, model.Finalize(model.Finding{
					RuleID: "ide.credential-file", Collector: "aiide", Severity: model.Info,
					Title: "credential-like file was not read", Path: p, Evidence: "name=" + name,
					Key: "cred:" + p,
				}))
				continue
			}
			out.Add(scanFile(p, kind, root))
		}
	}
	if fi.IsDir() {
		walk(dir, 0)
	}
	return out
}

func interesting(name string) bool {
	low := strings.ToLower(name)
	switch low {
	case "settings.json", "settings.local.json", "tasks.json", "mcp.json", "config.toml", "config.json", "claude.json":
		return true
	}
	switch filepath.Ext(low) {
	case ".json", ".jsonc", ".toml", ".yml", ".yaml":
		return strings.Contains(low, "setting") || strings.Contains(low, "mcp") || strings.Contains(low, "hook") || strings.Contains(low, "task")
	default:
		return false
	}
}

func extensions(dir, kind string) model.CollectorResult {
	return summarizeDir(dir, kind, "ide.extensions", "installed editor extensions")
}

func plugins(dir, kind string) model.CollectorResult {
	return summarizeDir(dir, kind, "ide.plugins", "installed Claude plugins")
}

func summarizeDir(dir, kind, rule, title string) model.CollectorResult {
	var out model.CollectorResult
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
		if len(names) >= 40 {
			break
		}
	}
	if len(names) == 0 {
		return out
	}
	out.Findings = append(out.Findings, model.Finalize(model.Finding{
		RuleID: rule, Collector: "aiide", Severity: model.Info,
		Title: title, Path: dir,
		Evidence:    "count=" + itoa(len(entries)) + " sample=" + strings.Join(names, ", "),
		Key:         rule + ":" + dir,
		Description: "Names only. Extension contents were not executed. kind=" + kind,
	}))
	return out
}

func scanFile(path, kind, root string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(root)
	if safeio.SensitiveName(filepath.Base(path)) {
		return out
	}
	f, err := safeio.Read(path, roots, safeio.MaxRead)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		if errors.Is(err, safeio.ErrEscape) {
			out.Findings = append(out.Findings, escape(path))
			return out
		}
		if errors.Is(err, safeio.ErrNotRegular) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
		return out
	}
	if f.Truncated {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "truncated at 1MiB; structured parse may be incomplete"})
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(base, ".toml") || kind == "codex" && base == "config.toml" {
		out.Add(codexTOML(path, string(f.Data)))
		return out
	}
	if strings.HasSuffix(base, ".toml") {
		out.Add(codexTOML(path, string(f.Data)))
		return out
	}
	if !strings.HasSuffix(base, ".json") && !strings.HasSuffix(base, ".jsonc") && base != ".claude.json" && filepath.Base(path) != ".claude.json" {
		if strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") {
			return out
		}
	}
	var v any
	if err := json.Unmarshal([]byte(parse.StripJSONC(string(f.Data))), &v); err != nil {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "JSON parse failed"})
		return out
	}
	if s, ok := lookupString(v, "task.allowAutomaticTasks"); ok && strings.EqualFold(s, "on") {
		out.Findings = append(out.Findings, model.Finalize(model.Finding{
			RuleID: "ide.automatic-tasks", Collector: "aiide", Severity: model.Medium,
			Title:       "task.allowAutomaticTasks is on",
			Description: "Folder-open tasks are allowed to run.",
			Path:        path, Evidence: "task.allowAutomaticTasks=on", Key: "auto-tasks:" + path,
		}))
	}
	for _, hit := range commands(v) {
		sev := model.Medium
		title := kind + " " + hit.Kind + " command"
		if hit.Kind == "task" && !hit.Auto {
			sev = model.Low
			title = kind + " task command"
		}
		if hit.Auto && hit.Kind == "task" {
			title = kind + " task runs on folder open"
		}
		if hs, why, ok := parse.ClassifyCommand(hit.Command); ok && hs.Rank() > sev.Rank() {
			sev = hs
			title = title + ": " + why
		}
		ev := hit.Command
		if hit.Label != "" {
			ev = hit.Label + ": " + hit.Command
		}
		out.Findings = append(out.Findings, model.Finalize(model.Finding{
			RuleID: "ide." + hit.Kind, Collector: "aiide", Severity: sev, Title: title,
			Description: "The command was not executed.",
			Path:        path, Evidence: ev, Key: hit.Kind + ":" + path + ":" + hit.Command,
		}))
	}
	return out
}

type cmdHit struct {
	Command string
	Kind    string
	Auto    bool
	Label   string
}

type walkCtx struct {
	inHook bool
	inMCP  bool
	inTask bool
	auto   bool
}

func commands(v any) []cmdHit {
	var hits []cmdHit
	var walk func(any, walkCtx)
	walk = func(v any, ctx walkCtx) {
		switch t := v.(type) {
		case map[string]any:
			next := ctx
			if ctx.inTask {
				if ro, ok := t["runOptions"].(map[string]any); ok {
					if s, _ := ro["runOn"].(string); strings.EqualFold(s, "folderOpen") {
						next.auto = true
					}
				}
			}
			if cmd, ok := t["command"].(string); ok && strings.TrimSpace(cmd) != "" && (next.inHook || next.inMCP || next.inTask) {
				kind := "hook"
				if next.inMCP {
					kind = "mcp"
				}
				if next.inTask {
					kind = "task"
				}
				if next.inHook {
					if typ, _ := t["type"].(string); typ != "" && !strings.EqualFold(typ, "command") {
						kind = ""
					}
				}
				if kind != "" {
					label, _ := t["label"].(string)
					hits = append(hits, cmdHit{Command: cmd, Kind: kind, Auto: next.auto || next.inHook, Label: label})
				}
			}
			for k, child := range t {
				c := next
				switch k {
				case "hooks":
					c.inHook = true
				case "mcpServers", "mcp_servers":
					c.inMCP = true
				case "tasks":
					c.inTask = true
				}
				walk(child, c)
			}
		case []any:
			for _, child := range t {
				walk(child, ctx)
			}
		}
	}
	walk(v, walkCtx{})
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Kind != hits[j].Kind {
			return hits[i].Kind < hits[j].Kind
		}
		if hits[i].Command != hits[j].Command {
			return hits[i].Command < hits[j].Command
		}
		return hits[i].Label < hits[j].Label
	})
	return hits
}

func lookupString(v any, key string) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}

func codexTOML(path, content string) model.CollectorResult {
	var out model.CollectorResult
	lines, _ := parse.Lines(content)
	section := ""
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			section = strings.ToLower(trim[1:strings.Index(trim, "]")])
			continue
		}
		if !strings.Contains(section, "mcp") {
			continue
		}
		key, val, ok := splitEq(trim)
		if !ok || !strings.EqualFold(key, "command") || strings.TrimSpace(val) == "" {
			continue
		}
		sev := model.Medium
		title := "codex MCP command"
		if hs, why, ok := parse.ClassifyCommand(val); ok && hs.Rank() > sev.Rank() {
			sev = hs
			title = title + ": " + why
		}
		out.Findings = append(out.Findings, model.Finalize(model.Finding{
			RuleID: "ide.mcp", Collector: "aiide", Severity: sev, Title: title,
			Description: "The command was not executed.",
			Path:        path, Line: i + 1, Evidence: val, Key: "mcp:" + path + ":" + section + ":" + val,
		}))
	}
	return out
}

func splitEq(trim string) (string, string, bool) {
	i := strings.Index(trim, "=")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(trim[:i]), strings.Trim(strings.TrimSpace(trim[i+1:]), `"'`), true
}

func escape(path string) model.Finding {
	return model.Finalize(model.Finding{
		RuleID: "ide.symlink-escape", Collector: "aiide", Severity: model.High,
		Title:       "IDE config symlink points outside the scan root",
		Description: "The link was not followed.",
		Path:        path, Key: "escape:" + path,
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
