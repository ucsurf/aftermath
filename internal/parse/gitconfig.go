package parse

import "strings"

// GitEntry is one assignment in a git config file.
type GitEntry struct {
	Line    int
	Section string
	Sub     string
	Key     string
	Value   string
}

// ParseGitConfig parses a git config document, including include subsections.
func ParseGitConfig(s string) (entries []GitEntry, truncated bool) {
	lines, truncated := Lines(s)
	var section, sub string
	var pending string
	pendingLine := 0
	for i, line := range lines {
		if strings.HasSuffix(strings.TrimRight(line, " \t"), `\`) {
			chunk := strings.TrimRight(line, " \t")
			chunk = strings.TrimSuffix(chunk, `\`)
			if pending == "" {
				pendingLine = i + 1
			}
			pending += chunk
			continue
		}
		full := pending + line
		lineNo := i + 1
		if pending != "" {
			lineNo = pendingLine
			pending = ""
		}
		trim := strings.TrimSpace(full)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			section, sub = gitSection(trim)
			continue
		}
		key, val, ok := splitKV(trim)
		if !ok {
			continue
		}
		entries = append(entries, GitEntry{
			Line:    lineNo,
			Section: strings.ToLower(section),
			Sub:     sub,
			Key:     strings.ToLower(key),
			Value:   val,
		})
	}
	return entries, truncated
}

func gitSection(trim string) (name, sub string) {
	end := strings.Index(trim, "]")
	inner := strings.TrimSpace(trim[1:end])
	if i := strings.IndexAny(inner, " \t"); i >= 0 {
		name = strings.TrimSpace(inner[:i])
		sub = strings.TrimSpace(inner[i+1:])
		sub = strings.Trim(sub, `"`)
		return name, sub
	}
	return inner, ""
}

func splitKV(trim string) (key, val string, ok bool) {
	if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
		return "", "", false
	}
	i := strings.IndexAny(trim, "= \t")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trim[:i])
	rest := strings.TrimSpace(trim[i:])
	rest = strings.TrimPrefix(rest, "=")
	val = strings.TrimSpace(rest)
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	if key == "" {
		return "", "", false
	}
	return key, val, true
}
