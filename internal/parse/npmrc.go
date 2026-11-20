package parse

import "strings"

// Prop is a key=value line from an rc file.
type Prop struct {
	Line  int
	Key   string
	Value string
}

// ParseProps parses simple key=value rc lines.
func ParseProps(s string) (props []Prop, truncated bool) {
	lines, truncated := Lines(s)
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		key, val, ok := splitKV(trim)
		if !ok {
			continue
		}
		props = append(props, Prop{Line: i + 1, Key: key, Value: val})
	}
	return props, truncated
}
