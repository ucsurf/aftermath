package parse

import "strings"

const maxLines = 20000
const maxInspect = 8192

// Lines splits s on newlines and caps the count.
func Lines(s string) (lines []string, truncated bool) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, "\n")
	if len(parts) > maxLines {
		return parts[:maxLines], true
	}
	return parts, false
}

func inspect(s string) string {
	if len(s) > maxInspect {
		return s[:maxInspect]
	}
	return s
}

// StripComment removes an unquoted '#' comment.
func StripComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			i++
			continue
		}
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}
