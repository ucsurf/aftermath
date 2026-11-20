package parse

import "strings"

// StripJSONC removes // and /* */ comments and trailing commas outside strings.
func StripJSONC(in string) string {
	if len(in) > 2<<20 {
		in = in[:2<<20]
	}
	var b strings.Builder
	b.Grow(len(in))
	inStr := false
	esc := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			b.WriteByte(c)
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(in) {
			if in[i+1] == '/' {
				for i+1 < len(in) && in[i+1] != '\n' {
					i++
				}
				continue
			}
			if in[i+1] == '*' {
				i += 2
				for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
					i++
				}
				if i+1 < len(in) && in[i] == '*' && in[i+1] == '/' {
					i++ // sit on the closing slash; the loop increment steps past it
				}
				continue
			}
		}
		b.WriteByte(c)
	}
	return stripTrailingCommas(b.String())
}

func stripTrailingCommas(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\n' || s[j] == '\r' || s[j] == '\t') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
