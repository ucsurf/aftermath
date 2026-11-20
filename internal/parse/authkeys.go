package parse

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// AuthKey is one authorized_keys entry.
type AuthKey struct {
	Line        int
	Options     []string
	Type        string
	Comment     string
	Fingerprint string
	Malformed   bool
}

// ParseAuthorizedKeys parses OpenSSH authorized_keys text.
func ParseAuthorizedKeys(s string) (keys []AuthKey, truncated bool) {
	lines, truncated := Lines(s)
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		keys = append(keys, parseAuthLine(i+1, trim))
		if len(keys) >= 5000 {
			return keys, true
		}
	}
	return keys, truncated
}

func parseAuthLine(line int, text string) AuthKey {
	toks := tokenize(text)
	typeAt := -1
	for i, tok := range toks {
		if isKeyType(tok) {
			typeAt = i
			break
		}
	}
	k := AuthKey{Line: line}
	if typeAt < 0 || typeAt+1 >= len(toks) {
		k.Malformed = true
		k.Comment = "malformed authorized_keys line"
		return k
	}
	for _, tok := range toks[:typeAt] {
		k.Options = append(k.Options, splitOptions(tok)...)
	}
	k.Type = toks[typeAt]
	fp, err := fingerprint(toks[typeAt+1])
	if err != nil {
		k.Malformed = true
		k.Fingerprint = "invalid"
	} else {
		k.Fingerprint = fp
	}
	if typeAt+2 < len(toks) {
		k.Comment = strings.Join(toks[typeAt+2:], " ")
	}
	return k
}

func tokenize(line string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			b.WriteByte(c)
			if c == quote {
				inQuote = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == ' ' || c == '\t' {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func splitOptions(tok string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	var quote byte
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if inQuote {
			b.WriteByte(c)
			if c == quote {
				inQuote = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func isKeyType(s string) bool {
	switch {
	case strings.HasPrefix(s, "ssh-"), strings.HasPrefix(s, "ecdsa-"), strings.HasPrefix(s, "sk-"):
		return true
	default:
		return false
	}
}

func fingerprint(keyB64 string) (string, error) {
	raw, err := decodeB64(keyB64)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func decodeB64(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

// HasOptionPrefix reports whether any option has the given prefix.
func HasOptionPrefix(opts []string, prefix string) bool {
	for _, o := range opts {
		if strings.HasPrefix(o, prefix) {
			return true
		}
	}
	return false
}

// HasOption reports an exact option match.
func HasOption(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}
