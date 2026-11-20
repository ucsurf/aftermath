// Package redact removes credential-shaped substrings from text that
// aftermath is about to print. It does not try to understand every secret.
package redact

import (
	"regexp"
	"strings"
)

const Mark = "[REDACTED]"

var (
	privateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	userinfo   = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@`)
	assigned   = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|auth|authorization|_authToken|_auth|_password|npm_auth_token)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|\S+)`)
	prefixed   = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat|npm|sk_live|sk_test|xox[baprs])_[A-Za-z0-9_\-]{16,}\b`)
	awsAccess  = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	pypiToken  = regexp.MustCompile(`\bpypi-AgE[A-Za-z0-9_\-]{16,}\b`)
	longB64    = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
)

// Text returns s with known secret shapes replaced by [REDACTED].
// The function is safe to call more than once on the same string.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = privateKey.ReplaceAllString(s, Mark)
	s = userinfo.ReplaceAllString(s, "${1}"+Mark+"@")
	s = prefixed.ReplaceAllString(s, Mark)
	s = awsAccess.ReplaceAllString(s, Mark)
	s = pypiToken.ReplaceAllString(s, Mark)
	s = assigned.ReplaceAllString(s, "${1}${2}"+Mark)
	s = longB64.ReplaceAllString(s, Mark)
	return s
}

// Assignment reports whether key is a credential field and value is non-empty.
// The value is never returned.
func Assignment(key, value string) (present bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	if strings.TrimSpace(value) == "" || strings.Trim(value, `"'`) == "" {
		return false
	}
	switch {
	case k == "password" || k == "passwd" || k == "pwd" || k == "secret":
		return true
	case strings.Contains(k, "token") || strings.Contains(k, "_auth") || strings.HasSuffix(k, "apikey") || strings.Contains(k, "api_key") || strings.Contains(k, "api-key"):
		return true
	default:
		return false
	}
}
