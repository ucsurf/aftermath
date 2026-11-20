// Package model holds findings, severities, and the scan report.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ucsurf/aftermath/internal/redact"
)

// Severity is an ordered aftermath severity.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Rank returns a sort key. Unknown severities rank as info.
func (s Severity) Rank() int {
	switch s {
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	default:
		return 0
	}
}

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	switch sev {
	case Info, Low, Medium, High, Critical:
		return sev, true
	default:
		return "", false
	}
}

// Finding is one inventory row or suspicious item.
// Key is the stable identity material and is not serialized.
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Collector   string   `json:"collector"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Path        string   `json:"path,omitempty"`
	Line        int      `json:"line,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Key         string   `json:"-"`
	Identity    string   `json:"identity"`
	Fingerprint string   `json:"fingerprint"`
	Source      string   `json:"source,omitempty"`
	Change      string   `json:"change,omitempty"`
}

// Diagnostic is a non-fatal read problem. Messages must not contain file contents.
type Diagnostic struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// CollectorResult is the output of one collector.
type CollectorResult struct {
	Findings    []Finding
	Diagnostics []Diagnostic
}

// Add appends another result.
func (r *CollectorResult) Add(o CollectorResult) {
	r.Findings = append(r.Findings, o.Findings...)
	r.Diagnostics = append(r.Diagnostics, o.Diagnostics...)
}

// Report is a finished scan.
type Report struct {
	Tool        string       `json:"tool"`
	Version     string       `json:"version"`
	ScannedAt   time.Time    `json:"scannedAt"`
	Home        string       `json:"home"`
	Project     string       `json:"project,omitempty"`
	Platform    string       `json:"platform"`
	Findings    []Finding    `json:"findings"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// Finalize redacts text fields and fills Identity and Fingerprint.
// Calling it again on the result yields the same fingerprints.
func Finalize(f Finding) Finding {
	f.Title = clip(redact.Text(f.Title), 300)
	f.Description = clip(redact.Text(f.Description), 1200)
	f.Evidence = clip(redact.Text(f.Evidence), 500)
	if strings.TrimSpace(f.Key) == "" {
		f.Key = f.Path + "\n" + strconv.Itoa(f.Line) + "\n" + f.Title
	}
	idMat := f.Collector + "\n" + f.RuleID + "\n" + f.Key
	sum := sha256.Sum256([]byte(idMat))
	f.Identity = hex.EncodeToString(sum[:16])
	fp := sha256.Sum256([]byte(idMat + "\n" + string(f.Severity) + "\n" + f.Evidence))
	f.Fingerprint = hex.EncodeToString(fp[:])
	return f
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if n <= 0 || len(s) <= n {
		return s
	}
	i := n
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return strings.TrimSpace(s[:i]) + "..."
}
