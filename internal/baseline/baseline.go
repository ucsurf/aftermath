// Package baseline stores and compares scan fingerprints.
package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/ucsurf/aftermath/internal/model"
)

// File is the on-disk baseline.
type File struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	Home      string    `json:"home"`
	Entries   []Entry   `json:"entries"`
}

// Entry is one finding identity.
type Entry struct {
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"ruleId"`
	Collector   string `json:"collector"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Path        string `json:"path,omitempty"`
}

// FromReport builds a baseline from a report.
func FromReport(rep model.Report) File {
	f := File{
		Format:    "aftermath-baseline",
		Version:   1,
		CreatedAt: rep.ScannedAt.UTC(),
		Home:      rep.Home,
	}
	for _, finding := range rep.Findings {
		f.Entries = append(f.Entries, Entry{
			Identity:    finding.Identity,
			Fingerprint: finding.Fingerprint,
			RuleID:      finding.RuleID,
			Collector:   finding.Collector,
			Severity:    string(finding.Severity),
			Title:       finding.Title,
			Path:        finding.Path,
		})
	}
	return f
}

// Save writes the baseline with mode 0600.
func Save(path string, f File) error {
	buf, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return os.WriteFile(path, buf, 0o600)
}

// Load reads a baseline file.
func Load(path string) (File, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	if len(buf) > 32<<20 {
		return File{}, errors.New("baseline file exceeds 32MiB")
	}
	var f File
	if err := json.Unmarshal(buf, &f); err != nil {
		return File{}, err
	}
	if f.Format != "aftermath-baseline" || f.Version != 1 {
		return File{}, errors.New("unrecognized baseline format")
	}
	return f, nil
}

// Diff returns findings that are new or whose fingerprint changed.
func Diff(base File, findings []model.Finding) []model.Finding {
	byID := make(map[string]Entry, len(base.Entries))
	for _, e := range base.Entries {
		byID[e.Identity] = e
	}
	var out []model.Finding
	for _, f := range findings {
		prev, ok := byID[f.Identity]
		if !ok {
			f.Change = "new"
			out = append(out, f)
			continue
		}
		if prev.Fingerprint != f.Fingerprint {
			f.Change = "changed"
			out = append(out, f)
		}
	}
	return out
}
