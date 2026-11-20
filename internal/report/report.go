// Package report renders a scan as text, JSON, Markdown, or SARIF 2.1.0.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ucsurf/aftermath/internal/model"
)

// Format names accepted by Render.
const (
	Text     = "text"
	JSON     = "json"
	Markdown = "markdown"
	SARIF    = "sarif"
)

// Render writes rep in format. Findings should already be ordered.
func Render(format string, rep model.Report) ([]byte, error) {
	rep = prepare(rep)
	switch strings.ToLower(format) {
	case "", Text:
		return []byte(renderText(rep)), nil
	case JSON:
		return renderJSON(rep)
	case Markdown, "md":
		return []byte(renderMarkdown(rep)), nil
	case SARIF:
		return renderSARIF(rep)
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func prepare(rep model.Report) model.Report {
	if rep.Tool == "" {
		rep.Tool = "aftermath"
	}
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	rep.ScannedAt = rep.ScannedAt.UTC()
	for i := range rep.Findings {
		rep.Findings[i] = model.Finalize(rep.Findings[i])
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if a.Evidence != b.Evidence {
			return a.Evidence < b.Evidence
		}
		return a.RuleID < b.RuleID
	})
	sort.SliceStable(rep.Diagnostics, func(i, j int) bool {
		if rep.Diagnostics[i].Path != rep.Diagnostics[j].Path {
			return rep.Diagnostics[i].Path < rep.Diagnostics[j].Path
		}
		return rep.Diagnostics[i].Message < rep.Diagnostics[j].Message
	})
	return rep
}

func renderText(rep model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "aftermath %s\n", rep.Version)
	fmt.Fprintf(&b, "scanned: %s\n", rep.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "home: %s\n", rep.Home)
	if rep.Project != "" {
		fmt.Fprintf(&b, "project: %s\n", rep.Project)
	}
	fmt.Fprintf(&b, "platform: %s\n", rep.Platform)
	fmt.Fprintf(&b, "findings: %d (%s)\n", len(rep.Findings), countSummary(rep.Findings))
	if len(rep.Findings) == 0 {
		b.WriteString("\nno findings\n")
	}
	for _, f := range rep.Findings {
		b.WriteByte('\n')
		fmt.Fprintf(&b, "%s  %s  %s\n", strings.ToUpper(string(f.Severity)), f.Collector, f.Title)
		fmt.Fprintf(&b, "  rule: %s\n", f.RuleID)
		if f.Change != "" {
			fmt.Fprintf(&b, "  change: %s\n", f.Change)
		}
		if f.Path != "" {
			if f.Line > 0 {
				fmt.Fprintf(&b, "  path: %s:%d\n", f.Path, f.Line)
			} else {
				fmt.Fprintf(&b, "  path: %s\n", f.Path)
			}
		}
		if f.Source != "" {
			fmt.Fprintf(&b, "  source: %s\n", f.Source)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "  evidence: %s\n", f.Evidence)
		}
	}
	if len(rep.Diagnostics) > 0 {
		b.WriteString("\ndiagnostics:\n")
		for _, d := range rep.Diagnostics {
			if d.Path != "" {
				fmt.Fprintf(&b, "  - %s: %s\n", d.Path, d.Message)
			} else {
				fmt.Fprintf(&b, "  - %s\n", d.Message)
			}
		}
	}
	return b.String()
}

func countSummary(fs []model.Finding) string {
	n := map[model.Severity]int{}
	for _, f := range fs {
		n[f.Severity]++
	}
	order := []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info}
	var parts []string
	for _, s := range order {
		parts = append(parts, fmt.Sprintf("%s %d", s, n[s]))
	}
	return strings.Join(parts, ", ")
}

func renderJSON(rep model.Report) ([]byte, error) {
	buf, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

func renderMarkdown(rep model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# aftermath %s\n\n", rep.Version)
	fmt.Fprintf(&b, "- scanned: `%s`\n", rep.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- home: `%s`\n", rep.Home)
	if rep.Project != "" {
		fmt.Fprintf(&b, "- project: `%s`\n", rep.Project)
	}
	fmt.Fprintf(&b, "- platform: `%s`\n", rep.Platform)
	fmt.Fprintf(&b, "- findings: %d (%s)\n\n", len(rep.Findings), countSummary(rep.Findings))
	if len(rep.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "## %s: %s\n\n", strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(&b, "- collector: `%s`\n", f.Collector)
		fmt.Fprintf(&b, "- rule: `%s`\n", f.RuleID)
		if f.Change != "" {
			fmt.Fprintf(&b, "- change: `%s`\n", f.Change)
		}
		if f.Path != "" {
			if f.Line > 0 {
				fmt.Fprintf(&b, "- path: `%s:%d`\n", f.Path, f.Line)
			} else {
				fmt.Fprintf(&b, "- path: `%s`\n", f.Path)
			}
		}
		if f.Source != "" {
			fmt.Fprintf(&b, "- source: %s\n", f.Source)
		}
		if f.Description != "" {
			fmt.Fprintf(&b, "- description: %s\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- evidence: `%s`\n", strings.ReplaceAll(f.Evidence, "`", "'"))
		}
		b.WriteByte('\n')
	}
	if len(rep.Diagnostics) > 0 {
		b.WriteString("## Diagnostics\n\n")
		for _, d := range rep.Diagnostics {
			if d.Path != "" {
				fmt.Fprintf(&b, "- `%s`: %s\n", d.Path, d.Message)
			} else {
				fmt.Fprintf(&b, "- %s\n", d.Message)
			}
		}
	}
	return b.String()
}

func renderSARIF(rep model.Report) ([]byte, error) {
	rules := map[string]sarifRule{}
	var results []sarifResult
	var order []string
	for _, f := range rep.Findings {
		if _, ok := rules[f.RuleID]; !ok {
			rules[f.RuleID] = sarifRule{
				ID:                   f.RuleID,
				Name:                 f.RuleID,
				ShortDescription:     sarifText{Text: f.Title},
				FullDescription:      sarifText{Text: firstNonEmpty(f.Description, f.Title)},
				HelpURI:              f.Source,
				DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
			}
			order = append(order, f.RuleID)
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: sarifMessage(f)},
		}
		if f.Path != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: fileURI(f.Path)},
			}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{loc}
		}
		results = append(results, res)
	}
	if results == nil {
		results = []sarifResult{}
	}
	var ruleList []sarifRule
	for _, id := range order {
		ruleList = append(ruleList, rules[id])
	}
	if ruleList == nil {
		ruleList = []sarifRule{}
	}
	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "aftermath",
				Version:        rep.Version,
				InformationURI: "https://github.com/ucsurf/aftermath",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

func sarifMessage(f model.Finding) string {
	msg := f.Title
	if f.Evidence != "" {
		msg += ": " + f.Evidence
	}
	if f.Change != "" {
		msg += " (" + f.Change + ")"
	}
	return msg
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}

func fileURI(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	if strings.HasPrefix(p, "/") {
		return "file://" + escapeURI(p)
	}
	return "file:///" + escapeURI(p)
}

func escapeURI(p string) string {
	var b bytes.Buffer
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~/:@+", rune(c)) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifText   `json:"shortDescription"`
	FullDescription      sarifText   `json:"fullDescription"`
	HelpURI              string      `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhys `json:"physicalLocation"`
}

type sarifPhys struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
