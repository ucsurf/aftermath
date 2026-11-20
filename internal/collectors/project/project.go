// Package project scans a repository's editor and assistant directories.
// It does not scan git hooks. That is hookjack's job, before the repo is opened.
package project

import (
	"github.com/ucsurf/aftermath/internal/collectors/aiide"
	"github.com/ucsurf/aftermath/internal/model"
)

// Collect scans project/.claude, project/.vscode, and project/.cursor.
// Findings use collector "project" so they stay distinct from the home scan.
func Collect(dir string) model.CollectorResult {
	got := aiide.CollectProject(dir)
	for i := range got.Findings {
		f := got.Findings[i]
		f.Collector = "project"
		// Re-finalize so identity includes the project collector.
		f.Identity = ""
		f.Fingerprint = ""
		got.Findings[i] = model.Finalize(f)
	}
	return got
}
