// Package scan runs every collector and the embedded IOC packs.
package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ucsurf/aftermath/internal/collectors/aiide"
	"github.com/ucsurf/aftermath/internal/collectors/autorun"
	"github.com/ucsurf/aftermath/internal/collectors/gitconfig"
	"github.com/ucsurf/aftermath/internal/collectors/pkgconfig"
	"github.com/ucsurf/aftermath/internal/collectors/project"
	"github.com/ucsurf/aftermath/internal/collectors/shellrc"
	"github.com/ucsurf/aftermath/internal/collectors/sshkeys"
	"github.com/ucsurf/aftermath/internal/ioc"
	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/version"
)

// Options selects what a scan reads.
type Options struct {
	Home       string
	Project    string
	SystemRoot string
	TempDir    string
	GOOS       string
	Username   string
	Now        time.Time
	IOCFiles   []string
	Registry   autorun.RegistryView
}

// Run reads the machine. It does not modify or execute what it finds.
func Run(ctx context.Context, opt Options) (model.Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return model.Report{}, err
	}
	home, err := absDir(opt.Home, "home")
	if err != nil {
		return model.Report{}, err
	}
	goos := opt.GOOS
	if goos == "" {
		goos = "linux"
	}
	sys := opt.SystemRoot
	if sys == "" {
		if goos == "windows" {
			sys = `C:\`
		} else {
			sys = string(filepath.Separator)
		}
	}
	sys, err = filepath.Abs(sys)
	if err != nil {
		return model.Report{}, err
	}
	projectDir := ""
	if opt.Project != "" {
		projectDir, err = absDir(opt.Project, "project")
		if err != nil {
			return model.Report{}, err
		}
		if filepath.Dir(projectDir) == projectDir {
			return model.Report{}, errors.New("project path is the filesystem root")
		}
	}
	temp := opt.TempDir
	if temp == "" {
		temp = os.TempDir()
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	packs, err := ioc.LoadEmbedded()
	if err != nil {
		return model.Report{}, err
	}
	for _, path := range opt.IOCFiles {
		b, err := readLimited(path, 1<<20+1)
		if err != nil {
			return model.Report{}, err
		}
		p, err := ioc.Parse(b)
		if err != nil {
			return model.Report{}, err
		}
		packs = append(packs, p)
	}

	var got model.CollectorResult
	if err := ctx.Err(); err != nil {
		return model.Report{}, err
	}
	got.Add(sshkeys.Collect(home))
	got.Add(shellrc.Collect(home, goos))
	got.Add(gitconfig.Collect(home))
	got.Add(pkgconfig.Collect(home, goos))
	got.Add(aiide.CollectHome(home, goos))
	loc := autorun.DefaultLocations(goos, home, sys, opt.Username)
	if opt.Registry != nil {
		loc.Registry = opt.Registry
		loc.ReadRegistry = true
	}
	got.Add(autorun.Collect(loc))
	if projectDir != "" {
		if samePath(projectDir, home) {
			got.Diagnostics = append(got.Diagnostics, model.Diagnostic{Path: projectDir, Message: "project is the home directory; user-level scan already covers it"})
		} else {
			got.Add(project.Collect(projectDir))
		}
	}
	got.Add(ioc.Apply(packs, ioc.Scope{
		Home:    home,
		Project: projectDir,
		System:  sys,
		Temp:    temp,
	}))

	if len(got.Findings) > 5000 {
		// Keep the highest severities. Report rendering sorts again for display.
		sort.SliceStable(got.Findings, func(i, j int) bool {
			return got.Findings[i].Severity.Rank() > got.Findings[j].Severity.Rank()
		})
		got.Findings = got.Findings[:5000]
		got.Diagnostics = append(got.Diagnostics, model.Diagnostic{Message: "finding list truncated at 5000"})
	}
	return model.Report{
		Tool:        "aftermath",
		Version:     version.Version,
		ScannedAt:   now.UTC(),
		Home:        home,
		Project:     projectDir,
		Platform:    goos,
		Findings:    got.Findings,
		Diagnostics: got.Diagnostics,
	}, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("ioc pack is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) >= max {
		return nil, errors.New("ioc pack exceeds 1MiB")
	}
	return b, nil
}

func absDir(path, label string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New(label + " is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", errors.New(label + " is not a directory")
	}
	return abs, nil
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}
