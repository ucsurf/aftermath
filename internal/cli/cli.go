// Package cli is the aftermath command line.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/ucsurf/aftermath/internal/baseline"
	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/report"
	"github.com/ucsurf/aftermath/internal/scan"
	"github.com/ucsurf/aftermath/internal/version"
)

const usageText = `aftermath is a local, read-only check of developer-machine persistence.

It does not use the network, and it does not run, delete, or quarantine anything it finds.

Usage:
  aftermath scan [flags]
  aftermath baseline save FILE [flags]
  aftermath diff FILE [flags]
  aftermath version

Flags:
  --home DIR          home directory to read (default: your home)
  --project DIR       also read DIR/.claude, DIR/.vscode, and DIR/.cursor
  --system-root DIR   OS root for system autoruns (default: / or C:\)
  --temp-dir DIR      directory to check for temp-file indicators
  --platform NAME     linux, darwin, or windows (default: this OS)
  --username NAME     crontab spool name (default: current user)
  --ioc FILE          extra local indicator pack (repeatable)
  --format FORMAT     text, json, sarif, or markdown (default: text)
  --fail-on LEVEL     exit 1 at this severity or above (default: high)
  --output FILE       write the report here (mode 0600) instead of stdout

Exit codes:
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  the scan could not be completed
`

// Run executes one invocation. args are the arguments after the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "aftermath %s\n", version.Version)
		return 0
	case "scan":
		return runReport(args[1:], stdout, stderr, reportModeScan)
	case "diff":
		return runReport(args[1:], stdout, stderr, reportModeDiff)
	case "baseline":
		if len(args) < 2 || args[1] != "save" {
			fmt.Fprint(stderr, usageText)
			return 2
		}
		return runBaseline(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
}

type reportMode int

const (
	reportModeScan reportMode = iota
	reportModeDiff
)

type options struct {
	home       string
	project    string
	systemRoot string
	tempDir    string
	platform   string
	username   string
	format     string
	failOn     string
	output     string
	ioc        multiFlag
	file       string
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parseFlags(args []string, needFile bool) (options, error) {
	var opt options
	if needFile {
		file, rest, err := extractFile(args)
		if err != nil {
			return options{}, err
		}
		opt.file = file
		args = rest
	}
	fs := flag.NewFlagSet("aftermath", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opt.home, "home", "", "home directory")
	fs.StringVar(&opt.project, "project", "", "project directory")
	fs.StringVar(&opt.systemRoot, "system-root", "", "OS root")
	fs.StringVar(&opt.tempDir, "temp-dir", "", "temp directory")
	fs.StringVar(&opt.platform, "platform", runtime.GOOS, "platform")
	fs.StringVar(&opt.username, "username", "", "username")
	fs.StringVar(&opt.format, "format", "text", "format")
	fs.StringVar(&opt.failOn, "fail-on", "high", "fail on severity")
	fs.StringVar(&opt.output, "output", "", "output file")
	fs.Var(&opt.ioc, "ioc", "ioc pack")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if len(fs.Args()) != 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Args()[0])
	}
	switch opt.platform {
	case "linux", "darwin", "windows":
	default:
		return options{}, fmt.Errorf("unknown platform %q", opt.platform)
	}
	if _, ok := model.ParseSeverity(opt.failOn); !ok {
		return options{}, fmt.Errorf("unknown severity %q", opt.failOn)
	}
	switch opt.format {
	case "text", "json", "sarif", "markdown", "md":
	default:
		return options{}, fmt.Errorf("unknown format %q", opt.format)
	}
	return opt, nil
}

func extractFile(args []string) (string, []string, error) {
	takesValue := map[string]bool{
		"home": true, "project": true, "system-root": true, "temp-dir": true,
		"platform": true, "username": true, "format": true, "fail-on": true,
		"output": true, "ioc": true,
	}
	var file string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return "", nil, fmt.Errorf("expected one file argument")
		}
		if strings.HasPrefix(a, "-") {
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				rest = append(rest, a)
				continue
			}
			rest = append(rest, a)
			if takesValue[name] {
				if i+1 >= len(args) {
					return "", nil, fmt.Errorf("missing value for --%s", name)
				}
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		if file != "" {
			return "", nil, fmt.Errorf("unexpected argument %q", a)
		}
		file = a
	}
	if file == "" {
		return "", nil, fmt.Errorf("expected one file argument")
	}
	return file, rest, nil
}

func runReport(args []string, stdout, stderr io.Writer, mode reportMode) int {
	opt, err := parseFlags(args, mode == reportModeDiff)
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		return 2
	}
	rep, err := doScan(opt)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %s\n", err)
		return 2
	}
	findings := rep.Findings
	if mode == reportModeDiff {
		base, err := baseline.Load(opt.file)
		if err != nil {
			fmt.Fprintf(stderr, "baseline: %s\n", err)
			return 2
		}
		findings = baseline.Diff(base, rep.Findings)
		rep.Findings = findings
	}
	buf, err := report.Render(opt.format, rep)
	if err != nil {
		fmt.Fprintf(stderr, "report: %s\n", err)
		return 2
	}
	if err := writeOut(opt.output, stdout, buf); err != nil {
		fmt.Fprintf(stderr, "output: %s\n", err)
		return 2
	}
	return exitFor(findings, opt.failOn)
}

func runBaseline(args []string, stdout, stderr io.Writer) int {
	opt, err := parseFlags(args, true)
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		return 2
	}
	rep, err := doScan(opt)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %s\n", err)
		return 2
	}
	if err := baseline.Save(opt.file, baseline.FromReport(rep)); err != nil {
		fmt.Fprintf(stderr, "baseline: %s\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "wrote %d entries to %s\n", len(rep.Findings), opt.file)
	return 0
}

func doScan(opt options) (model.Report, error) {
	home := opt.home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return model.Report{}, err
		}
	}
	username := opt.username
	if username == "" {
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
	}
	return scan.Run(context.Background(), scan.Options{
		Home:       home,
		Project:    opt.project,
		SystemRoot: opt.systemRoot,
		TempDir:    opt.tempDir,
		GOOS:       opt.platform,
		Username:   username,
		IOCFiles:   []string(opt.ioc),
	})
}

func writeOut(path string, stdout io.Writer, buf []byte) error {
	if path == "" || path == "-" {
		_, err := stdout.Write(buf)
		return err
	}
	return os.WriteFile(path, buf, 0o600)
}

func exitFor(findings []model.Finding, failOn string) int {
	min, _ := model.ParseSeverity(failOn)
	for _, f := range findings {
		if f.Severity.Rank() >= min.Rank() {
			return 1
		}
	}
	return 0
}
