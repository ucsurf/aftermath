package autorun

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
	"github.com/ucsurf/aftermath/internal/parse"
	"github.com/ucsurf/aftermath/internal/safeio"
)

// Collect reads autorun locations. It does not start the programs it finds.
func Collect(loc Locations) model.CollectorResult {
	var out model.CollectorResult
	for _, dir := range loc.UserLaunch {
		out.Add(launchAgents(dir, true))
	}
	for _, dir := range loc.SystemLaunch {
		out.Add(launchAgents(dir, false))
	}
	for _, path := range loc.UserCrontabs {
		out.Add(crontabFile(path, false, true))
	}
	for _, path := range loc.SystemCrontabs {
		out.Add(crontabFile(path, true, false))
	}
	for _, dir := range loc.SystemCronDirs {
		out.Add(crontabDir(dir))
	}
	for _, dir := range loc.CronScriptDirs {
		out.Add(cronScripts(dir))
	}
	for _, dir := range loc.UserSystemd {
		out.Add(systemdDir(dir, true))
	}
	for _, dir := range loc.SystemSystemd {
		out.Add(systemdDir(dir, false))
	}
	for _, dir := range loc.UserAutostart {
		out.Add(autostart(dir, true))
	}
	for _, dir := range loc.SystemAutostart {
		out.Add(autostart(dir, false))
	}
	for _, dir := range loc.UserStartup {
		out.Add(startup(dir, true))
	}
	for _, dir := range loc.SystemStartup {
		out.Add(startup(dir, false))
	}
	for _, dir := range loc.TaskDirs {
		out.Add(tasks(dir))
	}
	reg := loc.Registry
	if reg == nil && loc.ReadRegistry {
		live, err := platformRegistry()
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Message: "registry not opened"})
		} else {
			reg = live
		}
	}
	if reg != nil {
		out.Add(readRegistry(reg))
	}
	return out
}

func launchAgents(dir string, user bool) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".plist") {
			continue
		}
		path := filepath.Join(dir, name)
		readRoots, done := followAutorunLink(&out, path, roots, func(target string) linkClass {
			return classLaunchdLink(target, user)
		}, "LaunchAgent symlink")
		if done {
			continue
		}
		f, err := safeio.Read(path, readRoots, safeio.MaxRead)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
			continue
		}
		info, perr := parse.ParseLaunchPlist(f.Data)
		base := model.Info
		title := "LaunchAgent"
		if !user {
			title = "system LaunchAgent or LaunchDaemon"
		}
		if perr != nil {
			out.Findings = append(out.Findings, autorunFinding("autorun.launchd", base, title+" plist could not be parsed", path, name, path))
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "plist parse failed"})
			continue
		}
		if info.Binary {
			out.Findings = append(out.Findings, autorunFinding("autorun.launchd", model.Low, title+" binary plist was not decoded", path, "binary plist "+name, "bin:"+path))
			continue
		}
		cmd := strings.Join(info.Program, " ")
		sev := base
		if user && strings.HasPrefix(info.Label, "com.apple.") {
			sev = model.Medium
			title = "user LaunchAgent uses a com.apple. label"
		}
		ev := "label=" + info.Label
		if cmd != "" {
			ev += " program=" + cmd
		}
		if s, why, ok := parse.ClassifyCommand(cmd); ok && s.Rank() > sev.Rank() {
			sev = s
			title = title + ": " + why
		}
		key := "launch:" + path
		if info.Label != "" {
			key = "launch:" + info.Label + ":" + path
		}
		out.Findings = append(out.Findings, autorunFinding("autorun.launchd", sev, title, path, ev, key))
	}
	return out
}

func crontabFile(path string, withUser, userLevel bool) model.CollectorResult {
	var out model.CollectorResult
	dir := filepath.Dir(path)
	roots := safeio.NewRoots(dir)
	f, err := safeio.Read(path, roots, safeio.MaxRead)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		if errors.Is(err, safeio.ErrEscape) {
			out.Findings = append(out.Findings, escapeFinding(path, ""))
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "not read"})
		return out
	}
	entries, _ := parse.ParseCrontab(string(f.Data), withUser)
	for _, e := range entries {
		sev := model.Info
		title := "crontab entry"
		if !userLevel {
			title = "system crontab entry"
		}
		if s, why, ok := parse.ClassifyCommand(e.Command); ok && s.Rank() > sev.Rank() {
			sev = s
			title = title + ": " + why
		}
		ev := e.Schedule
		if e.User != "" {
			ev += " user=" + e.User
		}
		ev += " " + e.Command
		out.Findings = append(out.Findings, autorunFinding("autorun.cron", sev, title, path, ev, "cron:"+path+":"+e.Command))
	}
	return out
}

func crontabDir(dir string) model.CollectorResult {
	var out model.CollectorResult
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out.Add(crontabFile(filepath.Join(dir, e.Name()), true, false))
	}
	return out
}

func cronScripts(dir string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := safeio.Read(path, roots, safeio.MaxRead)
		sev := model.Info
		title := "cron directory script"
		ev := e.Name()
		if err == nil {
			if s, why, ok := suspicious(string(f.Data)); ok && s.Rank() > sev.Rank() {
				sev = s
				title = title + ": " + why
				ev = e.Name() + ": " + why
			}
		}
		out.Findings = append(out.Findings, autorunFinding("autorun.cron", sev, title, path, ev, "cronscript:"+path))
	}
	return out
}

func systemdDir(dir string, user bool) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	n := 0
	var walk func(string, int)
	walk = func(d string, depth int) {
		if depth > 3 || n > 1500 {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: d, Message: "not read"})
			}
			return
		}
		for _, e := range entries {
			name := e.Name()
			if safeio.SkipHeavyDir(name) {
				continue
			}
			p := filepath.Join(d, name)
			if e.IsDir() {
				walk(p, depth+1)
				continue
			}
			if !unitFile(name) {
				continue
			}
			n++
			readRoots, done := followAutorunLink(&out, p, roots, classSystemdLink, "systemd symlink")
			if done {
				continue
			}
			f, err := safeio.Read(p, readRoots, safeio.MaxRead)
			if err != nil {
				if errors.Is(err, safeio.ErrEscape) {
					out.Findings = append(out.Findings, escapeFinding(p, ""))
				}
				continue
			}
			cmds := execStarts(string(f.Data))
			sev := model.Info
			title := "systemd user unit"
			if !user {
				title = "systemd system unit"
			}
			ev := name
			if len(cmds) > 0 {
				ev = name + " ExecStart=" + strings.Join(cmds, " | ")
			}
			for _, c := range cmds {
				if s, why, ok := parse.ClassifyCommand(c); ok && s.Rank() > sev.Rank() {
					sev = s
					title = title + ": " + why
				}
			}
			out.Findings = append(out.Findings, autorunFinding("autorun.systemd", sev, title, p, ev, "unit:"+p))
		}
	}
	walk(dir, 0)
	return out
}

func unitFile(name string) bool {
	low := strings.ToLower(name)
	return strings.HasSuffix(low, ".service") || strings.HasSuffix(low, ".timer") || strings.HasSuffix(low, ".path") || strings.HasSuffix(low, ".conf")
}

func execStarts(content string) []string {
	var out []string
	lines, _ := parse.Lines(content)
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		low := strings.ToLower(trim)
		for _, key := range []string{"execstart=", "execstartpre="} {
			if strings.HasPrefix(low, key) {
				out = append(out, strings.TrimSpace(trim[len(key):]))
			}
		}
	}
	return out
}

func autostart(dir string, user bool) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".desktop") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := safeio.Read(path, roots, safeio.MaxRead)
		if err != nil {
			continue
		}
		d := parse.ParseDesktop(string(f.Data))
		if d.Hidden || d.Disabled {
			continue
		}
		sev := model.Info
		title := "XDG autostart entry"
		if !user {
			title = "system XDG autostart entry"
		}
		if s, why, ok := parse.ClassifyCommand(d.Exec); ok && s.Rank() > sev.Rank() {
			sev = s
			title = title + ": " + why
		}
		ev := d.Name
		if d.Exec != "" {
			ev = strings.TrimSpace(ev + " Exec=" + d.Exec)
		}
		out.Findings = append(out.Findings, autorunFinding("autorun.xdg", sev, title, path, ev, "xdg:"+path))
	}
	return out
}

func startup(dir string, user bool) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: dir, Message: "not read"})
		return out
	}
	for _, e := range entries {
		if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		readRoots, done := followAutorunLink(&out, path, roots, classStartupLink, "Startup folder symlink")
		if done {
			continue
		}
		sev := model.Info
		title := "Startup folder entry"
		if !user {
			title = "system Startup folder entry"
		}
		ev := e.Name()
		low := strings.ToLower(e.Name())
		if strings.HasSuffix(low, ".cmd") || strings.HasSuffix(low, ".bat") || strings.HasSuffix(low, ".ps1") || strings.HasSuffix(low, ".vbs") {
			f, err := safeio.Read(path, readRoots, safeio.MaxRead)
			if err == nil {
				if s, why, ok := suspicious(string(f.Data)); ok && s.Rank() > sev.Rank() {
					sev = s
					title = title + ": " + why
					ev = e.Name() + ": " + why
				}
			}
		}
		out.Findings = append(out.Findings, autorunFinding("autorun.startup", sev, title, path, ev, "startup:"+path))
	}
	return out
}

func tasks(dir string) model.CollectorResult {
	var out model.CollectorResult
	roots := safeio.NewRoots(dir)
	n := 0
	var walk func(string, int)
	walk = func(d string, depth int) {
		if depth > 5 || n > 2000 {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: d, Message: "not read"})
			}
			return
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			if e.IsDir() {
				walk(p, depth+1)
				continue
			}
			n++
			rel, _ := filepath.Rel(dir, p)
			rel = filepath.ToSlash(rel)
			microsoft := strings.HasPrefix(rel, "Microsoft/") || strings.Contains(rel, "/Microsoft/")
			f, err := safeio.Read(p, roots, safeio.MaxRead)
			if err != nil {
				continue
			}
			info, perr := parse.ParseTaskXML(f.Data)
			if perr != nil {
				if !microsoft {
					out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: p, Message: "task XML parse failed"})
				}
				continue
			}
			cmd := strings.Join(info.Commands, " | ")
			sev := model.Info
			title := "scheduled task"
			if s, why, ok := parse.ClassifyCommand(cmd); ok && s.Rank() > sev.Rank() {
				sev = s
				title = title + ": " + why
			}
			if microsoft && sev.Rank() < model.Medium.Rank() && !strings.EqualFold(e.Name(), "SysMon") {
				continue
			}
			ev := e.Name()
			if info.URI != "" {
				ev = info.URI
			}
			if cmd != "" {
				ev += " " + cmd
			}
			out.Findings = append(out.Findings, autorunFinding("autorun.task", sev, title, p, ev, "task:"+rel))
		}
	}
	walk(dir, 0)
	return out
}

func readRegistry(reg RegistryView) model.CollectorResult {
	var out model.CollectorResult
	for _, key := range RegistryKeys {
		vals, err := reg.ReadKey(key)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: key, Message: "not read"})
			continue
		}
		user := strings.HasPrefix(key, "HKCU")
		names := make([]string, 0, len(vals))
		for name := range vals {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			value := vals[name]
			sev := model.Info
			title := "registry Run value"
			if !user {
				title = "registry HKLM Run value"
			}
			if strings.Contains(key, "RunOnce") {
				title = "registry RunOnce value"
			}
			if s, why, ok := parse.ClassifyCommand(value); ok && s.Rank() > sev.Rank() {
				sev = s
				title = title + ": " + why
			}
			ev := name
			if value != "" {
				ev = name + "=" + value
			}
			out.Findings = append(out.Findings, autorunFinding("autorun.registry", sev, title, key, ev, "reg:"+key+":"+name))
		}
	}
	return out
}

func suspicious(content string) (model.Severity, string, bool) {
	lines, _ := parse.Lines(content)
	var best model.Severity
	why := ""
	okAny := false
	for _, line := range lines {
		sev, reason, ok := parse.ClassifyCommand(line)
		if !ok {
			continue
		}
		if !okAny || sev.Rank() > best.Rank() {
			best = sev
			why = reason
			okAny = true
		}
	}
	return best, why, okAny
}

func autorunFinding(rule string, sev model.Severity, title, path, evidence, key string) model.Finding {
	return model.Finalize(model.Finding{
		RuleID: rule, Collector: "autorun", Severity: sev, Title: title,
		Description: "The entry was not started.",
		Path:        path, Evidence: evidence, Key: key,
	})
}

func escapeFinding(path, target string) model.Finding {
	ev := "target not read"
	if target != "" {
		ev = "target=" + target
	}
	return model.Finalize(model.Finding{
		RuleID:      "autorun.symlink-escape",
		Collector:   "autorun",
		Severity:    model.High,
		Title:       "autorun symlink points at a home, temp, or shared-memory path",
		Description: "Links to /dev/null are ignored. Links into vendor directories are read. This link was not followed.",
		Path:        path,
		Evidence:    ev,
		Key:         "escape:" + path,
	})
}

// followAutorunLink classifies a symlink. The bool is true when the caller
// should not open the file.
func followAutorunLink(out *model.CollectorResult, path string, roots safeio.Roots, class func(string) linkClass, noun string) (safeio.Roots, bool) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return roots, false
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Path: path, Message: "symlink not resolved"})
		return roots, true
	}
	switch class(target) {
	case linkMask:
		return roots, true
	case linkSuspicious:
		out.Findings = append(out.Findings, escapeFinding(path, target))
		return roots, true
	case linkVendor:
		return roots.With(filepath.Dir(target)), false
	default:
		out.Findings = append(out.Findings, autorunFinding(
			"autorun.symlink",
			model.Info,
			noun,
			path,
			"target="+target,
			"link:"+path,
		))
		return roots, true
	}
}
