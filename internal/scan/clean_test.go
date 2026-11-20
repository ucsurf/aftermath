package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ucsurf/aftermath/internal/collectors/autorun"
	"github.com/ucsurf/aftermath/internal/model"
)

// TestCleanMachinesHaveNoHigh is the stock-desktop bar: zero high or critical
// findings. The Linux case matches the attached real-machine scan: masked
// units, the gh credential helper listed twice, and stock cron and XDG entries.
func TestCleanMachinesHaveNoHigh(t *testing.T) {
	t.Run("linux", func(t *testing.T) {
		home, sys := t.TempDir(), t.TempDir()
		writeLinuxDesktop(t, home, sys)
		rep := runOS(t, "linux", home, sys, nil)
		assertNoHigh(t, rep)
		if n := countRule(rep, "git.credential"); n != 2 {
			// gh (deduped to one) and store.
			t.Fatalf("credential findings %d, want 2", n)
		}
	})
	t.Run("darwin", func(t *testing.T) {
		home, sys := t.TempDir(), t.TempDir()
		writeDarwinDesktop(t, home, sys)
		assertNoHigh(t, runOS(t, "darwin", home, sys, nil))
	})
	t.Run("windows", func(t *testing.T) {
		home, sys := t.TempDir(), t.TempDir()
		writeWindowsDesktop(t, home, sys)
		reg := fakeReg{
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: {
				"OneDrive": `C:\Program Files\Microsoft OneDrive\OneDrive.exe`,
			},
			`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`: {
				"SecurityHealth": `C:\Windows\system32\SecurityHealthSystray.exe`,
			},
		}
		assertNoHigh(t, runOS(t, "windows", home, sys, reg))
	})
}

func TestLinuxMaskedUnitsAreNotHigh(t *testing.T) {
	home, sys := t.TempDir(), t.TempDir()
	// These 16 names were high symlink-escape findings on a real Debian box.
	masks := []string{
		"tpm-udev.path",
		"NetworkManager-dispatcher.service",
		"systemd-networkd-wait-online.service",
		"NetworkManager.service",
		"systemd-resolved.service",
		"NetworkManager-wait-online.service",
		"getty@tty1.service",
		"apt-daily-upgrade.timer",
		"apt-daily.timer",
		"console-getty.service",
		"man-db.timer",
		"e2scrub_all.timer",
		"systemd-timesyncd.service",
		"systemd-udev-trigger.service",
		"systemd-networkd.service",
		"systemd-udevd.service",
	}
	dir := filepath.Join(sys, "etc", "systemd", "system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range masks {
		if err := os.Symlink("/dev/null", filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	wants := filepath.Join(dir, "multi-user.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/lib/systemd/system/cron.service", filepath.Join(wants, "cron.service")); err != nil {
		t.Fatal(err)
	}
	rep := runOS(t, "linux", home, sys, nil)
	if n := countHigh(rep); n != 0 {
		t.Fatalf("high/critical %d, want 0 (this set was 16 high before)", n)
	}
}

func TestSystemdSymlinkToDevShmIsHigh(t *testing.T) {
	shm := filepath.Join("/dev/shm", "aftermath-link-test")
	if err := os.MkdirAll(shm, 0o755); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shm) })
	target := filepath.Join(shm, "evil.service")
	if err := os.WriteFile(target, []byte("[Service]\nExecStart=/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home, sys := t.TempDir(), t.TempDir()
	dir := filepath.Join(sys, "etc", "systemd", "system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "evil.service")); err != nil {
		t.Fatal(err)
	}
	rep := runOS(t, "linux", home, sys, nil)
	n := 0
	for _, f := range rep.Findings {
		if f.RuleID == "autorun.symlink-escape" && f.Severity == model.High {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("suspicious symlink findings %d", n)
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

func runOS(t *testing.T, goos, home, sys string, reg autorun.RegistryView) model.Report {
	t.Helper()
	rep, err := Run(context.Background(), Options{
		Home: home, SystemRoot: sys, TempDir: t.TempDir(),
		GOOS: goos, Username: "dev", Now: fixedNow, Registry: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func assertNoHigh(t *testing.T, rep model.Report) {
	t.Helper()
	if n := countHigh(rep); n != 0 {
		for _, f := range rep.Findings {
			if f.Severity == model.High || f.Severity == model.Critical {
				t.Errorf("%s %s %s %s", f.Severity, f.RuleID, f.Path, f.Title)
			}
		}
		t.Fatalf("high/critical %d", n)
	}
}

func countHigh(rep model.Report) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Severity == model.High || f.Severity == model.Critical {
			n++
		}
	}
	return n
}

func countRule(rep model.Report, rule string) int {
	n := 0
	for _, f := range rep.Findings {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

func writeLinuxDesktop(t *testing.T, home, sys string) {
	t.Helper()
	dir := filepath.Join(sys, "etc", "systemd", "system")
	mustWrite(t, filepath.Join(dir, "cron.service"), []byte("[Service]\nExecStart=/usr/sbin/cron -f\n"))
	if err := os.Symlink("/dev/null", filepath.Join(dir, "apt-daily.timer")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, "systemd-resolved.service")); err != nil {
		t.Fatal(err)
	}
	wants := filepath.Join(dir, "multi-user.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/lib/systemd/system/cron.service", filepath.Join(wants, "cron.service")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(sys, "etc", "cron.daily", "apt-compat"), []byte("#!/bin/sh\n# stock apt daily job\n"))
	mustWrite(t, filepath.Join(sys, "etc", "xdg", "autostart", "gnome-keyring-secrets.desktop"), []byte("[Desktop Entry]\nName=Secret Storage Service\nExec=/usr/bin/gnome-keyring-daemon --start --components=secrets\n"))
	mustWrite(t, filepath.Join(home, ".gitconfig"), []byte("[credential]\n\thelper = !/usr/local/bin/gh auth git-credential\n[credential \"https://github.com\"]\n\thelper = !/usr/local/bin/gh auth git-credential\n[credential]\n\thelper = store\n"))
	mustWrite(t, filepath.Join(home, ".bashrc"), []byte("export PATH=\"$HOME/.local/bin:$PATH\"\neval \"$(starship init bash)\"\n"))
}

func writeDarwinDesktop(t *testing.T, home, sys string) {
	t.Helper()
	agents := filepath.Join(sys, "Library", "LaunchAgents")
	daemons := filepath.Join(sys, "Library", "LaunchDaemons")
	plist := func(label, program string) string {
		return `<?xml version="1.0"?><plist><dict><key>Label</key><string>` + label + `</string><key>ProgramArguments</key><array><string>` + program + `</string></array></dict></plist>`
	}
	mustWrite(t, filepath.Join(agents, "com.google.keystone.agent.plist"), []byte(plist("com.google.keystone.agent", "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent")))
	mustWrite(t, filepath.Join(agents, "com.google.keystone.xpcservice.plist"), []byte(plist("com.google.keystone.xpcservice", "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateDaemon")))
	mustWrite(t, filepath.Join(daemons, "com.docker.vmnetd.plist"), []byte(plist("com.docker.vmnetd", "/Library/PrivilegedHelperTools/com.docker.vmnetd")))
	mustWrite(t, filepath.Join(agents, "com.docker.helper.plist"), []byte(plist("com.docker.helper", "/Library/PrivilegedHelperTools/com.docker.vmnetd")))
	mustWrite(t, filepath.Join(agents, "homebrew.mxcl.postgresql.plist"), []byte(plist("homebrew.mxcl.postgresql", "/opt/homebrew/opt/postgresql/bin/postgres")))
	mustWrite(t, filepath.Join(agents, "com.apple.installer.osmessagetracing.plist"), []byte(plist("com.apple.installer.osmessagetracing", "/System/Library/PrivateFrameworks/OSInstaller.framework/Resources/osmessagetracing")))
	_ = home
}

func writeWindowsDesktop(t *testing.T, home, sys string) {
	t.Helper()
	startup := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	mustWrite(t, filepath.Join(startup, "desktop.ini"), []byte(""))
	tasks := filepath.Join(sys, "Windows", "System32", "Tasks")
	mustWrite(t, filepath.Join(tasks, "OneDrive Standalone Update Task-S-1-5-21"), []byte(`<Task><RegistrationInfo><URI>\OneDrive Standalone Update Task</URI></RegistrationInfo><Actions><Exec><Command>C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe</Command></Exec></Actions></Task>`))
	mustWrite(t, filepath.Join(tasks, "Microsoft", "Windows", "UpdateOrchestrator", "Schedule Scan"), []byte(`<Task><Actions><Exec><Command>C:\Windows\system32\usoclient.exe</Command><Arguments>StartScan</Arguments></Exec></Actions></Task>`))
}
