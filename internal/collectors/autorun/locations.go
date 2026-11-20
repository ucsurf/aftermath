package autorun

import "path/filepath"

// Locations are the autorun paths for one scan.
// Tests set the slices directly. DefaultLocations fills them for a GOOS.
type Locations struct {
	Home       string
	SystemRoot string
	GOOS       string
	Username   string

	UserLaunch      []string
	SystemLaunch    []string
	UserCrontabs    []string
	SystemCrontabs  []string
	SystemCronDirs  []string
	CronScriptDirs  []string
	UserSystemd     []string
	SystemSystemd   []string
	UserAutostart   []string
	SystemAutostart []string
	UserStartup     []string
	SystemStartup   []string
	TaskDirs        []string
	Registry        RegistryView
	ReadRegistry    bool
}

// RegistryKeys are the Run and RunOnce keys aftermath reads.
var RegistryKeys = []string{
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
}

// RegistryView reads registry values. Keys are the logical names in RegistryKeys.
type RegistryView interface {
	ReadKey(name string) (map[string]string, error)
}

// DefaultLocations returns autorun locations for goos.
// systemRoot is the OS root ("/" or `C:\`). username selects crontab spool files.
func DefaultLocations(goos, home, systemRoot, username string) Locations {
	if systemRoot == "" {
		if goos == "windows" {
			systemRoot = `C:\`
		} else {
			systemRoot = string(filepath.Separator)
		}
	}
	home = filepath.Clean(home)
	systemRoot = filepath.Clean(systemRoot)
	loc := Locations{Home: home, SystemRoot: systemRoot, GOOS: goos, Username: username}
	switch goos {
	case "darwin":
		loc.UserLaunch = []string{filepath.Join(home, "Library", "LaunchAgents")}
		loc.SystemLaunch = []string{
			filepath.Join(systemRoot, "Library", "LaunchAgents"),
			filepath.Join(systemRoot, "Library", "LaunchDaemons"),
		}
		if username != "" {
			loc.UserCrontabs = []string{filepath.Join(systemRoot, "usr", "lib", "cron", "tabs", username)}
		}
		loc.UserAutostart = []string{filepath.Join(home, ".config", "autostart")}
	case "linux":
		loc.SystemCrontabs = []string{filepath.Join(systemRoot, "etc", "crontab")}
		loc.SystemCronDirs = []string{filepath.Join(systemRoot, "etc", "cron.d")}
		loc.CronScriptDirs = []string{
			filepath.Join(systemRoot, "etc", "cron.hourly"),
			filepath.Join(systemRoot, "etc", "cron.daily"),
			filepath.Join(systemRoot, "etc", "cron.weekly"),
			filepath.Join(systemRoot, "etc", "cron.monthly"),
		}
		if username != "" {
			loc.UserCrontabs = []string{
				filepath.Join(systemRoot, "var", "spool", "cron", "crontabs", username),
				filepath.Join(systemRoot, "var", "spool", "cron", username),
			}
		}
		loc.UserSystemd = []string{filepath.Join(home, ".config", "systemd", "user")}
		loc.SystemSystemd = []string{
			filepath.Join(systemRoot, "etc", "systemd", "user"),
			filepath.Join(systemRoot, "etc", "systemd", "system"),
		}
		loc.UserAutostart = []string{filepath.Join(home, ".config", "autostart")}
		loc.SystemAutostart = []string{filepath.Join(systemRoot, "etc", "xdg", "autostart")}
	case "windows":
		loc.UserStartup = []string{filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")}
		loc.SystemStartup = []string{filepath.Join(systemRoot, "ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")}
		loc.TaskDirs = []string{filepath.Join(systemRoot, "Windows", "System32", "Tasks")}
		loc.ReadRegistry = true
	}
	return loc
}
