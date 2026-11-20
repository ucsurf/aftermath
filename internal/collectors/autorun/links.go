package autorun

import (
	"strings"
)

// linkClass is how an autorun symlink should be treated.
// Masked units are ignored. Vendor targets may be read. Only unusual
// writable locations are high-severity findings.
type linkClass int

const (
	linkPlain linkClass = iota
	linkMask
	linkVendor
	linkSuspicious
	linkOther
)

func classSystemdLink(target string) linkClass {
	if isNullDevice(target) {
		return linkMask
	}
	if isWritableOddPath(target) || underDir(target, "/home") || underDir(target, "/Users") || underDir(target, "/root") {
		return linkSuspicious
	}
	for _, dir := range []string{
		"/usr/lib/systemd",
		"/lib/systemd",
		"/usr/local/lib/systemd",
		"/run/systemd",
		"/etc/systemd",
	} {
		if underDir(target, dir) {
			return linkVendor
		}
	}
	return linkOther
}

func classLaunchdLink(target string, user bool) linkClass {
	if isNullDevice(target) {
		return linkMask
	}
	if isWritableOddPath(target) {
		return linkSuspicious
	}
	if !user && (underDir(target, "/home") || underDir(target, "/Users") || underDir(target, "/root")) {
		return linkSuspicious
	}
	for _, dir := range []string{
		"/System",
		"/usr/libexec",
		"/usr/lib",
		"/Library",
		"/Applications",
		"/opt/homebrew",
		"/usr/local",
		"/opt/local",
		"/home",
		"/Users",
	} {
		if underDir(target, dir) {
			return linkVendor
		}
	}
	return linkOther
}

func classStartupLink(target string) linkClass {
	if isNullDevice(target) {
		return linkMask
	}
	if isWritableOddPath(target) || underDir(target, "/Windows/Temp") || underDir(target, "/AppData/Local/Temp") {
		return linkSuspicious
	}
	for _, dir := range []string{
		"/Windows/System32",
		"/Windows/SysWOW64",
		"/Program Files",
		"/Program Files (x86)",
	} {
		if underDir(target, dir) {
			return linkVendor
		}
	}
	return linkOther
}

func isNullDevice(target string) bool {
	p := slashLower(target)
	return p == "/dev/null" || p == "/dev/zero" || strings.HasSuffix(p, ":/nul") || p == "nul"
}

func isWritableOddPath(target string) bool {
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/run/user", "/var/folders"} {
		if underDir(target, dir) {
			return true
		}
	}
	return false
}

func underDir(path, dir string) bool {
	p := stripDrive(slashLower(path))
	d := stripDrive(slashLower(dir))
	if !strings.HasPrefix(d, "/") {
		d = "/" + d
	}
	if p == d || strings.HasPrefix(p, d+"/") {
		return true
	}
	rest := p
	for {
		i := strings.Index(rest, d)
		if i < 0 {
			return false
		}
		after := i + len(d)
		if after == len(rest) || rest[after] == '/' {
			return true
		}
		rest = rest[i+1:]
	}
}

func slashLower(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimSuffix(p, "/")
	return strings.ToLower(p)
}

func stripDrive(p string) string {
	if len(p) >= 3 && p[1] == ':' && p[2] == '/' {
		return p[2:]
	}
	return p
}
