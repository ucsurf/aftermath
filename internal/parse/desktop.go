package parse

import "strings"

// DesktopEntry is the subset of a .desktop file aftermath cares about.
type DesktopEntry struct {
	Name     string
	Exec     string
	Hidden   bool
	Disabled bool
}

// ParseDesktop reads a freedesktop desktop file.
func ParseDesktop(s string) DesktopEntry {
	var d DesktopEntry
	in := false
	lines, _ := Lines(s)
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			in = trim == "[Desktop Entry]"
			continue
		}
		if !in {
			continue
		}
		key, val, ok := splitKV(trim)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "name":
			if d.Name == "" {
				d.Name = val
			}
		case "exec":
			d.Exec = val
		case "hidden":
			d.Hidden = strings.EqualFold(val, "true")
		case "x-gnome-autostart-enabled":
			if strings.EqualFold(val, "false") {
				d.Disabled = true
			}
		}
	}
	return d
}
