package parse

import "strings"

// CronEntry is one command from a crontab.
type CronEntry struct {
	Line     int
	Schedule string
	User     string
	Command  string
}

// ParseCrontab parses crontab text. withUser is true for /etc/crontab and cron.d.
func ParseCrontab(s string, withUser bool) (entries []CronEntry, truncated bool) {
	lines, truncated := Lines(s)
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if isCronEnv(trim) {
			continue
		}
		e, ok := parseCronLine(i+1, trim, withUser)
		if ok {
			entries = append(entries, e)
		}
	}
	return entries, truncated
}

func isCronEnv(trim string) bool {
	if strings.HasPrefix(trim, "@") {
		return false
	}
	fields := strings.Fields(trim)
	if len(fields) == 0 {
		return false
	}
	if strings.Contains(fields[0], "=") && !isScheduleToken(fields[0]) {
		return true
	}
	return false
}

func parseCronLine(line int, trim string, withUser bool) (CronEntry, bool) {
	fields := strings.Fields(trim)
	if len(fields) == 0 {
		return CronEntry{}, false
	}
	e := CronEntry{Line: line}
	if strings.HasPrefix(fields[0], "@") {
		e.Schedule = fields[0]
		rest := fields[1:]
		if withUser {
			if len(rest) < 2 {
				return CronEntry{}, false
			}
			e.User = rest[0]
			e.Command = strings.Join(rest[1:], " ")
			return e, true
		}
		if len(rest) < 1 {
			return CronEntry{}, false
		}
		e.Command = strings.Join(rest, " ")
		return e, true
	}
	need := 5
	if withUser {
		need = 6
	}
	if len(fields) <= need {
		return CronEntry{}, false
	}
	if !isScheduleToken(fields[0]) {
		return CronEntry{}, false
	}
	e.Schedule = strings.Join(fields[:5], " ")
	if withUser {
		e.User = fields[5]
		e.Command = strings.Join(fields[6:], " ")
	} else {
		e.Command = strings.Join(fields[5:], " ")
	}
	return e, e.Command != ""
}

func isScheduleToken(s string) bool {
	if s == "*" || strings.HasPrefix(s, "*/") || strings.ContainsAny(s, "0123456789,-/") {
		return true
	}
	return false
}
