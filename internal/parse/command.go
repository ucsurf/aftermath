package parse

import (
	"strings"

	"github.com/ucsurf/aftermath/internal/model"
)

// ClassifyCommand reports whether cmd matches a suspicious execution pattern.
// The bool is false when nothing matched.
func ClassifyCommand(cmd string) (model.Severity, string, bool) {
	line := strings.TrimSpace(StripComment(cmd))
	if line == "" {
		return "", "", false
	}
	low := strings.ToLower(inspect(line))
	if isBenignEcho(line) {
		return "", "", false
	}
	if pipedDownload(line) {
		return model.High, "download or decode piped to a shell", true
	}
	if strings.Contains(low, "<(") && (strings.Contains(low, "curl") || strings.Contains(low, "wget")) {
		return model.High, "process substitution of a download", true
	}
	if remoteEval(low) {
		return model.High, "eval of remote or decoded content", true
	}
	if iexDownload(low) {
		return model.High, "Invoke-Expression of downloaded content", true
	}
	return "", "", false
}

func isBenignEcho(line string) bool {
	low := strings.ToLower(strings.TrimSpace(line))
	if !(strings.HasPrefix(low, "echo ") || strings.HasPrefix(low, "printf ")) {
		return false
	}
	if strings.Contains(low, "$(") || strings.Contains(low, "`") {
		return false
	}
	return len(splitPipes(line)) < 2
}

func pipedDownload(line string) bool {
	parts := splitPipes(line)
	if len(parts) < 2 {
		return false
	}
	if !shellStart(parts[len(parts)-1]) {
		return false
	}
	for _, p := range parts[:len(parts)-1] {
		low := strings.ToLower(p)
		if strings.Contains(low, "curl") || strings.Contains(low, "wget") || strings.Contains(low, "base64") {
			return true
		}
	}
	return false
}

func splitPipes(line string) []string {
	var out []string
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			b.WriteByte(c)
			i++
			b.WriteByte(line[i])
			continue
		}
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '|':
			if !inSingle && !inDouble {
				out = append(out, b.String())
				b.Reset()
				continue
			}
		}
		b.WriteByte(c)
	}
	out = append(out, b.String())
	return out
}

func shellStart(s string) bool {
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) == 0 {
		return false
	}
	if fields[0] == "sudo" || fields[0] == "command" || fields[0] == "exec" || fields[0] == "env" || fields[0] == "nohup" {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return false
	}
	switch strings.Trim(fields[0], `"'();`) {
	case "sh", "bash", "zsh", "dash", "fish", "ksh", "pwsh", "powershell", "powershell.exe", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

func remoteEval(low string) bool {
	if !strings.Contains(low, "eval ") && !strings.Contains(low, "eval\t") && !strings.HasPrefix(strings.TrimSpace(low), "eval") {
		return false
	}
	return strings.Contains(low, "curl") || strings.Contains(low, "wget") || strings.Contains(low, "base64") || strings.Contains(low, "http://") || strings.Contains(low, "https://")
}

func iexDownload(low string) bool {
	if !strings.Contains(low, "invoke-expression") && !strings.Contains(low, "iex ") && !strings.Contains(low, "|iex") && !strings.Contains(low, "| iex") {
		return false
	}
	return strings.Contains(low, "invoke-webrequest") || strings.Contains(low, "iwr ") || strings.Contains(low, "curl") || strings.Contains(low, "wget") || strings.Contains(low, "downloadstring") || strings.Contains(low, "base64") || strings.Contains(low, "http://") || strings.Contains(low, "https://")
}
