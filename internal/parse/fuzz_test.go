package parse

import "testing"

func FuzzParseAuthorizedKeys(f *testing.F) {
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake comment\n")
	f.Add("command=\"echo hi\",restrict ssh-ed25519 AAAA comment\n")
	f.Fuzz(func(t *testing.T, s string) {
		keys, _ := ParseAuthorizedKeys(s)
		for _, k := range keys {
			_ = k.Fingerprint
			_ = k.Options
		}
	})
}

func FuzzParseGitConfig(f *testing.F) {
	f.Add("[core]\n\thooksPath = /tmp/h\n")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseGitConfig(s)
	})
}

func FuzzScanShell(f *testing.F) {
	f.Add("curl https://example.invalid | sh\n")
	f.Add("export PATH=\"/tmp:$PATH\"\n")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ScanShell(s, "/home/dev")
	})
}

func FuzzParseCrontab(f *testing.F) {
	f.Add("@reboot root /bin/true\n")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseCrontab(s, true)
		_, _ = ParseCrontab(s, false)
	})
}

func FuzzParseDesktop(f *testing.F) {
	f.Add("[Desktop Entry]\nExec=/bin/true\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ParseDesktop(s)
	})
}

func FuzzParseProps(f *testing.F) {
	f.Add("registry=https://registry.npmjs.org/\n")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseProps(s)
	})
}

func FuzzStripJSONC(f *testing.F) {
	f.Add("{\"a\":1,}\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = StripJSONC(s)
	})
}

func FuzzParsePlist(f *testing.F) {
	f.Add(`<plist><dict><key>Label</key><string>x</string></dict></plist>`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseLaunchPlist([]byte(s))
	})
}

func FuzzParseTaskXML(f *testing.F) {
	f.Add(`<Task><Actions><Exec><Command>cmd</Command></Exec></Actions></Task>`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseTaskXML([]byte(s))
	})
}
