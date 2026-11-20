package autorun

import "testing"

func TestLinkClasses(t *testing.T) {
	if classSystemdLink("/dev/null") != linkMask {
		t.Fatal("mask")
	}
	if classSystemdLink("/lib/systemd/system/systemd-resolved.service") != linkVendor {
		t.Fatal("lib vendor")
	}
	if classSystemdLink("/usr/lib/systemd/system/cron.service") != linkVendor {
		t.Fatal("usr vendor")
	}
	if classSystemdLink("/tmp/evil.service") != linkSuspicious {
		t.Fatal("tmp")
	}
	if classSystemdLink("/dev/shm/evil.service") != linkSuspicious {
		t.Fatal("shm")
	}
	if classSystemdLink("/home/alice/.config/systemd/user/x.service") != linkSuspicious {
		t.Fatal("home")
	}
	if classSystemdLink("/opt/vendor/app.service") != linkOther {
		t.Fatal("other")
	}
	if classLaunchdLink("/Applications/Docker.app/Contents/Library/LaunchServices/com.docker.vmnetd.plist", false) != linkVendor {
		t.Fatal("docker plist")
	}
	if classLaunchdLink("/dev/null", false) != linkMask {
		t.Fatal("launchd mask")
	}
	if classLaunchdLink("/Users/other/Library/LaunchAgents/a.plist", false) != linkSuspicious {
		t.Fatal("system agent into home")
	}
	if classLaunchdLink("/Users/me/Library/Application Support/Docker/agent.plist", true) != linkVendor {
		t.Fatal("user agent inside home")
	}
	if classStartupLink(`C:\Program Files\Microsoft OneDrive\OneDrive.exe`) != linkVendor {
		t.Fatal("onedrive")
	}
	if classStartupLink(`C:\Users\me\AppData\Local\Temp\a.cmd`) != linkSuspicious {
		t.Fatal("windows temp")
	}
}
