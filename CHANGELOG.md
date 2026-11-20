# Changelog

## 0.1.0 - Unreleased

### Added

- `aftermath scan`, `aftermath baseline save`, and `aftermath diff`.
- Collectors for SSH `authorized_keys`, launchd, cron, systemd user and system units, XDG autostart, Windows Startup folders, Run/RunOnce keys, scheduled-task XML, shell startup files, global git config, package-manager config, and user-level Claude, Cursor, VS Code, Gemini, and Codex autoruns.
- Optional `--project` for a project's `.claude`, `.vscode`, and `.cursor` directories.
- Embedded public indicator pack `public-dev-persistence-2026.11`, plus `--ioc`.
- Text, JSON, Markdown, and SARIF 2.1.0 output.
- `--fail-on` and exit codes 0, 1, and 2.
- Redaction of common token and private-key shapes. npm, PyPI, cargo, and Maven secrets are reported as present and the values are not printed.
