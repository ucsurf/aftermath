# Contributing

## Tests

```sh
go test ./...
go test -race ./...
go vet ./...
bash scripts/check-imports.sh
```

`make fuzz` runs the parser fuzz targets for a few seconds each. CI does the same on Linux.

Golden files under `testdata/golden/` are compared on Linux. Regenerate them with:

```sh
UPDATE_GOLDEN=1 go test ./internal/scan -run TestDemoFixtureGolden
```

Review the diff. The demo fixtures are synthetic. Do not put real home-directory data or live secrets in them.

## Import boundary

Non-test code must not import `net`, `net/http`, or `os/exec`. Collector, parser, IOC, and `internal/scan` code must not create, write, remove, or chmod files. `internal/cli` and `internal/baseline` may write the report and the baseline file the user asked for.

`internal/depcheck` enforces this with `go list -deps` (linux, darwin, and windows; amd64 and arm64) and an AST scan. A Windows registry read uses `advapi32` `RegOpenKeyExW` with `KEY_QUERY_VALUE` only, so the module does not import `golang.org/x/sys/windows` (that package imports `net`).

## Indicator packs

Embedded indicators live in `internal/ioc/packs/`. Each indicator needs:

- a stable id
- a severity
- an https URL to a public writeup that actually describes that indicator
- a path, filename, content literal, or hash taken from that writeup

Do not add an indicator you cannot cite. Do not paste exploit code, private keys, or payload source into a pack or a fixture. Content matches are literals, not regular expressions. A pack path must be relative and must not contain `..`.

`--ioc FILE` loads an extra pack with the same rules. The file is data. It is not executed.

## Scope

aftermath lists persistence and access grants on a developer machine after an incident. Repo hook review before opening a project belongs in hookjack, not here. `--project` only adds that project's `.claude`, `.vscode`, and `.cursor` directories.
