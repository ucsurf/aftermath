.PHONY: build test vet race imports fuzz

build:
	go build -trimpath -o aftermath ./cmd/aftermath

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

imports:
	bash scripts/check-imports.sh

fuzz:
	go test ./internal/parse -fuzz=FuzzParseAuthorizedKeys -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParseGitConfig -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzScanShell -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParseCrontab -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParseDesktop -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParseProps -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzStripJSONC -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParsePlist -fuzztime=5s
	go test ./internal/parse -fuzz=FuzzParseTaskXML -fuzztime=5s
	go test ./internal/ioc -fuzz=FuzzParsePack -fuzztime=5s
	go test ./internal/redact -fuzz=FuzzText -fuzztime=5s
