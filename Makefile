.PHONY: fmt vet test lint fuzz build

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test -race -cover ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; ran gofmt + vet only"

sec:
	@command -v gosec >/dev/null 2>&1 && gosec ./... || echo "gosec not installed; skipping"

.PHONY: sec

fuzz:
	go test -run '^$$' -fuzz FuzzIsLoopback -fuzztime 30s ./cmd/cpscan

build:
	go build -o cpscan ./cmd/cpscan
