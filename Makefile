BINARY_NAME = agentburp
MODULE = github.com/msdbg/AgentBurp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -X '$(MODULE)/cmd.Version=$(VERSION)' -s -w

# Default target
.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME).exe .

# Build for multiple platforms
.PHONY: build-all
build-all:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64   .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64  .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64  .

# Run tests
.PHONY: test
test:
	go test ./... -v -race

# Run linter
.PHONY: lint
lint:
	golangci-lint run ./...

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME).exe
	rm -rf dist/

# Install locally
.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" .

# Run go mod tidy
.PHONY: tidy
tidy:
	go mod tidy

# Format code
.PHONY: fmt
fmt:
	gofmt -w .

# Quick dev check: format + build
.PHONY: dev
dev: fmt build
	@echo "✓ Build OK"
	@./$(BINARY_NAME).exe --help

.PHONY: help
help:
	@echo "AgentBurp Makefile targets:"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Cross-compile for all platforms"
	@echo "  test       - Run all tests"
	@echo "  lint       - Run golangci-lint"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to GOPATH/bin"
	@echo "  tidy       - Run go mod tidy"
	@echo "  fmt        - Format code"
