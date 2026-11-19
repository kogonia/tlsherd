GO ?= go
BIN_DIR ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
AGENT_LDFLAGS = -X github.com/kogonia/tlsherd/internal/agent.Version=$(VERSION)

.PHONY: build test vet lint check schema run-server run-agent clean

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/tlsherd-server ./cmd/tlsherd-server
	$(GO) build -ldflags='$(AGENT_LDFLAGS)' -o $(BIN_DIR)/tlsherd-agent ./cmd/tlsherd-agent

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed; skipped"

check: vet test

schema:
	@test -n "$(TLSHERD_DATABASE_URL)" || (echo "TLSHERD_DATABASE_URL required" && exit 1)
	psql "$(TLSHERD_DATABASE_URL)" -f migrations/schema.sql

run-server: build
	./$(BIN_DIR)/tlsherd-server

run-agent: build
	./$(BIN_DIR)/tlsherd-agent

clean:
	rm -rf $(BIN_DIR)
