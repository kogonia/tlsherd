GO ?= go
BIN_DIR ?= bin

.PHONY: build test vet lint check schema run-server run-agent bootstrap-admin clean

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/tlsherd-server ./cmd/tlsherd-server
	$(GO) build -o $(BIN_DIR)/tlsherd-agent ./cmd/tlsherd-agent
	$(GO) build -o $(BIN_DIR)/tlsherd-bootstrap ./cmd/tlsherd-bootstrap

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

bootstrap-admin: build
	./$(BIN_DIR)/tlsherd-bootstrap

clean:
	rm -rf $(BIN_DIR)
