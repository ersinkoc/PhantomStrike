.PHONY: build run dev test clean migrate lint fmt docker-up docker-down

# Variables
BINARY_NAME=phantomstrike
WORKER_NAME=phantomstrike-worker
CLI_NAME=ps-cli
MCP_NAME=phantomstrike-mcp
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Version=$(VERSION) -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Commit=$(COMMIT) -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Date=$(DATE)"

# Build
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/server
	go build $(LDFLAGS) -o bin/$(WORKER_NAME) ./cmd/worker
	go build $(LDFLAGS) -o bin/$(CLI_NAME) ./cmd/cli
	go build $(LDFLAGS) -o bin/$(MCP_NAME) ./cmd/mcp

build-server:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/server

# Run
run: build-server
	./bin/$(BINARY_NAME)

dev:
	go run ./cmd/server

# Test
test:
	go test -race -cover ./...

test-verbose:
	go test -race -cover -v ./...

# Quality
lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w .

# Database
migrate:
	go run ./cmd/server -migrate-only

# Docker
docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-build:
	docker compose build

# Clean
clean:
	rm -rf bin/
	go clean -cache

# Frontend
dev-web:
	cd web && npm run dev

# Dependencies
deps:
	go mod tidy
	go mod verify
	cd web && npm install

# Full development stack
dev-full: docker-up
	@echo "Waiting for services to start..."
	@sleep 5
	cd web && npm run dev
