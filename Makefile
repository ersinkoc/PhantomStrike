.PHONY: help build run dev test clean migrate lint fmt docker-up docker-down setup install generate build-all release build-release embed-frontend

# Variables
BINARY_NAME=phantomstrike
WORKER_NAME=phantomstrike-worker
CLI_NAME=ps-cli
MCP_NAME=phantomstrike-mcp
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Version=$(VERSION) -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Commit=$(COMMIT) -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Date=$(DATE)"
BUILD_DIR=bin

# Default target - show help
help:
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║           PhantomStrike Build System                       ║"
	@echo "╚════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Setup:"
	@echo "  make setup         Run setup script for your platform"
	@echo "  make install       Install all dependencies"
	@echo ""
	@echo "Build:"
	@echo "  make build         Build all binaries"
	@echo "  make build-server  Build API server only"
	@echo "  make build-cli     Build CLI only"
	@echo "  make build-worker  Build worker only"
	@echo "  make build-web     Build web UI"
	@echo "  make build-release Build server with embedded frontend"
	@echo "  make release       Build release binaries for all platforms"
	@echo ""
	@echo "Development:"
	@echo "  make dev           Run server in dev mode"
	@echo "  make dev-web       Run web UI dev server"
	@echo "  make dev-full      Start full development stack"
	@echo "  make run           Build and run server"
	@echo ""
	@echo "Testing:"
	@echo "  make test          Run all tests"
	@echo "  make test-verbose  Run tests with verbose output"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint          Run linters"
	@echo "  make fmt           Format code"
	@echo "  make vet           Run go vet"
	@echo "  make generate      Generate code (sqlc, swagger)"
	@echo ""
	@echo "Database:"
	@echo "  make migrate       Run database migrations"
	@echo "  make migrate-new   Create new migration"
	@echo "  make seed          Seed database"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up     Start services with Docker"
	@echo "  make docker-down   Stop Docker services"
	@echo "  make docker-build  Build Docker images"
	@echo "  make docker-logs   Show Docker logs"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean         Clean build artifacts"
	@echo "  make backup        Create backup"
	@echo "  make health        Check service health"

# Setup
setup:
	@echo "Running setup for your platform..."
	@python3 setup.py 2>/dev/null || python setup.py 2>/dev/null || \
	 (test -f setup.sh && bash setup.sh) || \
	 (test -f setup.ps1 && powershell -ExecutionPolicy Bypass -File setup.ps1)

# Dependencies
install:
	@echo "Installing dependencies..."
	go mod tidy
	go install github.com/air-verse/air@latest
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	cd web && npm install

# Code generation
generate:
	@echo "Generating code..."
	sqlc generate
	swag init -g cmd/server/main.go -o docs/swagger

# Build targets
build: build-server build-worker build-cli build-mcp

build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

build-worker:
	@echo "Building worker..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(WORKER_NAME) ./cmd/worker

build-cli:
	@echo "Building CLI..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_NAME) ./cmd/cli

build-mcp:
	@echo "Building MCP server..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_NAME) ./cmd/mcp

build-web:
	@echo "Building web UI..."
	cd web && npm run build

build-all: build build-web

# Embed frontend into server binary: build web, copy dist, then build server
embed-frontend:
	@echo "Copying web/dist to internal/server/static..."
	@rm -rf internal/server/static/*
	@cp -r web/dist/* internal/server/static/ 2>/dev/null || echo "web/dist not found — run 'make build-web' first"

# Build a release server binary with embedded frontend
build-release: build-web embed-frontend
	@echo "Building release server with embedded frontend..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server
	@echo "Release binary: $(BUILD_DIR)/$(BINARY_NAME)"

# Run
dev:
	@echo "Running in development mode..."
	air

dev-worker:
	@echo "Running worker in development mode..."
	air --build.cmd "go build -o bin/worker ./cmd/worker" --build.bin "./bin/worker"

dev-web:
	@echo "Starting web UI dev server..."
	cd web && npm run dev

dev-full: docker-up
	@echo "Waiting for services to start..."
	@sleep 5
	@make -j2 dev dev-web

run: build-server
	./$(BUILD_DIR)/$(BINARY_NAME)

# Testing
test:
	go test -race -cover ./...

test-verbose:
	go test -race -cover -v ./...

test-unit:
	go test -short -v ./...

# Quality
lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w . 2>/dev/null || true

vet:
	go vet ./...

# Database
migrate:
	go run ./cmd/server -migrate-only

migrate-new:
	@read -p "Migration name: " name; \
	migrate create -ext sql -dir migrations $$name

seed:
	@echo "Seeding database..."
	go run ./cmd/cli seed

# Docker
docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-build:
	docker compose build

docker-logs:
	docker compose logs -f

docker-clean:
	docker compose down -v --remove-orphans
	docker system prune -f

# Release builds for all platforms
release: clean
	@echo "Building release binaries..."
	@mkdir -p $(BUILD_DIR)/release

	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(WORKER_NAME)-linux-amd64 ./cmd/worker
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_NAME)-linux-amd64 ./cmd/cli

	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(WORKER_NAME)-linux-arm64 ./cmd/worker
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_NAME)-linux-arm64 ./cmd/cli

	@echo "Building for macOS AMD64..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(WORKER_NAME)-darwin-amd64 ./cmd/worker
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_NAME)-darwin-amd64 ./cmd/cli

	@echo "Building for macOS ARM64..."
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(WORKER_NAME)-darwin-arm64 ./cmd/worker
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_NAME)-darwin-arm64 ./cmd/cli

	@echo "Building for Windows AMD64..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(WORKER_NAME)-windows-amd64.exe ./cmd/worker
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_NAME)-windows-amd64.exe ./cmd/cli

	@echo "Release binaries built in $(BUILD_DIR)/release/"

# Clean
clean:
	rm -rf $(BUILD_DIR)/
	go clean -cache
	cd web && rm -rf dist node_modules/.cache 2>/dev/null || true

# Utilities
health:
	@echo "Checking service health..."
	@curl -s http://localhost:8080/api/health | jq . 2>/dev/null || curl -s http://localhost:8080/api/health

backup:
	@echo "Creating backup..."
	@mkdir -p backups
	tar -czf backups/phantomstrike-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz \
		data/ config.yaml .env tools/ roles/ skills/ knowledge/ 2>/dev/null || \
	(docker compose exec postgres pg_dump -U phantom phantomstrike > backups/db-backup-$(shell date +%Y%m%d-%H%M%S).sql)

logs:
	@tail -f logs/*.log 2>/dev/null || echo "No log files found"

swagger:
	@open http://localhost:8080/swagger/index.html || xdg-open http://localhost:8080/swagger/index.html || echo "Open: http://localhost:8080/swagger/index.html"

# Dependencies
deps:
	go mod tidy
	go mod verify
	cd web && npm install
