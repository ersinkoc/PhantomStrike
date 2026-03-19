# PhantomStrike Testing Guide

## Test Strategy

### 1. Unit Tests (Go Backend)

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific packages
go test ./internal/api/ -v
go test ./internal/agent/ -v

# Run with race detection
go test -race ./...
```

### 2. Frontend Tests (React)

```bash
cd web
npm test
npm run test:ui        # Vitest UI mode
npm run test:coverage  # With coverage report
```

## Running Tests

### Quick Check
```bash
make test
```

### With Verbose Output
```bash
make test-verbose
```

### Build Verification
```bash
go build ./...         # All Go binaries
cd web && npm run build  # Frontend
```

## Test Packages

| Package | Tests | Description |
|---------|-------|-------------|
| `internal/api/` | handler_test.go | API handler unit tests (JSON helpers, UUID parsing, WSHub) |
| `internal/agent/` | swarm_test.go | Agent swarm, phases, ReAct loop, mock provider tests |

## CI/CD

Tests run automatically via GitHub Actions on:
- Push to `main`
- Pull requests to `main`

The CI pipeline includes: lint, test (with Postgres + Redis), build, and web-build jobs.
See `.github/workflows/ci.yml` for details.

## Docker-Based Testing

```bash
# Start infrastructure for integration tests
docker compose up -d postgres redis

# Run tests against real DB
DATABASE_URL=postgres://phantom:phantom123@localhost:5432/phantomstrike go test ./...

# Cleanup
docker compose down
```
