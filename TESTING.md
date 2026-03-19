# PhantomStrike Testing Guide

## Test Strategy

### 1. Unit Tests (Go Backend)
Location: `internal/*/*_test.go`

```bash
cd /d/Codebox/PROJECTS/PhantomStrike
go test ./... -v
go test ./internal/api -v -run TestHandlers
go test ./internal/agents -v
go test ./internal/repository -v
```

### 2. Integration Tests
Location: `tests/integration/*_test.go`

```bash
go test ./tests/integration -v -tags=integration
```

### 3. Frontend Tests (React)
Location: `web/src/**/*.test.ts*`

```bash
cd web
npm test
npm run test:unit
npm run test:e2e  # Playwright
```

## Running Tests

### Quick Check
```bash
make test
```

### With Coverage
```bash
make test-coverage
```

### Pre-commit
```bash
make lint
make test-short
```

## Test Data

### Fixtures
- `testdata/nmap.xml` - Sample scan output
- `testdata/nuclei.json` - Sample vuln report
- `testdata/sslscan.txt` - Sample SSL report

### Mock Targets
- `test-targets/vulnerable-app/` - Intentionally vulnerable app for testing
- `test-targets/api-server/` - Mock API for testing
