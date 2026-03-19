# PhantomStrike

AI-Native Autonomous Security Testing Platform

PhantomStrike is a next-generation security testing platform that leverages AI agents to autonomously discover, exploit, and report vulnerabilities in your infrastructure.

## Features

- **AI-Powered Testing**: Multi-agent swarm using Planner, Executor, and Reviewer agents
- **ReAct Loop**: Reasoning + Acting framework for intelligent decision making
- **Docker Sandboxing**: Isolated tool execution for security
- **Real-time Monitoring**: WebSocket-based live mission streaming
- **Knowledge Base**: pgvector-powered semantic search for security knowledge
- **Attack Chain Visualization**: Interactive graph view of attack paths
- **Report Generation**: Multi-format reports (JSON, Markdown, HTML, PDF)
- **MCP Support**: Model Context Protocol for LLM integration

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    API Gateway                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────────────┐   │
│  │  Auth   │  │Missions │  │   WS    │  │     MCP       │   │
│  └─────────┘  └─────────┘  └─────────┘  └───────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Agent Swarm                               │
│  ┌─────────┐     ┌─────────┐      ┌─────────┐               │
│  │ Planner │───▶│ Executor │───▶│ Reviewer │               │
│  └─────────┘     └─────────┘      └─────────┘               │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Tool Executor (Docker/Process)                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  PostgreSQL + pgvector  │  Redis  │  Storage (Local/S3)     │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.26+
- PostgreSQL 16+ with pgvector extension
- Redis 7+
- Docker (optional, for tool sandboxing)
- Node.js 20+ (for frontend)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/ersinkoc/phantomstrike.git
cd phantomstrike
```

2. **Install dependencies:**
```bash
make deps
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Start services with Docker Compose:**
```bash
docker-compose up -d postgres redis
```

5. **Run migrations:**
```bash
make migrate
```

6. **Start the server:**
```bash
make run
```

7. **Start the frontend (in a new terminal):**
```bash
cd web && npm run dev
```

Access the application at http://localhost:5173

## Screenshots

*Coming soon - Screenshots of the dashboard, mission view, and attack chain visualization*

## Development Guide

### Hot Reload Development

For backend development with hot reload:

```bash
# Install air (hot reload for Go)
go install github.com/air-verse/air@latest

# Run with hot reload
air
```

### Database Migrations

Manual migration commands:

```bash
# Run migrations
make migrate

# Check migration status
go run ./cmd/server -migration-status
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make test-verbose

# Run specific package tests
go test -v ./internal/agent/...
```

### Code Quality

```bash
# Format Go code
gofmt -s -w .

# Run linter
make lint
```

### Frontend Development

```bash
cd web

# Install dependencies
npm install

# Run dev server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Deployment

### Docker Production Deployment

```bash
# Build all images
docker-compose build

# Start all services
docker-compose up -d

# Scale workers (optional)
docker-compose up -d --scale worker=3

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `JWT_SECRET` | JWT signing secret | Yes |
| `ADMIN_PASSWORD` | Default admin password | Yes |
| `ANTHROPIC_API_KEY` | Anthropic API key | No |
| `OPENAI_API_KEY` | OpenAI API key | No |
| `GROQ_API_KEY` | Groq API key | No |

## Troubleshooting

### Common Issues

**PostgreSQL connection failed**
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Reset database (WARNING: deletes all data)
docker-compose down -v postgres
docker-compose up -d postgres
```

**Redis connection failed**
```bash
# Check Redis status
docker-compose ps redis
docker-compose logs redis
```

**Docker not available for tools**
```bash
# Run in process mode instead
# Edit config.yaml:
tools:
  docker:
    enabled: false
  process:
    enabled: true
```

**Port conflicts**
```bash
# Change ports in docker-compose.yml
# Server: 8080
# MCP Server: 8081
# Frontend: 5173
# PostgreSQL: 5432
# Redis: 6379
```

### Health Checks

```bash
# API health check
curl http://localhost:8080/health

# MCP health check
curl http://localhost:8081/health
```

### Getting Help

- GitHub Issues: [github.com/ersinkoc/phantomstrike/issues](https://github.com/ersinkoc/phantomstrike/issues)
- Documentation: See [api/openapi.yaml](./api/openapi.yaml)
- CLI Help: `./bin/ps-cli help`

## Configuration
n
Create a `config.yaml` file:

```yaml
database:
  url: "${DATABASE_URL}"

auth:
  jwt_secret: "${JWT_SECRET}"
  default_admin:
    email: "admin@phantomstrike.local"
    password: "${ADMIN_PASSWORD}"

providers:
  default: "anthropic"
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-sonnet-4-20250514"
  openai:
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4o"

tools:
  dir: "./tools"
  docker:
    enabled: true
```

```yaml
database:
  url: "${DATABASE_URL}"

auth:
  jwt_secret: "${JWT_SECRET}"
  default_admin:
    email: "admin@phantomstrike.local"
    password: "${ADMIN_PASSWORD}"

providers:
  default: "anthropic"
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-sonnet-4-20250514"
  openai:
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4o"

tools:
  dir: "./tools"
  docker:
    enabled: true
```

## CLI Usage

```bash
# Build CLI
make build

# Login
./bin/ps-cli login

# List missions
./bin/ps-cli missions list

# Create mission
./bin/ps-cli missions create

# View dashboard
./bin/ps-cli dashboard
```

## API Documentation

See [OpenAPI Specification](./api/openapi.yaml)

## Available Tools

PhantomStrike includes 21+ security tools:

| Category | Tools |
|----------|-------|
| Network | nmap, masscan, rustscan |
| Web | sqlmap, nuclei, nikto, ffuf, gobuster, dalfox, dirsearch |
| Recon | subfinder, httpx, whatweb, amass, theHarvester |
| Vulnerability | testssl, wafw00f |
| Exploitation | metasploit |
| Password | hydra, hashcat |

## Commands

```bash
# Build all binaries
make build

# Run tests
make test

# Run linting
make lint

# Format code
make fmt

# Start with Docker Compose
make docker-up

# Stop services
make docker-down

# Clean build artifacts
make clean
```

## Project Structure

```
.
├── cmd/                    # Application entry points
│   ├── server/            # API server
│   ├── worker/            # Background job worker
│   ├── cli/               # CLI tool
│   └── mcp/               # MCP server
├── internal/              # Internal packages
│   ├── api/               # API handlers
│   ├── agent/             # Agent swarm
│   ├── auth/              # Authentication
│   ├── chain/             # Attack chain builder
│   ├── config/            # Configuration
│   ├── mcp/               # MCP implementation
│   ├── provider/          # LLM providers
│   ├── report/            # Report generation
│   ├── storage/           # File storage
│   ├── store/             # Database layer
│   └── tool/              # Tool execution
├── web/                   # Frontend (React + Vite)
├── tools/                 # Tool definitions (YAML)
├── roles/                 # Agent role definitions
├── skills/                # Skill modules
├── migrations/            # Database migrations
└── api/                   # API documentation
```

## Security Considerations

- **Tool Sandboxing**: All tools run in Docker containers with limited privileges
- **Network Isolation**: Tools run in isolated networks by default
- **Resource Limits**: Memory and CPU limits prevent resource exhaustion
- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Acknowledgments

- Inspired by the ReAct paper and autonomous agent research
- Built with Go, React, and PostgreSQL
- Uses industry-standard security tools
