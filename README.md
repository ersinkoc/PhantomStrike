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
│                    API Gateway                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────────────┐  │
│  │  Auth   │  │Missions │  │   WS    │  │     MCP       │  │
│  └─────────┘  └─────────┘  └─────────┘  └───────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Agent Swarm                                │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                 │
│  │ Planner │───▶│ Executor│───▶│ Reviewer│                 │
│  └─────────┘    └─────────┘    └─────────┘                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Tool Executor (Docker/Process)                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  PostgreSQL + pgvector  │  Redis  │  Storage (Local/S3)      │
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

## Configuration

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
