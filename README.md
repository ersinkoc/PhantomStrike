# PhantomStrike

> **AI-Native Autonomous Security Testing Platform**
> _"You point. It hunts."_

PhantomStrike is a next-generation security testing platform that leverages multi-agent AI to autonomously discover, exploit, and report vulnerabilities in your infrastructure.

## Key Features

- **Multi-Agent Swarm** — Planner, Executor, and Reviewer agents coordinate via ReAct loop
- **151 Security Tools** — Pre-configured YAML definitions across 21 categories
- **Multi-Provider AI** — Anthropic, OpenAI, Groq, Ollama + 10 more via OpenAI-compatible API
- **Docker Sandboxing** — Isolated tool execution with resource limits and network isolation
- **Real-time Streaming** — WebSocket-based live mission monitoring
- **Attack Chain Visualization** — Interactive graph view of attack paths
- **Knowledge Base** — pgvector-powered semantic search for security techniques
- **Report Generation** — JSON, Markdown, HTML report formats
- **MCP Protocol** — Full Model Context Protocol support (Streamable HTTP + stdio)
- **Scheduled Scans** — Cron-based recurring security assessments
- **Notifications** — Webhook, Slack, Discord notification channels
- **Multi-tenant RBAC** — Organizations, roles (admin/manager/analyst/viewer), API keys

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   React 19 + Tailwind 4 SPA                  │
│  Dashboard │ Missions │ Console │ Attack Graph │ Reports     │
│  Tools │ Skills │ Roles │ Knowledge │ Marketplace │ Settings │
├─────────────────────────────────────────────────────────────┤
│                    API Gateway (Go net/http)                  │
│  REST + WebSocket │ JWT Auth │ Rate Limiter │ Audit Log      │
├──────────────┬──────────────┬───────────────┬───────────────┤
│   MISSION    │    AGENT     │     MCP       │   SCHEDULER   │
│  CONTROLLER  │    SWARM     │   GATEWAY     │    ENGINE     │
├──────────────┴──────────────┴───────────────┴───────────────┤
│                   Tool Execution Engine                       │
│  Docker Sandbox │ Process Runner │ YAML Registry (151 tools) │
├─────────────────────────────────────────────────────────────┤
│                   Persistence Layer                           │
│  PostgreSQL + pgvector │ Redis Cache │ Local/S3 Storage       │
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

```bash
# Clone
git clone https://github.com/ersinkoc/phantomstrike.git
cd phantomstrike

# Configure
cp .env.example .env
# Edit .env with your API keys and database credentials

# Start infrastructure
docker compose up -d postgres redis

# Build and run
make build
make migrate
make run

# Start frontend (new terminal)
cd web && npm install && npm run dev
```

Access: **http://localhost:5173** (UI) | **http://localhost:8080** (API)

### One-liner with Docker Compose

```bash
docker compose up -d
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Go 1.26, net/http, pgx |
| **Database** | PostgreSQL 17 + pgvector |
| **Cache** | Redis 7 |
| **Frontend** | React 19, TypeScript, Vite, Tailwind 4, shadcn/ui |
| **State** | Zustand + TanStack Query |
| **Graph** | React Flow (attack chain visualization) |
| **Container** | Docker + Docker Compose |
| **CI/CD** | GitHub Actions |

## Security Tools (151)

| Category | Count | Examples |
|----------|-------|---------|
| **Network** | 10 | nmap, masscan, rustscan, arp-scan |
| **Web** | 13 | sqlmap, nuclei, nikto, ffuf, gobuster, dalfox |
| **Recon** | 10 | amass, subfinder, httpx, autorecon |
| **Exploit** | 10 | metasploit, crackmapexec, impacket |
| **Password** | 9 | hashcat, hydra, john, medusa |
| **Cloud** | 8 | prowler, pacu, scoutsuite, kube-bench |
| **Container** | 5 | trivy, grype, falco, docker-bench |
| **Forensics** | 10 | volatility, autopsy, binwalk |
| **Binary** | 9 | radare2, ghidra, angr, gdb |
| **API** | 6 | arjun, kiterunner, api-fuzzer |
| **+11 more** | 61 | vuln, database, protocol, secrets, etc. |

## Agent Roles (15)

Autonomous Pentester, Web App Security, Network Pentest, Cloud Security Audit, Container Security, API Security Audit, Bug Bounty Hunter, Red Team Operator, Blue Team Defender, Compliance Auditor, Vulnerability Researcher, Forensics Investigator, OSINT Specialist, CTF Player, Mobile Security

## LLM Providers

| Provider | Status |
|----------|--------|
| Anthropic (Claude) | Native API |
| OpenAI (GPT-4o) | Native API |
| Groq (Llama) | Native API |
| Ollama (local) | Native API |
| DeepSeek, Mistral, Gemini, Together, Cohere, Fireworks, Perplexity, OpenRouter, AI21 | OpenAI-compatible |

## Development

```bash
# Build all binaries
make build

# Run with hot reload
make dev

# Run tests
make test

# Lint
make lint

# Full dev stack (backend + frontend + infra)
make dev-full
```

## API

Full OpenAPI spec: [api/openapi.yaml](./api/openapi.yaml)

```
/api/v1/auth/*           # Login, register, refresh, logout
/api/v1/missions/*       # CRUD + start/pause/cancel + chain/vulns/tools/reports
/api/v1/conversations/*  # Messages + real-time chat
/api/v1/vulnerabilities/*# CRUD + stats + filtering
/api/v1/tools/*          # List, toggle, categories
/api/v1/knowledge/*      # Search, list, categories
/api/v1/reports/*        # Generate + download
/api/v1/scheduler/*      # CRUD + trigger
/api/v1/roles/*          # List roles
/api/v1/skills/*         # List skills
/api/v1/settings/*       # Get + update
/api/v1/marketplace/*    # Browse tools/skills
/ws                      # WebSocket real-time streaming
```

## CLI

```bash
./bin/ps-cli login
./bin/ps-cli missions list
./bin/ps-cli missions create
./bin/ps-cli missions start <id>
./bin/ps-cli missions logs <id>    # Real-time streaming
./bin/ps-cli vulns list
./bin/ps-cli tools list
./bin/ps-cli dashboard
```

## Project Structure

```
phantomstrike/
├── cmd/                    # Entry points (server, worker, cli, mcp)
├── internal/
│   ├── api/               # REST API handlers + WebSocket
│   ├── agent/             # Multi-agent swarm (planner/executor/reviewer)
│   ├── auth/              # JWT auth + RBAC middleware
│   ├── cache/             # Redis cache layer
│   ├── chain/             # Attack chain graph builder
│   ├── config/            # YAML + env config loader
│   ├── mcp/               # MCP protocol server
│   ├── notify/            # Notification dispatcher (webhook/slack/discord)
│   ├── audit/             # Audit logging middleware
│   ├── provider/          # LLM provider abstraction + router
│   ├── report/            # Multi-format report generation
│   ├── storage/           # File storage (local + S3/MinIO)
│   ├── store/             # PostgreSQL data layer
│   └── tool/              # Tool execution engine (Docker + process)
├── web/                   # React 19 SPA
├── tools/                 # 151 YAML tool definitions (21 categories)
├── roles/                 # 15 agent role definitions
├── skills/                # 92 skill modules (14 categories)
├── knowledge/             # Security knowledge base (15 docs)
├── migrations/            # PostgreSQL migrations
├── .github/workflows/     # CI/CD pipelines
└── docker-compose.yml     # Full stack orchestration
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | No |
| `JWT_SECRET` | JWT signing secret (256-bit) | Yes |
| `ADMIN_PASSWORD` | Default admin password | Yes |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | No* |
| `OPENAI_API_KEY` | OpenAI API key | No* |
| `GROQ_API_KEY` | Groq API key | No* |
| `STORAGE_PATH` | Local storage directory | No |
| `MCP_AUTH_TOKEN` | MCP server auth token | No |
| `LOG_LEVEL` | Log level (debug/info/warn/error) | No |

*At least one LLM provider API key is needed for AI features.

## Security

- **Tool Sandboxing**: Docker containers with read-only filesystem, no privileges, memory/CPU limits
- **Network Isolation**: Tools run in isolated Docker networks
- **JWT Auth**: HS256 tokens with refresh rotation
- **RBAC**: admin/manager/analyst/viewer roles
- **Audit Logging**: All mutations logged to audit_log table
- **Input Validation**: Parameterized SQL queries, request validation
- **Secrets**: All credentials via environment variables

## License

MIT License — see [LICENSE](./LICENSE) for details.
