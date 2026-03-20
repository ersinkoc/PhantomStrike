# PhantomStrike

> **AI-Native Autonomous Security Testing Platform**
> _"You point. It hunts."_

PhantomStrike is a next-generation security testing platform that leverages multi-agent AI to autonomously discover, exploit, and report vulnerabilities in your infrastructure. It ships with 248 security tools (80 custom Python scripts + 168 YAML-defined binary integrations) across 21 categories, all orchestrated by an AI agent swarm.

## Key Features

- **Multi-Agent Swarm** -- Planner, Executor, and Reviewer agents coordinate via ReAct loop
- **248 Security Tools** -- 80 custom Python scripts in `tools/_custom/` + 168 binary tool definitions across 21 categories
- **Multi-Provider AI** -- Anthropic, OpenAI, Groq, Ollama + 10 more via OpenAI-compatible API
- **Custom Tool Framework** -- Drop a Python script into `tools/_custom/` and it's immediately available
- **Docker Sandboxing** -- Isolated tool execution with resource limits and network isolation
- **Real-time Streaming** -- WebSocket-based live mission monitoring
- **Attack Chain Visualization** -- Interactive graph view of attack paths
- **Knowledge Base** -- 15 security technique documents with full-text search, auto-ingested on startup
- **Report Generation** -- JSON, Markdown, HTML, and PDF-ready (print-optimized HTML) formats
- **MCP Protocol** -- Full Model Context Protocol support (Streamable HTTP + stdio)
- **Mission Lifecycle** -- Create, start, pause, cancel, retry, and cascade-delete missions
- **Scheduled Scans** -- Cron-based recurring security assessments
- **Notifications** -- Webhook, Slack, Discord notification channels
- **Multi-tenant RBAC** -- Organizations, roles (admin/manager/analyst/viewer), API keys

## Architecture

```
+---------------------------------------------------------------+
|                 React 19 + Tailwind 4 SPA                     |
|  Dashboard | Missions | Console | Attack Graph | Reports      |
|  Tools | Skills | Roles | Knowledge | Marketplace | Settings  |
+---------------------------------------------------------------+
|                  API Gateway (Go net/http)                     |
|  REST + WebSocket | JWT Auth | Rate Limiter | Audit Log       |
+---------------+---------------+---------------+---------------+
|   MISSION     |    AGENT      |     MCP       |   SCHEDULER   |
|  CONTROLLER   |    SWARM      |   GATEWAY     |    ENGINE     |
+---------------+---------------+---------------+---------------+
|                 Tool Execution Engine                          |
|  Docker Sandbox | Process Runner | YAML Registry (248 tools)  |
+---------------------------------------------------------------+
|                 Persistence Layer                              |
|  PostgreSQL 17 + pgvector | Redis 7 | Local/S3 Storage        |
+---------------------------------------------------------------+
```

## Quick Start

### One Command (Docker Compose)

```bash
git clone https://github.com/ersinkoc/phantomstrike.git
cd phantomstrike
docker compose up -d
```

That's it. The full stack comes up at:

| Service      | URL                           | Port  |
|------------- |-------------------------------|-------|
| **Frontend** | http://localhost:15173         | 15173 |
| **API**      | http://localhost:18090         | 18090 |
| **PostgreSQL** | localhost:15432             | 15432 |
| **Redis**    | localhost:16379               | 16379 |

Default credentials: `admin` / `admin123` (change via `ADMIN_PASSWORD` env var).

### Manual Setup

```bash
# Prerequisites: Go 1.22+, PostgreSQL 16+ (pgvector), Redis 7+, Node.js 20+

# Configure
cp .env.example .env
# Edit .env with your API keys and database credentials

# Start infrastructure
docker compose up -d postgres redis

# Build and run backend
make build
make migrate
make run

# Start frontend (separate terminal)
cd web && npm install && npm run dev
```

## Security Tools (248)

PhantomStrike ships with 248 tools across two execution modes:

### Custom Python Tools (80)

Located in `tools/_custom/`, these are purpose-built Python scripts that run without external binary dependencies. Write a new `.py` script, drop it in the directory, and it's immediately available to the agent swarm.

Examples: `xss-scanner.py`, `ssl-analyzer.py`, `port-scanner.py`, `jwt-analyzer.py`, `cors-checker.py`, `metasploit-lite.py`, `bloodhound-lite.py`, `volatility-lite.py`

### Binary Tool Definitions (168 YAML)

YAML-defined wrappers for industry-standard security binaries, organized by category:

| Category | Count | Key Tools |
|----------|------:|-----------|
| **Web** | 35 | sqlmap, nuclei, nikto, ffuf, gobuster, dalfox, feroxbuster, wpscan |
| **Recon** | 24 | amass, subfinder, httpx, shodan, censys, theHarvester, waybackurls |
| **Network** | 17 | nmap, masscan, rustscan, arp-scan, enum4linux, nbtscan |
| **Forensics** | 12 | exiftool, foremost, steghide, sleuthkit, strings, zsteg |
| **Exploit** | 12 | metasploit, impacket, pwntools, linpeas, crackmapexec |
| **Cloud** | 9 | prowler, cloudsplaining, kube-bench, kube-hunter |
| **Binary** | 9 | ghidra, angr, checksec, gdb, binwalk |
| **Password** | 8 | hashcat, hydra, john, medusa, cewl, fcrackzip |
| **Vuln** | 7 | nuclei, wafw00f, ssl-analyzer |
| **API** | 6 | arjun, api-fuzzer, swagger-scan, kiterunner |
| **Container** | 5 | trivy, grype, docker-bench-security |
| **Wireless** | 5 | aircrack-ng, bully, reaver |
| **Secrets** | 4 | trufflehog, detect-secrets, git-secrets |
| **Protocol** | 4 | dnsenum, rpcclient, fierce |
| **Database** | 4 | sqlmap, oracle-scanner |
| **IaC** | 3 | checkov, terrascan, tfsec |
| **+5 more** | 4 | reverse, mobile, crypto, cms, social-engineering |

## Agent Roles (15)

Autonomous Pentester, Web App Security, Network Pentest, Cloud Security Audit, Container Security, API Security Audit, Bug Bounty Hunter, Red Team Operator, Blue Team Defender, Compliance Auditor, Vulnerability Researcher, Forensics Investigator, OSINT Specialist, CTF Player, Mobile Security

## Skills Library (92)

92 skill modules across 13 categories: API, Cloud, Container, Crypto, Exploit, Forensics, Mobile, Network, OSINT, Password, Recon, Social Engineering, Web.

## LLM Providers

| Provider | Integration |
|----------|------------|
| Anthropic (Claude) | Native API |
| OpenAI (GPT-4o) | Native API |
| Groq (Llama) | Native API |
| Ollama (local) | Native API |
| DeepSeek, Mistral, Gemini, Together, Cohere, Fireworks, Perplexity, OpenRouter, AI21 | OpenAI-compatible |

At least one provider API key is required for AI features.

## API

Full OpenAPI spec: [api/openapi.yaml](./api/openapi.yaml)

```
POST /api/v1/auth/login|register|refresh
GET  /api/v1/auth/me

GET|POST      /api/v1/missions
GET|PUT|DELETE/api/v1/missions/{id}
POST          /api/v1/missions/{id}/start|pause|cancel|retry
GET           /api/v1/missions/{id}/chain|vulns|tools|reports

GET|POST      /api/v1/vulnerabilities
GET           /api/v1/vulnerabilities/stats

GET           /api/v1/tools
POST          /api/v1/tools/{name}/run

GET|POST      /api/v1/reports
GET           /api/v1/reports/{id}/download

GET           /api/v1/knowledge
POST          /api/v1/knowledge/search|ingest

GET|POST      /api/v1/scheduler
POST          /api/v1/scheduler/{id}/trigger

/ws           WebSocket real-time streaming
```

## Development

```bash
make build          # Build all binaries
make dev            # Run with hot reload
make test           # Run tests
make lint           # Run linter
make dev-full       # Full dev stack (backend + frontend + infra)
```

## Project Structure

```
phantomstrike/
+-- cmd/                    # Entry points (server, worker, cli, mcp)
+-- internal/
|   +-- api/               # REST API handlers + WebSocket
|   +-- agent/             # Multi-agent swarm (planner/executor/reviewer)
|   +-- auth/              # JWT auth + RBAC + OAuth2
|   +-- cache/             # Redis cache layer
|   +-- chain/             # Attack chain graph builder
|   +-- config/            # YAML + env config loader
|   +-- knowledge/         # Knowledge base retriever + ingestion
|   +-- mcp/               # MCP protocol server
|   +-- notify/            # Notification dispatcher (webhook/slack/discord)
|   +-- audit/             # Audit logging middleware
|   +-- provider/          # LLM provider abstraction + router
|   +-- report/            # Multi-format report generation (JSON/MD/HTML/PDF)
|   +-- storage/           # File storage (local + S3/MinIO)
|   +-- store/             # PostgreSQL data layer
|   +-- tool/              # Tool execution engine (Docker + process)
+-- web/                   # React 19 SPA
+-- tools/                 # 168 YAML tool definitions (21 categories)
+-- tools/_custom/         # 80 custom Python tool scripts
+-- roles/                 # 15 agent role definitions
+-- skills/                # 92 skill modules (13 categories)
+-- knowledge/             # 15 security knowledge base documents
+-- migrations/            # PostgreSQL migrations
+-- docker-compose.yml     # Full stack orchestration
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

MIT License -- see [LICENSE](./LICENSE) for details.
