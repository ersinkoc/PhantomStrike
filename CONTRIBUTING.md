# Contributing to PhantomStrike

Thank you for your interest in contributing to PhantomStrike! This guide will help you get started.

## Getting Started

1. Fork the repo
2. Clone your fork
   ```bash
   git clone https://github.com/ersinkoc/phantomstrike.git
   cd phantomstrike
   ```
3. Create a branch
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Make changes
5. Run tests
   ```bash
   make test
   ```
6. Submit a PR

## Development Setup

### Prerequisites

- Go 1.26+
- Node.js 22+
- PostgreSQL 16+
- Docker (optional, for containerized tool execution)

### Backend

```bash
make build          # Build the server binary
make test           # Run Go tests
make lint           # Run linters
make dev            # Start development server with hot reload
```

### Frontend

```bash
cd web
npm install         # Install dependencies
npm run dev         # Start dev server
npm run build       # Production build
npm run test        # Run frontend tests
npm run lint        # Lint frontend code
```

### Full Stack

```bash
make dev-all        # Start both backend and frontend
make docker-up      # Start with Docker Compose
```

## Code Style

- **Go**: Follow standard `gofmt` formatting. Run `gofmt -w .` before committing.
- **Frontend**: ESLint + Prettier. Run `npm run lint` in the `web/` directory.
- **Commits**: Use [Conventional Commits](https://www.conventionalcommits.org/) format:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `test:` for adding or updating tests
  - `refactor:` for code refactoring
  - `chore:` for maintenance tasks

## Adding Tools

PhantomStrike tools are defined as YAML files in the `tools/` directory.

1. Create a new YAML file in the appropriate subdirectory under `tools/`
2. Follow the existing schema (see `tools/` for examples)
3. Required fields: `name`, `version`, `category`, `command`, `short_description`
4. Define parameters with proper types, flags, and validation
5. Add Docker configuration if the tool should run in a container

Example:
```yaml
name: "my-tool"
version: "1.0.0"
category: "recon"
command: "my-tool"
short_description: "Description of my tool"
parameters:
  - name: "target"
    type: "string"
    description: "Target to scan"
    required: true
    flag: "-t"
enabled: true
```

## Adding Skills

Skills are markdown-based prompt templates in the `skills/` directory.

1. Create a markdown file in `skills/`
2. Include a YAML frontmatter block with metadata
3. Write the skill prompt in the body

## Project Structure

```
phantomstrike/
  cmd/              # Application entrypoints
  internal/         # Go packages (server, API, tools, agents, etc.)
  web/              # React frontend (Vite + TypeScript + Tailwind)
  tools/            # Tool YAML definitions
  skills/           # Skill markdown templates
  migrations/       # Database migrations
```

## Reporting Issues

- Use [GitHub Issues](https://github.com/ersinkoc/phantomstrike/issues)
- Include steps to reproduce the problem
- Include expected vs actual behavior
- Include relevant logs or screenshots
- Tag the issue with appropriate labels (bug, enhancement, etc.)

## Pull Request Guidelines

- Keep PRs focused on a single change
- Write descriptive PR titles and descriptions
- Include tests for new functionality
- Ensure all existing tests pass
- Update documentation if needed
- Link related issues in the PR description
