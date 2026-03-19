#!/bin/bash
#
# PhantomStrike Universal Setup Script
# Works on: Linux, macOS, Windows (Git Bash, WSL)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="PhantomStrike"

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗      ║"
    echo "║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗     ║"
    echo "║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║     ║"
    echo "║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║     ║"
    echo "║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝     ║"
    echo "║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝      ║"
    echo "║                                                            ║"
    echo "║              AI-Powered Security Platform                  ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        OS="unknown"
    fi
    log_info "Detected OS: $OS"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
install_go() {
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}')
        log_info "Go is already installed: $GO_VERSION"
        return 0
    fi

    log_step "Installing Go..."

    local GO_VERSION="1.26.1"
    local GO_URL

    case $OS in
        linux)
            GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
            ;;
        macos)
            if [[ $(uname -m) == "arm64" ]]; then
                GO_URL="https://go.dev/dl/go${GO_VERSION}.darwin-arm64.tar.gz"
            else
                GO_URL="https://go.dev/dl/go${GO_VERSION}.darwin-amd64.tar.gz"
            fi
            ;;
        *)
            log_error "Automatic Go installation not supported for $OS"
            log_info "Please install Go manually from https://go.dev/dl/"
            exit 1
            ;;
    esac

    log_info "Downloading Go $GO_VERSION..."
    curl -fsSL "$GO_URL" -o /tmp/go.tar.gz

    log_info "Installing Go to /usr/local..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    # Add to PATH
    if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        log_info "Added Go to PATH in ~/.bashrc"
    fi

    export PATH=$PATH:/usr/local/go/bin
    log_info "Go installed successfully: $(go version)"
}

# Install Node.js if not present
install_node() {
    if command_exists node; then
        NODE_VERSION=$(node --version)
        log_info "Node.js is already installed: $NODE_VERSION"
        return 0
    fi

    log_step "Installing Node.js..."

    if command_exists nvm; then
        log_info "Using nvm to install Node.js..."
        nvm install 20
        nvm use 20
    elif command_exists apt-get; then
        log_info "Installing Node.js via apt..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif command_exists yum; then
        log_info "Installing Node.js via yum..."
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo yum install -y nodejs
    elif command_exists brew; then
        log_info "Installing Node.js via Homebrew..."
        brew install node@20
    else
        log_error "Could not install Node.js automatically"
        log_info "Please install Node.js 20+ manually from https://nodejs.org/"
        exit 1
    fi

    log_info "Node.js installed successfully: $(node --version)"
}

# Install Docker if not present
install_docker() {
    if command_exists docker; then
        DOCKER_VERSION=$(docker --version)
        log_info "Docker is already installed: $DOCKER_VERSION"
        return 0
    fi

    log_step "Installing Docker..."

    case $OS in
        linux)
            log_info "Installing Docker via official script..."
            curl -fsSL https://get.docker.com | sh
            sudo usermod -aG docker "$USER"
            log_warn "You may need to log out and back in for Docker permissions to take effect"
            ;;
        macos)
            log_info "Please install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop"
            ;;
        *)
            log_warn "Docker installation not automated for $OS"
            ;;
    esac
}

# Install dependencies
install_dependencies() {
    log_step "Installing dependencies..."

    # Backend dependencies
    log_info "Installing Go dependencies..."
    cd "$SCRIPT_DIR"
    go mod download
    go mod tidy

    # Frontend dependencies
    if [ -d "$SCRIPT_DIR/web" ]; then
        log_info "Installing frontend dependencies..."
        cd "$SCRIPT_DIR/web"
        npm install
    fi

    # Install additional tools
    log_info "Installing development tools..."

    # air (live reload)
    if ! command_exists air; then
        log_info "Installing air (live reload)..."
        go install github.com/air-verse/air@latest
    fi

    # sqlc
    if ! command_exists sqlc; then
        log_info "Installing sqlc..."
        go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
    fi

    # swag
    if ! command_exists swag; then
        log_info "Installing swag..."
        go install github.com/swaggo/swag/cmd/swag@latest
    fi
}

# Setup database
setup_database() {
    log_step "Setting up database..."

    # Create data directory
    mkdir -p "$SCRIPT_DIR/data"

    # Check for PostgreSQL
    if command_exists psql; then
        log_info "PostgreSQL detected"
    else
        log_warn "PostgreSQL not found. Using SQLite as fallback."
        log_info "For production, please install PostgreSQL"
    fi
}

# Create environment file
create_env_file() {
    log_step "Creating environment configuration..."

    local ENV_FILE="$SCRIPT_DIR/.env"

    if [ -f "$ENV_FILE" ]; then
        log_warn ".env file already exists. Skipping creation."
        return 0
    fi

    cat > "$ENV_FILE" << 'EOF'
# PhantomStrike Environment Configuration

# Database
DATABASE_URL=postgres://phantomstrike:phantomstrike@localhost:5432/phantomstrike?sslmode=disable

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=change-me-in-production-$(openssl rand -hex 32)

# Admin credentials
ADMIN_PASSWORD=admin123

# AI Providers (add your API keys here)
# ANTHROPIC_API_KEY=your_key_here
# OPENAI_API_KEY=your_key_here
# GROQ_API_KEY=your_key_here
# DEEPSEEK_API_KEY=your_key_here
# GLM_API_KEY=your_key_here
# TOGETHER_API_KEY=your_key_here
# MISTRAL_API_KEY=your_key_here

# Comma-separated list of providers to enable
# PROVIDERS=anthropic,openai,groq

# MCP
MCP_AUTH_TOKEN=$(openssl rand -hex 32)

# Storage
STORAGE_PATH=./data/storage

# Log level
LOG_LEVEL=info
EOF

    log_info "Created .env file at $ENV_FILE"
    log_warn "Please edit this file and add your API keys!"
}

# Build the application
build_application() {
    log_step "Building application..."

    cd "$SCRIPT_DIR"

    # Build backend
    log_info "Building backend..."
    go build -o bin/phantomstrike ./cmd/server
    go build -o bin/phantomstrike-cli ./cmd/cli
    go build -o bin/phantomstrike-worker ./cmd/worker

    # Build frontend
    if [ -d "$SCRIPT_DIR/web" ]; then
        log_info "Building frontend..."
        cd "$SCRIPT_DIR/web"
        npm run build
    fi

    log_info "Build complete!"
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [ "$OS" != "linux" ]; then
        return 0
    fi

    log_step "Creating systemd service..."

    local SERVICE_FILE="/etc/systemd/system/phantomstrike.service"

    if [ -f "$SERVICE_FILE" ]; then
        log_warn "Service file already exists. Skipping."
        return 0
    fi

    sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=PhantomStrike AI Security Platform
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/bin/phantomstrike
Restart=always
RestartSec=5
Environment=PATH=/usr/local/go/bin:/usr/bin:/bin
EnvironmentFile=$SCRIPT_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    log_info "Created systemd service. To start: sudo systemctl start phantomstrike"
}

# Run tests
run_tests() {
    log_step "Running tests..."

    cd "$SCRIPT_DIR"
    go test -v ./internal/... 2>&1 | head -50 || true
}

# Show usage
show_usage() {
    echo ""
    echo -e "${GREEN}Setup complete!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "  1. Edit ${YELLOW}.env${NC} file and add your API keys"
    echo "  2. Start the database: ${YELLOW}docker-compose up -d postgres${NC} (or use existing PostgreSQL)"
    echo "  3. Run migrations: ${YELLOW}go run ./cmd/cli db migrate${NC}"
    echo "  4. Start the server:"
    echo "     - Development: ${YELLOW}make dev${NC} or ${YELLOW}air${NC}"
    echo "     - Production: ${YELLOW}./bin/phantomstrike${NC}"
    echo ""
    echo -e "${BLUE}Available commands:${NC}"
    echo "  ./bin/phantomstrike      - Start API server"
    echo "  ./bin/phantomstrike-cli  - CLI tool"
    echo "  make dev                 - Start development mode"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  API Docs: http://localhost:8080/swagger/index.html"
    echo "  Web UI:   http://localhost:5173"
    echo ""
}

# Main function
main() {
    print_banner
    detect_os

    log_step "Starting PhantomStrike setup..."

    # Check prerequisites
    install_go
    install_node
    install_docker

    # Setup
    install_dependencies
    setup_database
    create_env_file
    build_application

    # Optional
    if [ "$1" == "--with-tests" ]; then
        run_tests
    fi

    if [ "$1" == "--with-service" ] && [ "$OS" == "linux" ]; then
        create_systemd_service
    fi

    show_usage
}

# Run main function
main "$@"
