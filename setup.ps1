# PhantomStrike Universal Setup Script for PowerShell
# Works on: Windows PowerShell 5.1+, PowerShell 7+, PowerShell Core

param(
    [switch]$WithTests,
    [switch]$WithService,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) { $ScriptDir = Get-Location }

function Print-Banner {
    Write-Host ""
    Write-Host "=================================="
    Write-Host "    PHANTOMSTRIKE SETUP"
    Write-Host "    AI-Powered Security Platform"
    Write-Host "=================================="
    Write-Host ""
}

function Log-Info($Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Log-Warn($Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Log-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Log-Step($Message) {
    Write-Host "[STEP] $Message" -ForegroundColor Cyan
}

function Test-Command($Command) {
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Install-Go {
    if (Test-Command "go") {
        $version = go version
        Log-Info "Go is already installed: $version"
        return
    }

    Log-Step "Installing Go..."

    $GoVersion = "1.23.4"
    $Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $GoZip = "go$($GoVersion).windows-$($Arch).zip"
    $GoUrl = "https://go.dev/dl/$($GoZip)"
    $TempPath = "$env:TEMP\$GoZip"

    Log-Info "Downloading Go $GoVersion..."
    Invoke-WebRequest -Uri $GoUrl -OutFile $TempPath -UseBasicParsing

    Log-Info "Installing Go to C:\Program Files\Go..."
    if (Test-Path "C:\Program Files\Go") {
        Remove-Item -Recurse -Force "C:\Program Files\Go"
    }

    Expand-Archive -Path $TempPath -DestinationPath "C:\Program Files\" -Force
    Remove-Item $TempPath

    # Add to PATH
    $GoBin = "C:\Program Files\Go\bin"
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($CurrentPath -notlike "*$GoBin*") {
        [Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$GoBin", "User")
        $env:PATH = "$env:PATH;$GoBin"
        Log-Info "Added Go to PATH"
    }

    Log-Info "Go installed successfully: $(go version)"
}

function Install-NodeJS {
    if (Test-Command "node") {
        $version = node --version
        Log-Info "Node.js is already installed: $version"
        return
    }

    Log-Step "Installing Node.js..."

    # Check for nvm-windows
    if (Test-Command "nvm") {
        Log-Info "Using nvm-windows to install Node.js..."
        nvm install 20.11.0
        nvm use 20.11.0
    }
    else {
        Log-Info "Downloading Node.js installer..."
        $NodeVersion = "20.11.0"
        $Arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        $Installer = "node-v$($NodeVersion)-$($Arch).msi"
        $NodeUrl = "https://nodejs.org/dist/v$($NodeVersion)/$($Installer)"
        $TempPath = "$env:TEMP\$Installer"

        Invoke-WebRequest -Uri $NodeUrl -OutFile $TempPath -UseBasicParsing

        Log-Info "Running Node.js installer..."
        Start-Process msiexec.exe -ArgumentList "/i", $TempPath, "/quiet", "/norestart" -Wait
        Remove-Item $TempPath

        # Refresh PATH
        $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    }

    Log-Info "Node.js installed successfully: $(node --version)"
}

function Install-Docker {
    if (Test-Command "docker") {
        $version = docker --version
        Log-Info "Docker is already installed: $version"
        return
    }

    Log-Step "Docker not found"
    Log-Warn "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    Log-Info "Press Enter to continue without Docker..."
    $null = Read-Host
}

function Install-Dependencies {
    Log-Step "Installing dependencies..."

    # Backend dependencies
    Log-Info "Installing Go dependencies..."
    Set-Location $ScriptDir
    go mod download
    go mod tidy

    # Frontend dependencies
    if (Test-Path "$ScriptDir\web") {
        Log-Info "Installing frontend dependencies..."
        Set-Location "$ScriptDir\web"
        npm install
    }

    # Install additional tools
    Log-Info "Installing development tools..."

    # air
    if (-not (Test-Command "air")) {
        Log-Info "Installing air (live reload)..."
        go install github.com/air-verse/air@latest
    }

    # sqlc
    if (-not (Test-Command "sqlc")) {
        Log-Info "Installing sqlc..."
        go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
    }

    Set-Location $ScriptDir
}

function Setup-Database {
    Log-Step "Setting up database..."
    New-Item -ItemType Directory -Force -Path "$ScriptDir\data" | Out-Null

    if (Test-Command "psql") {
        Log-Info "PostgreSQL detected"
    }
    else {
        Log-Warn "PostgreSQL not found. Using SQLite as fallback."
        Log-Info "For production, please install PostgreSQL"
    }
}

function Create-EnvFile {
    Log-Step "Creating environment configuration..."

    $EnvFile = "$ScriptDir\.env"

    if (Test-Path $EnvFile) {
        Log-Warn ".env file already exists. Skipping creation."
        return
    }

    $RandomChars = -join ((48..57) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    $McpToken = -join ((48..57) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

    $EnvContent = @"
# PhantomStrike Environment Configuration

# Database
DATABASE_URL=postgres://phantomstrike:phantomstrike@localhost:5432/phantomstrike?sslmode=disable

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=$RandomChars

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
MCP_AUTH_TOKEN=$McpToken

# Storage
STORAGE_PATH=.\data\storage

# Log level
LOG_LEVEL=info
"@

    Set-Content -Path $EnvFile -Value $EnvContent
    Log-Info "Created .env file at $EnvFile"
    Log-Warn "Please edit this file and add your API keys!"
}

function Build-Application {
    Log-Step "Building application..."

    Set-Location $ScriptDir

    # Create bin directory
    New-Item -ItemType Directory -Force -Path "$ScriptDir\bin" | Out-Null

    # Build backend
    Log-Info "Building backend..."
    go build -o bin\phantomstrike.exe .\cmd\server
    go build -o bin\phantomstrike-cli.exe .\cmd\cli
    go build -o bin\phantomstrike-worker.exe .\cmd\worker

    # Build frontend
    if (Test-Path "$ScriptDir\web") {
        Log-Info "Building frontend..."
        Set-Location "$ScriptDir\web"
        npm run build
    }

    Set-Location $ScriptDir
    Log-Info "Build complete!"
}

function Run-Tests {
    Log-Step "Running tests..."
    Set-Location $ScriptDir
    go test -v .\internal\... 2>&1 | Select-Object -First 50
}

function Show-Usage {
    Write-Host ""
    Write-Host "Setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Edit .env file and add your API keys"
    Write-Host "  2. Start the database: docker-compose up -d postgres"
    Write-Host "  3. Run migrations: go run .\cmd\cli db migrate"
    Write-Host "  4. Start the server:"
    Write-Host "     - Development: npm run dev (in web directory) and air (in root)"
    Write-Host "     - Production: .\bin\phantomstrike.exe"
    Write-Host ""
    Write-Host "Available commands:"
    Write-Host "  .\bin\phantomstrike.exe      - Start API server"
    Write-Host "  .\bin\phantomstrike-cli.exe  - CLI tool"
    Write-Host ""
    Write-Host "Documentation:"
    Write-Host "  API Docs: http://localhost:8080/swagger/index.html"
    Write-Host "  Web UI:   http://localhost:5173"
    Write-Host ""
}

# Main
if ($Help) {
    Write-Host "PhantomStrike Setup Script"
    Write-Host ""
    Write-Host "Usage: .\setup.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -WithTests     Run tests after setup"
    Write-Host "  -WithService   Create Windows service"
    Write-Host "  -Help          Show this help"
    exit 0
}

Print-Banner

Log-Step "Starting PhantomStrike setup..."

# Install prerequisites
Install-Go
Install-NodeJS
Install-Docker

# Setup
Install-Dependencies
Setup-Database
Create-EnvFile
Build-Application

# Optional
if ($WithTests) {
    Run-Tests
}

Show-Usage
