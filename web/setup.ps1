# PhantomStrike Setup Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File setup.ps1
# Or: ./setup.ps1 (in PowerShell with proper permissions)

$ErrorActionPreference = "Stop"

function Print-Banner {
    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "   PHANTOMSTRIKE - AI-POWERED SECURITY v2.0" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-CommandExists {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Install-Docker {
    Write-Host "Installing Docker Desktop..." -ForegroundColor Yellow
    Write-Host "Please download and install Docker Desktop from:" -ForegroundColor Yellow
    Write-Host "https://docs.docker.com/desktop/install/windows-install/" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "Press Enter after Docker is installed"
}

function Main {
    Print-Banner
    
    Write-Host "Checking dependencies..." -ForegroundColor Blue
    Write-Host ""
    
    # Check Python
    if (Test-CommandExists "python") {
        $pyVersion = python --version 2>&1
        Write-Host "  [OK] $pyVersion" -ForegroundColor Green
    } elseif (Test-CommandExists "python3") {
        $pyVersion = python3 --version 2>&1
        Write-Host "  [OK] $pyVersion" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Python 3 is required!" -ForegroundColor Red
        Write-Host "  Download from: https://www.python.org/downloads/"
        exit 1
    }
    
    # Check Docker
    if (Test-CommandExists "docker") {
        $dockerVersion = docker --version 2>&1
        Write-Host "  [OK] Docker found" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Docker not found (optional)" -ForegroundColor Yellow
        $installDocker = Read-Host "Install Docker? [Y/n]"
        if ($installDocker -ne "n" -and $installDocker -ne "N") {
            Install-Docker
        }
    }
    
    # Check Go
    if (Test-CommandExists "go") {
        $goVersion = go version 2>&1
        Write-Host "  [OK] Go found" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Go not found. Backend needs manual build." -ForegroundColor Yellow
    }
    
    # Check Node.js
    if (Test-CommandExists "node") {
        $nodeVersion = node --version 2>&1
        Write-Host "  [OK] Node.js $nodeVersion" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Node.js not found!" -ForegroundColor Yellow
        Write-Host "  Download from: https://nodejs.org/"
    }
    
    Write-Host ""
    Write-Host "Dependencies check complete!" -ForegroundColor Green
    Write-Host ""
    
    # Run interactive setup
    if (Test-Path "setup-interactive.py") {
        Write-Host "Starting interactive configuration..." -ForegroundColor Blue
        python setup-interactive.py
    } else {
        Write-Host "setup-interactive.py not found!" -ForegroundColor Red
        exit 1
    }
}

Main
