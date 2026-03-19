#!/bin/bash
# PhantomStrike Setup Script for Linux/macOS
# Usage: ./setup.sh or bash setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "==================================================="
    echo "   PHANTOMSTRIKE - AI-POWERED SECURITY v2.0"
    echo "==================================================="
    echo -e "${NC}"
}

check_dependency() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "${RED}✗${NC} $1 not found"
        return 1
    fi
}

install_docker() {
    echo -e "${YELLOW}Installing Docker...${NC}"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo usermod -aG docker $USER
        elif [ -f /etc/redhat-release ]; then
            # RHEL/CentOS/Fedora
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install --cask docker
        else
            echo -e "${YELLOW}Please install Docker Desktop for Mac:${NC}"
            echo "https://docs.docker.com/desktop/install/mac-install/"
            read -p "Press Enter after Docker is installed..."
        fi
    fi
}

main() {
    print_banner
    
    echo -e "${BLUE}Checking dependencies...${NC}\n"
    
    # Check Python
    if ! check_dependency python3; then
        echo -e "${RED}Python 3 is required. Please install it first.${NC}"
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo -e "  Python version: ${CYAN}$PYTHON_VERSION${NC}"
    
    # Check Docker
    if ! check_dependency docker; then
        echo -e "${YELLOW}Docker is optional but recommended.${NC}"
        read -p "Install Docker? [Y/n]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            install_docker
        fi
    fi
    
    # Check Go
    if ! check_dependency go; then
        echo -e "${YELLOW}Go not found. Backend will need to be built manually.${NC}"
    fi
    
    # Check Node.js
    if ! check_dependency node; then
        echo -e "${YELLOW}Node.js not found. Frontend will need Node.js to run.${NC}"
        echo "Install from: https://nodejs.org/"
    fi
    
    echo ""
    echo -e "${GREEN}Dependencies check complete!${NC}"
    echo ""
    
    # Run interactive setup
    if [ -f "setup-interactive.py" ]; then
        echo -e "${BLUE}Starting interactive configuration...${NC}"
        python3 setup-interactive.py
    else
        echo -e "${RED}setup-interactive.py not found!${NC}"
        exit 1
    fi
}

main "$@"
