#!/usr/bin/env python3
"""
PhantomStrike Interactive Setup
Cross-platform setup with interactive configuration

Features:
- Platform detection (Windows/Linux/macOS)
- Docker check & install option
- Database selection (SQLite/PostgreSQL)
- AI Provider selection with API key input
- Auto .env generation
- Dependency installation
- One-command start
"""

import os
import sys
import subprocess
import platform
import re
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors on Windows if not supported"""
        if platform.system() == 'Windows':
            cls.HEADER = cls.BLUE = cls.CYAN = cls.GREEN = cls.YELLOW = cls.RED = cls.BOLD = cls.UNDERLINE = cls.END = ''

# Detect if running in CI/non-interactive mode
NON_INTERACTIVE = not sys.stdin.isatty() or os.environ.get('CI', '') == 'true'

def print_banner():
    """Print the PhantomStrike banner"""
    banner = f"""
{Colors.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ██╗║
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗  ██║║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔██╗ ██║║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╗██║║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚████║║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝║
║                                                                ║
║              AI-Powered Security Platform                      ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def log_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.END} {msg}")

def log_step(msg: str):
    print(f"{Colors.CYAN}[STEP]{Colors.END} {msg}")

def log_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.END} {msg}")

def log_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")

def log_prompt(msg: str) -> str:
    """Create a formatted prompt"""
    return f"{Colors.BLUE}[INPUT]{Colors.END} {msg}"

def input_text(prompt: str, default: str = "", required: bool = False) -> str:
    """Get text input from user"""
    if NON_INTERACTIVE:
        return default

    while True:
        full_prompt = f"{log_prompt(prompt)}"
        if default:
            full_prompt += f" [{default}]: "
        else:
            full_prompt += ": "

        try:
            value = input(full_prompt).strip()
            if not value and default:
                return default
            if not value and required:
                log_error("This field is required")
                continue
            return value
        except (EOFError, KeyboardInterrupt):
            print("\n")
            sys.exit(1)

def input_password(prompt: str) -> str:
    """Get password input (hidden)"""
    if NON_INTERACTIVE:
        return ""

    import getpass
    full_prompt = f"{log_prompt(prompt)}: "
    try:
        return getpass.getpass(full_prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n")
        sys.exit(1)

def input_select(prompt: str, options: List[str], default: int = 0) -> int:
    """Show a selection menu"""
    if NON_INTERACTIVE:
        return default

    print(f"\n{Colors.CYAN}{prompt}{Colors.END}")
    for i, option in enumerate(options, 1):
        mark = "✓" if i - 1 == default else " "
        print(f"  [{mark}] {i}. {option}")

    while True:
        try:
            choice = input(f"{log_prompt('Select')} [1-{len(options)}, default: {default + 1}]: ").strip()
            if not choice:
                return default
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
            log_error(f"Please enter a number between 1 and {len(options)}")
        except ValueError:
            log_error("Please enter a valid number")
        except (EOFError, KeyboardInterrupt):
            print("\n")
            sys.exit(1)

def input_multi_select(prompt: str, options: List[Tuple[str, str]]) -> List[str]:
    """Show a multi-selection menu with descriptions"""
    if NON_INTERACTIVE:
        return []

    print(f"\n{Colors.CYAN}{prompt}{Colors.END}")
    print(f"  {Colors.YELLOW}Select multiple by entering numbers separated by commas (e.g., 1,3,5){Colors.END}")
    print(f"  {Colors.YELLOW}Press Enter to skip{Colors.END}\n")

    for i, (key, desc) in enumerate(options, 1):
        print(f"  {i}. {Colors.BOLD}{key}{Colors.END}")
        print(f"     {desc}")
        print()

    while True:
        try:
            choice = input(f"{log_prompt('Select')} [1-{len(options)} or 0 for all]: ").strip()
            if not choice:
                return []

            if choice == "0":
                return [key for key, _ in options]

            indices = [int(x.strip()) - 1 for x in choice.split(",")]
            selected = []
            for idx in indices:
                if 0 <= idx < len(options):
                    selected.append(options[idx][0])
                else:
                    log_error(f"Invalid selection: {idx + 1}")
                    break
            else:
                return selected
        except ValueError:
            log_error("Please enter valid numbers separated by commas")
        except (EOFError, KeyboardInterrupt):
            print("\n")
            sys.exit(1)

def input_confirm(prompt: str, default: bool = True) -> bool:
    """Yes/No confirmation"""
    if NON_INTERACTIVE:
        return default

    default_str = "Y/n" if default else "y/N"
    full_prompt = f"{log_prompt(prompt)} [{default_str}]: "

    try:
        value = input(full_prompt).strip().lower()
        if not value:
            return default
        return value in ['y', 'yes']
    except (EOFError, KeyboardInterrupt):
        print("\n")
        sys.exit(1)

def run_command(cmd: List[str], check: bool = True, capture: bool = True) -> Tuple[int, str, str]:
    """Run a shell command"""
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        if check:
            raise
        return -1, "", str(e)

def check_command(cmd: str) -> bool:
    """Check if a command exists"""
    try:
        subprocess.run([cmd, "--version"], capture_output=True, check=False)
        return True
    except:
        return False

def detect_platform() -> Tuple[str, str]:
    """Detect OS and architecture"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "macOS"
    elif system == "windows":
        os_name = "Windows"
    else:
        os_name = "Linux"

    if "arm" in machine or "aarch64" in machine:
        arch = "arm64"
    else:
        arch = "amd64"

    return os_name, arch

def check_docker() -> bool:
    """Check if Docker is installed and running"""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode == 0
    except:
        return False

def get_docker_install_info(os_name: str) -> str:
    """Get Docker installation instructions for the OS"""
    instructions = {
        "Windows": """
Docker Desktop for Windows:
  1. Download from: https://www.docker.com/products/docker-desktop
  2. Run the installer
  3. Restart your computer
  4. Open Docker Desktop
""",
        "macOS": """
Docker Desktop for Mac:
  1. Download from: https://www.docker.com/products/docker-desktop
  2. Open the .dmg file
  3. Drag Docker to Applications
  4. Open Docker from Applications
""",
        "Linux": """
Docker for Linux:
  # Run this command:
  curl -fsSL https://get.docker.com | sh

  # Then add your user to docker group:
  sudo usermod -aG docker $USER

  # Log out and back in for changes to take effect
"""
    }
    return instructions.get(os_name, instructions["Linux"])

# AI Provider definitions with pricing info
AI_PROVIDERS = [
    ("anthropic", "Anthropic Claude - High quality reasoning (Pricing: ~$3/1K tokens)", "claude-3-5-sonnet-20241022"),
    ("openai", "OpenAI GPT-4o - Well-rounded performance (Pricing: ~$5/1K tokens)", "gpt-4o"),
    ("groq", "Groq - Ultra-fast inference (Pricing: ~$0.27/1K tokens)", "llama-3.1-70b-versatile"),
    ("deepseek", "DeepSeek - Cost effective (Pricing: ~$0.14/1K tokens)", "deepseek-chat"),
    ("glm", "GLM-5 (Zhipu AI) - Chinese model (Pricing: ~$1/1K tokens)", "glm-4"),
    ("together", "Together AI - Open source models (Pricing: ~$0.8/1K tokens)", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    ("mistral", "Mistral AI - European provider (Pricing: ~$2/1K tokens)", "mistral-large-latest"),
    ("cohere", "Cohere Command R+ (Pricing: ~$3/1K tokens)", "command-r-plus"),
    ("fireworks", "Fireworks AI - Fast inference (Pricing: ~$0.9/1K tokens)", "accounts/fireworks/models/llama-v3p1-70b-instruct"),
    ("perplexity", "Perplexity - With web search (Pricing: ~$1/1K tokens)", "llama-3.1-sonar-large-128k-online"),
    ("gemini", "Google Gemini - Multimodal (Pricing: ~$0.5/1K tokens)", "gemini-1.5-pro"),
    ("openrouter", "OpenRouter - Universal access (Pricing: varies)", "anthropic/claude-3.5-sonnet"),
    ("ollama", "Ollama - Local models (Free, runs locally)", "llama3.1:70b"),
]

def get_api_key_url(provider: str) -> str:
    """Get API key URL for a provider"""
    urls = {
        "anthropic": "https://console.anthropic.com/settings/keys",
        "openai": "https://platform.openai.com/api-keys",
        "groq": "https://console.groq.com/keys",
        "deepseek": "https://platform.deepseek.com/api_keys",
        "glm": "https://open.bigmodel.cn/usercenter/apikeys",
        "together": "https://api.together.xyz/settings/api-keys",
        "mistral": "https://console.mistral.ai/api-keys/",
        "cohere": "https://dashboard.cohere.com/api-keys",
        "fireworks": "https://fireworks.ai/account/api-keys",
        "perplexity": "https://www.perplexity.ai/settings/api",
        "gemini": "https://aistudio.google.com/app/apikey",
        "openrouter": "https://openrouter.ai/keys",
    }
    return urls.get(provider, "")

def configure_providers() -> Dict[str, Dict]:
    """Configure AI providers interactively"""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}AI Provider Configuration{Colors.END}")
    print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")

    log_info("Select which AI providers you want to use.")
    log_info("You can select multiple providers for redundancy and load balancing.\n")

    selected = input_multi_select("Available AI Providers:", AI_PROVIDERS)

    if not selected:
        log_warn("No providers selected. Using default: Anthropic")
        selected = ["anthropic"]

    provider_configs = {}

    for provider in selected:
        # Find provider info
        info = next((p for p in AI_PROVIDERS if p[0] == provider), None)
        if not info:
            continue

        print(f"\n{Colors.CYAN}Configuring {provider.upper()}{Colors.END}")

        if provider == "ollama":
            # Ollama doesn't need API key
            provider_configs[provider] = {
                "model": info[2],
                "base_url": "http://localhost:11434"
            }
            log_info("Ollama configured (no API key needed)")
            continue

        api_key_url = get_api_key_url(provider)
        if api_key_url:
            print(f"  {Colors.YELLOW}Get API key: {api_key_url}{Colors.END}")

        api_key = input_password(f"Enter API key for {provider}")

        if not api_key:
            log_warn(f"No API key provided for {provider}, skipping")
            continue

        provider_configs[provider] = {
            "api_key": api_key,
            "model": info[2]
        }

    return provider_configs

def generate_env_file(config: Dict) -> str:
    """Generate .env file content"""
    providers = config.get('providers', {})
    database = config.get('database', 'sqlite')
    admin_pass = config.get('admin_password', 'admin123')

    # Generate random secrets
    import secrets
    jwt_secret = secrets.token_hex(32)
    mcp_token = secrets.token_hex(32)

    env_content = f"""# PhantomStrike Environment Configuration
# Generated by setup script on {platform.node()}

# =============================================================================
# SECURITY - Change these in production!
# =============================================================================
JWT_SECRET={jwt_secret}
ADMIN_PASSWORD={admin_pass}
MCP_AUTH_TOKEN={mcp_token}

# =============================================================================
# DATABASE
# =============================================================================
"""

    if database == 'postgresql':
        env_content += """DATABASE_URL=postgres://phantomstrike:phantomstrike@localhost:5432/phantomstrike?sslmode=disable
"""
    else:
        env_content += """# Using SQLite (no PostgreSQL required)
DATABASE_URL=sqlite://./data/phantomstrike.db
"""

    env_content += """
# Redis (optional, for caching)
# REDIS_URL=redis://localhost:6379/0

# =============================================================================
# AI PROVIDERS
# =============================================================================
"""

    # Provider list
    provider_names = list(providers.keys())
    if provider_names:
        env_content += f"PROVIDERS={','.join(provider_names)}\n\n"

    # Provider-specific config
    for name, cfg in providers.items():
        if name == 'ollama':
            env_content += f"""# Ollama (Local)
# OLLAMA_BASE_URL={cfg.get('base_url', 'http://localhost:11434')}
# OLLAMA_MODEL={cfg.get('model', 'llama3.1:70b')}

"""
        else:
            api_key = cfg.get('api_key', '')
            if api_key:
                env_content += f"""# {name.upper()}
{name.upper()}_API_KEY={api_key}
{name.upper()}_MODEL={cfg.get('model', '')}

"""

    env_content += """# =============================================================================
# DEFAULTS
# =============================================================================
DEFAULT_PROVIDER=anthropic
FALLBACK_CHAIN=anthropic,openai,groq

# =============================================================================
# STORAGE
# =============================================================================
STORAGE_PATH=./data/storage
LOG_LEVEL=info

# =============================================================================
# FEATURE FLAGS
# =============================================================================
# ENABLE_SCHEDULER=true
# ENABLE_MCP_SERVER=true
# MCP_SERVER_PORT=8081
"""

    return env_content

def create_config_yaml(config: Dict) -> str:
    """Generate config.yaml content"""
    providers = config.get('providers', {})
    database = config.get('database', 'sqlite')

    yaml_content = f"""# PhantomStrike Configuration
# Generated by setup script

server:
  host: 0.0.0.0
  port: 8080
  cors_origins:
    - http://localhost:5173
    - http://localhost:3000

database:
  url: ${'{'}DATABASE_URL{'}'}
  max_connections: 25
  migration_auto: true

providers:
  default: {list(providers.keys())[0] if providers else 'anthropic'}
  fallback_chain:
"""

    for name in providers.keys():
        yaml_content += f"    - {name}\n"

    yaml_content += """
  anthropic:
    model: claude-3-5-sonnet-20241022
    max_tokens: 8192

  openai:
    model: gpt-4o
    max_tokens: 4096

  ollama:
    base_url: http://localhost:11434
    model: llama3.1:70b

agent:
  max_iterations: 30
  max_parallel_tools: 3
  thinking_budget: 8192
  auto_review: true

tools:
  dir: tools
  docker:
    enabled: true
    default_timeout: 5m
    default_memory: 512m
    default_cpu: "1.0"
    cleanup_after: true

knowledge:
  enabled: true
  dir: knowledge
  retrieval:
    top_k: 5
    similarity_threshold: 0.7

logging:
  level: info
  format: json
  output: stdout
"""

    return yaml_content

def install_dependencies():
    """Install Go and npm dependencies"""
    log_step("Installing dependencies...")

    # Go dependencies
    log_info("Installing Go dependencies...")
    run_command(["go", "mod", "download"], check=False)
    run_command(["go", "mod", "tidy"], check=False)

    # Install Go tools
    tools = [
        ("air", "github.com/air-verse/air@latest"),
        ("sqlc", "github.com/sqlc-dev/sqlc/cmd/sqlc@latest"),
        ("swag", "github.com/swaggo/swag/cmd/swag@latest"),
    ]

    for tool, pkg in tools:
        if not check_command(tool):
            log_info(f"Installing {tool}...")
            run_command(["go", "install", pkg], check=False)

    # Frontend dependencies
    web_dir = Path("web")
    if web_dir.exists():
        log_info("Installing frontend dependencies...")
        os.chdir(web_dir)
        run_command(["npm", "install"], check=False)
        os.chdir("..")

def build_application():
    """Build the application"""
    log_step("Building application...")

    Path("bin").mkdir(exist_ok=True)

    # Build binaries
    builds = [
        ("phantomstrike", "./cmd/server"),
        ("phantomstrike-worker", "./cmd/worker"),
        ("phantomstrike-cli", "./cmd/cli"),
    ]

    for name, path in builds:
        log_info(f"Building {name}...")
        ext = ".exe" if platform.system() == "Windows" else ""
        run_command(["go", "build", "-o", f"bin/{name}{ext}", path], check=False)

    # Build frontend
    if Path("web").exists():
        log_info("Building frontend...")
        os.chdir("web")
        run_command(["npm", "run", "build"], check=False)
        os.chdir("..")

def print_next_steps(config: Dict):
    """Print next steps"""
    database = config.get('database', 'sqlite')

    print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Setup Complete!{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}\n")

    print(f"{Colors.CYAN}Next Steps:{Colors.END}\n")

    if database == 'postgresql':
        print("1. Start PostgreSQL:")
        print(f"   {Colors.YELLOW}docker compose up -d postgres{Colors.END}")

    print(f"{'2' if database == 'postgresql' else '1'}. Review your configuration:")
    print(f"   {Colors.YELLOW}.env{Colors.END} - Environment variables")
    print(f"   {Colors.YELLOW}config.yaml{Colors.END} - Application configuration\n")

    print(f"{'3' if database == 'postgresql' else '2'}. Run database migrations:")
    print(f"   {Colors.YELLOW}./bin/phantomstrike-cli migrate{Colors.END}\n")

    print(f"{'4' if database == 'postgresql' else '3'}. Start the application:")
    print(f"   {Colors.YELLOW}./bin/phantomstrike{Colors.END}          # API Server")
    print(f"   {Colors.YELLOW}./bin/phantomstrike-worker{Colors.END}   # Background worker\n")

    print(f"{'5' if database == 'postgresql' else '4'}. Access the web interface:")
    print(f"   {Colors.GREEN}http://localhost:5173{Colors.END}\n")

    print(f"{Colors.CYAN}Development Mode:{Colors.END}\n")
    print(f"   {Colors.YELLOW}make dev{Colors.END}       # Start with live reload")
    print(f"   {Colors.YELLOW}make dev-web{Colors.END}   # Start web UI dev server\n")

    print(f"{Colors.CYAN}Docker Compose (Recommended):{Colors.END}\n")
    print(f"   {Colors.YELLOW}docker compose up -d{Colors.END}  # Start all services\n")

def main():
    """Main setup function"""
    Colors.disable()
    print_banner()

    os_name, arch = detect_platform()
    log_info(f"Detected: {os_name} ({arch})")

    # Change to script directory
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    # Check prerequisites
    log_step("Checking prerequisites...")

    has_go = check_command("go")
    has_node = check_command("node")
    has_docker = check_docker()

    if has_go:
        _, stdout, _ = run_command(["go", "version"], check=False)
        log_info(f"Go: {stdout.strip()}")
    else:
        log_error("Go is not installed. Please install Go 1.21+ first.")
        sys.exit(1)

    if has_node:
        _, stdout, _ = run_command(["node", "--version"], check=False)
        log_info(f"Node.js: {stdout.strip()}")
    else:
        log_error("Node.js is not installed. Please install Node.js 20+ first.")
        sys.exit(1)

    if has_docker:
        log_info("Docker: Installed and running")
    else:
        log_warn("Docker: Not detected")
        if input_confirm("Docker is recommended for PostgreSQL. Install instructions?"):
            print(get_docker_install_info(os_name))

    # Configuration
    print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Configuration{Colors.END}")
    print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")

    # Database selection
    db_options = ["SQLite (embedded, no setup required)", "PostgreSQL (recommended for production)"]
    db_choice = input_select("Select database:", db_options, default=0)
    database = "sqlite" if db_choice == 0 else "postgresql"

    # Admin password
    print()
    admin_pass = input_password("Set admin password [default: admin123]")
    if not admin_pass:
        admin_pass = "admin123"

    # AI Providers
    providers = configure_providers()

    # Build config
    config = {
        "database": database,
        "admin_password": admin_pass,
        "providers": providers,
    }

    # Generate files
    log_step("Generating configuration files...")

    # .env file
    env_content = generate_env_file(config)
    with open(".env", "w") as f:
        f.write(env_content)
    log_info("Created .env")

    # config.yaml
    yaml_content = create_config_yaml(config)
    with open("config.yaml", "w") as f:
        f.write(yaml_content)
    log_info("Created config.yaml")

    # Create data directory
    Path("data").mkdir(exist_ok=True)
    Path("data/storage").mkdir(parents=True, exist_ok=True)

    # Install dependencies
    if input_confirm("\nInstall dependencies now?", default=True):
        install_dependencies()

    # Build
    if input_confirm("Build application now?", default=True):
        build_application()

    # Done
    print_next_steps(config)

    # Quick start option
    if input_confirm("Start the application now?", default=False):
        if database == "postgresql" and has_docker:
            log_step("Starting PostgreSQL...")
            run_command(["docker", "compose", "up", "-d", "postgres"], check=False)
            log_info("PostgreSQL started. Waiting 5 seconds...")
            import time
            time.sleep(5)

        log_step("Starting PhantomStrike...")
        if platform.system() == "Windows":
            subprocess.Popen(["start", "cmd", "/k", ".\\bin\\phantomstrike"], shell=True)
        else:
            subprocess.Popen(["./bin/phantomstrike"])

        log_info("API Server started on http://localhost:8080")

        # Start web dev server
        if Path("web").exists() and input_confirm("Start web UI dev server?", default=True):
            os.chdir("web")
            if platform.system() == "Windows":
                subprocess.Popen(["start", "cmd", "/k", "npm", "run", "dev"], shell=True)
            else:
                subprocess.Popen(["npm", "run", "dev"])
            os.chdir("..")
            log_info("Web UI starting on http://localhost:5173")

if __name__ == "__main__":
    main()
