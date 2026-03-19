#!/usr/bin/env python3
"""
PhantomStrike Launcher
Single command to start everything

Usage:
    python start.py              # Interactive setup if needed, then start
    python start.py --setup      # Force setup/reconfiguration
    python start.py --docker     # Start with Docker Compose
    python start.py --dev        # Development mode with live reload
    python start.py --quick      # Quick start without checks
"""

import os
import sys
import subprocess
import platform
import time
import signal
import argparse
from pathlib import Path
from typing import List, Optional

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log(msg: str, color: str = Colors.BLUE):
    print(f"{color}[START]{Colors.END} {msg}")

def error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")

def success(msg: str):
    print(f"{Colors.GREEN}[OK]{Colors.END} {msg}")

def check_prerequisites() -> bool:
    """Check if required tools are installed"""
    has_go = subprocess.run(["go", "version"], capture_output=True).returncode == 0
    has_node = subprocess.run(["node", "--version"], capture_output=True).returncode == 0
    has_docker = subprocess.run(["docker", "info"], capture_output=True).returncode == 0

    return has_go and has_node

def check_configured() -> bool:
    """Check if project is already configured"""
    return Path(".env").exists() and Path("config.yaml").exists()

def run_setup():
    """Run interactive setup"""
    log("Running interactive setup...")
    result = subprocess.run([sys.executable, "setup-interactive.py"])
    return result.returncode == 0

def start_docker():
    """Start with Docker Compose"""
    log("Starting with Docker Compose...")
    subprocess.run(["docker", "compose", "up", "-d"])
    success("Services started!")
    print(f"\n{Colors.CYAN}Access Points:{Colors.END}")
    print(f"  API:    http://localhost:8080")
    print(f"  Web UI: http://localhost:5173")
    print(f"\nLogs: docker compose logs -f")

def start_dev():
    """Start in development mode"""
    log("Starting in DEVELOPMENT mode...\n")

    processes = []

    # Start API server with air (if available)
    if subprocess.run(["where", "air"], capture_output=True).returncode == 0 or \
       subprocess.run(["which", "air"], capture_output=True).returncode == 0:
        log("Starting API server with air (live reload)...")
        api_proc = subprocess.Popen(["air"], cwd=".")
    else:
        log("Starting API server...")
        api_proc = subprocess.Popen(["go", "run", "./cmd/server"], cwd=".")
    processes.append(("API", api_proc))

    time.sleep(2)

    # Start web dev server
    if Path("web/package.json").exists():
        log("Starting web UI dev server...")
        web_proc = subprocess.Popen(["npm", "run", "dev"], cwd="web")
        processes.append(("Web", web_proc))

    success("\nDevelopment servers started!")
    print(f"\n{Colors.CYAN}Access Points:{Colors.END}")
    print(f"  API:    http://localhost:8080")
    print(f"  Web UI: http://localhost:5173")
    print(f"\n{Colors.YELLOW}Press Ctrl+C to stop all servers{Colors.END}\n")

    # Wait for interrupt
    try:
        while True:
            time.sleep(1)
            # Check if any process died
            for name, proc in processes:
                if proc.poll() is not None:
                    error(f"{name} server stopped unexpectedly!")
                    break
    except KeyboardInterrupt:
        print("\n")
        log("Shutting down...")
        for name, proc in processes:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except:
                proc.kill()
        success("All servers stopped")

def start_production():
    """Start in production mode"""
    log("Starting in PRODUCTION mode...\n")

    # Check if binaries exist
    bin_dir = Path("bin")
    ext = ".exe" if platform.system() == "Windows" else ""

    api_bin = bin_dir / f"phantomstrike{ext}"
    worker_bin = bin_dir / f"phantomstrike-worker{ext}"

    if not api_bin.exists():
        log("Building API server...")
        subprocess.run(["go", "build", "-o", str(api_bin), "./cmd/server"], check=True)

    if not worker_bin.exists():
        log("Building worker...")
        subprocess.run(["go", "build", "-o", str(worker_bin), "./cmd/worker"], check=True)

    # Check web build
    web_dist = Path("web/dist")
    if not web_dist.exists():
        log("Building web UI...")
        subprocess.run(["npm", "run", "build"], cwd="web", check=True)

    processes = []

    # Start API server
    log("Starting API server...")
    api_proc = subprocess.Popen([str(api_bin)])
    processes.append(("API", api_proc))

    time.sleep(2)

    # Start worker
    log("Starting worker...")
    worker_proc = subprocess.Popen([str(worker_bin)])
    processes.append(("Worker", worker_proc))

    success("\nProduction servers started!")
    print(f"\n{Colors.CYAN}Access Points:{Colors.END}")
    print(f"  API:    http://localhost:8080")
    print(f"  Web UI: http://localhost:8080 (served by API)")
    print(f"\n{Colors.YELLOW}Press Ctrl+C to stop all servers{Colors.END}\n")

    # Wait for interrupt
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        log("Shutting down...")
        for name, proc in processes:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except:
                proc.kill()
        success("All servers stopped")

def main():
    parser = argparse.ArgumentParser(
        description="PhantomStrike Launcher - Start everything with one command",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start.py              # Interactive setup and start
  python start.py --dev        # Development mode with hot reload
  python start.py --docker     # Start with Docker Compose
  python start.py --setup      # Force reconfiguration
        """
    )
    parser.add_argument("--setup", action="store_true", help="Force setup/reconfiguration")
    parser.add_argument("--docker", action="store_true", help="Start with Docker Compose")
    parser.add_argument("--dev", action="store_true", help="Development mode")
    parser.add_argument("--quick", action="store_true", help="Skip checks and start quickly")
    parser.add_argument("--build", action="store_true", help="Build before starting")

    args = parser.parse_args()

    print(f"""
{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   PHANTOMSTRIKE LAUNCHER                                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
{Colors.END}
""")

    # Change to script directory
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    # Quick start
    if args.quick:
        if args.dev:
            start_dev()
        elif args.docker:
            start_docker()
        else:
            start_production()
        return

    # Check prerequisites
    if not args.docker:
        if not check_prerequisites():
            error("Missing prerequisites!")
            print("\nPlease install:")
            print("  - Go 1.21+: https://go.dev/dl/")
            print("  - Node.js 20+: https://nodejs.org/")
            sys.exit(1)

    # Setup if needed
    if args.setup or not check_configured():
        if not run_setup():
            error("Setup failed!")
            sys.exit(1)

    # Build if requested
    if args.build:
        log("Building application...")
        subprocess.run(["make", "build"])

    # Start based on mode
    if args.docker:
        start_docker()
    elif args.dev:
        start_dev()
    else:
        start_production()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        error(f"Error: {e}")
        sys.exit(1)
