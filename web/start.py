#!/usr/bin/env python3
"""
PhantomStrike - One-Command Launcher
Starts all services: backend API, frontend, and optional Docker services
"""

import os
import sys
import platform
import subprocess
import time
import signal
from pathlib import Path
from typing import List, Optional

IS_WINDOWS = platform.system() == "Windows"
PROCESSES: List[subprocess.Popen] = []

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    PHANTOMSTRIKE v2.0                           ║
║                   Starting Services...                          ║
╚══════════════════════════════════════════════════════════════════╝
""")

def run_command(cmd: List[str], cwd: Optional[str] = None, env: Optional[dict] = None) -> subprocess.Popen:
    """Run a command in background"""
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    
    if IS_WINDOWS:
        return subprocess.Popen(
            cmd, cwd=cwd, env=process_env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        return subprocess.Popen(
            cmd, cwd=cwd, env=process_env,
            preexec_fn=os.setsid
        )

def check_command_exists(cmd: str) -> bool:
    """Check if a command exists"""
    check_cmd = "where" if IS_WINDOWS else "which"
    try:
        result = subprocess.run([check_cmd, cmd], capture_output=True)
        return result.returncode == 0
    except:
        return False

def load_env():
    """Load environment variables from .env file"""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key] = value

def start_backend() -> subprocess.Popen:
    """Start the Go backend API"""
    print("[1/3] Starting Backend API...")
    root = Path(__file__).parent
    
    # Check if binary exists
    binary_name = "phantomstrike.exe" if IS_WINDOWS else "phantomstrike"
    binary_path = root / binary_name
    
    if binary_path.exists():
        proc = run_command([str(binary_path)], cwd=str(root))
    else:
        # Try to run with go run
        if check_command_exists("go"):
            proc = run_command(["go", "run", "."], cwd=str(root))
        else:
            print("ERROR: No backend binary found and Go not installed")
            sys.exit(1)
    
    print(f"  Backend started (PID: {proc.pid})")
    return proc

def start_frontend() -> subprocess.Popen:
    """Start the frontend dev server"""
    print("[2/3] Starting Frontend...")
    root = Path(__file__).parent
    web_dir = root / "web"
    
    if not web_dir.exists():
        print("ERROR: web/ directory not found")
        sys.exit(1)
    
    # Check for node_modules
    if not (web_dir / "node_modules").exists():
        print("  Installing frontend dependencies...")
        subprocess.run(["npm", "install"], cwd=str(web_dir), check=True)
    
    proc = run_command(["npm", "run", "dev"], cwd=str(web_dir))
    print(f"  Frontend started (PID: {proc.pid})")
    return proc

def start_docker() -> Optional[subprocess.Popen]:
    """Start Docker services if docker-compose.yml exists"""
    root = Path(__file__).parent
    compose_file = root / "docker-compose.yml"
    
    if not compose_file.exists():
        return None
    
    if not check_command_exists("docker"):
        print("  Docker not found, skipping Docker services")
        return None
    
    print("[3/3] Starting Docker services...")
    proc = run_command(["docker-compose", "up", "-d"], cwd=str(root))
    print(f"  Docker services starting...")
    return proc

def signal_handler(sig, frame):
    """Handle shutdown gracefully"""
    print("\n\nShutting down PhantomStrike...")
    for proc in PROCESSES:
        try:
            if IS_WINDOWS:
                proc.terminate()
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except:
            pass
    time.sleep(1)
    print("Goodbye!")
    sys.exit(0)

def main():
    print_banner()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Load environment
    load_env()
    
    # Check for .env file
    if not (Path(__file__).parent / ".env").exists():
        print("WARNING: .env file not found!")
        print("Please run: python setup-interactive.py")
        if input("Run setup now? [Y/n]: ").strip().lower() in ['', 'y', 'yes']:
            subprocess.run([sys.executable, "setup-interactive.py"])
            return
        else:
            sys.exit(1)
    
    # Start services
    try:
        backend = start_backend()
        PROCESSES.append(backend)
        time.sleep(2)  # Give backend time to start
        
        frontend = start_frontend()
        PROCESSES.append(frontend)
        
        docker = start_docker()
        if docker:
            PROCESSES.append(docker)
        
        print("\n" + "="*50)
        print("All services started!")
        print("="*50)
        print("\nURLs:")
        print("  Frontend: http://localhost:5173")
        print("  Backend:  http://localhost:8080")
        print("\nPress Ctrl+C to stop all services\n")
        
        # Wait for all processes
        while True:
            for proc in PROCESSES[:]:
                ret = proc.poll()
                if ret is not None:
                    print(f"Process {proc.pid} exited with code {ret}")
                    PROCESSES.remove(proc)
            if not PROCESSES:
                break
            time.sleep(1)
            
    except Exception as e:
        print(f"ERROR: {e}")
        signal_handler(None, None)

if __name__ == "__main__":
    main()
