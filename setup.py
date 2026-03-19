#!/usr/bin/env python3
#
# PhantomStrike Universal Setup Script
# Works on: Linux, macOS, Windows (with Python 3.6+)
#
# This script detects the platform and runs the appropriate setup.
#

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    banner = """
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗      ║
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗     ║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║     ║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║     ║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝     ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝      ║
║                                                            ║
║              AI-Powered Security Platform                  ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"""
    print(banner)

def log_info(message):
    print(f"[INFO] {message}")

def log_warn(message):
    print(f"[WARN] {message}")

def log_error(message):
    print(f"[ERROR] {message}")

def log_step(message):
    print(f"[STEP] {message}")

def run_command(cmd, shell=False, check=True):
    """Run a command and return the result."""
    if shell and isinstance(cmd, list):
        cmd = ' '.join(cmd)

    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            capture_output=True,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        if check:
            raise
        return e

def detect_platform():
    """Detect the current platform."""
    system = platform.system().lower()

    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "macos"
    elif system == "windows":
        return "windows"
    else:
        return "unknown"

def main():
    print_banner()

    plat = detect_platform()
    log_step(f"Detected platform: {plat}")

    script_dir = Path(__file__).parent.absolute()

    if plat in ["linux", "macos"]:
        # Run bash script
        setup_script = script_dir / "setup.sh"
        if setup_script.exists():
            log_info("Running setup.sh...")
            os.chmod(setup_script, 0o755)
            subprocess.run([str(setup_script)] + sys.argv[1:])
        else:
            log_error("setup.sh not found!")
            sys.exit(1)

    elif plat == "windows":
        # Check if PowerShell is available
        ps_script = script_dir / "setup.ps1"
        if ps_script.exists():
            log_info("Running setup.ps1...")
            # Run with bypass execution policy
            cmd = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", str(ps_script)
            ] + sys.argv[1:]
            subprocess.run(cmd)
        else:
            log_error("setup.ps1 not found!")
            sys.exit(1)
    else:
        log_error(f"Unsupported platform: {plat}")
        log_info("Please run the appropriate setup script manually:")
        log_info("  - Linux/macOS: ./setup.sh")
        log_info("  - Windows: .\\setup.ps1")
        sys.exit(1)

if __name__ == "__main__":
    main()
