#!/usr/bin/env python3
"""Basic Linux privilege escalation checks."""
import argparse
import os
import subprocess
import sys


def run_cmd(cmd, timeout=10):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def check_suid():
    """Find SUID binaries."""
    print("\n=== SUID Binaries ===")
    output = run_cmd("find / -perm -4000 -type f 2>/dev/null", timeout=30)
    if output:
        known_exploitable = [
            "nmap", "vim", "find", "bash", "more", "less", "nano",
            "cp", "mv", "python", "python3", "perl", "ruby", "node",
            "php", "env", "awk", "strace", "gdb", "docker", "pkexec",
        ]
        lines = output.split("\n")
        print(f"  Found {len(lines)} SUID binaries:")
        for line in lines:
            binary = os.path.basename(line)
            marker = " [!] EXPLOITABLE" if binary in known_exploitable else ""
            print(f"    {line}{marker}")
    else:
        print("  No SUID binaries found (or insufficient permissions)")


def check_sgid():
    """Find SGID binaries."""
    print("\n=== SGID Binaries ===")
    output = run_cmd("find / -perm -2000 -type f 2>/dev/null", timeout=30)
    if output:
        lines = output.split("\n")
        print(f"  Found {len(lines)} SGID binaries:")
        for line in lines[:20]:
            print(f"    {line}")
        if len(lines) > 20:
            print(f"    ... and {len(lines) - 20} more")
    else:
        print("  No SGID binaries found")


def check_writable_files():
    """Check for writable sensitive files."""
    print("\n=== Writable Sensitive Files ===")
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
                 "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys"]
    for f in sensitive:
        if os.path.exists(f) and os.access(f, os.W_OK):
            print(f"  [!] WRITABLE: {f}")
        elif os.path.exists(f):
            print(f"  [OK] {f} (not writable)")


def check_sudo():
    """Check sudo permissions."""
    print("\n=== Sudo Permissions ===")
    output = run_cmd("sudo -l 2>/dev/null")
    if output and "not allowed" not in output.lower():
        print(f"  {output}")
        if "NOPASSWD" in output:
            print("  [!] NOPASSWD entries found - potential privilege escalation")
        if "(ALL)" in output or "(root)" in output:
            print("  [!] Can run commands as root")
    else:
        print("  Cannot check sudo (no permissions or not available)")


def check_cron():
    """Check cron jobs."""
    print("\n=== Cron Jobs ===")
    for cron_file in ["/etc/crontab", "/etc/cron.d"]:
        if os.path.exists(cron_file):
            if os.path.isfile(cron_file):
                output = run_cmd(f"cat {cron_file} 2>/dev/null")
                if output:
                    print(f"  {cron_file}:")
                    for line in output.split("\n"):
                        if line.strip() and not line.startswith("#"):
                            print(f"    {line}")
            elif os.path.isdir(cron_file):
                output = run_cmd(f"ls -la {cron_file}/ 2>/dev/null")
                if output:
                    print(f"  {cron_file}/:")
                    print(f"    {output}")

    user_crons = run_cmd("crontab -l 2>/dev/null")
    if user_crons:
        print(f"  User crontab:")
        print(f"    {user_crons}")


def check_env():
    """Check environment for sensitive data."""
    print("\n=== Environment Variables ===")
    sensitive_patterns = ["password", "secret", "key", "token", "api", "credential", "auth"]
    for key, value in os.environ.items():
        if any(p in key.lower() for p in sensitive_patterns):
            print(f"  [!] {key}={value[:20]}...")


def check_processes():
    """Check running processes for interesting ones."""
    print("\n=== Interesting Processes ===")
    output = run_cmd("ps aux 2>/dev/null")
    if output:
        interesting = ["mysql", "postgres", "mongo", "redis", "docker",
                       "apache", "nginx", "ssh", "ftp", "smb", "vnc"]
        for line in output.split("\n"):
            if any(p in line.lower() for p in interesting):
                print(f"    {line.strip()}")


def check_network():
    """Check listening services."""
    print("\n=== Listening Services ===")
    output = run_cmd("ss -tlnp 2>/dev/null") or run_cmd("netstat -tlnp 2>/dev/null")
    if output:
        for line in output.split("\n"):
            print(f"    {line}")


def check_os_info():
    """Get OS information."""
    print("=== System Information ===")
    info = {
        "Hostname": run_cmd("hostname"),
        "Kernel": run_cmd("uname -r"),
        "OS": run_cmd("cat /etc/os-release 2>/dev/null | head -2"),
        "Arch": run_cmd("uname -m"),
        "User": run_cmd("whoami"),
        "ID": run_cmd("id"),
    }
    for key, val in info.items():
        if val:
            print(f"  {key}: {val}")


def main():
    parser = argparse.ArgumentParser(description="Linux privilege escalation checks")
    parser.add_argument("--thorough", action="store_true", help="Run thorough checks")
    args = parser.parse_args()

    if sys.platform != "linux":
        print("[!] Warning: This tool is designed for Linux systems")

    print("[*] LinPEAS-Lite - Privilege Escalation Checker")
    print(f"[*] Running as: {os.getenv('USER', 'unknown')}\n")

    check_os_info()
    check_sudo()
    check_suid()
    check_sgid()
    check_writable_files()
    check_cron()
    check_env()
    check_processes()
    check_network()

    print("\n[*] Scan complete")


if __name__ == "__main__":
    main()
