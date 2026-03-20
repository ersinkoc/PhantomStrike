#!/usr/bin/env python3
"""SMB enumeration using smbclient and rpcclient."""
import argparse
import subprocess
import sys


def run_cmd(cmd, timeout=30):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", -1
    except FileNotFoundError:
        return "", "Command not found", -1


def enum_shares(target, user="", password=""):
    """Enumerate SMB shares."""
    print("\n=== SMB Shares ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(f"smbclient -L //{target} {creds} 2>/dev/null")
    if stdout:
        print(stdout)
        shares = []
        for line in stdout.split("\n"):
            line = line.strip()
            if line and "Disk" in line or "IPC" in line or "Printer" in line:
                parts = line.split()
                if parts:
                    shares.append(parts[0])
        return shares
    else:
        print(f"  Could not list shares: {stderr}")
        return []


def enum_users_rpc(target, user="", password=""):
    """Enumerate users via rpcclient."""
    print("\n=== Users (RPC) ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(
        f"rpcclient -c 'enumdomusers' {creds} {target} 2>/dev/null"
    )
    if stdout and "user:" in stdout.lower():
        users = []
        for line in stdout.split("\n"):
            if "user:" in line.lower():
                print(f"    {line.strip()}")
                users.append(line.strip())
        return users
    else:
        print(f"  Could not enumerate users: {stderr or 'no results'}")
        return []


def enum_groups_rpc(target, user="", password=""):
    """Enumerate groups via rpcclient."""
    print("\n=== Groups (RPC) ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(
        f"rpcclient -c 'enumdomgroups' {creds} {target} 2>/dev/null"
    )
    if stdout and "group:" in stdout.lower():
        for line in stdout.split("\n"):
            if "group:" in line.lower():
                print(f"    {line.strip()}")
    else:
        print(f"  Could not enumerate groups: {stderr or 'no results'}")


def enum_shares_access(target, shares, user="", password=""):
    """Check read/write access to shares."""
    print("\n=== Share Access ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    for share in shares:
        stdout, stderr, rc = run_cmd(
            f"smbclient //{target}/{share} {creds} -c 'dir' 2>/dev/null"
        )
        if rc == 0 and stdout:
            print(f"  [READ]  \\\\{target}\\{share}")
            # Try write
            _, _, wrc = run_cmd(
                f"smbclient //{target}/{share} {creds} -c 'mkdir .enumtest; rmdir .enumtest' 2>/dev/null"
            )
            if wrc == 0:
                print(f"  [WRITE] \\\\{target}\\{share}")
        else:
            print(f"  [DENY]  \\\\{target}\\{share}")


def enum_os_info(target, user="", password=""):
    """Get OS information via SMB."""
    print("\n=== OS Information ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(
        f"rpcclient -c 'srvinfo' {creds} {target} 2>/dev/null"
    )
    if stdout:
        print(f"    {stdout}")
    stdout, stderr, rc = run_cmd(
        f"smbclient -L //{target} {creds} 2>&1 | head -5"
    )
    if stdout:
        for line in stdout.split("\n"):
            if "OS=" in line or "Server=" in line or "Domain=" in line:
                print(f"    {line.strip()}")


def enum_password_policy(target, user="", password=""):
    """Get password policy."""
    print("\n=== Password Policy ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(
        f"rpcclient -c 'getdompwinfo' {creds} {target} 2>/dev/null"
    )
    if stdout:
        print(f"    {stdout}")
    else:
        print(f"  Could not retrieve password policy")


def enum_sessions(target, user="", password=""):
    """Enumerate active sessions."""
    print("\n=== Active Sessions ===")
    creds = f"-U '{user}%{password}'" if user else "-N"
    stdout, stderr, rc = run_cmd(
        f"rpcclient -c 'netsessenum' {creds} {target} 2>/dev/null"
    )
    if stdout:
        print(f"    {stdout}")
    else:
        print(f"  No sessions found or access denied")


def main():
    parser = argparse.ArgumentParser(description="SMB enumeration tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-u", "--user", default="", help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-a", "--all", action="store_true", help="Run all checks (default)")
    args = parser.parse_args()

    target = args.target.strip()
    print(f"[*] enum4linux-lite - SMB Enumeration")
    print(f"[*] Target: {target}")
    if args.user:
        print(f"[*] User: {args.user}")
    else:
        print(f"[*] Using null session")

    enum_os_info(target, args.user, args.password)
    shares = enum_shares(target, args.user, args.password)
    if shares:
        enum_shares_access(target, shares, args.user, args.password)
    enum_users_rpc(target, args.user, args.password)
    enum_groups_rpc(target, args.user, args.password)
    enum_password_policy(target, args.user, args.password)
    enum_sessions(target, args.user, args.password)

    print("\n[*] Enumeration complete")


if __name__ == "__main__":
    main()
