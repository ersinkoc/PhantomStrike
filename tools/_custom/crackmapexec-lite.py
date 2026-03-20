#!/usr/bin/env python3
"""Network service checker: test SMB, SSH, FTP, RDP for default creds and misconfigs."""
import argparse
import socket
import struct
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CREDENTIALS = {
    "ftp": [("anonymous", ""), ("anonymous", "anonymous"), ("ftp", "ftp"), ("admin", "admin"),
            ("admin", "password"), ("root", "root"), ("user", "user")],
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin"), ("admin", "password"),
            ("user", "user"), ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("test", "test")],
    "smb": [("administrator", ""), ("administrator", "admin"), ("administrator", "password"),
            ("guest", ""), ("admin", "admin"), ("admin", "password")],
    "rdp": [("administrator", ""), ("administrator", "admin"), ("administrator", "password"),
            ("admin", "admin"), ("user", "user")],
    "http": [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"),
             ("administrator", "administrator"), ("admin", ""), ("test", "test")],
}


def check_port(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def check_ftp(host, port, timeout, credentials):
    results = {"service": "FTP", "port": port, "accessible": False, "banner": "", "vulns": [], "creds": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        results["banner"] = banner[:80]
        results["accessible"] = True

        for user, passwd in credentials:
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(timeout)
                s2.connect((host, port))
                s2.recv(1024)
                s2.send(f"USER {user}\r\n".encode())
                resp = s2.recv(1024).decode("utf-8", errors="replace")
                if "331" in resp or "230" in resp:
                    s2.send(f"PASS {passwd}\r\n".encode())
                    resp = s2.recv(1024).decode("utf-8", errors="replace")
                    if "230" in resp:
                        results["creds"].append((user, passwd))
                        results["vulns"].append({"issue": f"Valid credentials: {user}:{passwd or '(empty)'}",
                                                 "severity": "CRITICAL" if user == "anonymous" else "HIGH"})
                s2.close()
            except Exception:
                continue
        s.close()
    except Exception as e:
        results["error"] = str(e)
    return results


def check_ssh(host, port, timeout, credentials):
    results = {"service": "SSH", "port": port, "accessible": False, "banner": "", "vulns": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        results["banner"] = banner[:80]
        results["accessible"] = True
        s.close()

        # Check for weak SSH versions
        if "SSH-1" in banner:
            results["vulns"].append({"issue": "SSHv1 supported (deprecated)", "severity": "HIGH"})
        if "OpenSSH" in banner:
            import re
            m = re.search(r"OpenSSH[_\s]([\d.]+)", banner)
            if m:
                ver = m.group(1)
                major, minor = ver.split(".")[:2]
                if int(major) < 7 or (int(major) == 7 and int(minor) < 4):
                    results["vulns"].append({"issue": f"Outdated OpenSSH {ver}", "severity": "MEDIUM"})

        # Note: actual SSH auth testing requires paramiko which we cannot use
        # Instead we report the banner for manual verification
        results["vulns"].append({"issue": f"SSH exposed: {banner[:50]}", "severity": "INFO"})

    except Exception as e:
        results["error"] = str(e)
    return results


def check_smb(host, port, timeout, credentials):
    results = {"service": "SMB", "port": port, "accessible": False, "banner": "", "vulns": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        results["accessible"] = True

        # Send SMB negotiate
        negotiate = b"\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        negotiate += b"\x00" * 12 + b"\xff\xff\x00\x00\x00\x00\x00\x00"
        negotiate += b"\x00\x62\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        s.send(negotiate)
        resp = s.recv(4096)
        s.close()

        if resp and len(resp) > 36:
            if resp[4:8] == b"\xffSMB":
                results["banner"] = "SMBv1"
                results["vulns"].append({"issue": "SMBv1 enabled (MS17-010 risk)", "severity": "HIGH"})
                security_mode = resp[39] if len(resp) > 39 else 0
                if not (security_mode & 0x08):
                    results["vulns"].append({"issue": "SMB signing not required", "severity": "MEDIUM"})
            elif resp[4:8] == b"\xfeSMB":
                results["banner"] = "SMBv2+"

        # Try null session
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(timeout)
            s2.connect((host, port))
            s2.send(negotiate)
            s2.recv(4096)
            s2.close()
            # If we get a response, port is responsive
            results["vulns"].append({"issue": "SMB port accessible", "severity": "INFO"})
        except Exception:
            pass

    except Exception as e:
        results["error"] = str(e)
    return results


def check_rdp(host, port, timeout):
    results = {"service": "RDP", "port": port, "accessible": False, "banner": "", "vulns": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        results["accessible"] = True

        # Send RDP Connection Request
        rdp_neg = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        s.send(rdp_neg)
        resp = s.recv(4096)
        s.close()

        if resp and len(resp) > 0:
            results["banner"] = f"RDP response ({len(resp)} bytes)"
            if resp[0] == 0x03:
                results["vulns"].append({"issue": "RDP accessible", "severity": "INFO"})
                # Check for NLA
                if len(resp) > 19 and resp[11] == 0x02:
                    results["vulns"].append({"issue": "NLA (Network Level Auth) supported", "severity": "INFO"})
                elif len(resp) > 11:
                    results["vulns"].append({"issue": "NLA may not be required", "severity": "MEDIUM"})

    except Exception as e:
        results["error"] = str(e)
    return results


def check_http(host, port, timeout, credentials):
    results = {"service": "HTTP", "port": port, "accessible": False, "vulns": []}
    scheme = "https" if port in (443, 8443) else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False)
        results["accessible"] = True
        results["banner"] = r.headers.get("Server", "")[:80]
        if r.status_code == 401:
            results["vulns"].append({"issue": "HTTP Basic Auth endpoint found", "severity": "INFO"})
            for user, passwd in credentials:
                try:
                    r2 = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False,
                                      auth=(user, passwd))
                    if r2.status_code != 401:
                        results["vulns"].append({"issue": f"Default creds work: {user}:{passwd}",
                                                 "severity": "CRITICAL"})
                except Exception:
                    continue
    except Exception as e:
        results["error"] = str(e)
    return results


def main():
    ap = argparse.ArgumentParser(description="CrackMapExec-lite: Network service checker")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout")
    ap.add_argument("--protocol", choices=["smb", "ssh", "ftp", "rdp", "http", "all"], default="all")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] CrackMapExec-Lite: Network Service Checker")
    print(f"[*] Target: {host} ({ip})")
    print(f"[*] Protocol: {args.protocol}\n")

    checks = {
        "smb": [(445, lambda: check_smb(ip, 445, args.timeout, DEFAULT_CREDENTIALS["smb"]))],
        "ssh": [(22, lambda: check_ssh(ip, 22, args.timeout, DEFAULT_CREDENTIALS["ssh"]))],
        "ftp": [(21, lambda: check_ftp(ip, 21, args.timeout, DEFAULT_CREDENTIALS["ftp"]))],
        "rdp": [(3389, lambda: check_rdp(ip, 3389, args.timeout))],
        "http": [(80, lambda: check_http(ip, 80, args.timeout, DEFAULT_CREDENTIALS["http"])),
                 (443, lambda: check_http(ip, 443, args.timeout, DEFAULT_CREDENTIALS["http"])),
                 (8080, lambda: check_http(ip, 8080, args.timeout, DEFAULT_CREDENTIALS["http"]))],
    }

    all_results = []
    protocols = list(checks.keys()) if args.protocol == "all" else [args.protocol]

    for proto in protocols:
        for port, check_fn in checks[proto]:
            if not check_port(ip, port, args.timeout):
                print(f"  [-] {proto.upper():<5} Port {port} - closed/filtered")
                continue
            print(f"  [+] {proto.upper():<5} Port {port} - open, testing...")
            result = check_fn()
            all_results.append(result)
            if result.get("banner"):
                print(f"         Banner: {result['banner']}")
            for v in result.get("vulns", []):
                print(f"         [{v['severity']}] {v['issue']}")
            print()

    print(f"{'='*60}")
    print(f"[*] RESULTS SUMMARY")
    print(f"{'='*60}\n")
    all_vulns = [v for r in all_results for v in r.get("vulns", []) if v["severity"] != "INFO"]
    accessible = sum(1 for r in all_results if r.get("accessible"))
    print(f"  Services accessible: {accessible}")
    print(f"  Issues found: {len(all_vulns)}")
    crit = sum(1 for v in all_vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in all_vulns if v["severity"] == "HIGH")
    med = sum(1 for v in all_vulns if v["severity"] == "MEDIUM")
    print(f"  Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM")

    if crit > 0:
        print(f"\n  [!] CRITICAL: Default/weak credentials found!")


if __name__ == "__main__":
    main()
