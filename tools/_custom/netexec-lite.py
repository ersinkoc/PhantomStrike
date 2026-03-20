#!/usr/bin/env python3
"""Multi-protocol checker: test SSH, FTP, SMB, RDP, HTTP for authentication issues."""
import argparse
import socket
import struct
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROTOCOL_PORTS = {
    "ssh": 22, "ftp": 21, "smb": 445, "rdp": 3389,
    "http": 80, "https": 443, "winrm": 5985, "mssql": 1433,
    "mysql": 3306, "postgresql": 5432, "vnc": 5900, "redis": 6379,
}

AUTH_CHECKS = {
    "ssh": {"default_port": 22, "banner_probe": b"",
            "weak_versions": [("SSH-1", "SSHv1 protocol supported (deprecated)")],
            "auth_methods": "Check SSH auth methods in banner"},
    "ftp": {"default_port": 21, "banner_probe": b"",
            "anon_test": ("USER anonymous\r\n", "331", "PASS anonymous@\r\n", "230")},
    "smb": {"default_port": 445, "null_session": True},
    "rdp": {"default_port": 3389, "nla_check": True},
    "http": {"default_port": 80, "auth_endpoints": ["/", "/admin", "/login", "/manager", "/console"]},
    "winrm": {"default_port": 5985, "endpoint": "/wsman"},
    "redis": {"default_port": 6379, "probe": b"PING\r\n", "expect": "+PONG"},
    "mysql": {"default_port": 3306, "banner_probe": b""},
    "mssql": {"default_port": 1433, "banner_probe": b""},
}


def check_port_open(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def grab_banner(host, port, timeout, send_data=b""):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if send_data:
            s.send(send_data)
        else:
            time.sleep(0.5)
        data = s.recv(4096)
        s.close()
        return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def check_ssh_service(host, port, timeout):
    findings = []
    banner = grab_banner(host, port, timeout)
    if banner:
        findings.append({"type": "INFO", "detail": f"Banner: {banner[:60]}"})
        if "SSH-1" in banner:
            findings.append({"type": "HIGH", "detail": "SSHv1 supported (deprecated, insecure)"})
        import re
        m = re.search(r"OpenSSH[_\s]([\d.]+)", banner)
        if m:
            ver_parts = m.group(1).split(".")
            if int(ver_parts[0]) < 8:
                findings.append({"type": "MEDIUM", "detail": f"Potentially outdated OpenSSH {m.group(1)}"})
    return findings


def check_ftp_service(host, port, timeout):
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        findings.append({"type": "INFO", "detail": f"Banner: {banner[:60]}"})

        s.send(b"USER anonymous\r\n")
        resp = s.recv(1024).decode("utf-8", errors="replace")
        if "331" in resp or "230" in resp:
            s.send(b"PASS anonymous@example.com\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            if "230" in resp:
                findings.append({"type": "CRITICAL", "detail": "Anonymous FTP access allowed"})
                s.send(b"PWD\r\n")
                pwd = s.recv(1024).decode("utf-8", errors="replace").strip()
                findings.append({"type": "INFO", "detail": f"FTP dir: {pwd[:60]}"})
        s.close()
    except Exception:
        pass
    return findings


def check_smb_service(host, port, timeout):
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        negotiate = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        negotiate += b"\x00" * 12 + b"\xff\xff\x00\x00\x00\x00\x00\x00"
        negotiate += b"\x00\x62\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        pkt = struct.pack(">I", len(negotiate)) + negotiate
        s.send(pkt)
        resp = s.recv(4096)
        s.close()

        if resp and len(resp) > 8:
            if resp[4:8] == b"\xffSMB":
                findings.append({"type": "HIGH", "detail": "SMBv1 enabled (EternalBlue/MS17-010 risk)"})
                if len(resp) > 39 and not (resp[39] & 0x08):
                    findings.append({"type": "MEDIUM", "detail": "SMB signing not required (relay risk)"})
            elif resp[4:8] == b"\xfeSMB":
                findings.append({"type": "INFO", "detail": "SMBv2+ negotiated"})
                if len(resp) > 71:
                    sec_mode = struct.unpack("<H", resp[70:72])[0]
                    if not (sec_mode & 0x02):
                        findings.append({"type": "MEDIUM", "detail": "SMB signing not required"})
    except Exception:
        pass
    return findings


def check_rdp_service(host, port, timeout):
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        rdp_req = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        s.send(rdp_req)
        resp = s.recv(4096)
        s.close()

        if resp:
            findings.append({"type": "INFO", "detail": f"RDP responsive ({len(resp)} bytes)"})
            if len(resp) > 11 and resp[0] == 0x03:
                if resp[11] == 0x02:
                    findings.append({"type": "INFO", "detail": "NLA (Network Level Auth) supported"})
                else:
                    findings.append({"type": "MEDIUM", "detail": "NLA may not be enforced"})
        findings.append({"type": "INFO", "detail": "RDP exposed - verify NLA and lockout policy"})
    except Exception:
        pass
    return findings


def check_http_service(host, port, timeout):
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False)
        findings.append({"type": "INFO", "detail": f"HTTP [{r.status_code}] Server: {r.headers.get('Server', 'N/A')}"})

        if r.status_code == 401:
            findings.append({"type": "INFO", "detail": "Basic/Digest auth required"})
            for user, passwd in [("admin", "admin"), ("admin", "password"), ("admin", "")]:
                try:
                    r2 = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False,
                                      auth=(user, passwd))
                    if r2.status_code != 401:
                        findings.append({"type": "CRITICAL", "detail": f"Default creds: {user}:{passwd or '(empty)'}"})
                except Exception:
                    continue

        for path in ["/admin", "/manager/html", "/console", "/.env", "/.git/config"]:
            try:
                r2 = requests.get(f"{scheme}://{host}:{port}{path}", timeout=timeout, verify=False,
                                  allow_redirects=False)
                if r2.status_code == 200 and len(r2.content) > 50:
                    findings.append({"type": "HIGH" if ".env" in path or ".git" in path else "MEDIUM",
                                     "detail": f"Sensitive endpoint: {path} [{r2.status_code}]"})
            except Exception:
                continue
    except Exception:
        pass
    return findings


def check_redis_service(host, port, timeout):
    findings = []
    banner = grab_banner(host, port, timeout, b"PING\r\n")
    if "+PONG" in banner:
        findings.append({"type": "CRITICAL", "detail": "Redis accessible without authentication"})
        info = grab_banner(host, port, timeout, b"INFO server\r\n")
        import re
        m = re.search(r"redis_version:(\S+)", info)
        if m:
            findings.append({"type": "INFO", "detail": f"Redis version: {m.group(1)}"})
    elif banner:
        if "NOAUTH" in banner or "Authentication required" in banner.lower():
            findings.append({"type": "INFO", "detail": "Redis requires authentication"})
    return findings


def main():
    ap = argparse.ArgumentParser(description="NetExec-lite: Multi-protocol authentication checker")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-p", "--protocols", nargs="+", default=["ssh", "ftp", "smb", "rdp", "http", "redis"],
                    help="Protocols to test")
    ap.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout")
    ap.add_argument("--port", type=int, help="Override port number")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] NetExec-Lite: Multi-Protocol Checker")
    print(f"[*] Target: {host} ({ip})")
    print(f"[*] Protocols: {', '.join(args.protocols)}\n")

    checkers = {
        "ssh": (22, check_ssh_service),
        "ftp": (21, check_ftp_service),
        "smb": (445, check_smb_service),
        "rdp": (3389, check_rdp_service),
        "http": (80, check_http_service),
        "https": (443, check_http_service),
        "redis": (6379, check_redis_service),
    }

    all_findings = []
    for proto in args.protocols:
        default_port, checker = checkers.get(proto, (None, None))
        if not checker:
            print(f"  [-] Unknown protocol: {proto}")
            continue

        port = args.port or default_port
        print(f"  {'='*50}")
        print(f"  {proto.upper()} (port {port})")
        print(f"  {'='*50}")

        if not check_port_open(ip, port, args.timeout):
            print(f"  [-] Port {port} closed/filtered\n")
            continue

        print(f"  [+] Port {port} open")
        findings = checker(ip, port, args.timeout)
        for f in findings:
            print(f"  [{f['type']}] {f['detail']}")
        all_findings.extend([(proto, f) for f in findings])
        print()

    print(f"{'='*60}")
    print(f"[*] ASSESSMENT SUMMARY")
    print(f"{'='*60}\n")
    non_info = [(p, f) for p, f in all_findings if f["type"] != "INFO"]
    print(f"  Total issues: {len(non_info)}")
    crit = sum(1 for _, f in all_findings if f["type"] == "CRITICAL")
    high = sum(1 for _, f in all_findings if f["type"] == "HIGH")
    med = sum(1 for _, f in all_findings if f["type"] == "MEDIUM")
    print(f"  Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM")
    if non_info:
        print(f"\n  Issues by protocol:")
        for proto, f in non_info:
            print(f"    [{f['type']}] {proto.upper()}: {f['detail']}")


if __name__ == "__main__":
    main()
