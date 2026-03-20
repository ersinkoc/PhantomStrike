#!/usr/bin/env python3
"""Network service detector: scan common ports, identify services, check for misconfigurations."""
import argparse
import asyncio
import re
import socket
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVICE_PORTS = {
    21: ("FTP", "tcp"), 22: ("SSH", "tcp"), 23: ("Telnet", "tcp"),
    25: ("SMTP", "tcp"), 53: ("DNS", "tcp/udp"), 80: ("HTTP", "tcp"),
    110: ("POP3", "tcp"), 111: ("RPCBind", "tcp"), 135: ("MSRPC", "tcp"),
    139: ("NetBIOS-SSN", "tcp"), 143: ("IMAP", "tcp"), 161: ("SNMP", "udp"),
    389: ("LDAP", "tcp"), 443: ("HTTPS", "tcp"), 445: ("SMB", "tcp"),
    465: ("SMTPS", "tcp"), 587: ("SMTP-Sub", "tcp"), 636: ("LDAPS", "tcp"),
    993: ("IMAPS", "tcp"), 995: ("POP3S", "tcp"), 1433: ("MSSQL", "tcp"),
    1521: ("Oracle", "tcp"), 2049: ("NFS", "tcp"), 3306: ("MySQL", "tcp"),
    3389: ("RDP", "tcp"), 5432: ("PostgreSQL", "tcp"), 5900: ("VNC", "tcp"),
    5985: ("WinRM", "tcp"), 6379: ("Redis", "tcp"), 6443: ("K8s-API", "tcp"),
    8080: ("HTTP-Proxy", "tcp"), 8443: ("HTTPS-Alt", "tcp"),
    9090: ("Prometheus", "tcp"), 9200: ("Elasticsearch", "tcp"),
    11211: ("Memcached", "tcp"), 27017: ("MongoDB", "tcp"),
}

MISCONFIG_CHECKS = {
    "FTP": {"send": b"USER anonymous\r\n", "expect": r"230|331.*anonymous|Anonymous login ok",
            "issue": "Anonymous FTP access allowed", "severity": "HIGH"},
    "Redis": {"send": b"INFO\r\n", "expect": r"redis_version",
              "issue": "Redis accessible without authentication", "severity": "CRITICAL"},
    "MongoDB": {"send": b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x10\x6c\x69\x73\x74\x44\x61\x74\x61\x62\x61\x73\x65\x73\x00\x01\x00\x00\x00\x00",
               "expect": r"totalSize|databases", "issue": "MongoDB accessible without authentication", "severity": "CRITICAL"},
    "Memcached": {"send": b"stats\r\n", "expect": r"STAT pid",
                  "issue": "Memcached accessible without authentication", "severity": "HIGH"},
    "Elasticsearch": {"send": b"GET / HTTP/1.0\r\n\r\n", "expect": r"cluster_name|elasticsearch",
                      "issue": "Elasticsearch accessible without authentication", "severity": "HIGH"},
    "MySQL": {"send": b"", "expect": r"mysql|MariaDB|is not allowed to connect",
              "issue": "MySQL port exposed", "severity": "MEDIUM"},
    "SMTP": {"send": b"VRFY root\r\n", "expect": r"252|root",
             "issue": "SMTP VRFY command enabled (user enumeration)", "severity": "MEDIUM"},
}

HTTP_MISCONFIGS = [
    ("/server-status", "Apache server-status exposed", "HIGH"),
    ("/server-info", "Apache server-info exposed", "HIGH"),
    ("/.env", "Environment file exposed", "CRITICAL"),
    ("/.git/config", "Git repository exposed", "CRITICAL"),
    ("/phpinfo.php", "PHP info page exposed", "HIGH"),
    ("/actuator", "Spring Actuator exposed", "HIGH"),
    ("/debug", "Debug endpoint accessible", "MEDIUM"),
    ("/console", "Debug console accessible", "HIGH"),
    ("/api/swagger.json", "Swagger API docs exposed", "LOW"),
    ("/robots.txt", "Robots.txt accessible", "INFO"),
]


async def check_port(host, port, timeout):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False


async def scan_ports(host, ports, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    async def bounded(port):
        async with sem:
            return await check_port(host, port, timeout)
    return await asyncio.gather(*[bounded(p) for p in ports])


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


def check_misconfig(host, port, service_name, timeout):
    findings = []
    if service_name in MISCONFIG_CHECKS:
        check = MISCONFIG_CHECKS[service_name]
        banner = grab_banner(host, port, timeout, check["send"])
        if banner and re.search(check["expect"], banner, re.I):
            findings.append({"port": port, "service": service_name, "issue": check["issue"],
                             "severity": check["severity"], "evidence": banner[:80]})
    return findings


def check_http_misconfigs(host, port, timeout):
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    for path, desc, severity in HTTP_MISCONFIGS:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                if "404" not in r.text[:200].lower() and "not found" not in r.text[:200].lower():
                    findings.append({"port": port, "service": "HTTP", "issue": desc,
                                     "severity": severity, "evidence": f"{url} [{r.status_code}] {len(r.content)} bytes"})
        except Exception:
            continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="Responder-lite: Network service detector and misconfig checker")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-t", "--timeout", type=float, default=3, help="Connection timeout")
    ap.add_argument("--skip-misconfig", action="store_true", help="Skip misconfiguration checks")
    ap.add_argument("--skip-http", action="store_true", help="Skip HTTP misconfiguration checks")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/").split(":")[0]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    ports = sorted(SERVICE_PORTS.keys())
    print(f"[*] Responder-Lite: Network Service Detector")
    print(f"[*] Target: {host} ({ip})")
    print(f"[*] Scanning {len(ports)} service ports\n")

    print("[*] Phase 1: Service Discovery...")
    results = asyncio.run(scan_ports(ip, ports, args.timeout, 100))
    open_ports = sorted([p for p, s in results if s])
    print(f"  [+] {len(open_ports)} services found\n")

    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'PROTO':<8} {'BANNER'}")
        print(f"  {'-'*8} {'-'*15} {'-'*8} {'-'*40}")
        for port in open_ports:
            svc, proto = SERVICE_PORTS.get(port, ("unknown", "tcp"))
            banner = grab_banner(ip, port, args.timeout)[:60]
            print(f"  {port:<8} {svc:<15} {proto:<8} {banner}")
        print()

    all_findings = []
    if not args.skip_misconfig and open_ports:
        print("[*] Phase 2: Misconfiguration Checks...")
        for port in open_ports:
            svc, _ = SERVICE_PORTS.get(port, ("unknown", "tcp"))
            findings = check_misconfig(ip, port, svc, args.timeout)
            all_findings.extend(findings)
            for f in findings:
                print(f"  [{f['severity']}] Port {f['port']}/{f['service']}: {f['issue']}")
                print(f"    Evidence: {f['evidence'][:60]}")
        if not all_findings:
            print("  [OK] No misconfigurations found in service banners")
        print()

    http_findings = []
    if not args.skip_http:
        http_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8000, 8888)]
        if http_ports:
            print("[*] Phase 3: HTTP Misconfiguration Checks...")
            for port in http_ports:
                findings = check_http_misconfigs(ip, port, args.timeout + 2)
                http_findings.extend(findings)
                for f in findings:
                    if f["severity"] != "INFO":
                        print(f"  [{f['severity']}] {f['issue']}")
                        print(f"    {f['evidence']}")
            if not http_findings:
                print("  [OK] No HTTP misconfigurations found")
            print()

    all_findings.extend(http_findings)
    print(f"{'='*60}")
    print(f"[*] SCAN SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Host: {host} ({ip})")
    print(f"  Open services: {len(open_ports)}")
    print(f"  Issues found: {len(all_findings)}")
    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"  Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM")
    if crit > 0:
        print(f"\n  [!] CRITICAL issues require immediate attention!")


if __name__ == "__main__":
    main()
