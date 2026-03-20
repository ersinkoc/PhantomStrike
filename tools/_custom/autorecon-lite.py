#!/usr/bin/env python3
"""Automated recon pipeline: port scan + HTTP probe + subdomain enum in one script."""
import argparse
import asyncio
import socket
import sys
import time
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 636, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389,
    4443, 5432, 5900, 5985, 6379, 6443, 8000, 8008, 8080, 8443, 8888,
    9090, 9200, 9300, 11211, 27017,
]

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 4443: "https-alt", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 6443: "k8s-api", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9300: "es-transport",
    11211: "memcached", 27017: "mongodb",
}

SUBDOMAIN_PREFIXES = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
    "blog", "shop", "store", "app", "m", "mobile", "cdn", "static", "media",
    "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail", "remote", "vpn",
    "git", "gitlab", "jenkins", "ci", "cd", "jira", "confluence", "wiki",
    "docs", "support", "help", "status", "monitor", "grafana", "kibana",
    "elastic", "db", "database", "redis", "cache", "search", "auth", "sso",
    "login", "oauth", "id", "accounts", "billing", "pay", "payments",
]


async def scan_port(host, port, timeout):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False


async def scan_ports(host, ports, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    async def bounded(port):
        async with sem:
            return await scan_port(host, port, timeout)
    return await asyncio.gather(*[bounded(p) for p in ports])


def probe_http(host, port, timeout):
    schemes = ["https"] if port in (443, 8443, 4443) else ["http"] if port in (80, 8080, 8000, 8008, 8888) else ["https", "http"]
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                             headers={"User-Agent": "PhantomStrike/1.0 AutoRecon"})
            title = ""
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            if m:
                title = m.group(1).strip()[:60]
            return {"url": r.url, "status": r.status_code, "title": title,
                    "server": r.headers.get("Server", ""), "size": len(r.content),
                    "redirect": r.url != url}
        except Exception:
            continue
    return None


def enum_subdomains(domain, timeout):
    found = []
    for prefix in SUBDOMAIN_PREFIXES:
        sub = f"{prefix}.{domain}"
        try:
            answers = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set(a[4][0] for a in answers))
            if ips:
                found.append({"subdomain": sub, "ips": ips})
        except socket.gaierror:
            continue
    return found


def crtsh_subdomains(domain, timeout):
    found = []
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            names = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        names.add(name)
            for name in sorted(names):
                try:
                    ip = socket.gethostbyname(name)
                    found.append({"subdomain": name, "ips": [ip]})
                except socket.gaierror:
                    found.append({"subdomain": name, "ips": []})
    except Exception:
        pass
    return found


def main():
    ap = argparse.ArgumentParser(description="AutoRecon-lite: Automated recon pipeline")
    ap.add_argument("target", help="Target domain or IP")
    ap.add_argument("-t", "--timeout", type=float, default=2, help="Connection timeout")
    ap.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    ap.add_argument("--skip-http", action="store_true", help="Skip HTTP probing")
    args = ap.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").rstrip("/").split(":")[0]
    start = time.time()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] AutoRecon-Lite: Automated Reconnaissance")
    print(f"[*] Target: {target} ({ip})\n")

    # Phase 1: Port Scan
    print(f"[*] Phase 1: Port Scanning ({len(TOP_PORTS)} ports)...")
    results = asyncio.run(scan_ports(ip, TOP_PORTS, args.timeout, 100))
    open_ports = sorted([p for p, s in results if s])
    print(f"  [+] Open ports: {len(open_ports)}\n")

    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'STATE'}")
        print(f"  {'-'*8} {'-'*15} {'-'*5}")
        for port in open_ports:
            svc = PORT_SERVICES.get(port, "unknown")
            print(f"  {port:<8} {svc:<15} open")
        print()

    # Phase 2: HTTP Probing
    http_results = []
    if not args.skip_http:
        http_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8000, 8008, 8888, 4443, 3000, 5000, 9090)]
        if not http_ports:
            http_ports = [p for p in open_ports if p not in (21, 22, 25, 53, 110, 143, 445, 3306, 5432)]
        print(f"[*] Phase 2: HTTP Probing ({len(http_ports)} ports)...")
        for port in http_ports:
            info = probe_http(target, port, args.timeout + 3)
            if info:
                http_results.append(info)
                print(f"  [+] {info['url']} [{info['status']}] {info['title']} (Server: {info['server']})")
        if not http_results:
            print("  [!] No HTTP services found")
        print()

    # Phase 3: Subdomain Enumeration
    all_subs = []
    if not args.skip_subdomains and not target.replace(".", "").isdigit():
        print(f"[*] Phase 3: Subdomain Enumeration...")
        print(f"  [*] DNS brute-force ({len(SUBDOMAIN_PREFIXES)} prefixes)...")
        dns_subs = enum_subdomains(target, args.timeout)
        print(f"  [+] Found {len(dns_subs)} via DNS")

        print(f"  [*] Querying crt.sh certificate transparency...")
        crt_subs = crtsh_subdomains(target, args.timeout + 5)
        print(f"  [+] Found {len(crt_subs)} via crt.sh")

        seen = set()
        for s in dns_subs + crt_subs:
            if s["subdomain"] not in seen:
                seen.add(s["subdomain"])
                all_subs.append(s)

        if all_subs:
            print(f"\n  {'SUBDOMAIN':<40} {'IP(s)'}")
            print(f"  {'-'*40} {'-'*20}")
            for s in sorted(all_subs, key=lambda x: x["subdomain"]):
                ips = ", ".join(s["ips"]) if s["ips"] else "unresolved"
                print(f"  {s['subdomain']:<40} {ips}")
        print()

    elapsed = time.time() - start
    print(f"{'='*60}")
    print(f"[*] RECON SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Target:      {target} ({ip})")
    print(f"  Open ports:  {len(open_ports)} ({', '.join(str(p) for p in open_ports[:15])}{'...' if len(open_ports) > 15 else ''})")
    print(f"  HTTP svcs:   {len(http_results)}")
    print(f"  Subdomains:  {len(all_subs)}")
    print(f"  Scan time:   {elapsed:.1f}s")

    risky = [p for p in open_ports if p in (21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211, 27017)]
    if risky:
        svc_list = ", ".join(str(p) + "/" + PORT_SERVICES.get(p, "?") for p in risky)
        print(f"\n  [!] Risky services: {svc_list}")


if __name__ == "__main__":
    main()
