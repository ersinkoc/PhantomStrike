#!/usr/bin/env python3
"""Service fingerprinting from banner grabbing: connect to ports, grab banners, identify services."""
import argparse
import asyncio
import re
import socket
import ssl
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVICE_PROBES = [
    {"name": "HTTP", "send": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
     "patterns": [(r"HTTP/[\d.]+ (\d+)", "HTTP"), (r"Server:\s*(.+)", "Server")]},
    {"name": "FTP", "send": b"", "patterns": [(r"^220[- ](.+)", "FTP")]},
    {"name": "SSH", "send": b"", "patterns": [(r"^SSH-([\d.]+)-(.+)", "SSH")]},
    {"name": "SMTP", "send": b"EHLO test\r\n", "patterns": [(r"^220[- ](.+)", "SMTP"), (r"^250[- ](.+)", "SMTP")]},
    {"name": "POP3", "send": b"", "patterns": [(r"^\+OK (.+)", "POP3")]},
    {"name": "IMAP", "send": b"", "patterns": [(r"^\* OK (.+)", "IMAP")]},
    {"name": "MySQL", "send": b"", "patterns": [(r"mysql|MariaDB", "MySQL")]},
    {"name": "Redis", "send": b"INFO\r\n", "patterns": [(r"redis_version:(.+)", "Redis")]},
    {"name": "MongoDB", "send": b"", "patterns": [(r"mongodb|ismaster", "MongoDB")]},
    {"name": "RDP", "send": b"", "patterns": [(r"\x03\x00", "RDP")]},
    {"name": "VNC", "send": b"", "patterns": [(r"^RFB ([\d.]+)", "VNC")]},
    {"name": "Telnet", "send": b"", "patterns": [(r"login:|Username:", "Telnet")]},
]

WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    6443: "Kubernetes", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9090: "Prometheus",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
             587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985,
             6379, 8000, 8080, 8443, 8888, 9090, 9200, 11211, 27017]


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


def grab_banner(host, port, timeout):
    """Grab service banner by sending appropriate probes."""
    banners = []
    for probe in SERVICE_PROBES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            send_data = probe["send"].replace(b"{host}", host.encode())
            if send_data:
                s.send(send_data)
            else:
                time.sleep(0.3)  # Wait for banner push
            data = s.recv(4096)
            s.close()
            decoded = data.decode("utf-8", errors="replace").strip()
            if decoded:
                for pattern, svc_name in probe["patterns"]:
                    m = re.search(pattern, decoded, re.I | re.M)
                    if m:
                        banners.append({"service": svc_name, "version": m.group(1).strip()[:60] if m.groups() else "",
                                        "raw": decoded[:120], "matched_probe": probe["name"]})
                if not banners:
                    banners.append({"service": "unknown", "version": "", "raw": decoded[:120], "matched_probe": probe["name"]})
                break
        except Exception:
            continue
    return banners


def grab_ssl_info(host, port, timeout):
    """Get SSL/TLS certificate info."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    return {"cn": subject.get("commonName", ""), "protocol": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "",
                            "expires": cert.get("notAfter", "")}
                return {"protocol": ssock.version(), "cipher": ssock.cipher()[0] if ssock.cipher() else ""}
    except Exception:
        return None


def fingerprint_http(host, port, timeout):
    """Fingerprint HTTP service."""
    scheme = "https" if port in (443, 8443, 4443) else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False, allow_redirects=True,
                         headers={"User-Agent": "PhantomStrike/1.0"})
        info = {"status": r.status_code, "server": r.headers.get("Server", ""),
                "powered_by": r.headers.get("X-Powered-By", ""), "content_type": r.headers.get("Content-Type", "")}
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        info["title"] = m.group(1).strip()[:60] if m else ""
        return info
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="ZoomEye-lite: Service fingerprinting via banner grabbing")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443,8080 or 1-1000)")
    ap.add_argument("-t", "--timeout", type=float, default=3, help="Connection timeout")
    ap.add_argument("--deep", action="store_true", help="Deep fingerprinting (slower, more probes)")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/").split(":")[0]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    if args.ports:
        ports = []
        for p in args.ports.split(","):
            if "-" in p:
                s, e = p.split("-")
                ports.extend(range(int(s), int(e) + 1))
            else:
                ports.append(int(p))
    else:
        ports = TOP_PORTS

    print(f"[*] ZoomEye-Lite: Service Fingerprinting")
    print(f"[*] Target: {host} ({ip})")
    print(f"[*] Scanning {len(ports)} ports\n")

    print("[*] Phase 1: Port Discovery...")
    results = asyncio.run(scan_ports(ip, ports, args.timeout, 100))
    open_ports = sorted([p for p, s in results if s])
    print(f"  [+] {len(open_ports)} open port(s) found\n")

    if not open_ports:
        print("[*] No open ports found. Scan complete.")
        return

    print("[*] Phase 2: Service Fingerprinting...\n")
    print(f"  {'PORT':<8} {'SERVICE':<15} {'VERSION/BANNER':<45} {'DETAILS'}")
    print(f"  {'-'*8} {'-'*15} {'-'*45} {'-'*25}")

    services = []
    for port in open_ports:
        svc_name = WELL_KNOWN.get(port, "unknown")
        banners = grab_banner(ip, port, args.timeout)
        ssl_info = None
        http_info = None

        if port in (443, 8443, 4443, 993, 995, 636, 465):
            ssl_info = grab_ssl_info(ip, port, args.timeout)

        if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 4443):
            http_info = fingerprint_http(ip, port, args.timeout)

        if banners:
            b = banners[0]
            version = b["version"][:45] if b["version"] else b["raw"][:45]
            svc = b["service"] if b["service"] != "unknown" else svc_name
            detail = ""
            if ssl_info:
                detail = f"TLS:{ssl_info.get('protocol','')} CN:{ssl_info.get('cn','')[:20]}"
            if http_info:
                detail = f"[{http_info['status']}] {http_info.get('title','')[:20]} Srv:{http_info.get('server','')[:15]}"
            print(f"  {port:<8} {svc:<15} {version:<45} {detail}")
            services.append({"port": port, "service": svc, "version": version, "ssl": ssl_info, "http": http_info})
        else:
            detail = ""
            if http_info:
                detail = f"[{http_info['status']}] {http_info.get('title','')[:25]} Srv:{http_info.get('server','')[:15]}"
            print(f"  {port:<8} {svc_name:<15} {'(no banner)':<45} {detail}")
            services.append({"port": port, "service": svc_name, "version": "", "ssl": ssl_info, "http": http_info})

    print(f"\n{'='*60}")
    print(f"[*] FINGERPRINT SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Host: {host} ({ip})")
    print(f"  Open ports: {len(open_ports)}")
    print(f"  Services identified: {sum(1 for s in services if s['service'] != 'unknown')}")
    http_svcs = [s for s in services if s.get("http")]
    if http_svcs:
        print(f"  Web services: {len(http_svcs)}")
    tls_svcs = [s for s in services if s.get("ssl")]
    if tls_svcs:
        print(f"  TLS services: {len(tls_svcs)}")


if __name__ == "__main__":
    main()
