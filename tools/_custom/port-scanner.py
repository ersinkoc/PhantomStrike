#!/usr/bin/env python3
"""Fast async TCP port scanner."""
import argparse
import asyncio
import socket
import sys
import time

# Well-known port to service mapping
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission", 631: "ipp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1434: "mssql-m", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl", 3306: "mysql", 3389: "rdp", 3690: "svn",
    4443: "https-alt", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 6443: "kubernetes", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb",
}

# Top 100 most common ports
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
    2049, 2082, 2083, 2086, 2087, 3306, 3389, 3690, 4443, 5432, 5900,
    5985, 5986, 6379, 6443, 8000, 8008, 8080, 8443, 8888, 9090, 9200,
    9300, 11211, 27017, 27018,
]

# Top 1000 nmap ports (subset - most commonly open)
TOP_1000_PORTS = sorted(set(TOP_100_PORTS + list(range(1, 1024)) + [
    1025, 1026, 1027, 1028, 1029, 1030, 1110, 1194, 1214, 1241, 1311,
    1337, 1433, 1434, 1512, 1524, 1720, 1723, 1755, 1812, 1813, 1900,
    2000, 2049, 2082, 2083, 2086, 2087, 2100, 2222, 2375, 2376, 2483,
    2484, 3000, 3128, 3268, 3269, 3306, 3389, 3690, 4000, 4443, 4444,
    4567, 4711, 4848, 5000, 5001, 5060, 5432, 5555, 5800, 5900, 5901,
    5984, 5985, 5986, 6000, 6001, 6379, 6443, 6666, 6667, 7000, 7001,
    7002, 7070, 7443, 7474, 7777, 8000, 8008, 8009, 8042, 8080, 8081,
    8082, 8088, 8443, 8880, 8888, 9000, 9042, 9043, 9060, 9080, 9090,
    9091, 9100, 9200, 9300, 9418, 9999, 10000, 10443, 11211, 15672,
    27017, 27018, 28017, 50000, 50070,
]))


async def scan_port(host, port, timeout):
    """Scan a single port using asyncio."""
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
    except Exception:
        return port, False


async def scan_ports(host, ports, timeout, concurrency):
    """Scan multiple ports with concurrency control."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def bounded_scan(port):
        async with semaphore:
            return await scan_port(host, port, timeout)

    tasks = [bounded_scan(port) for port in ports]
    results = await asyncio.gather(*tasks)
    return results


def grab_banner(host, port, timeout):
    """Try to grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def parse_ports(port_str):
    """Parse port specification (e.g., '80,443,8000-8100')."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(description="Fast async TCP port scanner")
    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument("-p", "--ports", help="Port specification (e.g., 80,443,8000-8100)")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Connection timeout per port")
    parser.add_argument("--threads", type=int, default=200, help="Concurrent connections")
    parser.add_argument("--top100", action="store_true", help="Scan top 100 ports only")
    parser.add_argument("--banner", action="store_true", help="Attempt banner grabbing on open ports")
    args = parser.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    if ":" in host:
        host = host.split(":")[0]

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve hostname: {host}", file=sys.stderr)
        sys.exit(1)

    # Determine ports to scan
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top100:
        ports = TOP_100_PORTS
    else:
        ports = TOP_1000_PORTS

    print(f"[*] Port Scanner - Target: {host} ({ip})")
    print(f"[*] Scanning {len(ports)} ports (timeout: {args.timeout}s, threads: {args.threads})")

    start_time = time.time()

    # Run async scan
    results = asyncio.run(scan_ports(ip, ports, args.timeout, args.threads))

    elapsed = time.time() - start_time
    open_ports = [(port, status) for port, status in results if status]

    print(f"[*] Scan completed in {elapsed:.2f}s\n")

    if open_ports:
        print("=== Open Ports ===\n")
        print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'BANNER'}")
        print(f"  {'-'*10} {'-'*10} {'-'*20} {'-'*30}")
        for port, _ in sorted(open_ports):
            service = WELL_KNOWN_PORTS.get(port, "unknown")
            banner = ""
            if args.banner:
                banner = grab_banner(ip, port, args.timeout)
            print(f"  {port:<10} {'open':<10} {service:<20} {banner}")
    else:
        print("[*] No open ports found")

    print(f"\n{'='*50}")
    print(f"[*] Host: {host} ({ip})")
    print(f"[*] Open ports: {len(open_ports)}/{len(ports)} scanned")
    print(f"[*] Scan time: {elapsed:.2f}s ({len(ports)/elapsed:.0f} ports/sec)")

    # Flag interesting findings
    if open_ports:
        risky = [p for p, _ in open_ports if p in (21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211, 27017)]
        if risky:
            print(f"[!] Potentially risky services exposed: {', '.join(str(p) for p in risky)}")


if __name__ == "__main__":
    main()
