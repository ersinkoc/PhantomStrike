#!/usr/bin/env python3
"""Internet asset search: query public APIs for exposed services (Shodan-style using free sources)."""
import argparse
import json
import re
import socket
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CENSYS_SEARCH = "https://search.censys.io/api"
COMMON_PORTS_HTTP = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090]


def search_crtsh(domain, timeout):
    """Search certificate transparency logs."""
    results = []
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            seen = set()
            for entry in data[:100]:
                name = entry.get("name_value", "").strip().lower()
                issuer = entry.get("issuer_name", "")
                not_after = entry.get("not_after", "")
                if name not in seen:
                    seen.add(name)
                    results.append({"name": name, "issuer": issuer, "expires": not_after})
    except Exception:
        pass
    return results


def search_hackertarget(target, timeout):
    """Use HackerTarget free API for host search."""
    results = {}
    endpoints = {
        "hostsearch": f"https://api.hackertarget.com/hostsearch/?q={target}",
        "dnslookup": f"https://api.hackertarget.com/dnslookup/?q={target}",
        "reversedns": f"https://api.hackertarget.com/reversedns/?q={target}",
        "httpheaders": f"https://api.hackertarget.com/httpheaders/?q={target}",
    }
    for name, url in endpoints.items():
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200 and "API count exceeded" not in r.text and "error" not in r.text.lower()[:20]:
                results[name] = r.text.strip()
        except Exception:
            pass
    return results


def search_urlscan(domain, timeout):
    """Search urlscan.io for indexed results."""
    results = []
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            for entry in data.get("results", []):
                page = entry.get("page", {})
                results.append({
                    "url": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "server": page.get("server", ""),
                    "title": entry.get("task", {}).get("title", "")[:60],
                    "country": page.get("country", ""),
                })
    except Exception:
        pass
    return results


def search_securitytrails(domain, timeout):
    """Check SecurityTrails for subdomains (free tier)."""
    results = []
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                         headers={"Accept": "application/json"}, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                results.append(f"{sub}.{domain}")
    except Exception:
        pass
    return results


def probe_service(ip, port, timeout):
    """Probe a specific port and grab banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8000, 8888, 3000, 5000, 9090):
            s.send(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
        elif port in (443, 8443):
            s.close()
            return {"port": port, "status": "open", "banner": "(TLS - use HTTPS)"}
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()[:120]
        s.close()
        return {"port": port, "status": "open", "banner": banner}
    except Exception:
        return None


def search_internetdb(ip, timeout):
    """Query Shodan InternetDB (free, no API key)."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description="FOFA-lite: Internet asset search using free public APIs")
    ap.add_argument("target", help="Domain, IP, or search query")
    ap.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout")
    ap.add_argument("--probe", action="store_true", help="Probe discovered IPs for open services")
    args = ap.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    print(f"[*] FOFA-Lite: Internet Asset Discovery")
    print(f"[*] Target: {target}\n")

    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        pass

    # Shodan InternetDB (works for IPs)
    ip = target if is_ip else None
    if not is_ip:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            pass

    if ip:
        print(f"[*] Querying Shodan InternetDB for {ip}...")
        idb = search_internetdb(ip, args.timeout)
        if idb:
            print(f"  Ports:    {', '.join(str(p) for p in idb.get('ports', []))}")
            print(f"  CPEs:     {', '.join(idb.get('cpes', [])[:5])}")
            print(f"  Vulns:    {', '.join(idb.get('vulns', [])[:10])}")
            print(f"  Hostnames: {', '.join(idb.get('hostnames', [])[:5])}")
            print(f"  Tags:     {', '.join(idb.get('tags', []))}")
        else:
            print("  [!] No data in InternetDB")
        print()

    if not is_ip:
        # Certificate transparency
        print(f"[*] Searching certificate transparency (crt.sh)...")
        certs = search_crtsh(target, args.timeout)
        if certs:
            print(f"  [+] Found {len(certs)} certificate entries:")
            for c in certs[:15]:
                print(f"    {c['name']:<40} expires: {c['expires'][:10]}")
            if len(certs) > 15:
                print(f"    ... and {len(certs) - 15} more")
        print()

        # HackerTarget
        print(f"[*] Querying HackerTarget API...")
        ht = search_hackertarget(target, args.timeout)
        if ht.get("hostsearch"):
            hosts = ht["hostsearch"].split("\n")
            print(f"  [+] Host search results ({len(hosts)}):")
            for h in hosts[:15]:
                print(f"    {h}")
        if ht.get("httpheaders"):
            print(f"\n  HTTP Headers:")
            for line in ht["httpheaders"].split("\n")[:10]:
                print(f"    {line}")
        print()

        # URLScan
        print(f"[*] Searching urlscan.io...")
        uscan = search_urlscan(target, args.timeout)
        if uscan:
            print(f"  [+] Found {len(uscan)} indexed results:")
            for u in uscan[:10]:
                print(f"    {u['url'][:60]:<62} [{u['ip']}] {u['server']}")
        print()

    # Probe discovered services
    if args.probe and ip:
        print(f"[*] Probing services on {ip}...")
        ports_to_probe = COMMON_PORTS_HTTP
        if idb and idb.get("ports"):
            ports_to_probe = list(set(ports_to_probe + idb["ports"]))
        for port in sorted(ports_to_probe):
            result = probe_service(ip, port, min(args.timeout, 3))
            if result:
                print(f"  [{result['port']}] {result['status']} - {result['banner'][:60]}")
        print()

    print(f"{'='*60}")
    print(f"[*] Asset search complete for {target}")
    if ip:
        print(f"[*] Primary IP: {ip}")


if __name__ == "__main__":
    main()
