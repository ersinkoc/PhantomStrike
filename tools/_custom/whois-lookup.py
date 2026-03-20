#!/usr/bin/env python3
"""WHOIS lookup and IP geolocation tool."""
import argparse
import json
import re
import socket
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "ru": "whois.tcinet.ru",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "nl": "whois.sidn.nl",
    "be": "whois.dns.be",
    "cloud": "whois.nic.cloud",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
}


def whois_query(domain, server=None, timeout=10):
    """Perform a raw WHOIS query."""
    if server is None:
        tld = domain.rsplit(".", 1)[-1].lower()
        server = WHOIS_SERVERS.get(tld, "whois.iana.org")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.send((domain + "\r\n").encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"


def parse_whois(raw):
    """Parse WHOIS response into structured data."""
    info = {}
    field_map = {
        "domain name": "domain",
        "registrar": "registrar",
        "registrar url": "registrar_url",
        "creation date": "created",
        "updated date": "updated",
        "registry expiry date": "expires",
        "expir": "expires",
        "name server": "nameservers",
        "registrant organization": "registrant_org",
        "registrant country": "registrant_country",
        "registrant state": "registrant_state",
        "registrant name": "registrant_name",
        "admin email": "admin_email",
        "tech email": "tech_email",
        "dnssec": "dnssec",
        "status": "status",
    }

    nameservers = []
    statuses = []

    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            for pattern, field in field_map.items():
                if pattern in key:
                    if field == "nameservers":
                        nameservers.append(value.lower())
                    elif field == "status":
                        statuses.append(value)
                    elif field not in info:
                        info[field] = value
                    break

    if nameservers:
        info["nameservers"] = nameservers
    if statuses:
        info["status"] = statuses

    return info


def resolve_ip(domain, timeout=5):
    """Resolve domain to IP addresses."""
    ips = []
    try:
        results = socket.getaddrinfo(domain, None)
        seen = set()
        for family, kind, proto, canonname, sockaddr in results:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def ip_geolocation(ip, timeout=10):
    """Get IP geolocation info using ip-api.com."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,"
                            f"regionName,city,zip,lat,lon,isp,org,as,asname",
                            timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="WHOIS lookup and IP geolocation")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Query timeout")
    parser.add_argument("--raw", action="store_true", help="Show raw WHOIS response")
    args = parser.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").rstrip("/")

    # Determine if target is IP or domain
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        pass

    print(f"[*] WHOIS Lookup - Target: {target}\n")

    if not is_ip:
        # Domain WHOIS
        print("=== Domain WHOIS ===\n")
        raw = whois_query(target, timeout=args.timeout)

        if args.raw:
            print(raw)
            print()

        # Check if we need to follow a referral
        referral_match = re.search(r'Registrar WHOIS Server:\s*(\S+)', raw)
        if referral_match:
            referral_server = referral_match.group(1)
            detailed_raw = whois_query(target, server=referral_server, timeout=args.timeout)
            if "domain name" in detailed_raw.lower() or "registrar" in detailed_raw.lower():
                raw = detailed_raw

        info = parse_whois(raw)

        fields = [
            ("Domain", info.get("domain", target)),
            ("Registrar", info.get("registrar", "N/A")),
            ("Registrar URL", info.get("registrar_url", "N/A")),
            ("Created", info.get("created", "N/A")),
            ("Updated", info.get("updated", "N/A")),
            ("Expires", info.get("expires", "N/A")),
            ("Registrant Org", info.get("registrant_org", "N/A")),
            ("Registrant Country", info.get("registrant_country", "N/A")),
            ("DNSSEC", info.get("dnssec", "N/A")),
        ]

        for label, value in fields:
            print(f"  {label:<20} {value}")

        if info.get("nameservers"):
            print(f"\n  Nameservers:")
            for ns in info["nameservers"]:
                print(f"    {ns}")

        if info.get("status"):
            print(f"\n  Status:")
            for s in info["status"][:5]:
                print(f"    {s}")

        # Security observations
        print(f"\n=== Security Notes ===\n")
        if info.get("dnssec", "").lower() in ("unsigned", "no"):
            print(f"  [MEDIUM] DNSSEC is not enabled")
        elif info.get("dnssec", "").lower() in ("signeddelegation", "yes"):
            print(f"  [OK] DNSSEC is enabled")

        registrant = info.get("registrant_org", "")
        if any(w in registrant.lower() for w in ["privacy", "proxy", "redacted", "whoisguard"]):
            print(f"  [INFO] Domain uses privacy/proxy registration")

        # Resolve IPs
        print(f"\n=== IP Resolution ===\n")
        ips = resolve_ip(target, args.timeout)
        if ips:
            for ip in ips:
                print(f"  {ip}")
                geo = ip_geolocation(ip, args.timeout)
                if geo:
                    print(f"    Country:  {geo.get('country', 'N/A')}")
                    print(f"    City:     {geo.get('city', 'N/A')}, {geo.get('regionName', 'N/A')}")
                    print(f"    ISP:      {geo.get('isp', 'N/A')}")
                    print(f"    Org:      {geo.get('org', 'N/A')}")
                    print(f"    ASN:      {geo.get('as', 'N/A')}")
                print()
        else:
            print(f"  [!] Could not resolve domain")

    else:
        # IP WHOIS
        print("=== IP Information ===\n")
        print(f"  IP: {target}")
        geo = ip_geolocation(target, args.timeout)
        if geo:
            print(f"  Country:  {geo.get('country', 'N/A')}")
            print(f"  Region:   {geo.get('regionName', 'N/A')}")
            print(f"  City:     {geo.get('city', 'N/A')}")
            print(f"  ISP:      {geo.get('isp', 'N/A')}")
            print(f"  Org:      {geo.get('org', 'N/A')}")
            print(f"  ASN:      {geo.get('as', 'N/A')}")
            print(f"  AS Name:  {geo.get('asname', 'N/A')}")
            if geo.get("lat") and geo.get("lon"):
                print(f"  Location: {geo['lat']}, {geo['lon']}")
        else:
            print(f"  [!] Could not retrieve IP information")

        # WHOIS for IP
        print(f"\n=== IP WHOIS ===\n")
        raw = whois_query(target, server="whois.arin.net", timeout=args.timeout)
        if args.raw:
            print(raw)
        else:
            for line in raw.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("%"):
                    print(f"  {line}")

    print(f"\n{'='*50}")
    print(f"[*] WHOIS lookup complete for {target}")


if __name__ == "__main__":
    main()
