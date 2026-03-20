#!/usr/bin/env python3
"""OSINT data gatherer: DNS, WHOIS, subdomains, emails, social profiles from public sources."""
import argparse
import re
import socket
import struct
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOCIAL_PLATFORMS = {
    "GitHub": "https://github.com/{user}",
    "Twitter": "https://twitter.com/{user}",
    "LinkedIn": "https://www.linkedin.com/in/{user}",
    "Instagram": "https://www.instagram.com/{user}",
    "Facebook": "https://www.facebook.com/{user}",
    "Reddit": "https://www.reddit.com/user/{user}",
    "Medium": "https://medium.com/@{user}",
    "YouTube": "https://www.youtube.com/@{user}",
}


def dns_lookup(domain, timeout):
    records = {}
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        records["A"] = list(set(a[4][0] for a in answers))
    except socket.gaierror:
        records["A"] = []
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        records["AAAA"] = list(set(a[4][0] for a in answers))
    except (socket.gaierror, OSError):
        records["AAAA"] = []
    for prefix in ["", "_dmarc."]:
        try:
            full = f"{prefix}{domain}"
            ip = socket.gethostbyname(full)
        except socket.gaierror:
            pass
    return records


def whois_query(domain, timeout):
    tld = domain.split(".")[-1]
    whois_servers = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
                     "org": "whois.pir.org", "io": "whois.nic.io", "dev": "whois.nic.google",
                     "info": "whois.afilias.net", "co": "whois.nic.co"}
    server = whois_servers.get(tld, f"whois.nic.{tld}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


def parse_whois(raw):
    info = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
        "expiry_date": r"(?:Expir(?:y|ation)|Registry Expiry)\s*Date:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "registrant": r"Registrant\s*(?:Name|Organization):\s*(.+)",
        "status": r"(?:Domain )?Status:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.I)
        if matches:
            info[key] = matches if key in ("name_servers", "status") else matches[0].strip()
    return info


def crtsh_subdomains(domain, timeout):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
    except Exception:
        pass
    return sorted(subs)


def find_emails_web(domain, timeout):
    emails = set()
    search_urls = [
        f"https://www.google.com/search?q=%22{domain}%22+email&num=20",
        f"https://www.google.com/search?q=site%3A{domain}+%22%40{domain}%22&num=20",
    ]
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    try:
        r = session.get(f"https://{domain}", timeout=timeout, verify=False)
        found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), r.text)
        emails.update(e.lower() for e in found)
    except Exception:
        pass
    try:
        r = session.get(f"https://{domain}/contact", timeout=timeout, verify=False)
        found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), r.text)
        emails.update(e.lower() for e in found)
    except Exception:
        pass
    try:
        r = session.get(f"https://{domain}/about", timeout=timeout, verify=False)
        found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), r.text)
        emails.update(e.lower() for e in found)
    except Exception:
        pass
    common = ["info", "admin", "contact", "support", "hello", "sales", "security", "abuse", "postmaster", "webmaster"]
    for prefix in common:
        emails.add(f"{prefix}@{domain}")
    return sorted(emails)


def check_social(domain, timeout):
    results = []
    name = domain.split(".")[0]
    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 OSINT"
    for platform, url_template in SOCIAL_PLATFORMS.items():
        url = url_template.format(user=name)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and name.lower() in r.text.lower():
                results.append({"platform": platform, "url": url, "status": "found"})
            else:
                results.append({"platform": platform, "url": url, "status": "not found"})
        except Exception:
            results.append({"platform": platform, "url": url, "status": "error"})
    return results


def main():
    ap = argparse.ArgumentParser(description="Maltego-lite: OSINT data gatherer")
    ap.add_argument("target", help="Target domain (e.g., example.com)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--skip-social", action="store_true", help="Skip social profile checks")
    ap.add_argument("--skip-emails", action="store_true", help="Skip email harvesting")
    args = ap.parse_args()

    domain = args.target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    print(f"[*] Maltego-Lite: OSINT Data Gatherer")
    print(f"[*] Target: {domain}\n")

    # DNS
    print("[*] Phase 1: DNS Lookup...")
    dns = dns_lookup(domain, args.timeout)
    for rtype, records in dns.items():
        if records:
            print(f"  [{rtype}] {', '.join(records)}")
    print()

    # WHOIS
    print("[*] Phase 2: WHOIS Lookup...")
    raw_whois = whois_query(domain, args.timeout)
    whois_info = parse_whois(raw_whois)
    if whois_info:
        for key, val in whois_info.items():
            if isinstance(val, list):
                print(f"  {key}: {', '.join(v.strip() for v in val[:5])}")
            else:
                print(f"  {key}: {val}")
    else:
        print("  [!] No WHOIS data parsed")
    print()

    # Subdomains
    print("[*] Phase 3: Subdomain Enumeration (crt.sh)...")
    subs = crtsh_subdomains(domain, args.timeout)
    if subs:
        print(f"  [+] Found {len(subs)} subdomains:")
        for s in subs[:30]:
            try:
                ip = socket.gethostbyname(s)
                print(f"    {s:<40} {ip}")
            except socket.gaierror:
                print(f"    {s:<40} (unresolved)")
        if len(subs) > 30:
            print(f"    ... and {len(subs) - 30} more")
    else:
        print("  [!] No subdomains found")
    print()

    # Emails
    if not args.skip_emails:
        print("[*] Phase 4: Email Discovery...")
        emails = find_emails_web(domain, args.timeout)
        if emails:
            print(f"  [+] Found/guessed {len(emails)} emails:")
            for e in emails:
                print(f"    {e}")
        print()

    # Social
    if not args.skip_social:
        print("[*] Phase 5: Social Profile Discovery...")
        social = check_social(domain, args.timeout)
        for s in social:
            status = "[+]" if s["status"] == "found" else "[-]"
            print(f"  {status} {s['platform']}: {s['url']} ({s['status']})")
        print()

    print(f"{'='*60}")
    print(f"[*] OSINT Summary for {domain}")
    print(f"{'='*60}")
    print(f"  IPs:        {', '.join(dns.get('A', [])) or 'none'}")
    print(f"  Subdomains: {len(subs)}")
    if not args.skip_emails:
        print(f"  Emails:     {len(emails)}")
    if whois_info.get("registrar"):
        print(f"  Registrar:  {whois_info['registrar']}")
    if whois_info.get("creation_date"):
        print(f"  Created:    {whois_info['creation_date']}")


if __name__ == "__main__":
    main()
