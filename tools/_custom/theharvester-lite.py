#!/usr/bin/env python3
"""Lightweight email/subdomain harvester using public sources."""
import argparse
import json
import re
import sys
import requests

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SUBDOMAIN_RE = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+')


def query_crtsh(domain, timeout):
    """Query crt.sh for certificate transparency subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub.lstrip("*."))
    except Exception as e:
        print(f"  [!] crt.sh error: {e}", file=sys.stderr)
    return subdomains


def query_hackertarget(domain, timeout):
    """Query HackerTarget for subdomains."""
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception as e:
        print(f"  [!] HackerTarget error: {e}", file=sys.stderr)
    return subdomains


def query_rapiddns(domain, timeout):
    """Query RapidDNS for subdomains."""
    subdomains = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = requests.get(url, timeout=timeout, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            matches = re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>',
                                 resp.text)
            for m in matches:
                subdomains.add(m.lower())
    except Exception as e:
        print(f"  [!] RapidDNS error: {e}", file=sys.stderr)
    return subdomains


def search_emails(domain, timeout):
    """Search for emails using public sources."""
    emails = set()
    try:
        url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            found = EMAIL_RE.findall(resp.text)
            for email in found:
                if domain in email.lower():
                    emails.add(email.lower())
    except Exception:
        pass
    return emails


def main():
    parser = argparse.ArgumentParser(description="Lightweight email/subdomain harvester")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("-s", "--sources", default="all",
                        help="Sources: all, crtsh, hackertarget, rapiddns")
    args = parser.parse_args()

    domain = args.target.lower().strip()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    all_subdomains = set()
    sources = args.sources.split(",") if args.sources != "all" else ["crtsh", "hackertarget", "rapiddns"]

    print(f"[*] Harvesting subdomains and emails for: {domain}")
    print(f"[*] Sources: {', '.join(sources)}\n")

    if "crtsh" in sources:
        print("[*] Querying crt.sh (Certificate Transparency)...")
        subs = query_crtsh(domain, args.timeout)
        print(f"    Found {len(subs)} subdomains")
        all_subdomains.update(subs)

    if "hackertarget" in sources:
        print("[*] Querying HackerTarget...")
        subs = query_hackertarget(domain, args.timeout)
        print(f"    Found {len(subs)} subdomains")
        all_subdomains.update(subs)

    if "rapiddns" in sources:
        print("[*] Querying RapidDNS...")
        subs = query_rapiddns(domain, args.timeout)
        print(f"    Found {len(subs)} subdomains")
        all_subdomains.update(subs)

    print("\n[*] Searching for emails...")
    emails = search_emails(domain, args.timeout)

    print(f"\n{'='*60}")
    print(f"[*] Results for {domain}")
    print(f"{'='*60}")
    print(f"\n[+] Subdomains ({len(all_subdomains)}):")
    for sub in sorted(all_subdomains):
        print(f"    {sub}")

    if emails:
        print(f"\n[+] Emails ({len(emails)}):")
        for email in sorted(emails):
            print(f"    {email}")
    else:
        print("\n[-] No emails found")

    print(f"\n[*] Total: {len(all_subdomains)} subdomains, {len(emails)} emails")


if __name__ == "__main__":
    main()
