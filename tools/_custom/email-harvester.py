#!/usr/bin/env python3
"""Harvest emails from multiple public sources."""
import argparse
import re
import sys
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

COMMON_PREFIXES = [
    "info", "admin", "support", "contact", "sales", "help",
    "webmaster", "postmaster", "abuse", "security", "hr",
    "billing", "noreply", "no-reply", "press", "media",
    "marketing", "dev", "ops", "team", "hello",
]

PAGES_TO_CHECK = [
    "/", "/contact", "/about", "/about-us", "/team",
    "/contact-us", "/imprint", "/impressum", "/privacy",
    "/legal", "/support",
]


def query_crtsh(domain, timeout):
    """Query crt.sh certificate transparency logs for emails."""
    emails = set()
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
                # Check for emails in other fields
                for field in ["name_value", "common_name"]:
                    val = entry.get(field, "")
                    found = EMAIL_REGEX.findall(val)
                    for e in found:
                        if domain in e.lower():
                            emails.add(e.lower())
    except Exception as e:
        print(f"  [!] crt.sh error: {e}", file=sys.stderr)
    return emails, subdomains


def scrape_page(session, url, domain, timeout):
    """Scrape a page for email addresses."""
    emails = set()
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomStrike/1.0)"})
        if resp.status_code == 200:
            # Decode HTML entities for mailto links
            text = resp.text
            # Find mailto: links
            mailto_emails = re.findall(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', text)
            for e in mailto_emails:
                if domain in e.lower():
                    emails.add(e.lower())
            # Find emails in text
            found = EMAIL_REGEX.findall(text)
            for e in found:
                if domain in e.lower():
                    # Filter out obvious false positives
                    if not any(e.endswith(ext) for ext in [".png", ".jpg", ".gif", ".css", ".js"]):
                        emails.add(e.lower())
    except Exception:
        pass
    return emails


def check_common_emails(domain):
    """Generate common email addresses to check."""
    return [f"{prefix}@{domain}" for prefix in COMMON_PREFIXES]


def query_pgp_keys(domain, timeout):
    """Query PGP key servers for emails."""
    emails = set()
    try:
        url = f"https://keyserver.ubuntu.com/pks/lookup?search={domain}&op=index&options=mr"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            found = EMAIL_REGEX.findall(resp.text)
            for e in found:
                if domain in e.lower():
                    emails.add(e.lower())
    except Exception:
        pass
    return emails


def query_hackertarget(domain, timeout):
    """Query HackerTarget for page content with emails."""
    emails = set()
    try:
        url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
            found = EMAIL_REGEX.findall(resp.text)
            for e in found:
                if domain in e.lower():
                    emails.add(e.lower())
    except Exception:
        pass
    return emails


def main():
    parser = argparse.ArgumentParser(description="Email harvester from public sources")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("--deep", action="store_true", help="Scrape target website pages")
    parser.add_argument("--common", action="store_true", help="Include common email guesses")
    args = parser.parse_args()

    domain = args.target.lower().strip()
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain
    domain = domain.rstrip("/")

    session = requests.Session()

    print(f"[*] Email Harvester - Target: {domain}")
    print(f"[*] Sources: crt.sh, HackerTarget, PGP keys, website scraping\n")

    all_emails = {}  # email -> set of sources

    def add_emails(emails, source):
        for e in emails:
            if e not in all_emails:
                all_emails[e] = set()
            all_emails[e].add(source)

    # Certificate Transparency
    print("[*] Querying crt.sh (Certificate Transparency)...")
    ct_emails, subdomains = query_crtsh(domain, args.timeout)
    add_emails(ct_emails, "crt.sh")
    print(f"    Found {len(ct_emails)} email(s), {len(subdomains)} subdomain(s)")

    # HackerTarget
    print("[*] Querying HackerTarget...")
    ht_emails = query_hackertarget(domain, args.timeout)
    add_emails(ht_emails, "hackertarget")
    print(f"    Found {len(ht_emails)} email(s)")

    # PGP Key Servers
    print("[*] Querying PGP key servers...")
    pgp_emails = query_pgp_keys(domain, args.timeout)
    add_emails(pgp_emails, "pgp_keyserver")
    print(f"    Found {len(pgp_emails)} email(s)")

    # Website scraping
    if args.deep:
        print("[*] Scraping target website pages...")
        base_url = f"https://{domain}"
        for page in PAGES_TO_CHECK:
            url = urljoin(base_url, page)
            page_emails = scrape_page(session, url, domain, args.timeout)
            add_emails(page_emails, f"website:{page}")
            if page_emails:
                print(f"    {page}: {len(page_emails)} email(s)")
    else:
        # At minimum, scrape the homepage
        print("[*] Scraping homepage...")
        base_url = f"https://{domain}"
        page_emails = scrape_page(session, base_url, domain, args.timeout)
        add_emails(page_emails, "website:/")
        print(f"    Found {len(page_emails)} email(s)")

    # Common email guesses
    if args.common:
        print("[*] Generating common email patterns...")
        common = check_common_emails(domain)
        add_emails(common, "common_pattern")
        print(f"    Generated {len(common)} common addresses")

    # Output results
    print(f"\n{'='*60}")
    print(f"[*] Results for {domain}")
    print(f"{'='*60}")

    if all_emails:
        print(f"\n[+] Emails Found ({len(all_emails)}):\n")
        print(f"  {'EMAIL':<40} {'SOURCES'}")
        print(f"  {'-'*40} {'-'*30}")
        for email in sorted(all_emails.keys()):
            sources = ", ".join(sorted(all_emails[email]))
            print(f"  {email:<40} {sources}")
    else:
        print("\n[-] No emails found")

    if subdomains:
        print(f"\n[+] Related Subdomains ({len(subdomains)}):")
        for sub in sorted(subdomains)[:20]:
            print(f"    {sub}")
        if len(subdomains) > 20:
            print(f"    ... and {len(subdomains) - 20} more")

    confirmed = sum(1 for v in all_emails.values() if len(v) > 1 or "common_pattern" not in v)
    print(f"\n[*] Total: {len(all_emails)} email(s), {confirmed} confirmed from sources")


if __name__ == "__main__":
    main()
