#!/usr/bin/env python3
"""Fetch URLs from the Wayback Machine (web.archive.org CDX API)."""
import argparse
import sys
import requests


def fetch_wayback_urls(domain, timeout, include_subs=True, limit=0):
    """Query the Wayback Machine CDX API for archived URLs."""
    prefix = f"*.{domain}" if include_subs else domain
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={prefix}/*&output=text&fl=original&collapse=urlkey"
    )
    if limit > 0:
        url += f"&limit={limit}"

    print(f"[*] Querying Wayback Machine for: {prefix}")
    print(f"[*] API URL: {url}\n")

    try:
        resp = requests.get(url, timeout=timeout, stream=True,
                            headers={"User-Agent": "PhantomStrike/1.0"})
        if resp.status_code != 200:
            print(f"[!] HTTP {resp.status_code} from Wayback Machine", file=sys.stderr)
            return []

        urls = set()
        for line in resp.iter_lines(decode_unicode=True):
            line = line.strip()
            if line:
                urls.add(line)

        return sorted(urls)

    except requests.exceptions.Timeout:
        print("[!] Request timed out", file=sys.stderr)
        return []
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        return []


def main():
    parser = argparse.ArgumentParser(description="Fetch URLs from Wayback Machine")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-l", "--limit", type=int, default=0, help="Max URLs to fetch (0=all)")
    parser.add_argument("--no-subs", action="store_true", help="Exclude subdomains")
    parser.add_argument("-f", "--filter", help="Filter URLs containing this string")
    args = parser.parse_args()

    domain = args.target.lower().strip()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain

    urls = fetch_wayback_urls(domain, args.timeout, not args.no_subs, args.limit)

    if args.filter:
        urls = [u for u in urls if args.filter in u]

    if urls:
        print(f"[+] Found {len(urls)} unique URLs:\n")
        for url in urls:
            print(url)
    else:
        print("[-] No URLs found")

    print(f"\n[*] Total: {len(urls)} URLs")


if __name__ == "__main__":
    main()
