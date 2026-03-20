#!/usr/bin/env python3
"""Find URL parameters from web archives."""
import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs
import requests


def fetch_parameterized_urls(domain, timeout, limit=0):
    """Fetch URLs with parameters from Wayback Machine."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    )
    if limit > 0:
        url += f"&limit={limit}"

    try:
        resp = requests.get(url, timeout=timeout, stream=True,
                            headers={"User-Agent": "PhantomStrike/1.0"})
        if resp.status_code != 200:
            print(f"[!] HTTP {resp.status_code}", file=sys.stderr)
            return []

        urls = set()
        for line in resp.iter_lines(decode_unicode=True):
            line = line.strip()
            if "?" in line and "=" in line:
                urls.add(line)
        return sorted(urls)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return []


def extract_params(urls):
    """Extract unique parameters from URLs."""
    params = {}
    for u in urls:
        try:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param not in params:
                    params[param] = {"count": 0, "example_urls": []}
                params[param]["count"] += 1
                if len(params[param]["example_urls"]) < 2:
                    params[param]["example_urls"].append(u)
        except Exception:
            continue
    return params


# Common parameters that may indicate vulnerabilities
INTERESTING_PARAMS = {
    "url", "redirect", "next", "return", "redir", "callback", "goto", "out",
    "file", "path", "page", "doc", "document", "template", "dir", "folder",
    "id", "uid", "user", "account", "username", "email",
    "q", "query", "search", "s", "keyword",
    "cmd", "exec", "command", "run",
    "debug", "test", "admin", "config",
    "token", "key", "api_key", "secret", "password",
    "lang", "language", "locale",
    "include", "require", "load", "read", "fetch",
}


def main():
    parser = argparse.ArgumentParser(description="Find URL parameters from web archives")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-l", "--limit", type=int, default=5000, help="Max URLs to fetch")
    parser.add_argument("--exclude-ext", default="css,js,png,jpg,gif,svg,woff,ttf,ico",
                        help="Exclude file extensions")
    args = parser.parse_args()

    domain = args.target.lower().strip()
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    exclude = set(args.exclude_ext.split(","))

    print(f"[*] Mining parameters for: {domain}")
    print(f"[*] Fetching URLs from Wayback Machine...\n")

    urls = fetch_parameterized_urls(domain, args.timeout, args.limit)

    # Filter out static files
    filtered = []
    for u in urls:
        parsed = urlparse(u)
        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
        if ext not in exclude:
            filtered.append(u)

    print(f"[+] Found {len(urls)} URLs with parameters ({len(filtered)} after filtering)\n")

    params = extract_params(filtered)

    # Find interesting parameters
    interesting = {k: v for k, v in params.items() if k.lower() in INTERESTING_PARAMS}

    if interesting:
        print(f"[!] Potentially interesting parameters ({len(interesting)}):")
        for name, info in sorted(interesting.items(), key=lambda x: -x[1]["count"]):
            print(f"    {name} (seen {info['count']}x)")
            for ex in info["example_urls"]:
                print(f"      -> {ex[:120]}")
        print()

    print(f"[+] All parameters ({len(params)}):")
    for name, info in sorted(params.items(), key=lambda x: -x[1]["count"]):
        marker = " [!]" if name.lower() in INTERESTING_PARAMS else ""
        print(f"    {name}: {info['count']}x{marker}")

    # Output parameterized URLs
    print(f"\n[+] Parameterized URLs ({len(filtered)}):")
    for u in filtered[:100]:
        print(f"    {u}")
    if len(filtered) > 100:
        print(f"    ... and {len(filtered) - 100} more")

    print(f"\n[*] Total: {len(params)} unique parameters, {len(filtered)} URLs")


if __name__ == "__main__":
    main()
