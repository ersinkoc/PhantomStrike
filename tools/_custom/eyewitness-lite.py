#!/usr/bin/env python3
"""Capture HTTP response info: title, server, headers, redirect chain, SSL info, page summary."""
import argparse
import re
import ssl
import socket
import sys
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via",
    "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-XSS-Protection", "Access-Control-Allow-Origin",
    "Set-Cookie", "WWW-Authenticate", "X-Runtime", "X-Request-Id",
]
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS protects against downgrade attacks",
    "Content-Security-Policy": "CSP prevents XSS and data injection",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-XSS-Protection": "Legacy XSS protection (deprecated)",
}
DEFAULT_CREDS_INDICATORS = [
    "login", "sign in", "log in", "username", "password", "auth", "admin",
    "dashboard", "default password", "enter your credentials",
]
TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Joomla": [r"com_content", r"/joomla", r"Joomla!"],
    "Drupal": [r"Drupal", r"drupal.js", r"/sites/default/"],
    "Django": [r"csrfmiddlewaretoken", r"__admin__"],
    "Laravel": [r"laravel_session", r"Laravel"],
    "ASP.NET": [r"__VIEWSTATE", r"asp\.net", r"\.aspx"],
    "React": [r"react", r"_react", r"reactroot"],
    "Angular": [r"ng-version", r"ng-app"],
    "nginx": [r"nginx"],
    "Apache": [r"Apache", r"apache"],
    "IIS": [r"Microsoft-IIS"],
}


def get_ssl_info(hostname, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["notBefore"] = cert.get("notBefore", "")
                    info["notAfter"] = cert.get("notAfter", "")
                    info["serialNumber"] = cert.get("serialNumber", "")
                    san = cert.get("subjectAltName", [])
                    info["altNames"] = [x[1] for x in san] if san else []
                info["version"] = ssock.version()
                info["cipher"] = ssock.cipher()
    except Exception as e:
        info["error"] = str(e)
    return info


def extract_title(html):
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return match.group(1).strip() if match else "(no title)"


def describe_page(html, status_code):
    parts = []
    title = extract_title(html)
    parts.append(f"Title: {title}")
    form_count = len(re.findall(r"<form", html, re.I))
    link_count = len(re.findall(r"<a\s+", html, re.I))
    img_count = len(re.findall(r"<img\s+", html, re.I))
    input_count = len(re.findall(r"<input", html, re.I))
    parts.append(f"Elements: {form_count} forms, {link_count} links, {img_count} images, {input_count} inputs")
    login_indicators = sum(1 for kw in DEFAULT_CREDS_INDICATORS if kw in html.lower())
    if login_indicators >= 2:
        parts.append("Appears to be a login/authentication page")
    if status_code == 403:
        parts.append("Access forbidden (403)")
    elif status_code == 401:
        parts.append("Authentication required (401)")
    elif status_code == 200 and len(html) < 500:
        parts.append("Minimal content / possibly a redirect landing or API endpoint")
    techs = []
    for tech, patterns in TECH_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, html, re.I):
                techs.append(tech)
                break
    if techs:
        parts.append(f"Technologies detected: {', '.join(techs)}")
    return parts


def scan_url(session, url, timeout):
    result = {"url": url}
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        result["status"] = resp.status_code
        result["final_url"] = resp.url
        result["content_length"] = len(resp.content)
        result["content_type"] = resp.headers.get("Content-Type", "unknown")
        result["title"] = extract_title(resp.text)
        result["redirects"] = []
        if resp.history:
            for r in resp.history:
                result["redirects"].append({"status": r.status_code, "url": r.url, "location": r.headers.get("Location", "")})
        result["headers"] = {}
        for h in INTERESTING_HEADERS:
            if h in resp.headers:
                result["headers"][h] = resp.headers[h]
        result["missing_security"] = []
        for h, desc in SECURITY_HEADERS.items():
            if h not in resp.headers:
                result["missing_security"].append(f"{h} ({desc})")
        result["page_summary"] = describe_page(resp.text, resp.status_code)
    except Exception as e:
        result["error"] = str(e)
    parsed = urlparse(url)
    if parsed.scheme == "https":
        result["ssl"] = get_ssl_info(parsed.hostname, parsed.port or 443)
    return result


def main():
    ap = argparse.ArgumentParser(description="EyeWitness-lite: HTTP response info capture")
    ap.add_argument("target", help="Target URL or file with URLs (one per line)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--no-ssl", action="store_true", help="Skip SSL certificate info")
    args = ap.parse_args()

    urls = []
    try:
        with open(args.target, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except (OSError, IOError):
        urls = [args.target]

    urls = [u if u.startswith("http") else f"https://{u}" for u in urls]
    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 EyeWitness-Lite"

    print(f"[*] EyeWitness-Lite - Scanning {len(urls)} URL(s)\n")

    for url in urls:
        print(f"{'='*60}")
        r = scan_url(session, url, args.timeout)
        if "error" in r:
            print(f"  [!] Error: {r['error']}\n")
            continue
        print(f"  URL:            {r['url']}")
        print(f"  Final URL:      {r['final_url']}")
        print(f"  Status:         {r['status']}")
        print(f"  Title:          {r['title']}")
        print(f"  Content-Type:   {r['content_type']}")
        print(f"  Content-Length: {r['content_length']} bytes")

        if r["redirects"]:
            print(f"\n  Redirect Chain:")
            for rd in r["redirects"]:
                print(f"    {rd['status']} -> {rd['location']}")

        if r["headers"]:
            print(f"\n  Notable Headers:")
            for k, v in r["headers"].items():
                print(f"    {k}: {v[:80]}")

        if r["missing_security"]:
            print(f"\n  Missing Security Headers:")
            for h in r["missing_security"]:
                print(f"    [!] {h}")

        if not args.no_ssl and "ssl" in r and "error" not in r["ssl"]:
            s = r["ssl"]
            print(f"\n  SSL/TLS Info:")
            print(f"    Protocol: {s.get('version', 'unknown')}")
            if s.get("cipher"):
                print(f"    Cipher:   {s['cipher'][0]} ({s['cipher'][2]} bits)")
            if s.get("subject"):
                print(f"    Subject:  {s['subject'].get('commonName', 'N/A')}")
            if s.get("issuer"):
                print(f"    Issuer:   {s['issuer'].get('organizationName', 'N/A')}")
            if s.get("notAfter"):
                print(f"    Expires:  {s['notAfter']}")
            if s.get("altNames"):
                print(f"    SANs:     {', '.join(s['altNames'][:5])}")

        print(f"\n  Page Summary:")
        for line in r["page_summary"]:
            print(f"    {line}")
        print()

    print(f"{'='*60}")
    print(f"[*] Scan complete: {len(urls)} URL(s) processed")


if __name__ == "__main__":
    main()
