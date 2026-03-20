#!/usr/bin/env python3
"""Check for subdomain takeover vulnerabilities."""
import argparse
import socket
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CNAME fingerprints for takeover-vulnerable services
TAKEOVER_FINGERPRINTS = {
    "github.io": {
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "response_fingerprint": "There isn't a GitHub Pages site here",
        "severity": "HIGH",
    },
    "herokuapp.com": {
        "service": "Heroku",
        "cname": ["herokuapp.com", "herokussl.com"],
        "response_fingerprint": "No such app",
        "severity": "HIGH",
    },
    "s3.amazonaws.com": {
        "service": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website"],
        "response_fingerprint": "NoSuchBucket",
        "severity": "HIGH",
    },
    "azurewebsites.net": {
        "service": "Azure",
        "cname": ["azurewebsites.net", "cloudapp.net", "azure-api.net", "azurefd.net",
                   "blob.core.windows.net", "trafficmanager.net"],
        "response_fingerprint": "404 Web Site not found",
        "severity": "HIGH",
    },
    "shopify.com": {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "response_fingerprint": "Sorry, this shop is currently unavailable",
        "severity": "MEDIUM",
    },
    "fastly.net": {
        "service": "Fastly",
        "cname": ["fastly.net"],
        "response_fingerprint": "Fastly error: unknown domain",
        "severity": "HIGH",
    },
    "ghost.io": {
        "service": "Ghost",
        "cname": ["ghost.io"],
        "response_fingerprint": "The thing you were looking for is no longer here",
        "severity": "MEDIUM",
    },
    "pantheon.io": {
        "service": "Pantheon",
        "cname": ["pantheonsite.io"],
        "response_fingerprint": "The gods are wise",
        "severity": "MEDIUM",
    },
    "surge.sh": {
        "service": "Surge.sh",
        "cname": ["surge.sh"],
        "response_fingerprint": "project not found",
        "severity": "MEDIUM",
    },
    "zendesk.com": {
        "service": "Zendesk",
        "cname": ["zendesk.com"],
        "response_fingerprint": "Help Center Closed",
        "severity": "MEDIUM",
    },
    "readme.io": {
        "service": "Readme.io",
        "cname": ["readme.io"],
        "response_fingerprint": "Project doesnt exist",
        "severity": "MEDIUM",
    },
    "bitbucket.io": {
        "service": "Bitbucket",
        "cname": ["bitbucket.io"],
        "response_fingerprint": "Repository not found",
        "severity": "HIGH",
    },
    "wordpress.com": {
        "service": "WordPress.com",
        "cname": ["wordpress.com"],
        "response_fingerprint": "Do you want to register",
        "severity": "MEDIUM",
    },
    "fly.dev": {
        "service": "Fly.io",
        "cname": ["fly.dev", "edgeapp.net"],
        "response_fingerprint": "404",
        "severity": "MEDIUM",
    },
}


def resolve_cname(domain):
    """Resolve CNAME records for a domain using socket."""
    cnames = []
    try:
        result = socket.getaddrinfo(domain, None)
        # Try to get the canonical name
        for family, kind, proto, canonname, sockaddr in result:
            if canonname and canonname != domain:
                cnames.append(canonname)
    except socket.gaierror:
        return cnames, False

    # Also try direct resolution
    try:
        host = socket.gethostbyname_ex(domain)
        if host[0] and host[0] != domain:
            cnames.append(host[0])
    except socket.gaierror:
        pass
    except socket.herror:
        pass

    return list(set(cnames)), True


def check_http_fingerprint(subdomain, fingerprint_text, timeout):
    """Check HTTP response for takeover fingerprints."""
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{subdomain}", timeout=timeout, verify=False,
                                allow_redirects=True, headers={"User-Agent": "PhantomStrike/1.0"})
            if fingerprint_text.lower() in resp.text.lower():
                return True, resp.status_code
        except Exception:
            continue
    return False, None


def check_dns_resolves(domain):
    """Check if a domain resolves to any IP."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def check_subdomain(subdomain, timeout):
    """Check a single subdomain for takeover vulnerability."""
    findings = []

    # Resolve CNAME
    cnames, resolves = resolve_cname(subdomain)

    if not resolves:
        # NXDOMAIN - if there was a CNAME, this could be vulnerable
        findings.append({
            "subdomain": subdomain,
            "status": "NXDOMAIN",
            "service": "Unknown",
            "severity": "MEDIUM",
            "confidence": "low",
            "detail": "Domain does not resolve - check if CNAME exists via DNS tools",
        })
        return findings

    # Check CNAME against known vulnerable services
    for cname in cnames:
        for service_key, service_info in TAKEOVER_FINGERPRINTS.items():
            for pattern in service_info["cname"]:
                if pattern.lower() in cname.lower():
                    # Check HTTP fingerprint
                    vuln, status_code = check_http_fingerprint(
                        subdomain, service_info["response_fingerprint"], timeout)
                    if vuln:
                        findings.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service_info["service"],
                            "severity": service_info["severity"],
                            "confidence": "high",
                            "status_code": status_code,
                            "detail": f"CNAME points to {cname}, response matches takeover fingerprint",
                        })
                    else:
                        findings.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service_info["service"],
                            "severity": "LOW",
                            "confidence": "low",
                            "detail": f"CNAME points to {pattern} service but fingerprint not matched",
                        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover checker")
    parser.add_argument("target", help="Target domain or file with subdomains (one per line)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--stdin", action="store_true", help="Read subdomains from stdin")
    args = parser.parse_args()

    subdomains = []

    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if line:
                subdomains.append(line)
    else:
        # Check if target is a file
        try:
            with open(args.target, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            # Treat as domain - generate common subdomain prefixes
            domain = args.target.replace("https://", "").replace("http://", "").rstrip("/")
            prefixes = [
                "www", "mail", "blog", "dev", "staging", "test", "api", "admin",
                "app", "beta", "demo", "docs", "help", "shop", "store", "support",
                "cdn", "assets", "media", "static", "img", "portal", "vpn", "m",
                "forum", "wiki", "git", "ci", "jenkins", "status", "monitor",
            ]
            subdomains = [f"{p}.{domain}" for p in prefixes]
            subdomains.insert(0, domain)

    print(f"[*] Subdomain Takeover Checker")
    print(f"[*] Checking {len(subdomains)} subdomain(s)")
    print(f"[*] Known vulnerable services: {len(TAKEOVER_FINGERPRINTS)}\n")

    all_findings = []

    print("=== Scanning ===\n")
    for sub in subdomains:
        sub = sub.strip().lower()
        if not sub:
            continue
        findings = check_subdomain(sub, args.timeout)
        if findings:
            for f in findings:
                sev = f["severity"]
                conf = f["confidence"]
                print(f"  [{sev}] {f['subdomain']}")
                print(f"         Service: {f.get('service', 'N/A')}")
                if f.get("cname"):
                    print(f"         CNAME: {f['cname']}")
                print(f"         Confidence: {conf}")
                print(f"         Detail: {f['detail']}")
                print()
            all_findings.extend(findings)

    print(f"{'='*50}")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH" and f["confidence"] == "high")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")
    print(f"[*] Results: {len(all_findings)} finding(s)")
    print(f"[*] Confirmed vulnerable: {high}")
    print(f"[*] Possible: {med}, Informational: {low}")
    if high > 0:
        print(f"[!] CRITICAL: {high} subdomain(s) likely vulnerable to takeover!")


if __name__ == "__main__":
    main()
