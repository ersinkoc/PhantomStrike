#!/usr/bin/env python3
"""Detect CDN/WAF and attempt to find the real origin IP."""
import argparse
import re
import socket
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CDN_HEADER_SIGNATURES = {
    "cf-ray": {"name": "Cloudflare", "type": "cdn/waf"},
    "cf-cache-status": {"name": "Cloudflare", "type": "cdn"},
    "x-sucuri-id": {"name": "Sucuri", "type": "waf"},
    "x-sucuri-cache": {"name": "Sucuri", "type": "waf"},
    "server: cloudflare": {"name": "Cloudflare", "type": "cdn/waf"},
    "x-cdn": {"name": "CDN (generic)", "type": "cdn"},
    "x-cache": {"name": "CDN Cache", "type": "cdn"},
    "x-fastly-request-id": {"name": "Fastly", "type": "cdn"},
    "x-served-by": {"name": "Fastly/Varnish", "type": "cdn"},
    "x-amz-cf-id": {"name": "AWS CloudFront", "type": "cdn"},
    "x-amz-cf-pop": {"name": "AWS CloudFront", "type": "cdn"},
    "x-azure-ref": {"name": "Azure CDN", "type": "cdn"},
    "x-ms-ref": {"name": "Azure Front Door", "type": "cdn"},
    "x-hw": {"name": "Huawei CDN", "type": "cdn"},
    "x-edge-ip": {"name": "CDN Edge", "type": "cdn"},
    "x-akamai": {"name": "Akamai", "type": "cdn"},
    "x-iinfo": {"name": "Incapsula/Imperva", "type": "waf"},
    "x-cdn-geo": {"name": "KeyCDN", "type": "cdn"},
    "server: akamaighost": {"name": "Akamai", "type": "cdn"},
    "server: yunjiasu": {"name": "Baidu CDN", "type": "cdn"},
    "x-powered-by-anquanbao": {"name": "Anquanbao WAF", "type": "waf"},
    "x-protected-by": {"name": "WAF Protected", "type": "waf"},
}

CDN_CNAME_PATTERNS = {
    "cloudflare": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "akamai": "Akamai",
    "akadns": "Akamai",
    "fastly": "Fastly",
    "cdn.shopify": "Shopify CDN",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door",
    "stackpath": "StackPath",
    "maxcdn": "MaxCDN/StackPath",
    "incapdns": "Incapsula/Imperva",
    "edgecast": "Edgecast/Verizon",
    "sucuri": "Sucuri WAF",
    "imperva": "Imperva WAF",
    "googleapis.com": "Google Cloud CDN",
    "googleusercontent.com": "Google Cloud",
    "netlify": "Netlify CDN",
    "vercel": "Vercel CDN",
}

WAF_SIGNATURES = {
    "cloudflare": {"name": "Cloudflare WAF", "headers": ["cf-ray", "server: cloudflare"]},
    "aws_waf": {"name": "AWS WAF", "headers": ["x-amzn-waf"]},
    "akamai_kona": {"name": "Akamai Kona", "headers": ["server: akamaighost"]},
    "sucuri": {"name": "Sucuri WAF", "headers": ["x-sucuri-id"]},
    "incapsula": {"name": "Incapsula WAF", "headers": ["x-iinfo", "x-cdn: incapsula"]},
    "f5_bigip": {"name": "F5 BIG-IP", "headers": ["server: big-ip", "x-cnection"]},
    "barracuda": {"name": "Barracuda WAF", "headers": ["server: barracuda"]},
    "fortiweb": {"name": "FortiWeb WAF", "headers": ["server: fortiweb"]},
}


def detect_cdn_headers(headers):
    """Detect CDN/WAF from response headers."""
    detections = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for sig, info in CDN_HEADER_SIGNATURES.items():
        if ":" in sig:
            hdr, val = sig.split(":", 1)
            hdr = hdr.strip().lower()
            val = val.strip().lower()
            if hdr in headers_lower and val in headers_lower[hdr].lower():
                detections.append(info)
        else:
            if sig.lower() in headers_lower:
                detections.append(info)

    return detections


def detect_cdn_dns(domain):
    """Detect CDN from DNS CNAME records."""
    detections = []
    try:
        result = socket.gethostbyname_ex(domain)
        canonical = result[0]
        aliases = result[1]
        all_names = [canonical] + aliases

        for name in all_names:
            for pattern, cdn_name in CDN_CNAME_PATTERNS.items():
                if pattern.lower() in name.lower():
                    detections.append({"name": cdn_name, "cname": name})
    except socket.gaierror:
        pass
    return detections


def detect_waf(session, url, timeout):
    """Detect WAF by sending malicious-looking requests."""
    waf_detected = []

    # Test with a simple XSS payload
    test_payloads = [
        ("?test=<script>alert(1)</script>", "XSS payload"),
        ("?test=' OR 1=1--", "SQLi payload"),
        ("/../../../etc/passwd", "Path traversal"),
    ]

    for payload, desc in test_payloads:
        try:
            test_url = url.rstrip("/") + payload
            resp = session.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code in (403, 406, 501):
                waf_detected.append({
                    "trigger": desc,
                    "status": resp.status_code,
                    "evidence": f"Blocked with HTTP {resp.status_code}",
                })
            # Check response body for WAF signatures
            body_lower = resp.text.lower()
            if "access denied" in body_lower or "blocked" in body_lower:
                waf_detected.append({
                    "trigger": desc,
                    "status": resp.status_code,
                    "evidence": "Response contains block message",
                })
        except Exception:
            continue

    return waf_detected


def find_real_ip(domain, timeout):
    """Attempt to find the real IP behind CDN."""
    possible_ips = []

    # Check MX records for real IP (mail often bypasses CDN)
    try:
        import struct
        # Query MX via socket
        mx_hosts = []
        # Try to resolve common mail subdomains
        mail_subs = [f"mail.{domain}", f"smtp.{domain}", f"mx.{domain}",
                     f"webmail.{domain}", f"mx1.{domain}", f"mx2.{domain}"]
        for sub in mail_subs:
            try:
                ip = socket.gethostbyname(sub)
                possible_ips.append({"ip": ip, "source": f"mail subdomain ({sub})"})
            except socket.gaierror:
                continue
    except Exception:
        pass

    # Check common subdomains that might bypass CDN
    bypass_subs = [
        "direct", "origin", "real", "backend", "server", "old",
        "staging", "dev", "test", "cpanel", "ftp", "ssh",
        "vpn", "admin", "panel", "api",
    ]
    for sub in bypass_subs:
        try:
            subdomain = f"{sub}.{domain}"
            ip = socket.gethostbyname(subdomain)
            # Check if this IP is different from the CDN IP
            main_ip = socket.gethostbyname(domain)
            if ip != main_ip:
                possible_ips.append({"ip": ip, "source": f"subdomain ({subdomain})"})
        except socket.gaierror:
            continue

    # Check for IP in SPF record via SecurityTrails (free API alternative)
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=timeout, verify=False
        )
        if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
            main_ip = socket.gethostbyname(domain)
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip != main_ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        possible_ips.append({"ip": ip, "source": f"host search ({parts[0].strip()})"})
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for entry in possible_ips:
        if entry["ip"] not in seen:
            seen.add(entry["ip"])
            unique.append(entry)
    return unique


def main():
    parser = argparse.ArgumentParser(description="CDN/WAF detector and origin IP finder")
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--deep", action="store_true", help="Deep scan for real IP")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.hostname

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; PhantomStrike/1.0)"

    print(f"[*] CDN/WAF Detector - Target: {domain}\n")

    # Resolve main IP
    try:
        main_ip = socket.gethostbyname(domain)
        print(f"[*] Resolved IP: {main_ip}")
    except socket.gaierror:
        print(f"[!] Cannot resolve {domain}", file=sys.stderr)
        sys.exit(1)

    # HTTP header analysis
    print(f"\n=== HTTP Header Analysis ===\n")
    try:
        resp = session.get(target, timeout=args.timeout, verify=False, allow_redirects=True)
        header_detections = detect_cdn_headers(resp.headers)
        if header_detections:
            for det in header_detections:
                print(f"  [DETECTED] {det['name']} ({det['type']})")
        else:
            print(f"  [INFO] No CDN/WAF signatures found in headers")
    except Exception as e:
        print(f"  [ERROR] Could not fetch headers: {e}")
        header_detections = []

    # DNS analysis
    print(f"\n=== DNS Analysis ===\n")
    dns_detections = detect_cdn_dns(domain)
    if dns_detections:
        for det in dns_detections:
            print(f"  [DETECTED] {det['name']} (CNAME: {det['cname']})")
    else:
        print(f"  [INFO] No CDN signatures in DNS records")

    # WAF detection
    print(f"\n=== WAF Detection ===\n")
    waf_results = detect_waf(session, target, args.timeout)
    if waf_results:
        seen_triggers = set()
        for w in waf_results:
            if w["trigger"] not in seen_triggers:
                print(f"  [DETECTED] WAF blocked {w['trigger']} (HTTP {w['status']})")
                print(f"             {w['evidence']}")
                seen_triggers.add(w["trigger"])
    else:
        print(f"  [INFO] No WAF behavior detected (or WAF is transparent)")

    # Real IP search
    is_cdn = bool(header_detections or dns_detections)
    if is_cdn or args.deep:
        print(f"\n=== Origin IP Discovery ===\n")
        real_ips = find_real_ip(domain, args.timeout)
        if real_ips:
            for entry in real_ips:
                print(f"  [POSSIBLE] {entry['ip']} (via {entry['source']})")
        else:
            print(f"  [INFO] No alternative IPs discovered")
    else:
        real_ips = []

    # Summary
    all_cdns = set()
    for d in header_detections:
        all_cdns.add(d["name"])
    for d in dns_detections:
        all_cdns.add(d["name"])

    print(f"\n{'='*50}")
    print(f"[*] CDN detected: {'Yes - ' + ', '.join(all_cdns) if all_cdns else 'No'}")
    print(f"[*] WAF detected: {'Yes' if waf_results else 'No/Unknown'}")
    print(f"[*] Main IP: {main_ip}")
    if real_ips:
        print(f"[*] Possible origin IPs: {len(real_ips)}")
        for entry in real_ips[:5]:
            print(f"    {entry['ip']} ({entry['source']})")


if __name__ == "__main__":
    main()
