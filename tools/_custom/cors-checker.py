#!/usr/bin/env python3
"""Check CORS misconfiguration on target domains."""
import argparse
import sys
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_origins(target_domain):
    """Generate test origins for CORS checks."""
    return [
        ("evil.com", "Arbitrary external origin"),
        ("null", "Null origin"),
        (f"sub.{target_domain}", "Subdomain reflection"),
        (f"{target_domain}.evil.com", "Domain suffix match"),
        (f"evil-{target_domain}", "Domain prefix match"),
        (f"evil{target_domain}", "Appended domain"),
        ("http://localhost", "Localhost origin"),
        ("http://127.0.0.1", "Loopback IP origin"),
        (f"https://{target_domain}", "Same-origin HTTPS"),
        (f"http://{target_domain}", "Same-origin HTTP"),
    ]


def check_cors(session, url, origin, timeout):
    """Send a request with a specific Origin header and check CORS response."""
    headers = {"Origin": origin, "User-Agent": "PhantomStrike/1.0 CORS-Checker"}
    try:
        resp = session.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    acam = resp.headers.get("Access-Control-Allow-Methods", "")
    acah = resp.headers.get("Access-Control-Allow-Headers", "")
    aceo = resp.headers.get("Access-Control-Expose-Headers", "")

    return {
        "status": resp.status_code,
        "acao": acao,
        "acac": acac.lower() == "true",
        "acam": acam,
        "acah": acah,
        "aceo": aceo,
    }


def assess_severity(origin, desc, result):
    """Assess the severity of a CORS finding."""
    acao = result.get("acao", "")
    acac = result.get("acac", False)

    if not acao:
        return None, ""

    # Wildcard with credentials is a browser error but still worth reporting
    if acao == "*" and acac:
        return "HIGH", "Wildcard origin with credentials (browser will block but server misconfigured)"

    if acao == "*":
        return "LOW", "Wildcard Access-Control-Allow-Origin (no credentials leak)"

    if acao == "null" and acac:
        return "CRITICAL", "Null origin accepted with credentials - exploitable via sandboxed iframe"

    if acao == "null":
        return "HIGH", "Null origin reflected - exploitable via sandboxed iframe"

    # Check if arbitrary origin is reflected
    if "evil.com" in origin and acao == origin:
        if acac:
            return "CRITICAL", "Arbitrary origin reflected WITH credentials - full CORS bypass"
        return "HIGH", "Arbitrary origin reflected - partial CORS bypass"

    # Domain suffix/prefix tricks
    if "evil" in origin and acao == origin:
        if acac:
            return "CRITICAL", "Weak origin validation with credentials - domain spoofing possible"
        return "HIGH", "Weak origin validation - domain spoofing possible"

    # Subdomain reflected
    if "sub." in origin and acao == origin:
        if acac:
            return "MEDIUM", "Subdomain origin accepted with credentials - XSS on subdomain escalates"
        return "LOW", "Subdomain origin accepted"

    if acao == origin:
        return "INFO", "Origin reflected (same-origin or expected)"

    return None, ""


def check_preflight(session, url, timeout):
    """Send an OPTIONS preflight request to check allowed methods."""
    try:
        resp = session.options(url, headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Header",
        }, timeout=timeout, verify=False)
        return {
            "status": resp.status_code,
            "allow_methods": resp.headers.get("Access-Control-Allow-Methods", ""),
            "allow_headers": resp.headers.get("Access-Control-Allow-Headers", ""),
            "max_age": resp.headers.get("Access-Control-Max-Age", ""),
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="CORS misconfiguration checker")
    parser.add_argument("target", help="Target URL (e.g., https://api.example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--methods", action="store_true", help="Also check preflight/OPTIONS")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.hostname

    session = requests.Session()
    origins = generate_origins(domain)

    print(f"[*] CORS Checker - Target: {target}")
    print(f"[*] Testing {len(origins)} origin variations\n")

    findings = []

    print("=== Origin Testing ===\n")
    for origin, desc in origins:
        origin_url = origin if origin.startswith("http") or origin == "null" else f"https://{origin}"
        result = check_cors(session, target, origin_url, args.timeout)

        if "error" in result:
            print(f"  [ERROR] {origin}: {result['error']}")
            continue

        severity, detail = assess_severity(origin_url, desc, result)
        if severity:
            findings.append({"origin": origin_url, "severity": severity, "detail": detail, **result})
            print(f"  [{severity}] Origin: {origin_url}")
            print(f"           ACAO: {result['acao']}")
            print(f"           Credentials: {result['acac']}")
            print(f"           Detail: {detail}")
            if result.get("acam"):
                print(f"           Methods: {result['acam']}")
            print()

    if args.methods:
        print("=== Preflight Check ===\n")
        pf = check_preflight(session, target, args.timeout)
        if "error" in pf:
            print(f"  [ERROR] {pf['error']}")
        else:
            print(f"  Status: {pf['status']}")
            print(f"  Allowed Methods: {pf['allow_methods'] or 'not specified'}")
            print(f"  Allowed Headers: {pf['allow_headers'] or 'not specified'}")
            print(f"  Max Age: {pf['max_age'] or 'not specified'}")
            if "PUT" in pf.get("allow_methods", "") or "DELETE" in pf.get("allow_methods", ""):
                print(f"  [WARNING] Dangerous methods allowed in preflight")
        print()

    print(f"{'='*50}")
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"[*] Findings: {len(findings)} total")
    print(f"[*] Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM")
    if crit > 0:
        print(f"[!] CRITICAL: CORS policy allows credential theft from arbitrary origins")
    elif high > 0:
        print(f"[!] HIGH: CORS policy has significant weaknesses")
    elif not findings:
        print(f"[*] No CORS misconfigurations detected (or CORS not enabled)")


if __name__ == "__main__":
    main()
