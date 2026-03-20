#!/usr/bin/env python3
"""Check HTTP security headers."""
import argparse
import sys
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "HIGH",
        "recommendation": "Add CSP header to prevent XSS and data injection attacks",
    },
    "X-Frame-Options": {
        "description": "Clickjacking protection",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "MIME type sniffing protection",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "description": "XSS filter (legacy browsers)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP)",
    },
    "Referrer-Policy": {
        "description": "Referrer information control",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Browser feature permissions",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy to restrict browser features",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Cross-origin embedding control",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Cross-origin opener control",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Cross-origin resource sharing control",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}

INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "Via", "X-Backend-Server",
]


def check_headers(url, timeout):
    """Check security headers for a URL."""
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                            headers={"User-Agent": "PhantomStrike/1.0"})
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[!] Request timed out", file=sys.stderr)
        sys.exit(1)

    headers = resp.headers
    print(f"[*] Checking {url}")
    print(f"[*] Status: {resp.status_code}")
    print(f"[*] Headers received: {len(headers)}\n")

    present = []
    missing = []

    print("=== Security Headers ===\n")
    for header_name, info in SECURITY_HEADERS.items():
        value = headers.get(header_name)
        if value:
            print(f"  [PASS] {header_name}")
            print(f"         Value: {value[:100]}")
            present.append(header_name)

            # Check for weak values
            if header_name == "Strict-Transport-Security":
                if "max-age=0" in value:
                    print(f"         [WARNING] max-age=0 effectively disables HSTS")
            if header_name == "X-Frame-Options":
                if value.upper() == "ALLOWALL":
                    print(f"         [WARNING] ALLOWALL provides no protection")
            if header_name == "Content-Security-Policy":
                if "unsafe-inline" in value:
                    print(f"         [WARNING] unsafe-inline weakens CSP")
                if "unsafe-eval" in value:
                    print(f"         [WARNING] unsafe-eval weakens CSP")
        else:
            severity = info["severity"]
            print(f"  [FAIL] {header_name} - MISSING [{severity}]")
            print(f"         {info['description']}")
            print(f"         Fix: {info['recommendation']}")
            missing.append((header_name, severity))
        print()

    # Check for information disclosure headers
    print("=== Information Disclosure ===\n")
    leaks = []
    for header_name in INFO_LEAK_HEADERS:
        value = headers.get(header_name)
        if value:
            print(f"  [WARN] {header_name}: {value}")
            leaks.append((header_name, value))
    if not leaks:
        print("  [OK]   No information disclosure headers found")

    # Check cookies
    print("\n=== Cookie Security ===\n")
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        if "Secure" not in cookies:
            print("  [WARN] Cookie missing Secure flag")
        if "HttpOnly" not in cookies:
            print("  [WARN] Cookie missing HttpOnly flag")
        if "SameSite" not in cookies:
            print("  [WARN] Cookie missing SameSite attribute")
        if all(f in cookies for f in ["Secure", "HttpOnly", "SameSite"]):
            print("  [OK]   Cookie flags look good")
    else:
        print("  [INFO] No Set-Cookie headers found")

    # Summary
    score = len(present) / len(SECURITY_HEADERS) * 100
    high_missing = sum(1 for _, s in missing if s == "HIGH")
    med_missing = sum(1 for _, s in missing if s == "MEDIUM")

    print(f"\n{'='*50}")
    print(f"[*] Score: {score:.0f}% ({len(present)}/{len(SECURITY_HEADERS)} headers present)")
    print(f"[*] Missing: {high_missing} HIGH, {med_missing} MEDIUM, {len(missing) - high_missing - med_missing} LOW")
    print(f"[*] Information leaks: {len(leaks)}")

    grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    print(f"[*] Grade: {grade}")


def main():
    parser = argparse.ArgumentParser(description="HTTP security headers checker")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    check_headers(target, args.timeout)


if __name__ == "__main__":
    main()
