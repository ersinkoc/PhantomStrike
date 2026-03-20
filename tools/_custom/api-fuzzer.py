#!/usr/bin/env python3
"""Simple API endpoint fuzzer using common paths."""
import argparse
import sys
import urllib.parse
import requests

COMMON_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql",
    "/swagger.json", "/swagger/", "/swagger-ui/", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/docs", "/redoc",
    "/health", "/healthz", "/status", "/metrics",
    "/admin", "/admin/login", "/dashboard",
    "/auth", "/auth/login", "/oauth/token",
    "/users", "/user", "/account", "/profile",
    "/config", "/configuration", "/settings",
    "/debug", "/debug/vars", "/debug/pprof",
    "/actuator", "/actuator/health", "/actuator/env",
    "/env", "/info", "/.env",
    "/robots.txt", "/sitemap.xml",
    "/wp-json/wp/v2/users", "/wp-admin",
    "/api/swagger", "/api/docs",
    "/rest", "/rest/api",
    "/jsonapi", "/odata",
    "/.well-known/openid-configuration",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
]

METHODS = ["GET", "POST", "OPTIONS"]


def fuzz_target(base_url, paths, timeout, verbose):
    base_url = base_url.rstrip("/")
    found = []
    total = len(paths)

    print(f"[*] Fuzzing {base_url} with {total} paths...")
    print(f"[*] Timeout: {timeout}s per request\n")

    for i, path in enumerate(paths, 1):
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                verify=False, headers={"User-Agent": "PhantomStrike/1.0"})
            status = resp.status_code
            length = len(resp.content)

            if status < 404:
                tag = "FOUND" if status < 300 else "REDIRECT" if status < 400 else "AUTH"
                print(f"  [{tag}] {status} | {length:>8} bytes | {path}")
                found.append({"path": path, "status": status, "length": length})
            elif verbose:
                print(f"  [MISS]  {status} | {length:>8} bytes | {path}")
        except requests.exceptions.Timeout:
            if verbose:
                print(f"  [TIME]  ---  | {path}")
        except requests.exceptions.ConnectionError:
            if verbose:
                print(f"  [FAIL]  ---  | {path}")

    print(f"\n[*] Scan complete: {len(found)}/{total} endpoints discovered")
    if found:
        print("\n=== Summary ===")
        for entry in found:
            print(f"  {entry['status']} {entry['path']} ({entry['length']} bytes)")
    return found


def main():
    parser = argparse.ArgumentParser(description="API endpoint fuzzer")
    parser.add_argument("target", help="Target base URL (e.g., http://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout (seconds)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file (one path per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show missed paths too")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    paths = COMMON_PATHS
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}", file=sys.stderr)
            sys.exit(1)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    fuzz_target(target, paths, args.timeout, args.verbose)


if __name__ == "__main__":
    main()
