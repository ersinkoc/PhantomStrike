#!/usr/bin/env python3
"""Hidden parameter discovery: brute-force URL parameters, detect reflected params."""
import argparse
import sys
import time
from urllib.parse import urlparse, urlencode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PARAMS = [
    "id", "page", "q", "search", "query", "s", "lang", "language", "dir", "action",
    "file", "path", "url", "uri", "redirect", "next", "return", "continue", "dest",
    "destination", "rurl", "redirect_uri", "callback", "view", "template", "type",
    "category", "cat", "name", "user", "username", "email", "password", "pass",
    "token", "key", "api_key", "apikey", "secret", "auth", "access_token",
    "admin", "debug", "test", "dev", "mode", "config", "cmd", "exec", "command",
    "filter", "sort", "order", "limit", "offset", "count", "from", "to",
    "format", "output", "download", "upload", "export", "import", "include",
    "load", "read", "write", "delete", "edit", "update", "create", "remove",
    "method", "module", "plugin", "theme", "style", "css", "js", "script",
    "callback", "jsonp", "json", "xml", "data", "body", "content", "text",
    "message", "comment", "title", "description", "tag", "tags", "label",
    "status", "state", "enabled", "disabled", "active", "visible", "hidden",
    "role", "permission", "group", "level", "scope", "source", "target",
    "host", "port", "ip", "domain", "server", "proxy", "ref", "referrer",
    "utm_source", "utm_medium", "utm_campaign", "tracking", "session",
    "sid", "ssid", "cookie", "csrf", "nonce", "_token", "authenticity_token",
    "version", "v", "ver", "rev", "build", "release", "env", "environment",
    "locale", "tz", "timezone", "date", "time", "year", "month", "day",
    "width", "height", "size", "color", "bg", "font", "image", "img", "photo",
    "avatar", "icon", "logo", "thumb", "thumbnail", "preview", "crop", "resize",
    "cache", "refresh", "reload", "retry", "timeout", "wait", "sleep", "delay",
    "encoding", "charset", "utf8", "accept", "content_type", "mime",
    "redir", "return_to", "goto", "forward", "back", "returnUrl", "returl",
]

CANARY = "x8pHaNt0m"


def load_wordlist(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[!] Cannot load wordlist: {e}", file=sys.stderr)
        sys.exit(1)


def get_baseline(session, url, timeout):
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        return {"status": resp.status_code, "length": len(resp.content), "body": resp.text}
    except Exception:
        return None


def test_param(session, url, param, baseline, timeout):
    value = CANARY
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{param}={value}"
    try:
        resp = session.get(test_url, timeout=timeout, verify=False)
        result = {"param": param, "status": resp.status_code, "length": len(resp.content), "reflected": False,
                  "status_change": False, "size_change": 0, "interesting": False}
        if CANARY in resp.text:
            result["reflected"] = True
            result["interesting"] = True
        if baseline:
            if resp.status_code != baseline["status"]:
                result["status_change"] = True
                result["interesting"] = True
            size_diff = abs(len(resp.content) - baseline["length"])
            result["size_change"] = size_diff
            if size_diff > 50:
                result["interesting"] = True
        return result
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="x8-lite: Hidden parameter discovery")
    ap.add_argument("target", help="Target URL (e.g., http://example.com/page)")
    ap.add_argument("-w", "--wordlist", help="Custom parameter wordlist")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    ap.add_argument("--batch", type=int, default=1, help="Test N params at once (batch mode)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show all tested parameters")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    params = load_wordlist(args.wordlist) if args.wordlist else COMMON_PARAMS

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 x8-lite"

    print(f"[*] x8-lite: Hidden Parameter Discovery")
    print(f"[*] Target: {target}")
    print(f"[*] Parameters to test: {len(params)}\n")

    print("[*] Getting baseline response...")
    baseline = get_baseline(session, target, args.timeout)
    if baseline:
        print(f"  Baseline: status={baseline['status']}, size={baseline['length']}\n")
    else:
        print("  [!] Could not get baseline\n")

    found = []
    reflected = []
    tested = 0

    if args.batch > 1:
        print(f"[*] Batch mode: testing {args.batch} params per request\n")
        for i in range(0, len(params), args.batch):
            batch = params[i:i + args.batch]
            batch_params = "&".join(f"{p}={CANARY}{j}" for j, p in enumerate(batch))
            sep = "&" if "?" in target else "?"
            test_url = f"{target}{sep}{batch_params}"
            try:
                resp = session.get(test_url, timeout=args.timeout, verify=False)
                for j, p in enumerate(batch):
                    marker = f"{CANARY}{j}"
                    if marker in resp.text:
                        print(f"  [FOUND] {p} - REFLECTED in response")
                        reflected.append(p)
                        found.append({"param": p, "reflected": True, "status": resp.status_code, "size": len(resp.content)})
                tested += len(batch)
            except Exception:
                tested += len(batch)
            if args.delay > 0:
                time.sleep(args.delay)
    else:
        for param in params:
            tested += 1
            result = test_param(session, target, param, baseline, args.timeout)
            if result is None:
                continue
            if result["interesting"]:
                flags = []
                if result["reflected"]:
                    flags.append("REFLECTED")
                    reflected.append(param)
                if result["status_change"]:
                    flags.append(f"STATUS:{result['status']}")
                if result["size_change"] > 50:
                    flags.append(f"SIZE_DIFF:{result['size_change']}")
                flag_str = ", ".join(flags)
                print(f"  [FOUND] {param:<25} {flag_str}")
                found.append(result)
            elif args.verbose:
                print(f"  [    ] {param:<25} status={result['status']} size={result['length']}")
            if args.delay > 0:
                time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"[*] DISCOVERY RESULTS")
    print(f"{'='*60}\n")
    print(f"  Parameters tested: {tested}")
    print(f"  Hidden params found: {len(found)}")
    print(f"  Reflected params: {len(reflected)}\n")

    if found:
        print("  Discovered Parameters:")
        for f in found:
            p = f["param"] if isinstance(f, dict) and "param" in f else f
            r = "REFLECTED" if (isinstance(f, dict) and f.get("reflected")) else ""
            print(f"    - {p} {r}")

        if reflected:
            print(f"\n  [!] {len(reflected)} parameter(s) reflect input - potential XSS vectors:")
            for p in reflected:
                print(f"      {target}{'&' if '?' in target else '?'}{p}=PAYLOAD")
    else:
        print("  [OK] No hidden parameters discovered")


if __name__ == "__main__":
    main()
