#!/usr/bin/env python3
"""API route discovery: brute-force common API routes with smart wordlist."""
import argparse, sys, time
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

ROUTES = ["/api","/api/v1","/api/v2","/api/v1/users","/api/v1/admin","/api/v1/login",
    "/api/v1/auth","/api/v1/token","/api/v1/health","/api/v1/config","/api/v1/upload",
    "/graphql","/graphiql","/api/graphql","/graphql/playground",
    "/swagger","/swagger.json","/swagger.yaml","/swagger-ui","/swagger-ui.html",
    "/api-docs","/api-docs.json","/openapi.json","/v2/api-docs","/v3/api-docs","/docs",
    "/admin","/admin/login","/dashboard","/portal","/console","/manage",
    "/health","/healthz","/readyz","/status","/ping","/metrics","/prometheus",
    "/actuator","/actuator/health","/actuator/env","/actuator/info","/actuator/beans",
    "/debug","/debug/pprof","/_debug","/internal","/env","/config","/info","/version","/.env",
    "/login","/register","/oauth","/oauth/token","/auth","/token","/sso",
    "/wp-json","/wp-json/wp/v2/users","/wp-admin","/server-status","/.git/HEAD",
    "/robots.txt","/.well-known/security.txt","/.git/config","/.DS_Store",
    "/backup.sql","/config.json","/.htaccess","/web.config"]

def test_route(base, route, method, timeout, headers):
    if not HAS_REQ: return None
    url = f"{base.rstrip('/')}{route}"
    try:
        r = requests.request(method, url, timeout=timeout, allow_redirects=False, headers=headers)
        return {"url":url,"status":r.status_code,"length":len(r.content),
                "ct":r.headers.get("Content-Type","")[:20]}
    except: return None

def main():
    parser = argparse.ArgumentParser(description="API route discovery")
    parser.add_argument("target", help="Base URL")
    parser.add_argument("-w","--wordlist", help="Custom wordlist")
    parser.add_argument("-m","--method", default="GET")
    parser.add_argument("-t","--timeout", type=float, default=5)
    parser.add_argument("--filter-status", help="Status codes to show (comma-sep)")
    args = parser.parse_args()
    if not HAS_REQ:
        print("[!] requests required\n[*] Wordlist:")
        for r in ROUTES: print(r)
        return
    base = args.target if args.target.startswith("http") else f"https://{args.target}"
    print(f"[*] KiteRunner-Lite\n[*] Target: {base}\n[*] Method: {args.method}\n")
    hdrs = {"User-Agent": "Mozilla/5.0"}
    routes = ROUTES
    if args.wordlist:
        try:
            with open(args.wordlist) as f: routes = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            print(f"[*] Loaded {len(routes)} routes")
        except Exception as e: print(f"[!] {e}")
    filt = set(int(c) for c in args.filter_status.split(",")) if args.filter_status else None
    bl = test_route(base, "/nonexistent-xyz123", args.method, args.timeout, hdrs)
    bl_len = bl.get("length",0) if bl else 0
    print(f"[*] Scanning {len(routes)} routes...\n")
    print(f"{'STATUS':<8} {'LEN':<10} {'ROUTE':<45} {'TYPE'}")
    print(f"{'-'*8} {'-'*10} {'-'*45} {'-'*15}")
    found = []; start = time.time()
    interesting = {200,201,204,301,302,307,400,401,403,405,500}
    for route in routes:
        r = test_route(base, route, args.method, args.timeout, hdrs)
        if not r: continue
        s, l = r["status"], r["length"]
        if s == 404 and abs(l-bl_len) < 50: continue
        if filt and s not in filt: continue
        if s in interesting:
            print(f"{s:<8} {l:<10} {route:<45} {r['ct']}")
            found.append(r)
    elapsed = time.time() - start
    print(f"\n{'='*60}\n[*] Done in {elapsed:.1f}s | Tested: {len(routes)} | Found: {len(found)}")
    crit = [f for f in found if any(p in f["url"] for p in [".env",".git","actuator","swagger","graphql","debug","admin"])]
    if crit:
        print(f"\n[!] High-interest ({len(crit)}):")
        for c in crit: print(f"    {c['status']} {c['url']}")

if __name__ == "__main__":
    main()
