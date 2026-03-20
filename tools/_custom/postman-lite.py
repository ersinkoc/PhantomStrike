#!/usr/bin/env python3
"""API collection tester: test API endpoints from a simple JSON collection format."""
import argparse, json, os, sys, time
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

SEC_HEADERS = [("Strict-Transport-Security","MISSING","No HSTS"),("Content-Security-Policy","MISSING","No CSP"),
               ("X-Content-Type-Options","MISSING","No XCTO"),("X-Frame-Options","MISSING","No XFO"),
               ("Access-Control-Allow-Origin","*","CORS: *")]

def resolve_vars(text, vrs):
    if not isinstance(text, str): return text
    for k, v in vrs.items(): text = text.replace(f"{{{{{k}}}}}", str(v))
    return text

def run_req(req, vrs, timeout=10):
    if not HAS_REQ: return None, "requests not available"
    url = resolve_vars(req.get("url",""), vrs)
    method = req.get("method","GET").upper()
    hdrs = {"User-Agent": "PostmanLite/1.0"}
    for k, v in req.get("headers",{}).items(): hdrs[resolve_vars(k,vrs)] = resolve_vars(v,vrs)
    body = req.get("body")
    try:
        start = time.time()
        r = requests.request(method, url, json=body if isinstance(body,dict) else None,
                             headers=hdrs, timeout=timeout, allow_redirects=False)
        return {"status":r.status_code,"time_ms":int((time.time()-start)*1000),
                "size":len(r.content),"headers":dict(r.headers),"body":r.text[:300]}, None
    except requests.exceptions.Timeout: return None, "Timeout"
    except Exception as e: return None, str(e)

def load_collection(fp):
    with open(fp) as f: data = json.load(f)
    if "item" in data:
        c = {"info":data.get("info",{}),"variables":{},"requests":[]}
        for v in data.get("variable",[]): c["variables"][v["key"]] = v.get("value","")
        for item in data["item"]:
            rq = item.get("request",{})
            url = rq.get("url",{}).get("raw","") if isinstance(rq.get("url"),dict) else rq.get("url","")
            r = {"name":item.get("name","?"),"method":rq.get("method","GET"),"url":url}
            if rq.get("body",{}).get("raw"):
                try: r["body"] = json.loads(rq["body"]["raw"])
                except: pass
            c["requests"].append(r)
        return c
    return data

def main():
    parser = argparse.ArgumentParser(description="API collection tester")
    parser.add_argument("target", help="Collection JSON or base URL")
    parser.add_argument("-v","--var", action="append", help="key=value")
    parser.add_argument("-t","--timeout", type=float, default=10)
    parser.add_argument("--security", action="store_true")
    parser.add_argument("--sample", action="store_true")
    args = parser.parse_args()
    print("[*] Postman-Lite - API Collection Tester\n")
    if args.sample:
        print(json.dumps({"info":{"name":"Sample"},"variables":{"base_url":"https://httpbin.org"},
              "requests":[{"name":"GET","method":"GET","url":"{{base_url}}/get"}]}, indent=2)); return
    if not HAS_REQ: print("[!] requests library required"); sys.exit(1)
    if os.path.isfile(args.target):
        try: col = load_collection(args.target)
        except Exception as e: print(f"[!] {e}"); sys.exit(1)
    else:
        base = args.target.rstrip("/")
        col = {"info":{"name":"Quick"},"variables":{"base_url":base},
               "requests":[{"name":"GET /","method":"GET","url":"{{base_url}}/"},
                           {"name":"Health","method":"GET","url":"{{base_url}}/health"},
                           {"name":"API","method":"GET","url":"{{base_url}}/api"}]}
    vrs = col.get("variables",{})
    if args.var:
        for v in args.var:
            if "=" in v: k,val = v.split("=",1); vrs[k] = val
    print(f"[*] Collection: {col.get('info',{}).get('name','?')}")
    print(f"[*] Requests: {len(col.get('requests',[]))}\n")
    results = []
    for req in col.get("requests",[]):
        name = req.get("name","?"); method = req.get("method","GET")
        result, err = run_req(req, vrs, args.timeout)
        if err: print(f"  [{method}] {name}: ERROR - {err}"); continue
        s = result["status"]; icon = "[+]" if 200<=s<300 else "[~]" if 300<=s<400 else "[-]"
        print(f"  {icon} [{method}] {name}: {s} ({result['time_ms']}ms, {result['size']}B)")
        if args.security:
            for h, bad, msg in SEC_HEADERS:
                v = result["headers"].get(h)
                if (bad=="MISSING" and not v) or (v==bad): print(f"      [!] {msg}")
        results.append(result)
    ok = sum(1 for r in results if 200<=r.get("status",0)<300)
    print(f"\n{'='*50}\n[*] Passed: {ok} | Total: {len(results)}")

if __name__ == "__main__":
    main()
