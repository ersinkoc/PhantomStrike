#!/usr/bin/env python3
"""Cloud asset discovery: enumerate cloud resources from DNS/IP patterns."""
import argparse, socket, sys
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

CLOUD_SVC = {"s3":"{n}.s3.amazonaws.com","azure_blob":"{n}.blob.core.windows.net",
    "azure_web":"{n}.azurewebsites.net","gcp_storage":"{n}.storage.googleapis.com",
    "gcp_app":"{n}.appspot.com","gcp_run":"{n}.run.app","firebase":"{n}.firebaseio.com",
    "heroku":"{n}.herokuapp.com","do_spaces":"{n}.digitaloceanspaces.com",
    "netlify":"{n}.netlify.app","vercel":"{n}.vercel.app"}
SUBS = ["www","api","app","dev","staging","test","admin","portal","mail","cdn","static",
        "assets","docs","help","status","blog","dashboard","vpn","git","ci","jenkins",
        "grafana","monitoring","kibana","redis","db","mysql","postgres","internal"]

def resolve(host, timeout=3):
    try: socket.setdefaulttimeout(timeout); return socket.gethostbyname(host)
    except: return None

def http_check(url, timeout=5):
    if not HAS_REQ: return None, None
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
        return r.status_code, r.headers.get("Server","")
    except: return None, None

def cloud_provider(ip):
    o = int(ip.split(".")[0]) if ip else 0
    if o in (3,18,34,35,44,52,54,99,174): return "AWS"
    if o in (13,20,23,40,51,65,104,168): return "Azure"
    if o in (8,34,35,104,108,142,216): return "GCP"
    return "?"

def main():
    parser = argparse.ArgumentParser(description="Cloud asset discovery")
    parser.add_argument("target", help="Domain or org name")
    parser.add_argument("--subdomains", action="store_true"); parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--all", action="store_true"); parser.add_argument("-t","--timeout", type=float, default=5)
    args = parser.parse_args()
    if args.all: args.subdomains = args.cloud = True
    if not (args.subdomains or args.cloud): args.subdomains = args.cloud = True
    print(f"[*] CloudMapper-Lite\n[*] Target: {args.target}\n")
    domain = args.target.replace("https://","").replace("http://","").rstrip("/")
    base = domain.split(".")[0]
    ip = resolve(domain, args.timeout)
    if ip: print(f"  Main: {domain} -> {ip} ({cloud_provider(ip)})")
    else: print(f"  Main: {domain} -> NXDOMAIN")
    assets = []
    if args.subdomains:
        print(f"\n=== Subdomains ({len(SUBS)}) ===\n")
        for sub in SUBS:
            h = f"{sub}.{domain}"; ip = resolve(h, args.timeout)
            if ip:
                p = cloud_provider(ip)
                print(f"  [+] {h:<40} {ip:<16} ({p})")
                assets.append(h)
        print(f"\n  Found: {len(assets)}")
    if args.cloud:
        print(f"\n=== Cloud Services ===\n")
        names = list(set([base, base.replace("-",""), domain.replace(".","-")]))
        cloud_found = 0
        for name in names:
            for svc, tmpl in CLOUD_SVC.items():
                host = tmpl.format(n=name); ip = resolve(host, args.timeout)
                if ip:
                    st, srv = http_check(f"https://{host}", args.timeout)
                    accessible = st is not None and st < 500
                    icon = "[+]" if accessible else "[-]"
                    print(f"  {icon} {svc:<15} {host:<45} {ip:<16} HTTP:{st or 'N/A'}")
                    if accessible: cloud_found += 1; assets.append(host)
        print(f"\n  Accessible: {cloud_found}")
    print(f"\n{'='*60}\n[*] Total assets: {len(assets)}")

if __name__ == "__main__":
    main()
