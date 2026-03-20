#!/usr/bin/env python3
"""AWS security checker: check for common AWS misconfigs (public buckets, exposed services, metadata)."""
import argparse, socket, sys
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

BUCKET_SUFFIXES = ["","backup","-backup","-dev","-staging","-prod","-assets","-media",
                   "-static","-uploads","-logs","-data","-public","-config","-files"]
METADATA = [("http://169.254.169.254/latest/meta-data/","EC2 Metadata v1"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/","IAM Creds"),
            ("http://169.254.169.254/latest/user-data","User Data")]

def check_bucket(name, timeout=5):
    if not HAS_REQ: return None, None
    for url in [f"https://{name}.s3.amazonaws.com/",f"https://s3.amazonaws.com/{name}/"]:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return {200:"PUBLIC",403:"PRIVATE",404:"NOT_FOUND"}.get(r.status_code,f"HTTP_{r.status_code}"), url
        except: continue
    return "UNREACHABLE", None

def check_services(host, timeout=3):
    ports = {9200:"Elasticsearch",6379:"Redis",27017:"MongoDB",5432:"PostgreSQL",
             3306:"MySQL",11211:"Memcached",8080:"HTTP-Proxy",2379:"etcd",3000:"Grafana"}
    found = []
    for p, n in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0: found.append((p, n))
            s.close()
        except: pass
    return found

def main():
    parser = argparse.ArgumentParser(description="AWS security checker")
    parser.add_argument("target", help="Target org/domain")
    parser.add_argument("--buckets", action="store_true"); parser.add_argument("--metadata", action="store_true")
    parser.add_argument("--services", action="store_true"); parser.add_argument("--all", action="store_true")
    parser.add_argument("-t","--timeout", type=float, default=5)
    args = parser.parse_args()
    if args.all: args.buckets = args.metadata = args.services = True
    if not (args.buckets or args.metadata or args.services): args.buckets = args.services = True
    print(f"[*] PACU-Lite - AWS Security\n[*] Target: {args.target}\n")
    findings = 0
    if args.buckets:
        print("=== S3 Buckets ===\n")
        base = args.target.replace(".","-").replace("https://","").replace("http://","")
        pub, priv = 0, 0
        for sfx in BUCKET_SUFFIXES:
            name = f"{base}{sfx}" if not sfx.startswith("-") else f"{base}{sfx}"
            st, url = check_bucket(name, args.timeout)
            if st == "PUBLIC": print(f"  [!!!] PUBLIC: {name}"); pub += 1; findings += 1
            elif st == "PRIVATE": print(f"  [+] Exists (private): {name}"); priv += 1
        print(f"\n  Public: {pub} | Private: {priv}")
    if args.metadata and HAS_REQ:
        print("\n=== EC2 Metadata ===\n")
        for url, desc in METADATA:
            try:
                r = requests.get(url, timeout=args.timeout, headers={"User-Agent":"curl/7.68.0"})
                if r.status_code == 200:
                    print(f"  [!!!] {desc}: {r.text[:150]}"); findings += 1
                else: print(f"  [-] {desc}: HTTP {r.status_code}")
            except Exception as e: print(f"  [-] {desc}: {e}")
    if args.services:
        print("\n=== Exposed Services ===\n")
        try: host = socket.gethostbyname(args.target)
        except: host = args.target
        exposed = check_services(host, args.timeout)
        for p, n in exposed: print(f"  [!] {n} on port {p}"); findings += 1
        if not exposed: print("  [+] No risky services exposed")
    print(f"\n{'='*50}\n[*] Findings: {findings}")
    if findings: print("[!] Review and remediate")

if __name__ == "__main__":
    main()
