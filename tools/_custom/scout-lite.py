#!/usr/bin/env python3
"""Cloud security auditor: check multiple cloud providers for common security issues."""
import argparse, socket, sys
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
               "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
               "Referrer-Policy", "Permissions-Policy"]
STORAGE_CHECKS = {
    "AWS S3": "https://{b}.s3.amazonaws.com/",
    "Azure Blob": "https://{b}.blob.core.windows.net/{b}?restype=container&comp=list",
    "GCP Storage": "https://storage.googleapis.com/{b}/",
}
METADATA_URLS = {
    "AWS": ("http://169.254.169.254/latest/meta-data/", {}),
    "Azure": ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata":"true"}),
    "GCP": ("http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor":"Google"}),
}

def check_headers(url, timeout=5):
    if not HAS_REQ: return {}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
        res = {"_server": r.headers.get("Server",""), "_status": r.status_code}
        for h in SEC_HEADERS: res[h] = r.headers.get(h, "MISSING")
        return res
    except Exception as e: return {"_error": str(e)}

def check_storage(name, timeout=5):
    if not HAS_REQ: return []
    results = []
    for prov, tmpl in STORAGE_CHECKS.items():
        try:
            r = requests.get(tmpl.format(b=name), timeout=timeout)
            results.append((prov, r.status_code))
        except Exception: results.append((prov, None))
    return results

def check_ports(host, timeout=2):
    ports = {22:"SSH",3389:"RDP",5432:"PostgreSQL",3306:"MySQL",27017:"MongoDB",
             6379:"Redis",9200:"Elasticsearch",8080:"HTTP-Proxy",2379:"etcd",11211:"Memcached"}
    found = []
    for p, n in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0: found.append((p, n))
            s.close()
        except Exception: pass
    return found

def check_metadata(timeout=3):
    if not HAS_REQ: return {}
    results = {}
    for prov, (url, hdrs) in METADATA_URLS.items():
        try:
            r = requests.get(url, timeout=timeout, headers=hdrs)
            if r.status_code == 200: results[prov] = r.text[:200]
        except Exception: pass
    return results

def main():
    parser = argparse.ArgumentParser(description="Multi-cloud security auditor")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--headers", action="store_true"); parser.add_argument("--storage", action="store_true")
    parser.add_argument("--metadata", action="store_true"); parser.add_argument("--ports", action="store_true")
    parser.add_argument("--all", action="store_true"); parser.add_argument("-t","--timeout",type=float,default=5)
    args = parser.parse_args()
    if args.all: args.headers = args.storage = args.metadata = args.ports = True
    if not (args.headers or args.storage or args.metadata or args.ports): args.headers = args.ports = True
    print(f"[*] Scout-Lite - Cloud Security Auditor\n[*] Target: {args.target}\n")
    findings = 0
    try: ip = socket.gethostbyname(args.target); print(f"  IP: {ip}")
    except: ip = args.target
    if args.headers:
        print("\n=== Security Headers ===\n")
        url = f"https://{args.target}" if not args.target.startswith("http") else args.target
        h = check_headers(url, args.timeout)
        if "_error" in h: print(f"  [!] {h['_error']}")
        else:
            print(f"  Server: {h.get('_server','N/A')}")
            for hdr in SEC_HEADERS:
                v = h.get(hdr,"MISSING"); icon = "[+]" if v != "MISSING" else "[-]"
                print(f"  {icon} {hdr}: {v[:60]}")
                if v == "MISSING": findings += 1
    if args.ports:
        print("\n=== Exposed Services ===\n")
        for p, n in check_ports(ip, args.timeout): print(f"  [!] {n}:{p}"); findings += 1
    if args.storage:
        print("\n=== Storage ===\n")
        base = args.target.replace(".","-").split(":")[0]
        for prov, status in check_storage(base, args.timeout):
            icon = "[!!!]" if status == 200 else "[+]" if status == 403 else "[-]"
            print(f"  {icon} {prov} ({base}): {status or 'N/A'}")
            if status == 200: findings += 1
    if args.metadata:
        print("\n=== Metadata ===\n")
        for prov, data in check_metadata(args.timeout).items():
            print(f"  [!!!] {prov}: {data[:100]}"); findings += 1
    print(f"\n{'='*50}\n[*] Findings: {findings}")

if __name__ == "__main__":
    main()
