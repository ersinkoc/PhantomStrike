#!/usr/bin/env python3
"""Dependency vulnerability checker: parse package.json/requirements.txt/go.mod for known vulns."""
import argparse, json, os, re, sys

VULN_DB = {
    "npm": {
        "lodash": [("< 4.17.21","CVE-2021-23337","HIGH","Command injection")],
        "minimist": [("< 1.2.6","CVE-2021-44906","CRITICAL","Prototype pollution")],
        "express": [("< 4.17.3","CVE-2022-24999","HIGH","Open redirect")],
        "axios": [("< 0.21.2","CVE-2021-3749","HIGH","ReDoS")],
        "jsonwebtoken": [("< 9.0.0","CVE-2022-23529","CRITICAL","RCE")],
        "shelljs": [("< 0.8.5","CVE-2022-0144","CRITICAL","Privilege escalation")],
        "moment": [("< 2.29.4","CVE-2022-31129","HIGH","ReDoS")],
        "tar": [("< 6.1.11","CVE-2021-37701","HIGH","Arbitrary file creation")],
        "node-fetch": [("< 2.6.7","CVE-2022-0235","HIGH","Info exposure")],
    },
    "pip": {
        "django": [("< 4.0.2","CVE-2022-22818","HIGH","XSS")],
        "flask": [("< 2.2.5","CVE-2023-30861","HIGH","Session cookie vuln")],
        "requests": [("< 2.31.0","CVE-2023-32681","MEDIUM","Proxy-Auth leak")],
        "pyyaml": [("< 6.0","CVE-2020-14343","CRITICAL","Arbitrary code exec")],
        "urllib3": [("< 1.26.5","CVE-2021-33503","HIGH","ReDoS")],
        "cryptography": [("< 39.0.1","CVE-2023-23931","HIGH","Memory corruption")],
        "jinja2": [("< 3.1.3","CVE-2024-22195","MEDIUM","XSS")],
        "paramiko": [("< 3.4.0","CVE-2023-48795","HIGH","Terrapin attack")],
    },
    "go": {
        "golang.org/x/crypto": [("< 0.17.0","CVE-2023-48795","HIGH","Terrapin attack")],
        "golang.org/x/net": [("< 0.17.0","CVE-2023-44487","HIGH","HTTP/2 DoS")],
        "github.com/dgrijalva/jwt-go": [("*","CVE-2020-26160","HIGH","Use golang-jwt instead")],
    },
}

def parse_ver(v):
    parts = re.sub(r"[^\d.]","",v.split(",")[0]).split(".")
    return tuple(int(p) for p in (parts + ["0"]*4)[:4])

def ver_match(installed, constraint):
    if constraint == "*": return True
    m = re.match(r"<\s*([\d.]+)", constraint)
    return parse_ver(installed) < parse_ver(m.group(1)) if m else False

def parse_pkg_json(fp):
    with open(fp) as f: d = json.load(f)
    deps = {}
    for sec in ["dependencies","devDependencies"]:
        for pkg, ver in d.get(sec,{}).items():
            c = re.sub(r"[^0-9.]","",ver)
            if c: deps[pkg] = c
    return deps, "npm"

def parse_requirements(fp):
    deps = {}
    with open(fp) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"): continue
            m = re.match(r"([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*([\d.]+)", line)
            if m: deps[m.group(1).lower()] = m.group(2)
    return deps, "pip"

def parse_gomod(fp):
    deps = {}
    with open(fp) as f:
        in_req = False
        for line in f:
            l = line.strip()
            if l.startswith("require"): in_req = True; continue
            if in_req and l == ")": in_req = False; continue
            if in_req:
                m = re.match(r"([\w./-]+)\s+v?([\d.]+)", l)
                if m: deps[m.group(1)] = m.group(2)
    return deps, "go"

def main():
    parser = argparse.ArgumentParser(description="Dependency vulnerability checker")
    parser.add_argument("target", help="File or directory")
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"], default="MEDIUM")
    args = parser.parse_args()
    sev_ord = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    min_s = sev_ord[args.severity]
    print(f"[*] Snyk-Lite - Dependency Vuln Checker\n[*] Target: {args.target}\n")
    parsers = {"package.json":parse_pkg_json,"requirements.txt":parse_requirements,"go.mod":parse_gomod}
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            dirs[:] = [d for d in dirs if d not in ("node_modules",".git","vendor","__pycache__")]
            for f in fns:
                if f in parsers: files.append(os.path.join(r, f))
    total_v = []
    for fp in files:
        pf = parsers.get(os.path.basename(fp))
        if not pf: continue
        try: deps, eco = pf(fp)
        except Exception as e: print(f"[!] {fp}: {e}"); continue
        db = VULN_DB.get(eco, {})
        vulns = []
        for pkg, ver in deps.items():
            for constraint, cve, sev, desc in db.get(pkg.lower(), []):
                if ver_match(ver, constraint) and sev_ord.get(sev,3) <= min_s:
                    vulns.append((pkg, ver, cve, sev, desc, constraint.replace("< ",">=")))
        print(f"=== {fp} ({eco}, {len(deps)} deps) ===")
        if vulns:
            for pkg, ver, cve, sev, desc, fix in sorted(vulns, key=lambda x: sev_ord.get(x[3],3)):
                icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(sev,"[*]")
                print(f"  {icon} {pkg} {ver} | {cve} [{sev}]: {desc} | Fix: {fix}")
            total_v.extend(vulns)
        else: print("  [+] No known vulnerabilities")
        print()
    print(f"{'='*50}\n[*] Manifests: {len(files)} | Vulnerabilities: {len(total_v)}")

if __name__ == "__main__":
    main()
