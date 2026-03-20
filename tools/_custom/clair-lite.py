#!/usr/bin/env python3
"""Container vulnerability scanner: check Docker image configs for known vulnerabilities."""
import argparse, os, re, sys
try:
    import requests; HAS_REQ = True
except ImportError: HAS_REQ = False

VULN_IMAGES = {"alpine:3.12":["CVE-2021-36159"],"ubuntu:18.04":["CVE-2021-3449","CVE-2022-0778"],
    "debian:stretch":["CVE-2021-3449"],"node:12":["CVE-2021-22959"],"node:14":["CVE-2021-44228"],
    "python:3.6":["CVE-2021-3177"],"nginx:1.18":["CVE-2021-23017"],"redis:5":["CVE-2021-32625"]}
DF_RULES = [
    (r"FROM\s+.*:latest","WARN","Using :latest tag"),
    (r"RUN.*curl.*\|\s*(?:sh|bash)","CRITICAL","Pipe-to-shell"),
    (r"ADD\s+https?://","WARN","ADD with URL"),
    (r"ENV.*(PASSWORD|SECRET|API_KEY)","CRITICAL","Secret in ENV"),
    (r"COPY\s+\.\s+\.","WARN","Copying entire context"),
    (r"RUN.*chmod\s+777","WARN","Setting 777 permissions"),
    (r"EXPOSE\s+22\b","WARN","SSH exposed"),
]
COMPOSE_RULES = [
    (r"privileged:\s*true","CRITICAL","Privileged container"),
    (r"network_mode:\s*host","WARN","Host network"),
    (r"pid:\s*host","CRITICAL","Host PID namespace"),
    (r"cap_add:.*SYS_ADMIN","CRITICAL","SYS_ADMIN capability"),
    (r"cap_add:.*ALL","CRITICAL","ALL capabilities"),
    (r"/var/run/docker\.sock","CRITICAL","Docker socket mounted"),
]

def analyze_dockerfile(fp):
    findings = []
    with open(fp) as f: content = f.read(); lines = content.split("\n")
    base_image = None; has_user = False
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("FROM") and len(s.split()) >= 2: base_image = s.split()[1].lower()
        if s.startswith("USER") and "root" not in s.lower(): has_user = True
        for pat, sev, desc in DF_RULES:
            if re.search(pat, s, re.IGNORECASE): findings.append((sev, desc, i))
    if base_image:
        for vi, cves in VULN_IMAGES.items():
            if vi in base_image:
                for c in cves: findings.append(("HIGH", f"Base {base_image}: {c}", 1))
    if not has_user: findings.append(("WARN","No USER - runs as root", 0))
    return findings

def analyze_compose(fp):
    findings = []
    with open(fp) as f: content = f.read()
    for pat, sev, desc in COMPOSE_RULES:
        for m in re.finditer(pat, content, re.IGNORECASE):
            findings.append((sev, desc, content[:m.start()].count("\n")+1))
    return findings

def main():
    parser = argparse.ArgumentParser(description="Container vulnerability scanner")
    parser.add_argument("target", help="Dockerfile/compose or directory")
    parser.add_argument("--socket", action="store_true")
    args = parser.parse_args()
    print(f"[*] Clair-Lite\n[*] Target: {args.target}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            for f in fns:
                if f.startswith("Dockerfile") or "compose" in f.lower(): files.append(os.path.join(r,f))
    totals = {"CRITICAL":0,"HIGH":0,"WARN":0}
    for fp in files:
        print(f"=== {fp} ===")
        try:
            if "compose" in os.path.basename(fp).lower(): findings = analyze_compose(fp)
            else: findings = analyze_dockerfile(fp)
        except Exception as e: print(f"  [!] {e}\n"); continue
        for sev, desc, line in sorted(findings, key=lambda x: ["CRITICAL","HIGH","WARN"].index(x[0]) if x[0] in ["CRITICAL","HIGH","WARN"] else 3):
            icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","WARN":"[!]"}.get(sev,"[*]")
            ln = f" line {line}" if line > 0 else ""
            print(f"  {icon} [{sev}] {desc}{ln}")
            if sev in totals: totals[sev] += 1
        if not findings: print("  [+] No issues")
        print()
    if args.socket and HAS_REQ:
        for p in [2375,2376]:
            try:
                r = requests.get(f"http://localhost:{p}/version", timeout=3)
                if r.status_code == 200: print(f"[!!!] Docker API exposed on {p}!"); totals["CRITICAL"]+=1
            except: pass
    print(f"{'='*50}\n[*] Files: {len(files)}")
    for s, c in totals.items():
        if c: print(f"  {s}: {c}")

if __name__ == "__main__":
    main()
