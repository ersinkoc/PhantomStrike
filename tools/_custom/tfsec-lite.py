#!/usr/bin/env python3
"""Terraform security scanner: check .tf files for misconfigurations."""
import argparse, os, re, sys

RULES = [
    ("AWS001","CRITICAL",r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"',"SG open to world","Restrict CIDR"),
    ("AWS002","CRITICAL",r'acl\s*=\s*"public-read(-write)?"',"S3 public ACL","Set private"),
    ("AWS003","HIGH",r'encrypted\s*=\s*false',"Encryption disabled","Enable"),
    ("AWS004","HIGH",r'publicly_accessible\s*=\s*true',"DB publicly accessible","Set false"),
    ("AWS005","CRITICAL",r'(password|secret_key|access_key)\s*=\s*"[^$\{"]',"Hardcoded creds","Use vars"),
    ("AWS006","HIGH",r'protocol\s*=\s*"-1"',"All protocols","Specify protocols"),
    ("AWS007","HIGH",r'storage_encrypted\s*=\s*false',"RDS unencrypted","Enable"),
    ("AWS008","HIGH",r'enable_key_rotation\s*=\s*false',"KMS rotation off","Enable"),
    ("AWS009","HIGH",r'deletion_protection\s*=\s*false',"No delete protection","Enable"),
    ("AZU001","CRITICAL",r'source_address_prefix\s*=\s*"\*"',"NSG open","Restrict"),
    ("AZU002","HIGH",r'public_network_access_enabled\s*=\s*true',"Public access","Disable"),
    ("GCP001","CRITICAL",r'source_ranges\s*=\s*\[?"0\.0\.0\.0/0"',"GCP FW open","Restrict"),
    ("GEN001","MEDIUM",r'description\s*=\s*""',"Empty description","Add description"),
    ("GEN002","MEDIUM",r'tags\s*=\s*\{\}',"Empty tags","Add tags"),
]

def scan_tf(filepath):
    findings = []
    try:
        with open(filepath) as f: content = f.read()
    except Exception as e: return [{"id":"ERR","severity":"ERROR","msg":str(e),"line":0}]
    for rid, sev, pat, msg, fix in RULES:
        for m in re.finditer(pat, content, re.IGNORECASE):
            line = content[:m.start()].count("\n") + 1
            res = "unknown"
            bp = content.rfind("resource", 0, m.start())
            if bp != -1:
                rm = re.match(r'resource\s+"(\w+)"\s+"(\w+)"', content[bp:bp+100])
                if rm: res = f"{rm.group(1)}.{rm.group(2)}"
            findings.append({"id":rid,"severity":sev,"msg":msg,"fix":fix,
                             "line":line,"match":m.group()[:50].strip(),"resource":res})
    return findings

def main():
    parser = argparse.ArgumentParser(description="Terraform security scanner")
    parser.add_argument("target", help="File or directory")
    parser.add_argument("--minimum-severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"], default="MEDIUM")
    args = parser.parse_args()
    sev = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}; ms = sev[args.minimum_severity]
    print(f"[*] TFSec-Lite\n[*] Target: {args.target}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in fns:
                if f.endswith(".tf"): files.append(os.path.join(r, f))
    if not files: print("[!] No .tf files"); sys.exit(0)
    print(f"[*] Scanning {len(files)} file(s)\n")
    all_f = []
    for fp in files:
        findings = [f for f in scan_tf(fp) if sev.get(f["severity"],3) <= ms]
        if findings:
            print(f"=== {fp} ===")
            for f in sorted(findings, key=lambda x: sev.get(x["severity"],3)):
                icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(f["severity"],"[*]")
                print(f"  {icon} {f['id']} [{f['severity']}] {f['msg']}")
                print(f"      {f['resource']} line:{f['line']} | Fix: {f['fix']}")
            print()
            all_f.extend(findings)
    print(f"{'='*60}\n[*] Files: {len(files)} | Issues: {len(all_f)}")
    sm = {}
    for f in all_f: sm[f["severity"]] = sm.get(f["severity"],0) + 1
    for s in ["CRITICAL","HIGH","MEDIUM"]:
        if s in sm: print(f"  {s}: {sm[s]}")
    if not all_f: print("[+] All files passed!")

if __name__ == "__main__":
    main()
