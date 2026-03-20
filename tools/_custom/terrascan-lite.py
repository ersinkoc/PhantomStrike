#!/usr/bin/env python3
"""IaC security scanner: check Terraform/CloudFormation files for security issues."""
import argparse, os, re, sys

RULES = [
    ("TF-001", "CRITICAL", r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"', "SG open to 0.0.0.0/0", "Restrict CIDR"),
    ("TF-002", "CRITICAL", r'acl\s*=\s*"public-read"', "S3 bucket public", "Set ACL to private"),
    ("TF-003", "HIGH", r'encrypted\s*=\s*false', "Encryption disabled", "Enable encryption"),
    ("TF-004", "CRITICAL", r'(password|secret|api_key|token)\s*=\s*"[^"$]', "Hardcoded secret", "Use variables"),
    ("TF-005", "HIGH", r'publicly_accessible\s*=\s*true', "RDS publicly accessible", "Set to false"),
    ("TF-006", "HIGH", r'protocol\s*=\s*"-1"', "All protocols allowed", "Specify protocols"),
    ("TF-007", "HIGH", r'storage_encrypted\s*=\s*false', "RDS not encrypted", "Enable encryption"),
    ("TF-008", "CRITICAL", r'effect\s*=\s*"Allow"[^}]*actions?\s*=\s*\[?\s*"\*"', "IAM wildcard",
     "Follow least privilege"),
    ("TF-009", "HIGH", r'enable_key_rotation\s*=\s*false', "KMS rotation off", "Enable rotation"),
    ("TF-010", "MEDIUM", r'multi_az\s*=\s*false', "No multi-AZ", "Enable for HA"),
    ("TF-011", "HIGH", r'deletion_protection\s*=\s*false', "No delete protection", "Enable for prod"),
    ("CF-001", "CRITICAL", r"CidrIp:\s*0\.0\.0\.0/0", "CF SG open to world", "Restrict CIDR"),
    ("CF-002", "HIGH", r"PubliclyAccessible:\s*true", "CF resource public", "Set to false"),
    ("CF-003", "CRITICAL", r"(Password|Secret|ApiKey):\s*['\"][^$\{]", "CF hardcoded secret", "Use Ref/SSM"),
    ("TF-012", "CRITICAL", r'ipv6_cidr_blocks\s*=\s*\[?"::/0"', "SG open to ::/0", "Restrict IPv6"),
    ("TF-013", "MEDIUM", r'versioning\s*\{[^}]*enabled\s*=\s*false', "S3 versioning off", "Enable versioning"),
]

def scan_file(filepath):
    findings = []
    try:
        with open(filepath) as f: content = f.read()
    except Exception as e: return [{"id":"ERR","severity":"ERROR","name":str(e),"line":0,"fix":""}]
    for rid, sev, pat, name, fix in RULES:
        for m in re.finditer(pat, content, re.IGNORECASE | re.DOTALL):
            line = content[:m.start()].count("\n") + 1
            res_block = content.rfind("resource", 0, m.start())
            resource = "unknown"
            if res_block != -1:
                rm = re.match(r'resource\s+"(\w+)"\s+"(\w+)"', content[res_block:res_block+100])
                if rm: resource = f"{rm.group(1)}.{rm.group(2)}"
            findings.append({"id":rid,"severity":sev,"name":name,"line":line,
                             "match":m.group()[:50].strip(),"fix":fix,"resource":resource})
    return findings

def main():
    parser = argparse.ArgumentParser(description="IaC security scanner for Terraform/CloudFormation")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"], default="MEDIUM")
    args = parser.parse_args()
    sev_ord = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    min_s = sev_ord[args.severity]
    print(f"[*] Terrascan-Lite - IaC Security Scanner\n[*] Target: {args.target}\n")
    files = []
    exts = {".tf",".yaml",".yml",".json",".template"}
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in fns:
                if os.path.splitext(f)[1].lower() in exts: files.append(os.path.join(r, f))
    all_f = []
    for fp in files:
        findings = [f for f in scan_file(fp) if sev_ord.get(f["severity"],3) <= min_s]
        if findings:
            print(f"=== {fp} ===")
            for f in sorted(findings, key=lambda x: sev_ord.get(x["severity"],3)):
                icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(f["severity"],"[*]")
                print(f"  {icon} {f['id']} [{f['severity']}] {f['name']} (line {f['line']})")
                if f.get("match"): print(f"      Match: {f['match']}")
                if f.get("fix"): print(f"      Fix: {f['fix']}")
            print()
            all_f.extend(findings)
    print(f"{'='*50}\n[*] Files: {len(files)} | Issues: {len(all_f)}")
    summary = {}
    for f in all_f: summary[f["severity"]] = summary.get(f["severity"],0) + 1
    for s in ["CRITICAL","HIGH","MEDIUM"]:
        if s in summary: print(f"  {s}: {summary[s]}")

if __name__ == "__main__":
    main()
