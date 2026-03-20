#!/usr/bin/env python3
"""Secret scanner: scan files/repos for hardcoded secrets, API keys, passwords using regex patterns."""
import argparse, os, re, sys

PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "CRITICAL"),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}", "HIGH"),
    ("GCP Service Account", r'"type":\s*"service_account"', "CRITICAL"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36}", "CRITICAL"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "HIGH"),
    ("Slack Webhook", r"hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}", "HIGH"),
    ("Private Key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "CRITICAL"),
    ("Password", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "HIGH"),
    ("API Key", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9]{16,}['\"]", "HIGH"),
    ("Secret/Token", r"(?i)(secret|token|auth)\s*[=:]\s*['\"][A-Za-z0-9/+=]{16,}['\"]", "HIGH"),
    ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9_.~+/=-]{20,}", "HIGH"),
    ("Database URL", r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]{10,}", "CRITICAL"),
    ("Connection String", r"(?i)(server|host)=[^;]+;.*(?:password|pwd)=[^;]+", "CRITICAL"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "MEDIUM"),
    ("Stripe Key", r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    ("SendGrid Key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "HIGH"),
    ("Creds in URL", r"https?://[^:]+:[^@]+@[^\s]+", "HIGH"),
    ("Dotenv Secret", r"(?i)^[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|AUTH)[A-Z_]*\s*=\s*\S{8,}", "HIGH"),
]

SKIP_EXT = {".jpg",".png",".gif",".zip",".tar",".gz",".exe",".dll",".so",".bin",".pyc",
            ".woff",".ttf",".pdf",".ico",".mp3",".mp4",".svg",".min.js",".map"}
SKIP_DIR = {".git","node_modules","__pycache__",".venv","venv","vendor","dist","build","coverage"}
RISK_FILES = {".env",".env.local",".env.production","credentials.json","key.json",
              ".htpasswd",".pgpass",".netrc","id_rsa","id_dsa","id_ed25519"}

def scan_file(filepath):
    findings = []
    bn = os.path.basename(filepath).lower()
    if bn in RISK_FILES:
        findings.append({"type":"High-Risk File","severity":"HIGH","line":0,"match":bn})
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for ln, line in enumerate(f, 1):
                line = line.rstrip()
                if not line: continue
                for name, pat, sev in PATTERNS:
                    for m in re.finditer(pat, line):
                        mt = m.group()
                        if len(mt) < 8: continue
                        masked = mt[:6] + "..." + mt[-4:] if len(mt) > 12 else mt[:4] + "..."
                        findings.append({"type":name,"severity":sev,"line":ln,"match":masked})
                if len(findings) > 50: break
    except Exception: pass
    return findings

def main():
    parser = argparse.ArgumentParser(description="Secret scanner for files and repositories")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"], default="MEDIUM")
    args = parser.parse_args()
    sev_map = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    min_s = sev_map[args.severity]
    print(f"[*] Git-Secrets-Lite - Secret Scanner\n[*] Target: {args.target}\n[*] Patterns: {len(PATTERNS)}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for root, dirs, fnames in os.walk(args.target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIR]
            for f in fnames:
                fp = os.path.join(root, f)
                _, ext = os.path.splitext(f.lower())
                try:
                    if ext not in SKIP_EXT and 0 < os.path.getsize(fp) < 1048576: files.append(fp)
                except OSError: pass
    print(f"[*] Scanning {len(files)} file(s)...\n")
    all_f = []
    for fp in files:
        findings = [f for f in scan_file(fp) if sev_map.get(f["severity"],3) <= min_s]
        if findings:
            print(f"  {fp}")
            for f in findings:
                icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(f["severity"],"[*]")
                print(f"    {icon} [{f['severity']}] {f['type']} (line {f['line']}): {f['match']}")
            print()
            for f in findings: f["file"] = fp
            all_f.extend(findings)
    print(f"{'='*60}\n[*] Files: {len(files)} | Secrets: {len(all_f)}")
    summary = {}
    for f in all_f: summary[f["severity"]] = summary.get(f["severity"],0) + 1
    for s in ["CRITICAL","HIGH","MEDIUM"]:
        if s in summary: print(f"  {s}: {summary[s]}")
    if all_f: print("\n[!] Rotate exposed secrets immediately")
    else: print("[+] No secrets detected")

if __name__ == "__main__":
    main()
