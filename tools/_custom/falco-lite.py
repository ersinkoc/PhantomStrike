#!/usr/bin/env python3
"""Container security rules checker: validate Docker/K8s configs against security best practices."""
import argparse, json, os, re, sys

RULES = [
    ("K8S-001", "CRITICAL", r"privileged:\s*true", "Privileged container"),
    ("K8S-002", "CRITICAL", r"hostPID:\s*true", "Host PID namespace shared"),
    ("K8S-003", "CRITICAL", r"hostNetwork:\s*true", "Host network namespace shared"),
    ("K8S-004", "HIGH", r"runAsUser:\s*0", "Running as root UID 0"),
    ("K8S-005", "HIGH", r"readOnlyRootFilesystem:\s*false", "Writable root filesystem"),
    ("K8S-006", "HIGH", r"(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)", "Dangerous capability"),
    ("K8S-007", "MEDIUM", r"image:.*:latest", "Using :latest tag"),
    ("K8S-008", "CRITICAL", r"(PASSWORD|SECRET|API_KEY|PRIVATE_KEY)\s*:", "Secret in env var"),
    ("K8S-009", "HIGH", r"hostPath:", "hostPath volume mount"),
    ("K8S-010", "HIGH", r"allowPrivilegeEscalation:\s*true", "Privilege escalation allowed"),
    ("K8S-011", "MEDIUM", r"automountServiceAccountToken:\s*true", "SA token auto-mounted"),
    ("K8S-012", "CRITICAL", r"/var/run/docker\.sock", "Docker socket mounted"),
    ("K8S-013", "HIGH", r"cap_add:.*ALL", "ALL capabilities granted"),
    ("K8S-014", "MEDIUM", r"ports:.*0\.0\.0\.0", "Port bound to all interfaces"),
    ("K8S-015", "MEDIUM", r"network_mode:\s*host", "Host network mode"),
]

def check_content(content, filename):
    findings = []
    for rid, sev, pat, name in RULES:
        for m in re.finditer(pat, content, re.IGNORECASE):
            line = content[:m.start()].count("\n") + 1
            findings.append({"id": rid, "severity": sev, "name": name,
                             "line": line, "match": m.group()[:50]})
    is_k8s = "apiVersion:" in content
    if is_k8s and "securityContext" not in content:
        findings.append({"id": "K8S-SC", "severity": "MEDIUM", "name": "No securityContext",
                         "line": 0, "match": ""})
    if is_k8s and "livenessProbe" not in content and "Deployment" in content:
        findings.append({"id": "K8S-LP", "severity": "MEDIUM", "name": "No livenessProbe",
                         "line": 0, "match": ""})
    if is_k8s and "resources:" not in content and ("Deployment" in content or "Pod" in content):
        findings.append({"id": "K8S-RL", "severity": "HIGH", "name": "No resource limits",
                         "line": 0, "match": ""})
    return findings

def scan_dir(path):
    exts = {".yaml", ".yml", ".json"}
    names = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
    files = []
    if os.path.isfile(path): return [path]
    for root, dirs, fnames in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for f in fnames:
            if os.path.splitext(f)[1].lower() in exts or f in names:
                files.append(os.path.join(root, f))
    return files

def main():
    parser = argparse.ArgumentParser(description="Container/K8s security rules checker")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"], default="MEDIUM")
    args = parser.parse_args()
    sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_s = sev_ord[args.severity]
    print(f"[*] Falco-Lite - Container Security Rules\n[*] Target: {args.target}\n")
    files = scan_dir(args.target)
    print(f"[*] Found {len(files)} config file(s)\n")
    all_f = []
    for fp in files:
        try:
            with open(fp) as f: content = f.read()
        except Exception as e: print(f"[!] {fp}: {e}"); continue
        findings = [f for f in check_content(content, os.path.basename(fp))
                    if sev_ord.get(f["severity"], 3) <= min_s]
        if findings:
            print(f"=== {fp} ===")
            for f in sorted(findings, key=lambda x: sev_ord.get(x["severity"], 3)):
                icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(f["severity"],"[*]")
                ln = f" (line {f['line']})" if f["line"] > 0 else ""
                print(f"  {icon} {f['id']} [{f['severity']}] {f['name']}{ln}")
                if f["match"]: print(f"      {f['match']}")
            print()
            all_f.extend(findings)
    print(f"{'='*50}\n[*] Files: {len(files)} | Findings: {len(all_f)}")
    summary = {}
    for f in all_f: summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    for s in ["CRITICAL","HIGH","MEDIUM"]:
        if s in summary: print(f"  {s}: {summary[s]}")
    if not all_f: print("[+] No issues found!")

if __name__ == "__main__":
    main()
