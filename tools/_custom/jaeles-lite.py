#!/usr/bin/env python3
"""Signature-based web scanner: test for common vulns using pattern matching."""
import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SIGNATURES = [
    {
        "id": "SQL-ERROR-001", "name": "SQL Error Disclosure", "severity": "HIGH", "category": "SQL Injection",
        "payloads": ["'", "\"", "' OR '1'='1", "1' AND '1'='2"],
        "patterns": [r"SQL syntax.*MySQL", r"Warning.*\Wmysql_", r"PostgreSQL.*ERROR", r"ORA-\d{5}",
                     r"SQLITE_ERROR", r"Unclosed quotation mark", r"syntax error at or near",
                     r"Microsoft.*ODBC.*SQL Server", r"com\.mysql\.jdbc", r"org\.postgresql\.util"]
    },
    {
        "id": "XSS-REFLECT-001", "name": "Reflected XSS", "severity": "HIGH", "category": "Cross-Site Scripting",
        "payloads": ["<script>alert(9)</script>", "\"><img src=x onerror=alert(9)>", "<svg/onload=alert(9)>"],
        "patterns": [r"<script>alert\(9\)</script>", r"onerror=alert\(9\)", r"onload=alert\(9\)"]
    },
    {
        "id": "INFO-STACK-001", "name": "Stack Trace Disclosure", "severity": "MEDIUM", "category": "Information Leak",
        "payloads": ["", "'", "{{invalid}}", "%00"],
        "patterns": [r"Traceback \(most recent call last\)", r"at\s+[\w.$]+\([\w]+\.java:\d+\)",
                     r"Exception in thread", r"Fatal error:.*on line \d+", r"Stack trace:",
                     r"Microsoft\.AspNetCore", r"System\.NullReferenceException"]
    },
    {
        "id": "INFO-DEBUG-001", "name": "Debug Information", "severity": "MEDIUM", "category": "Information Leak",
        "payloads": [""],
        "patterns": [r"DJANGO_SETTINGS_MODULE", r"settings\.DEBUG\s*=\s*True", r"Whoops!.*error",
                     r"Laravel.*exception", r"Symfony.*Exception", r"PHP Fatal error",
                     r"display_errors\s*=\s*On", r"WEB-INF/web\.xml"]
    },
    {
        "id": "INFO-SERVER-001", "name": "Server Version Disclosure", "severity": "LOW", "category": "Information Leak",
        "payloads": [""],
        "check_headers": True,
        "header_patterns": {"Server": r"(Apache|nginx|IIS|Tomcat|Jetty)/[\d.]+", "X-Powered-By": r".+"}
    },
    {
        "id": "LFI-001", "name": "Local File Inclusion", "severity": "CRITICAL", "category": "File Inclusion",
        "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd",
                     "..\\..\\..\\windows\\win.ini"],
        "patterns": [r"root:x:0:0:", r"root:\*:0:0:", r"\[extensions\]", r"for 16-bit app support"]
    },
    {
        "id": "SSTI-001", "name": "Server-Side Template Injection", "severity": "HIGH", "category": "Injection",
        "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"],
        "patterns": [r"\b49\b"]
    },
    {
        "id": "REDIRECT-001", "name": "Open Redirect", "severity": "MEDIUM", "category": "Redirect",
        "payloads": ["//evil.com", "https://evil.com", "/\\evil.com"],
        "check_redirect": True,
        "redirect_pattern": r"evil\.com"
    },
    {
        "id": "INFO-BACKUP-001", "name": "Backup File Exposure", "severity": "MEDIUM", "category": "Information Leak",
        "paths": [".bak", "~", ".old", ".swp", ".save", ".orig", ".copy"],
        "check_path_suffix": True,
        "success_codes": [200]
    },
    {
        "id": "INFO-SENSITIVE-001", "name": "Sensitive Endpoint", "severity": "MEDIUM", "category": "Information Leak",
        "paths": ["/.env", "/.git/config", "/wp-config.php.bak", "/server-status", "/server-info",
                  "/phpinfo.php", "/.htaccess", "/web.config", "/crossdomain.xml", "/robots.txt"],
        "check_path": True,
        "success_codes": [200]
    },
]


def test_signature(session, base_url, params, sig, timeout):
    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    if sig.get("check_path"):
        for path in sig["paths"]:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            try:
                r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code in sig.get("success_codes", [200]):
                    if len(r.content) > 0 and "404" not in r.text[:200].lower():
                        findings.append({"sig_id": sig["id"], "name": sig["name"], "severity": sig["severity"],
                                         "url": url, "detail": f"Accessible ({r.status_code}), {len(r.content)} bytes"})
            except Exception:
                continue
        return findings

    if sig.get("check_path_suffix"):
        for suffix in sig["paths"]:
            url = f"{base}{suffix}"
            try:
                r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code in sig.get("success_codes", [200]):
                    findings.append({"sig_id": sig["id"], "name": sig["name"], "severity": sig["severity"],
                                     "url": url, "detail": f"Backup file accessible ({r.status_code})"})
            except Exception:
                continue
        return findings

    if not params:
        params = {"_test_": [""]}

    for param in params:
        for payload in sig.get("payloads", [""]):
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            try:
                if sig.get("check_redirect"):
                    r = session.get(base, params=test_params, timeout=timeout, verify=False, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if r.status_code in (301, 302, 303, 307, 308) and re.search(sig["redirect_pattern"], loc):
                        findings.append({"sig_id": sig["id"], "name": sig["name"], "severity": sig["severity"],
                                         "url": base, "detail": f"Redirect to: {loc[:60]} via param={param}"})
                else:
                    r = session.get(base, params=test_params, timeout=timeout, verify=False)
                    if sig.get("check_headers"):
                        for header, pattern in sig.get("header_patterns", {}).items():
                            val = r.headers.get(header, "")
                            if val and re.search(pattern, val):
                                findings.append({"sig_id": sig["id"], "name": sig["name"], "severity": sig["severity"],
                                                 "url": base, "detail": f"{header}: {val}"})
                    for pattern in sig.get("patterns", []):
                        if re.search(pattern, r.text, re.I):
                            match = re.search(pattern, r.text, re.I).group()[:80]
                            findings.append({"sig_id": sig["id"], "name": sig["name"], "severity": sig["severity"],
                                             "url": base, "detail": f"Match: {match} (param={param}, payload={payload[:30]})"})
                            break
            except Exception:
                continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="Jaeles-lite: Signature-based web scanner")
    ap.add_argument("target", help="Target URL")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Minimum severity")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)

    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_sev = sev_order.get(args.severity, 0)

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 Jaeles-Lite"

    print(f"[*] Jaeles-Lite: Signature-Based Scanner")
    print(f"[*] Target: {target}")
    print(f"[*] Signatures: {len(SIGNATURES)}")
    print(f"[*] Min severity: {args.severity or 'ALL'}\n")

    all_findings = []
    for sig in SIGNATURES:
        if sev_order.get(sig["severity"], 0) < min_sev:
            continue
        print(f"  [*] Testing: {sig['id']} - {sig['name']}")
        findings = test_signature(session, target, params, sig, args.timeout)
        all_findings.extend(findings)
        if findings:
            for f in findings:
                print(f"    [{f['severity']}] {f['detail'][:70]}")

    print(f"\n{'='*60}")
    print(f"[*] SCAN RESULTS")
    print(f"{'='*60}\n")
    if all_findings:
        for i, f in enumerate(all_findings, 1):
            print(f"  [{f['severity']}] #{i} {f['name']} ({f['sig_id']})")
            print(f"    URL:    {f['url']}")
            print(f"    Detail: {f['detail']}\n")
    else:
        print("  [OK] No vulnerabilities detected\n")

    by_sev = {}
    for f in all_findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    parts = [f"{v} {k}" for k, v in sorted(by_sev.items(), key=lambda x: sev_order.get(x[0], 0), reverse=True)]
    print(f"[*] Total: {len(all_findings)} findings ({', '.join(parts) if parts else 'none'})")


if __name__ == "__main__":
    main()
