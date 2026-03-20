#!/usr/bin/env python3
"""Detect and test web frameworks: identify version, check known misconfigurations."""
import argparse
import re
import sys
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FRAMEWORK_SIGNATURES = {
    "WordPress": {
        "detect": [r"wp-content", r"wp-includes", r"wp-json", r"/xmlrpc\.php"],
        "version_paths": ["/readme.html", "/wp-includes/version.php", "/feed/"],
        "version_pattern": r"(?:Version|ver(?:sion)?)\s*([\d.]+)",
        "misconfig_paths": [
            ("/wp-json/wp/v2/users", "User enumeration via REST API"),
            ("/xmlrpc.php", "XML-RPC enabled (brute-force/DDoS risk)"),
            ("/?author=1", "User enumeration via author parameter"),
            ("/wp-config.php.bak", "Backup config file exposed"),
            ("/wp-admin/install.php", "Installation script accessible"),
            ("/wp-content/debug.log", "Debug log exposed"),
        ],
    },
    "Django": {
        "detect": [r"csrfmiddlewaretoken", r"django", r"__debug__"],
        "version_paths": [],
        "version_pattern": r"Django[/ ]([\d.]+)",
        "misconfig_paths": [
            ("/__debug__/", "Django Debug Toolbar exposed"),
            ("/admin/", "Admin interface accessible"),
            ("/static/admin/", "Admin static files confirm Django"),
        ],
    },
    "Laravel": {
        "detect": [r"laravel_session", r"Laravel", r"XSRF-TOKEN"],
        "version_paths": [],
        "version_pattern": r"Laravel[/ v]*([\d.]+)",
        "misconfig_paths": [
            ("/.env", "Environment file exposed"),
            ("/storage/logs/laravel.log", "Log file exposed"),
            ("/telescope", "Telescope debug tool exposed"),
            ("/_debugbar/open", "Debug bar exposed"),
        ],
    },
    "Express/Node.js": {
        "detect": [r"X-Powered-By.*Express", r"connect\.sid"],
        "version_paths": [],
        "version_pattern": r"Express[/ ]([\d.]+)",
        "misconfig_paths": [
            ("/package.json", "package.json exposed"),
            ("/.env", "Environment file exposed"),
            ("/server.js", "Server source exposed"),
        ],
    },
    "ASP.NET": {
        "detect": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net", r"X-AspNet-Version"],
        "version_paths": [],
        "version_pattern": r"ASP\.NET[/ ]?([\d.]+)|X-AspNet-Version:\s*([\d.]+)",
        "misconfig_paths": [
            ("/web.config", "Web.config exposed"),
            ("/trace.axd", "Trace information exposed"),
            ("/elmah.axd", "Error log exposed"),
        ],
    },
    "Spring Boot": {
        "detect": [r"Whitelabel Error Page", r"Spring", r"spring-boot"],
        "version_paths": ["/actuator/info"],
        "version_pattern": r"Spring Boot[/ ]([\d.]+)|\"version\":\"([\d.]+)\"",
        "misconfig_paths": [
            ("/actuator", "Spring Actuator endpoints exposed"),
            ("/actuator/env", "Environment variables exposed"),
            ("/actuator/health", "Health endpoint accessible"),
            ("/actuator/mappings", "URL mappings exposed"),
            ("/actuator/configprops", "Configuration properties exposed"),
            ("/actuator/heapdump", "Heap dump accessible"),
        ],
    },
    "Flask": {
        "detect": [r"Werkzeug", r"flask"],
        "version_paths": [],
        "version_pattern": r"Werkzeug[/ ]([\d.]+)",
        "misconfig_paths": [
            ("/console", "Werkzeug debugger console exposed"),
        ],
    },
    "Ruby on Rails": {
        "detect": [r"_rails", r"X-Runtime", r"Rails"],
        "version_paths": [],
        "version_pattern": r"Rails[/ ]([\d.]+)",
        "misconfig_paths": [
            ("/rails/info/properties", "Rails info page exposed"),
            ("/rails/mailers", "Mailer previews accessible"),
        ],
    },
    "nginx": {
        "detect": [r"Server: nginx"],
        "version_paths": [],
        "version_pattern": r"nginx/([\d.]+)",
        "misconfig_paths": [
            ("/nginx_status", "Nginx status page exposed"),
            ("/.git/config", "Git repository exposed behind nginx"),
        ],
    },
    "Apache": {
        "detect": [r"Server: Apache"],
        "version_paths": [],
        "version_pattern": r"Apache/([\d.]+)",
        "misconfig_paths": [
            ("/server-status", "Apache server-status exposed"),
            ("/server-info", "Apache server-info exposed"),
            ("/.htaccess", "htaccess file readable"),
        ],
    },
}


def detect_frameworks(session, url, timeout):
    detected = []
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        body = resp.text
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        combined = body + "\n" + headers_str
        for name, sig in FRAMEWORK_SIGNATURES.items():
            for pattern in sig["detect"]:
                if re.search(pattern, combined, re.I):
                    version = None
                    m = re.search(sig["version_pattern"], combined, re.I)
                    if m:
                        version = next((g for g in m.groups() if g), None)
                    detected.append({"name": name, "version": version, "confidence": "high"})
                    break
    except Exception as e:
        print(f"  [!] Error fetching page: {e}", file=sys.stderr)
    return detected


def check_version_paths(session, url, framework, timeout):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sig = FRAMEWORK_SIGNATURES.get(framework, {})
    versions = []
    for path in sig.get("version_paths", []):
        try:
            r = session.get(f"{base}{path}", timeout=timeout, verify=False)
            if r.status_code == 200:
                m = re.search(sig["version_pattern"], r.text, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), None)
                    if ver:
                        versions.append({"path": path, "version": ver})
        except Exception:
            continue
    return versions


def check_misconfigs(session, url, framework, timeout):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sig = FRAMEWORK_SIGNATURES.get(framework, {})
    findings = []
    for path, desc in sig.get("misconfig_paths", []):
        try:
            r = session.get(f"{base}{path}", timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                if "404" not in r.text[:300].lower() and "not found" not in r.text[:300].lower():
                    findings.append({"path": path, "description": desc, "status": r.status_code,
                                     "size": len(r.content), "severity": "HIGH" if "exposed" in desc.lower() else "MEDIUM"})
        except Exception:
            continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="HTTP Framework Detector and Tester")
    ap.add_argument("target", help="Target URL")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--skip-misconfig", action="store_true", help="Skip misconfiguration checks")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 FrameworkTest"

    print(f"[*] HTTP Framework Detector & Tester")
    print(f"[*] Target: {target}\n")

    print("[*] Phase 1: Framework Detection...")
    detected = detect_frameworks(session, target, args.timeout)
    if detected:
        for fw in detected:
            ver_str = f" v{fw['version']}" if fw['version'] else ""
            print(f"  [+] {fw['name']}{ver_str} (confidence: {fw['confidence']})")
    else:
        print("  [!] No known framework detected")

    all_findings = []
    for fw in detected:
        print(f"\n[*] Phase 2: Checking {fw['name']} version info...")
        versions = check_version_paths(session, target, fw["name"], args.timeout)
        for v in versions:
            print(f"  [+] Version {v['version']} found at {v['path']}")

        if not args.skip_misconfig:
            print(f"[*] Phase 3: Testing {fw['name']} misconfigurations...")
            misconfigs = check_misconfigs(session, target, fw["name"], args.timeout)
            for mc in misconfigs:
                print(f"  [{mc['severity']}] {mc['description']}")
                print(f"    Path: {mc['path']} (status: {mc['status']}, size: {mc['size']})")
                all_findings.append(mc)

    print(f"\n{'='*60}")
    print(f"[*] RESULTS SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Frameworks detected: {len(detected)}")
    for fw in detected:
        ver_str = f" v{fw['version']}" if fw['version'] else ""
        print(f"    - {fw['name']}{ver_str}")
    print(f"\n  Misconfigurations: {len(all_findings)}")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"  Severity: {high} HIGH, {med} MEDIUM")


if __name__ == "__main__":
    main()
