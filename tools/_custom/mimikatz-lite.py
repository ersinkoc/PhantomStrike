#!/usr/bin/env python3
"""Credential checker: test for common credential leaks (.env, git config, debug endpoints)."""
import argparse
import re
import sys
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CREDENTIAL_PATHS = [
    ("/.env", "Environment file", "CRITICAL"),
    ("/.env.bak", "Environment backup", "CRITICAL"),
    ("/.env.local", "Local environment file", "CRITICAL"),
    ("/.env.production", "Production environment file", "CRITICAL"),
    ("/.env.development", "Development environment file", "CRITICAL"),
    ("/.git/config", "Git configuration", "HIGH"),
    ("/.git/HEAD", "Git HEAD reference", "HIGH"),
    ("/.gitconfig", "Git user config", "MEDIUM"),
    ("/.svn/entries", "SVN entries", "HIGH"),
    ("/.hg/hgrc", "Mercurial config", "HIGH"),
    ("/wp-config.php.bak", "WordPress config backup", "CRITICAL"),
    ("/wp-config.php.old", "WordPress config old", "CRITICAL"),
    ("/wp-config.php.save", "WordPress config save", "CRITICAL"),
    ("/config.php.bak", "PHP config backup", "CRITICAL"),
    ("/configuration.php.bak", "Joomla config backup", "CRITICAL"),
    ("/web.config", "ASP.NET config", "HIGH"),
    ("/web.config.bak", "ASP.NET config backup", "CRITICAL"),
    ("/appsettings.json", "ASP.NET Core settings", "HIGH"),
    ("/config/database.yml", "Rails database config", "CRITICAL"),
    ("/config/secrets.yml", "Rails secrets", "CRITICAL"),
    ("/config/master.key", "Rails master key", "CRITICAL"),
    ("/phpinfo.php", "PHP info page", "MEDIUM"),
    ("/info.php", "PHP info page", "MEDIUM"),
    ("/.htpasswd", "Apache password file", "CRITICAL"),
    ("/.htaccess", "Apache access config", "MEDIUM"),
    ("/server-status", "Apache server status", "MEDIUM"),
    ("/server-info", "Apache server info", "MEDIUM"),
    ("/.DS_Store", "macOS directory metadata", "LOW"),
    ("/debug", "Debug endpoint", "MEDIUM"),
    ("/_debug", "Debug endpoint", "MEDIUM"),
    ("/debug/vars", "Go debug vars", "HIGH"),
    ("/debug/pprof/", "Go profiling", "HIGH"),
    ("/actuator/env", "Spring Actuator env", "CRITICAL"),
    ("/actuator/configprops", "Spring config properties", "CRITICAL"),
    ("/actuator/heapdump", "Spring heap dump", "CRITICAL"),
    ("/console", "Debug console", "HIGH"),
    ("/__debug__/", "Django debug toolbar", "HIGH"),
    ("/telescope", "Laravel Telescope", "HIGH"),
    ("/_debugbar/open", "Laravel debugbar", "HIGH"),
    ("/storage/logs/laravel.log", "Laravel log file", "HIGH"),
    ("/elmah.axd", "ASP.NET error log", "HIGH"),
    ("/trace.axd", "ASP.NET trace", "HIGH"),
    ("/crossdomain.xml", "Flash crossdomain policy", "LOW"),
    ("/clientaccesspolicy.xml", "Silverlight policy", "LOW"),
    ("/api/swagger.json", "Swagger API docs", "LOW"),
    ("/swagger-ui.html", "Swagger UI", "LOW"),
    ("/graphql", "GraphQL endpoint", "MEDIUM"),
    ("/.well-known/security.txt", "Security contact", "INFO"),
    ("/robots.txt", "Robots.txt", "INFO"),
    ("/sitemap.xml", "Sitemap", "INFO"),
    ("/package.json", "Node.js package file", "MEDIUM"),
    ("/composer.json", "PHP Composer file", "LOW"),
    ("/Gemfile", "Ruby Gemfile", "LOW"),
    ("/requirements.txt", "Python requirements", "LOW"),
    ("/backup.sql", "SQL backup", "CRITICAL"),
    ("/dump.sql", "SQL dump", "CRITICAL"),
    ("/database.sql", "SQL database dump", "CRITICAL"),
    ("/db.sql", "SQL database dump", "CRITICAL"),
]

CREDENTIAL_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{3,})", "Password in config"),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([^\s'\"]{10,})", "API key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([^\s'\"]{10,})", "Secret key"),
    (r"(?i)(access[_-]?token|token)\s*[=:]\s*['\"]?([^\s'\"]{10,})", "Access token"),
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*['\"]?([A-Z0-9]{16,})", "AWS Access Key"),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{30,})", "AWS Secret Key"),
    (r"(?i)(database[_-]?url|db[_-]?url|mongodb[_-]?uri)\s*[=:]\s*['\"]?([^\s'\"]{10,})", "Database URL"),
    (r"(?i)(smtp[_-]?password|mail[_-]?password)\s*[=:]\s*['\"]?([^\s'\"]{3,})", "Mail password"),
    (r"(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{20,})", "Private key reference"),
    (r"(ghp_[a-zA-Z0-9]{36})", "GitHub Personal Access Token"),
    (r"(sk-[a-zA-Z0-9]{32,})", "OpenAI/Stripe Secret Key"),
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID"),
    (r"(xox[bpras]-[0-9a-zA-Z-]{10,})", "Slack Token"),
    (r"(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in response"),
]


def check_path(session, base_url, path, description, severity, timeout):
    url = urljoin(base_url, path)
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code == 200 and len(r.content) > 0:
            body = r.text[:5000]
            # Filter false positives
            if "404" in body[:200].lower() and "not found" in body[:200].lower():
                return None
            if r.headers.get("Content-Type", "").startswith("text/html") and len(body) < 100:
                return None

            credentials_found = []
            for pattern, cred_type in CREDENTIAL_PATTERNS:
                matches = re.findall(pattern, body)
                if matches:
                    for match in matches[:3]:
                        if isinstance(match, tuple):
                            key = match[0]
                            val = match[1][:20] + "..." if len(match[1]) > 20 else match[1]
                            credentials_found.append(f"{cred_type}: {key}={val}")
                        else:
                            credentials_found.append(f"{cred_type}: {match[:30]}...")

            return {
                "path": path, "url": url, "description": description, "severity": severity,
                "status": r.status_code, "size": len(r.content),
                "content_type": r.headers.get("Content-Type", ""),
                "credentials": credentials_found,
            }
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description="Mimikatz-lite: Credential leak checker")
    ap.add_argument("target", help="Target URL (e.g., http://example.com)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--quick", action="store_true", help="Quick scan (top 20 paths only)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show all tested paths")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    target = target.rstrip("/")

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 CredChecker"

    paths = CREDENTIAL_PATHS[:20] if args.quick else CREDENTIAL_PATHS

    print(f"[*] Mimikatz-Lite: Credential Leak Checker")
    print(f"[*] Target: {target}")
    print(f"[*] Checking {len(paths)} paths\n")

    all_findings = []
    tested = 0

    for path, desc, severity in paths:
        tested += 1
        if args.verbose:
            print(f"  [*] Testing: {path}")
        result = check_path(session, target, path, desc, severity, args.timeout)
        if result:
            cred_info = ""
            if result["credentials"]:
                cred_info = f" [CREDENTIALS: {len(result['credentials'])}]"
                result["severity"] = "CRITICAL"
            print(f"  [{result['severity']}] {result['path']:<40} ({result['description']}){cred_info}")
            print(f"         Status: {result['status']} | Size: {result['size']} bytes | Type: {result['content_type'][:40]}")
            for cred in result["credentials"]:
                print(f"         >>> {cred}")
            all_findings.append(result)

    print(f"\n{'='*60}")
    print(f"[*] CREDENTIAL LEAK REPORT")
    print(f"{'='*60}\n")
    print(f"  Target: {target}")
    print(f"  Paths tested: {tested}")
    print(f"  Findings: {len(all_findings)}\n")

    if all_findings:
        crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in all_findings if f["severity"] == "HIGH")
        med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in all_findings if f["severity"] in ("LOW", "INFO"))
        print(f"  Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM, {low} LOW/INFO\n")

        cred_count = sum(len(f["credentials"]) for f in all_findings)
        if cred_count > 0:
            print(f"  [!!!] {cred_count} CREDENTIAL PATTERN(S) FOUND IN EXPOSED FILES")
            print(f"  [!!!] Immediate remediation required!\n")
            print(f"  Exposed credentials:")
            for f in all_findings:
                for cred in f["credentials"]:
                    print(f"    {f['path']}: {cred}")

        print(f"\n  Exposed files:")
        for f in all_findings:
            print(f"    [{f['severity']}] {f['url']}")
    else:
        print("  [OK] No credential leaks detected")


if __name__ == "__main__":
    main()
