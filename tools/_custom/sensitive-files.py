#!/usr/bin/env python3
"""Check for exposed sensitive files and directories."""
import argparse
import sys
from urllib.parse import urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sensitive files grouped by category
SENSITIVE_FILES = {
    "Configuration Files": [
        (".env", "Environment variables - may contain secrets"),
        (".env.bak", "Backup environment file"),
        (".env.local", "Local environment overrides"),
        (".env.production", "Production environment variables"),
        ("config.php", "PHP configuration"),
        ("config.yml", "YAML configuration"),
        ("config.json", "JSON configuration"),
        ("wp-config.php", "WordPress configuration"),
        ("wp-config.php.bak", "WordPress config backup"),
        ("wp-config.php.old", "WordPress config old"),
        ("configuration.php", "Joomla configuration"),
        ("web.config", "IIS/ASP.NET configuration"),
        ("appsettings.json", "ASP.NET app settings"),
        (".htaccess", "Apache configuration"),
        (".htpasswd", "Apache password file"),
        ("nginx.conf", "Nginx configuration"),
    ],
    "Version Control": [
        (".git/config", "Git configuration (repo exposure)"),
        (".git/HEAD", "Git HEAD reference"),
        (".gitignore", "Git ignore rules (info disclosure)"),
        (".svn/entries", "SVN repository data"),
        (".svn/wc.db", "SVN working copy database"),
        (".hg/hgrc", "Mercurial configuration"),
    ],
    "Backup Files": [
        ("backup.sql", "SQL database backup"),
        ("backup.zip", "Backup archive"),
        ("backup.tar.gz", "Backup archive"),
        ("db.sql", "Database dump"),
        ("database.sql", "Database dump"),
        ("dump.sql", "Database dump"),
        ("site.tar.gz", "Site backup archive"),
        ("www.zip", "Web root backup"),
    ],
    "Debug / Info": [
        ("phpinfo.php", "PHP information page"),
        ("info.php", "PHP info page"),
        ("test.php", "Test PHP script"),
        ("debug.php", "Debug script"),
        ("server-status", "Apache server status"),
        ("server-info", "Apache server info"),
        ("elmah.axd", "ASP.NET error log"),
        ("trace.axd", "ASP.NET trace"),
    ],
    "Credentials / Keys": [
        (".ssh/id_rsa", "SSH private key"),
        (".ssh/authorized_keys", "SSH authorized keys"),
        ("id_rsa", "SSH private key"),
        ("id_rsa.pub", "SSH public key"),
        ("credentials.json", "Credentials file"),
        ("secrets.json", "Secrets file"),
        ("api_keys.json", "API keys file"),
        (".aws/credentials", "AWS credentials"),
        (".docker/config.json", "Docker config with auth"),
    ],
    "Documentation / Metadata": [
        ("robots.txt", "Robots exclusion (may reveal paths)"),
        ("sitemap.xml", "Site map (reveals structure)"),
        ("crossdomain.xml", "Flash cross-domain policy"),
        ("clientaccesspolicy.xml", "Silverlight access policy"),
        ("security.txt", "Security contact info"),
        (".well-known/security.txt", "Security contact info"),
        ("humans.txt", "Human-readable site info"),
        ("readme.html", "Readme file (version disclosure)"),
        ("README.md", "Readme file"),
        ("CHANGELOG.md", "Change log (version disclosure)"),
        ("composer.json", "PHP dependencies"),
        ("package.json", "Node.js dependencies"),
        ("Gemfile", "Ruby dependencies"),
        ("requirements.txt", "Python dependencies"),
    ],
}


def check_file(session, base_url, path, timeout):
    """Check if a sensitive file is accessible."""
    url = urljoin(base_url.rstrip("/") + "/", path)
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        size = len(resp.content)

        # Determine if the file actually exists (not just a custom 404)
        is_found = False
        if resp.status_code == 200 and size > 0:
            # Filter out custom 404 pages (usually large HTML)
            content_type = resp.headers.get("Content-Type", "")
            if size < 50 and "html" in content_type:
                is_found = False  # Probably a tiny redirect or empty page
            elif "not found" in resp.text.lower()[:500] or "404" in resp.text[:200]:
                is_found = False
            else:
                is_found = True
        elif resp.status_code == 403:
            is_found = True  # Exists but forbidden - still interesting

        return {
            "url": url,
            "status": resp.status_code,
            "size": size,
            "found": is_found,
            "content_type": resp.headers.get("Content-Type", "unknown"),
        }
    except Exception:
        return None


def parse_robots_txt(session, base_url, timeout):
    """Parse robots.txt for interesting disallowed paths."""
    interesting_paths = []
    url = urljoin(base_url, "/robots.txt")
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            for line in resp.text.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        interesting_paths.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    interesting_paths.append(f"SITEMAP: {sitemap_url}")
    except Exception:
        pass
    return interesting_paths


def assess_severity(path, status):
    """Assess the severity of a found file."""
    critical_patterns = [".env", "credentials", "secrets", "api_key", "id_rsa",
                         ".aws", "wp-config", ".htpasswd", "backup.sql", "db.sql",
                         "dump.sql", "database.sql"]
    high_patterns = [".git/", ".svn/", "phpinfo", "server-status", "server-info",
                     "config.php", "web.config", "appsettings", ".docker"]
    medium_patterns = [".htaccess", "backup", ".zip", ".tar.gz", "composer.json",
                       "package.json", "requirements.txt", "elmah", "trace.axd"]

    path_lower = path.lower()
    if any(p in path_lower for p in critical_patterns):
        return "CRITICAL"
    if any(p in path_lower for p in high_patterns):
        return "HIGH"
    if any(p in path_lower for p in medium_patterns):
        return "MEDIUM"
    if status == 403:
        return "LOW"
    return "INFO"


def main():
    parser = argparse.ArgumentParser(description="Sensitive file exposure checker")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--category", help="Check specific category only")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; PhantomStrike/1.0)"

    total_checks = sum(len(files) for files in SENSITIVE_FILES.values())
    print(f"[*] Sensitive Files Checker - Target: {target}")
    print(f"[*] Checking {total_checks} paths across {len(SENSITIVE_FILES)} categories\n")

    # Get a baseline 404 response for comparison
    baseline = check_file(session, target, "/__phantomstrike_nonexistent_404__", args.timeout)
    baseline_size = baseline["size"] if baseline else 0

    all_findings = []

    for category, files in SENSITIVE_FILES.items():
        if args.category and args.category.lower() not in category.lower():
            continue

        print(f"=== {category} ===\n")
        category_found = False

        for path, description in files:
            result = check_file(session, target, path, args.timeout)
            if result is None:
                continue

            # Additional 404 detection: compare size with baseline
            if result["found"] and baseline_size > 0:
                if abs(result["size"] - baseline_size) < 50 and result["status"] == 200:
                    result["found"] = False  # Likely a custom 404 with same size

            if result["found"]:
                severity = assess_severity(path, result["status"])
                finding = {
                    "path": path,
                    "description": description,
                    "severity": severity,
                    **result,
                }
                all_findings.append(finding)
                category_found = True

                size_str = f"{result['size']}B" if result['size'] < 1024 else f"{result['size']//1024}KB"
                print(f"  [{severity}] /{path}")
                print(f"         Status: {result['status']} | Size: {size_str} | Type: {result['content_type']}")
                print(f"         {description}")
                print()

        if not category_found:
            print(f"  [OK] No sensitive files found\n")

    # Check robots.txt for interesting paths
    print("=== Robots.txt Analysis ===\n")
    robot_paths = parse_robots_txt(session, target, args.timeout)
    if robot_paths:
        for path in robot_paths[:15]:
            print(f"  [INFO] {path}")
        if len(robot_paths) > 15:
            print(f"  ... and {len(robot_paths) - 15} more")
    else:
        print(f"  [INFO] No robots.txt or no disallowed paths")

    # Summary
    print(f"\n{'='*50}")
    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"[*] Files found: {len(all_findings)}")
    print(f"[*] Severity: {crit} CRITICAL, {high} HIGH, {med} MEDIUM")
    if crit > 0:
        print(f"[!] CRITICAL: Sensitive files exposed - immediate remediation needed")
    elif high > 0:
        print(f"[!] HIGH: Configuration/debug files exposed")


if __name__ == "__main__":
    main()
