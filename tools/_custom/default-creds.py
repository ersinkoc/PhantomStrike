#!/usr/bin/env python3
"""Check for default credentials on common services."""
import argparse
import sys
from urllib.parse import urljoin, urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Login paths to check
LOGIN_PATHS = [
    ("/admin/", "Generic Admin"),
    ("/login", "Generic Login"),
    ("/login/", "Generic Login"),
    ("/wp-login.php", "WordPress"),
    ("/wp-admin/", "WordPress Admin"),
    ("/administrator/", "Joomla Admin"),
    ("/admin/login", "Admin Login"),
    ("/user/login", "Drupal/Generic"),
    ("/manager/html", "Tomcat Manager"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/adminer.php", "Adminer"),
    ("/jenkins/login", "Jenkins"),
    ("/grafana/login", "Grafana"),
    ("/kibana/", "Kibana"),
]

# Default credential pairs
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
]

# Service-specific credentials
SERVICE_CREDS = {
    "WordPress": [("admin", "admin"), ("admin", "password"), ("admin", "wordpress")],
    "Joomla Admin": [("admin", "admin"), ("admin", "joomla")],
    "Tomcat Manager": [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret"),
                        ("manager", "manager"), ("admin", "tomcat")],
    "phpMyAdmin": [("root", ""), ("root", "root"), ("root", "mysql"), ("pma", "")],
    "Jenkins": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
    "Grafana": [("admin", "admin"), ("admin", "grafana")],
    "Adminer": [("root", ""), ("root", "root"), ("admin", "admin")],
}

# Common form field names for username/password
USERNAME_FIELDS = ["username", "user", "login", "email", "log", "usr", "user_login", "name"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd", "user_pass", "secret"]


def find_login_pages(session, base_url, timeout):
    """Find login pages on the target."""
    found_pages = []
    for path, service in LOGIN_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                # Check if it looks like a login page
                has_form = "<form" in body_lower
                has_password = 'type="password"' in body_lower or "type='password'" in body_lower
                if has_form and has_password:
                    found_pages.append({
                        "path": path,
                        "url": url,
                        "service": service,
                        "status": resp.status_code,
                    })
                elif resp.status_code == 200 and ("login" in body_lower or "sign in" in body_lower):
                    found_pages.append({
                        "path": path,
                        "url": url,
                        "service": service,
                        "status": resp.status_code,
                    })
            elif resp.status_code == 401:
                # HTTP Basic Auth
                found_pages.append({
                    "path": path,
                    "url": url,
                    "service": f"{service} (HTTP Auth)",
                    "status": resp.status_code,
                    "basic_auth": True,
                })
        except Exception:
            continue
    return found_pages


def try_basic_auth(session, url, username, password, timeout):
    """Try HTTP Basic Authentication."""
    try:
        resp = session.get(url, auth=(username, password), timeout=timeout,
                           verify=False, allow_redirects=False)
        if resp.status_code in (200, 301, 302):
            return True, resp.status_code
        return False, resp.status_code
    except Exception:
        return False, None


def try_form_login(session, url, username, password, timeout):
    """Try form-based login with common field names."""
    try:
        # First get the page to find form fields
        resp = session.get(url, timeout=timeout, verify=False)
        body = resp.text.lower()

        # Determine action URL
        import re
        action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body)
        action_url = urljoin(url, action_match.group(1)) if action_match else url

        # Find the actual field names used
        user_field = "username"
        pass_field = "password"

        for field in USERNAME_FIELDS:
            if f'name="{field}"' in body or f"name='{field}'" in body:
                user_field = field
                break

        for field in PASSWORD_FIELDS:
            if f'name="{field}"' in body or f"name='{field}'" in body:
                pass_field = field
                break

        # Find any hidden fields (CSRF tokens, etc.)
        hidden_fields = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
            resp.text, re.IGNORECASE
        )
        # Also match reverse order (name before type)
        hidden_fields += re.findall(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
            resp.text, re.IGNORECASE
        )

        data = {user_field: username, pass_field: password}
        for name, value in hidden_fields:
            data[name] = value

        login_resp = session.post(action_url, data=data, timeout=timeout,
                                   verify=False, allow_redirects=True)

        # Heuristic: check if login succeeded
        resp_lower = login_resp.text.lower()
        failed_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "denied", "bad credentials", "login failed", "try again",
        ]
        success_indicators = [
            "dashboard", "welcome", "logout", "sign out",
            "my account", "profile", "admin panel",
        ]

        is_fail = any(ind in resp_lower for ind in failed_indicators)
        is_success = any(ind in resp_lower for ind in success_indicators)

        if is_success and not is_fail:
            return True, login_resp.status_code
        if login_resp.status_code in (301, 302):
            location = login_resp.headers.get("Location", "")
            if "dashboard" in location or "admin" in location or "home" in location:
                return True, login_resp.status_code

        return False, login_resp.status_code
    except Exception:
        return False, None


def main():
    parser = argparse.ArgumentParser(description="Default credentials checker")
    parser.add_argument("target", help="Target URL or host:port")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--no-form", action="store_true", help="Skip form-based login attempts")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    print(f"[*] Default Credentials Checker - Target: {target}")
    print(f"[!] WARNING: Only use with explicit authorization!")
    print(f"[*] Credential pairs: {len(DEFAULT_CREDS)}\n")

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; PhantomStrike/1.0)"

    # Find login pages
    print("=== Discovering Login Pages ===\n")
    login_pages = find_login_pages(session, target, args.timeout)

    if not login_pages:
        print("  [INFO] No login pages found")
        print(f"\n{'='*50}")
        print("[*] No login endpoints discovered")
        return

    for page in login_pages:
        print(f"  [FOUND] {page['path']} - {page['service']} (HTTP {page['status']})")
    print()

    # Test credentials
    print("=== Testing Default Credentials ===\n")
    all_findings = []

    for page in login_pages:
        service = page["service"]
        url = page["url"]
        is_basic = page.get("basic_auth", False)

        # Get service-specific creds + default creds
        creds = SERVICE_CREDS.get(service, []) + DEFAULT_CREDS

        print(f"  [*] Testing {service} at {page['path']}...")

        for username, password in creds:
            display_pass = password if password else "(empty)"
            if is_basic:
                success, status = try_basic_auth(session, url, username, password, args.timeout)
            elif not args.no_form:
                success, status = try_form_login(session, url, username, password, args.timeout)
            else:
                continue

            if success:
                finding = {
                    "service": service,
                    "path": page["path"],
                    "username": username,
                    "password": display_pass,
                    "auth_type": "basic" if is_basic else "form",
                    "status": status,
                }
                all_findings.append(finding)
                print(f"    [CRITICAL] {username}:{display_pass} - LOGIN SUCCESSFUL (HTTP {status})")

    print(f"\n{'='*50}")
    if all_findings:
        print(f"[!] CRITICAL: {len(all_findings)} default credential(s) found!")
        for f in all_findings:
            print(f"    {f['service']}: {f['username']}:{f['password']} ({f['auth_type']})")
        print(f"[!] Immediate action required: change all default passwords")
    else:
        print(f"[*] No default credentials found on {len(login_pages)} login page(s)")
        print(f"[*] Tested {len(DEFAULT_CREDS)} credential pairs per page")


if __name__ == "__main__":
    main()
