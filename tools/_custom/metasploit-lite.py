#!/usr/bin/env python3
"""Vulnerability verifier: given a CVE and target, check if the service is vulnerable."""
import argparse
import re
import socket
import ssl
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CVE_CHECKS = {
    "CVE-2017-0144": {"name": "EternalBlue (MS17-010)", "port": 445, "service": "SMB",
                      "check": "smb_version", "vuln_condition": "smbv1_enabled",
                      "severity": "CRITICAL", "description": "SMBv1 Remote Code Execution"},
    "CVE-2014-0160": {"name": "Heartbleed", "port": 443, "service": "HTTPS/TLS",
                      "check": "ssl_version", "vuln_condition": "openssl_1.0.1",
                      "severity": "CRITICAL", "description": "OpenSSL TLS Heartbeat memory disclosure"},
    "CVE-2021-44228": {"name": "Log4Shell", "port": 8080, "service": "HTTP/Java",
                       "check": "http_header", "vuln_condition": "java_app",
                       "severity": "CRITICAL", "description": "Apache Log4j2 RCE via JNDI"},
    "CVE-2019-0708": {"name": "BlueKeep", "port": 3389, "service": "RDP",
                      "check": "rdp_check", "vuln_condition": "rdp_vulnerable",
                      "severity": "CRITICAL", "description": "RDP Remote Code Execution"},
    "CVE-2021-26855": {"name": "ProxyLogon", "port": 443, "service": "Exchange",
                       "check": "exchange_check", "vuln_condition": "exchange_vuln",
                       "severity": "CRITICAL", "description": "Microsoft Exchange Server SSRF"},
    "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset", "port": 443, "service": "HTTP/2",
                       "check": "http2_check", "vuln_condition": "http2_supported",
                       "severity": "HIGH", "description": "HTTP/2 Rapid Reset DoS"},
    "CVE-2023-22515": {"name": "Confluence Auth Bypass", "port": 8090, "service": "Confluence",
                       "check": "confluence_check", "vuln_condition": "confluence_vuln",
                       "severity": "CRITICAL", "description": "Atlassian Confluence privilege escalation"},
    "CVE-2024-3400": {"name": "PAN-OS GlobalProtect", "port": 443, "service": "Palo Alto",
                      "check": "panos_check", "vuln_condition": "panos_vuln",
                      "severity": "CRITICAL", "description": "PAN-OS GlobalProtect command injection"},
}


def lookup_cve(cve_id, timeout):
    """Lookup CVE details from NIST NVD or cveawg."""
    info = {"id": cve_id, "description": "", "severity": "", "references": []}
    try:
        r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            cna = data.get("containers", {}).get("cna", {})
            descs = cna.get("descriptions", [])
            if descs:
                info["description"] = descs[0].get("value", "")[:200]
            metrics = cna.get("metrics", [])
            for m in metrics:
                cvss = m.get("cvssV3_1", m.get("cvssV3_0", {}))
                if cvss:
                    info["severity"] = cvss.get("baseSeverity", "")
                    info["score"] = cvss.get("baseScore", "")
                    info["vector"] = cvss.get("vectorString", "")
            refs = cna.get("references", [])
            info["references"] = [r.get("url", "") for r in refs[:5]]
            affected = cna.get("affected", [])
            info["affected"] = []
            for a in affected[:5]:
                product = a.get("product", "")
                vendor = a.get("vendor", "")
                versions = [v.get("version", "") for v in a.get("versions", [])[:5]]
                info["affected"].append({"vendor": vendor, "product": product, "versions": versions})
    except Exception:
        pass

    if not info["description"]:
        try:
            r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    descs = cve_data.get("descriptions", [])
                    for d in descs:
                        if d.get("lang") == "en":
                            info["description"] = d.get("value", "")[:200]
                    metrics = cve_data.get("metrics", {})
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics:
                            cvss = metrics[key][0].get("cvssData", {})
                            info["score"] = cvss.get("baseScore", "")
                            info["severity"] = cvss.get("baseSeverity", "")
                            break
        except Exception:
            pass
    return info


def check_smb_version(host, port, timeout):
    """Check SMBv1 support."""
    try:
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        negotiate = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        negotiate += b"\x00" * 12 + b"\xff\xff\x00\x00\x00\x00\x00\x00"
        negotiate += b"\x00\x62\x00\x02NT LM 0.12\x00"
        pkt = struct.pack(">I", len(negotiate)) + negotiate
        s.send(pkt)
        resp = s.recv(4096)
        s.close()
        if resp and resp[4:8] == b"\xffSMB":
            return {"smbv1": True, "banner": "SMBv1 negotiated"}
        return {"smbv1": False, "banner": "SMBv2+"}
    except Exception as e:
        return {"error": str(e)}


def check_ssl_service(host, port, timeout):
    """Check SSL/TLS info."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                return {"version": version, "cipher": cipher[0] if cipher else "",
                        "protocol": version}
    except Exception as e:
        return {"error": str(e)}


def check_http_service(host, port, timeout, paths=None):
    """Check HTTP service."""
    scheme = "https" if port in (443, 8443) else "http"
    results = {}
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False,
                         headers={"User-Agent": "PhantomStrike/1.0"})
        results["status"] = r.status_code
        results["server"] = r.headers.get("Server", "")
        results["powered_by"] = r.headers.get("X-Powered-By", "")
        results["headers"] = dict(r.headers)
        results["body_snippet"] = r.text[:500]
    except Exception as e:
        results["error"] = str(e)

    if paths:
        results["paths"] = {}
        for path in paths:
            try:
                r = requests.get(f"{scheme}://{host}:{port}{path}", timeout=timeout, verify=False)
                results["paths"][path] = {"status": r.status_code, "size": len(r.content)}
            except Exception:
                results["paths"][path] = {"status": "error"}
    return results


def verify_cve(host, cve_id, timeout):
    """Attempt to verify if target is vulnerable to a specific CVE."""
    findings = []

    if cve_id in CVE_CHECKS:
        check = CVE_CHECKS[cve_id]
        port = check["port"]

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
        except Exception:
            findings.append({"status": "NOT_APPLICABLE", "detail": f"Port {port} not open"})
            return findings

        if check["check"] == "smb_version":
            result = check_smb_version(host, port, timeout)
            if result.get("smbv1"):
                findings.append({"status": "LIKELY_VULNERABLE", "severity": check["severity"],
                                 "detail": f"SMBv1 is enabled - {check['name']} may be exploitable"})
            else:
                findings.append({"status": "NOT_VULNERABLE", "detail": "SMBv1 not enabled"})

        elif check["check"] == "ssl_version":
            result = check_ssl_service(host, port, timeout)
            if result.get("error"):
                findings.append({"status": "ERROR", "detail": result["error"]})
            else:
                findings.append({"status": "CHECK_MANUALLY", "detail":
                                 f"TLS: {result.get('version', '?')} - verify OpenSSL version on server"})

        elif check["check"] == "http_header":
            result = check_http_service(host, port, timeout)
            server = result.get("server", "") + result.get("powered_by", "")
            if "java" in server.lower() or "tomcat" in server.lower() or "spring" in server.lower():
                findings.append({"status": "POTENTIALLY_VULNERABLE", "severity": check["severity"],
                                 "detail": f"Java application detected: {server[:50]}"})
            else:
                findings.append({"status": "CHECK_MANUALLY", "detail": f"Server: {server[:50]}"})

        elif check["check"] == "rdp_check":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((host, port))
                rdp_req = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
                s.send(rdp_req)
                resp = s.recv(4096)
                s.close()
                if resp:
                    findings.append({"status": "CHECK_MANUALLY", "severity": "HIGH",
                                     "detail": "RDP is accessible - verify Windows version and patches"})
            except Exception:
                findings.append({"status": "ERROR", "detail": "Could not connect to RDP"})

        elif check["check"] == "exchange_check":
            result = check_http_service(host, 443, timeout, ["/owa/", "/autodiscover/autodiscover.json",
                                                              "/mapi/nspi/"])
            if result.get("paths", {}).get("/owa/", {}).get("status") == 200:
                findings.append({"status": "POTENTIALLY_VULNERABLE", "severity": check["severity"],
                                 "detail": "Exchange OWA accessible - verify patch level"})
            else:
                findings.append({"status": "NOT_APPLICABLE", "detail": "Exchange OWA not detected"})
        else:
            findings.append({"status": "CHECK_MANUALLY", "detail": "Automated check not available"})
    else:
        findings.append({"status": "UNKNOWN_CVE", "detail": f"No automated check for {cve_id}"})

    return findings


def main():
    ap = argparse.ArgumentParser(description="Metasploit-lite: Vulnerability verifier")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-c", "--cve", help="CVE ID to check (e.g., CVE-2017-0144)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Connection timeout")
    ap.add_argument("--list", action="store_true", help="List available CVE checks")
    ap.add_argument("--lookup", help="Look up CVE details (e.g., CVE-2021-44228)")
    args = ap.parse_args()

    if args.list:
        print("[*] Available CVE Checks:\n")
        for cve_id, info in sorted(CVE_CHECKS.items()):
            print(f"  {cve_id:<18} {info['name']:<30} Port:{info['port']:<6} {info['severity']}")
        return

    if args.lookup:
        print(f"[*] Looking up {args.lookup}...")
        info = lookup_cve(args.lookup, args.timeout)
        print(f"\n  CVE:         {info['id']}")
        print(f"  Severity:    {info.get('severity', 'N/A')} ({info.get('score', 'N/A')})")
        print(f"  Description: {info.get('description', 'N/A')}")
        if info.get("vector"):
            print(f"  CVSS Vector: {info['vector']}")
        if info.get("affected"):
            print(f"  Affected:")
            for a in info["affected"]:
                vers = ", ".join(a["versions"][:3]) if a["versions"] else "N/A"
                print(f"    {a['vendor']}/{a['product']}: {vers}")
        if info.get("references"):
            print(f"  References:")
            for r in info["references"]:
                print(f"    {r}")
        return

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Metasploit-Lite: Vulnerability Verifier")
    print(f"[*] Target: {host} ({ip})\n")

    if args.cve:
        cves_to_check = [args.cve.upper()]
    else:
        cves_to_check = list(CVE_CHECKS.keys())
        print(f"[*] Running all {len(cves_to_check)} CVE checks...\n")

    for cve_id in cves_to_check:
        info = CVE_CHECKS.get(cve_id, {"name": cve_id, "port": 0, "description": ""})
        name = info.get("name", cve_id) if cve_id in CVE_CHECKS else cve_id
        print(f"  [{cve_id}] {name}")

        findings = verify_cve(ip, cve_id, args.timeout)
        for f in findings:
            status = f["status"]
            marker = {"LIKELY_VULNERABLE": "[!!!]", "POTENTIALLY_VULNERABLE": "[!!]",
                      "CHECK_MANUALLY": "[?]", "NOT_VULNERABLE": "[OK]",
                      "NOT_APPLICABLE": "[-]", "ERROR": "[ERR]"}.get(status, "[?]")
            sev = f" ({f.get('severity', '')})" if f.get("severity") else ""
            print(f"    {marker}{sev} {f['detail']}")
        print()

    all_findings = []
    for cve_id in cves_to_check:
        all_findings.extend(verify_cve(ip, cve_id, args.timeout))

    vuln = sum(1 for f in all_findings if f["status"] in ("LIKELY_VULNERABLE", "POTENTIALLY_VULNERABLE"))
    print(f"{'='*60}")
    print(f"[*] Potential vulnerabilities: {vuln}")
    if vuln > 0:
        print("[!] Manual verification recommended for all findings")


if __name__ == "__main__":
    main()
