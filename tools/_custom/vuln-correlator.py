#!/usr/bin/env python3
"""Correlate and deduplicate security findings from multiple tools."""
import argparse
import json
import re
import sys
from collections import defaultdict


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}

# Vulnerability type classification patterns
VULN_PATTERNS = {
    "xss": ["xss", "cross-site scripting", "reflected", "script injection"],
    "sqli": ["sql injection", "sqli", "sql", "database injection"],
    "cors": ["cors", "cross-origin", "access-control"],
    "ssl_tls": ["ssl", "tls", "certificate", "cipher", "protocol"],
    "info_disclosure": ["information disclosure", "info leak", "sensitive file", "exposed",
                        "server header", "version disclosure", "directory listing"],
    "auth": ["authentication", "default credential", "weak password", "brute force",
             "login", "session", "cookie"],
    "config": ["misconfiguration", "config", "security header", "missing header"],
    "injection": ["injection", "command injection", "rce", "remote code"],
    "cve": ["cve-", "vulnerability", "exploit"],
    "dns": ["dns", "zone transfer", "spf", "dmarc", "dkim", "subdomain"],
    "network": ["port", "service", "open port", "exposed service"],
}


def classify_finding(finding):
    """Classify a finding into a vulnerability type."""
    text = ""
    for key in ["type", "description", "detail", "vulnerability", "finding",
                 "message", "title", "name", "category"]:
        val = finding.get(key, "")
        if isinstance(val, str):
            text += " " + val.lower()

    for vuln_type, patterns in VULN_PATTERNS.items():
        for pattern in patterns:
            if pattern in text:
                return vuln_type
    return "other"


def normalize_severity(finding):
    """Extract and normalize severity from a finding."""
    for key in ["severity", "risk", "level", "criticality", "priority"]:
        val = finding.get(key, "")
        if isinstance(val, str):
            val_upper = val.upper().strip()
            if val_upper in SEVERITY_ORDER:
                return val_upper

    # Try to extract from CVSS score
    cvss = finding.get("cvss_score") or finding.get("cvss") or finding.get("score")
    if cvss is not None:
        try:
            score = float(cvss)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0:
                return "LOW"
        except (ValueError, TypeError):
            pass

    return "UNKNOWN"


def extract_target(finding):
    """Extract the target from a finding."""
    for key in ["target", "host", "url", "domain", "ip", "address", "endpoint"]:
        val = finding.get(key, "")
        if val:
            return str(val)
    return "unknown"


def get_finding_key(finding):
    """Generate a deduplication key for a finding."""
    target = extract_target(finding)
    vuln_type = classify_finding(finding)
    # Include specific identifiers for dedup
    param = finding.get("param", finding.get("parameter", ""))
    path = finding.get("path", finding.get("url", ""))
    cve_id = finding.get("cve_id", finding.get("id", ""))

    key_parts = [vuln_type, target]
    if cve_id:
        key_parts.append(str(cve_id))
    if param:
        key_parts.append(str(param))
    if path:
        # Normalize path
        key_parts.append(re.sub(r'https?://[^/]+', '', str(path)))

    return "|".join(key_parts)


def parse_findings(input_data):
    """Parse various input formats into a list of findings."""
    findings = []

    # Try to parse as JSON
    try:
        data = json.loads(input_data)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            # Could be a single finding or wrapped
            for key in ["findings", "results", "vulnerabilities", "issues", "data"]:
                if key in data and isinstance(data[key], list):
                    findings = data[key]
                    break
            else:
                findings = [data]
        return findings
    except json.JSONDecodeError:
        pass

    # Try line-by-line JSON
    for line in input_data.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                findings.append(item)
            elif isinstance(item, list):
                findings.extend(item)
        except json.JSONDecodeError:
            # Try to parse as plain text finding
            severity_match = re.match(r'\[(\w+)\]\s*(.*)', line)
            if severity_match:
                findings.append({
                    "severity": severity_match.group(1),
                    "description": severity_match.group(2),
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Correlate and deduplicate security findings")
    parser.add_argument("target", nargs="?", default="-",
                        help="Input file (JSON findings) or '-' for stdin")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--dedup-only", action="store_true", help="Only deduplicate, no grouping")
    args = parser.parse_args()

    # Read input
    if args.target == "-" or args.target is None:
        input_data = sys.stdin.read()
    else:
        try:
            with open(args.target, "r") as f:
                input_data = f.read()
        except FileNotFoundError:
            print(f"[!] File not found: {args.target}", file=sys.stderr)
            sys.exit(1)

    if not input_data.strip():
        print("[!] No input data received", file=sys.stderr)
        print("[*] Usage: cat findings.json | python3 vuln-correlator.py -")
        sys.exit(1)

    findings = parse_findings(input_data)
    print(f"[*] Vulnerability Correlator")
    print(f"[*] Input findings: {len(findings)}\n")

    if not findings:
        print("[!] No parseable findings found in input")
        sys.exit(1)

    # Enrich findings
    for f in findings:
        f["_severity"] = normalize_severity(f)
        f["_type"] = classify_finding(f)
        f["_target"] = extract_target(f)
        f["_key"] = get_finding_key(f)

    # Deduplicate
    dedup = {}
    for f in findings:
        key = f["_key"]
        if key not in dedup:
            dedup[key] = f
        else:
            # Keep the higher severity
            if SEVERITY_ORDER.get(f["_severity"], 0) > SEVERITY_ORDER.get(dedup[key]["_severity"], 0):
                dedup[key] = f

    deduped = list(dedup.values())
    removed = len(findings) - len(deduped)

    print(f"[*] After deduplication: {len(deduped)} unique ({removed} duplicates removed)\n")

    if args.dedup_only:
        for f in sorted(deduped, key=lambda x: SEVERITY_ORDER.get(x["_severity"], 0), reverse=True):
            print(f"  [{f['_severity']}] [{f['_type']}] {f.get('description', f.get('detail', f.get('title', 'N/A')))[:100]}")
        return

    # Group by target
    by_target = defaultdict(list)
    for f in deduped:
        by_target[f["_target"]].append(f)

    # Group by vulnerability type
    by_type = defaultdict(list)
    for f in deduped:
        by_type[f["_type"]].append(f)

    # Output correlated report
    print("=== By Target ===\n")
    for target, target_findings in sorted(by_target.items()):
        sev_counts = defaultdict(int)
        for f in target_findings:
            sev_counts[f["_severity"]] += 1
        severity_str = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items(),
                                key=lambda x: SEVERITY_ORDER.get(x[0], 0), reverse=True))
        print(f"  Target: {target}")
        print(f"  Findings: {len(target_findings)} ({severity_str})")
        for f in sorted(target_findings, key=lambda x: SEVERITY_ORDER.get(x["_severity"], 0), reverse=True):
            desc = f.get("description", f.get("detail", f.get("title", "N/A")))[:80]
            print(f"    [{f['_severity']}] [{f['_type']}] {desc}")
        print()

    print("=== By Vulnerability Type ===\n")
    for vuln_type, type_findings in sorted(by_type.items(),
            key=lambda x: max(SEVERITY_ORDER.get(f["_severity"], 0) for f in x[1]), reverse=True):
        max_sev = max(f["_severity"] for f in type_findings)
        print(f"  {vuln_type.upper()} ({len(type_findings)} finding(s), max severity: {max_sev})")
        for f in sorted(type_findings, key=lambda x: SEVERITY_ORDER.get(x["_severity"], 0), reverse=True)[:5]:
            desc = f.get("description", f.get("detail", f.get("title", "N/A")))[:80]
            print(f"    [{f['_severity']}] {f['_target']}: {desc}")
        if len(type_findings) > 5:
            print(f"    ... and {len(type_findings) - 5} more")
        print()

    # Risk assessment
    print("=== Risk Assessment ===\n")
    total_crit = sum(1 for f in deduped if f["_severity"] == "CRITICAL")
    total_high = sum(1 for f in deduped if f["_severity"] == "HIGH")
    total_med = sum(1 for f in deduped if f["_severity"] == "MEDIUM")
    total_low = sum(1 for f in deduped if f["_severity"] == "LOW")

    print(f"  CRITICAL: {total_crit}")
    print(f"  HIGH:     {total_high}")
    print(f"  MEDIUM:   {total_med}")
    print(f"  LOW:      {total_low}")

    if total_crit > 0:
        risk_level = "CRITICAL"
    elif total_high > 0:
        risk_level = "HIGH"
    elif total_med > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    print(f"\n  Overall Risk Level: {risk_level}")

    if args.json:
        output = {
            "total_input": len(findings),
            "deduplicated": len(deduped),
            "duplicates_removed": removed,
            "risk_level": risk_level,
            "severity_counts": {"critical": total_crit, "high": total_high,
                                "medium": total_med, "low": total_low},
            "findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in deduped],
        }
        print(f"\n=== JSON Output ===\n")
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
