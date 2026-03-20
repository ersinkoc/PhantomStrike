#!/usr/bin/env python3
"""Calculate overall risk score from security findings."""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}

RISK_THRESHOLDS = {
    "CRITICAL": 50,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 0,
}


def normalize_severity(finding):
    """Extract and normalize severity from a finding."""
    for key in ["severity", "risk", "level", "criticality"]:
        val = finding.get(key, "")
        if isinstance(val, str):
            val_upper = val.upper().strip()
            if val_upper in SEVERITY_WEIGHTS:
                return val_upper

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


def extract_category(finding):
    """Classify finding into a security category."""
    text = " ".join(str(v) for v in finding.values() if isinstance(v, str)).lower()
    categories = {
        "Authentication": ["auth", "credential", "login", "password", "session", "token"],
        "Injection": ["injection", "xss", "sqli", "sql", "rce", "command"],
        "Configuration": ["config", "header", "cors", "ssl", "tls", "cipher"],
        "Information Disclosure": ["disclosure", "exposed", "sensitive", "leak", "info"],
        "Network": ["port", "service", "dns", "subdomain", "network"],
        "Vulnerability": ["cve", "vulnerability", "exploit", "patch"],
        "Access Control": ["access", "authorization", "permission", "privilege"],
    }
    for category, keywords in categories.items():
        if any(kw in text for kw in keywords):
            return category
    return "Other"


def parse_findings(input_data):
    """Parse input data into findings list."""
    findings = []
    try:
        data = json.loads(input_data)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            for key in ["findings", "results", "vulnerabilities", "issues", "data"]:
                if key in data and isinstance(data[key], list):
                    findings = data[key]
                    break
            else:
                findings = [data]
    except json.JSONDecodeError:
        for line in input_data.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    findings.append(item)
            except json.JSONDecodeError:
                sev_match = re.match(r'\[(\w+)\]\s*(.*)', line)
                if sev_match:
                    findings.append({
                        "severity": sev_match.group(1),
                        "description": sev_match.group(2),
                    })
    return findings


def calculate_risk_score(severity_counts):
    """Calculate weighted risk score."""
    total_score = 0
    for severity, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        total_score += weight * count
    return total_score


def determine_risk_level(score):
    """Determine overall risk level from score."""
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def generate_bar(value, max_val, width=30):
    """Generate a simple ASCII bar chart."""
    if max_val == 0:
        return ""
    filled = int((value / max_val) * width)
    return "#" * filled + "-" * (width - filled)


def main():
    parser = argparse.ArgumentParser(description="Security risk score calculator")
    parser.add_argument("target", nargs="?", default="-",
                        help="Input file with JSON findings or '-' for stdin")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--threshold", type=int, default=0,
                        help="Alert threshold score (exit code 1 if exceeded)")
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
        print("[*] Usage: cat findings.json | python3 risk-scorer.py -")
        sys.exit(1)

    findings = parse_findings(input_data)
    if not findings:
        print("[!] No parseable findings in input")
        sys.exit(1)

    # Process findings
    severity_counts = defaultdict(int)
    category_counts = defaultdict(lambda: defaultdict(int))
    targets = set()

    for f in findings:
        severity = normalize_severity(f)
        category = extract_category(f)
        severity_counts[severity] += 1
        category_counts[category][severity] += 1

        for key in ["target", "host", "url", "domain"]:
            if f.get(key):
                targets.add(str(f[key]))

    # Calculate scores
    total_score = calculate_risk_score(severity_counts)
    risk_level = determine_risk_level(total_score)
    max_possible = len(findings) * 10  # If all were CRITICAL

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Output dashboard
    print(f"{'='*60}")
    print(f"        PHANTOMSTRIKE RISK ASSESSMENT DASHBOARD")
    print(f"{'='*60}")
    print(f"  Generated: {now}")
    print(f"  Targets:   {len(targets) if targets else 'N/A'}")
    print(f"  Findings:  {len(findings)}")
    print(f"{'='*60}\n")

    # Risk score display
    print(f"  RISK SCORE: {total_score}/{max_possible}")
    print(f"  RISK LEVEL: {risk_level}")
    score_bar = generate_bar(total_score, max(max_possible, 1), 40)
    print(f"  [{score_bar}] {total_score * 100 // max(max_possible, 1)}%\n")

    # Severity breakdown
    print(f"  {'='*50}")
    print(f"  SEVERITY BREAKDOWN")
    print(f"  {'='*50}\n")

    max_count = max(severity_counts.values()) if severity_counts else 1
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(severity, 0)
        weight = SEVERITY_WEIGHTS[severity]
        weighted = count * weight
        bar = generate_bar(count, max_count, 20)
        print(f"  {severity:<10} {count:>4} findings  (score: {weighted:>4})  [{bar}]")

    # Category breakdown
    print(f"\n  {'='*50}")
    print(f"  CATEGORY BREAKDOWN")
    print(f"  {'='*50}\n")

    category_scores = {}
    for category, sev_counts in category_counts.items():
        cat_score = calculate_risk_score(sev_counts)
        category_scores[category] = cat_score

    for category, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
        sev_counts = category_counts[category]
        total_in_cat = sum(sev_counts.values())
        severity_str = ", ".join(f"{v} {k}" for k, v in sorted(
            sev_counts.items(), key=lambda x: SEVERITY_WEIGHTS.get(x[0], 0), reverse=True) if v > 0)
        print(f"  {category:<25} Score: {score:>4}  ({total_in_cat} findings: {severity_str})")

    # Key metrics
    print(f"\n  {'='*50}")
    print(f"  KEY METRICS")
    print(f"  {'='*50}\n")

    total_findings = len(findings)
    crit_pct = (severity_counts.get("CRITICAL", 0) / max(total_findings, 1)) * 100
    high_pct = (severity_counts.get("HIGH", 0) / max(total_findings, 1)) * 100
    exploit_risk = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    print(f"  Total Findings:          {total_findings}")
    print(f"  Critical Rate:           {crit_pct:.1f}%")
    print(f"  High+ Rate:              {crit_pct + high_pct:.1f}%")
    print(f"  Exploitable (Crit+High): {exploit_risk}")
    print(f"  Risk Score:              {total_score}")
    print(f"  Risk Level:              {risk_level}")

    # Recommendations
    print(f"\n  {'='*50}")
    print(f"  RECOMMENDATIONS")
    print(f"  {'='*50}\n")

    if severity_counts.get("CRITICAL", 0) > 0:
        print(f"  [!!!] IMMEDIATE ACTION REQUIRED")
        print(f"        {severity_counts['CRITICAL']} critical finding(s) need urgent remediation")
    if severity_counts.get("HIGH", 0) > 0:
        print(f"  [!!]  HIGH PRIORITY")
        print(f"        {severity_counts['HIGH']} high severity finding(s) should be addressed promptly")
    if severity_counts.get("MEDIUM", 0) > 0:
        print(f"  [!]   PLANNED REMEDIATION")
        print(f"        {severity_counts['MEDIUM']} medium finding(s) for scheduled remediation")
    if severity_counts.get("LOW", 0) > 0:
        print(f"  [i]   INFORMATIONAL")
        print(f"        {severity_counts['LOW']} low priority finding(s) for backlog")

    print(f"\n{'='*60}")

    # JSON output
    if args.json:
        output = {
            "timestamp": now,
            "total_findings": total_findings,
            "risk_score": total_score,
            "max_score": max_possible,
            "risk_level": risk_level,
            "severity_counts": dict(severity_counts),
            "category_scores": category_scores,
            "targets": list(targets),
        }
        print(json.dumps(output, indent=2))

    # Exit code for CI/CD
    if args.threshold > 0 and total_score >= args.threshold:
        sys.exit(1)


if __name__ == "__main__":
    main()
