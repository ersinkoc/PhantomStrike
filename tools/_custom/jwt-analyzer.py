#!/usr/bin/env python3
"""Analyze JWT tokens for weaknesses."""
import argparse
import base64
import json
import sys
import time


def b64_decode(data):
    """Decode base64url with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token):
    """Decode a JWT token into header, payload, signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    header = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    signature = parts[2]

    return header, payload, signature


WEAK_ALGORITHMS = {
    "none": "CRITICAL - Algorithm 'none' allows forging tokens without a key",
    "HS256": "INFO - HMAC-SHA256; ensure secret is strong (>256 bits)",
    "HS384": "INFO - HMAC-SHA384; ensure secret is strong",
    "HS512": "INFO - HMAC-SHA512; ensure secret is strong",
}

KNOWN_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret",
    "changeme", "test", "admin", "default",
]


def analyze_header(header):
    """Analyze JWT header for issues."""
    issues = []
    alg = header.get("alg", "MISSING")

    if alg == "none":
        issues.append(("CRITICAL", "Algorithm is 'none' - token can be forged"))
    elif alg in ("HS256", "HS384", "HS512"):
        issues.append(("INFO", f"Symmetric algorithm ({alg}) - key must be kept secret"))
        issues.append(("WARNING", "Possible algorithm confusion: try changing to RS256"))
    elif alg in ("RS256", "RS384", "RS512"):
        issues.append(("INFO", f"Asymmetric algorithm ({alg}) - verify key management"))
    elif alg == "MISSING":
        issues.append(("CRITICAL", "No algorithm specified in header"))

    if "kid" in header:
        issues.append(("INFO", f"Key ID (kid): {header['kid']}"))
        issues.append(("WARNING", "kid header present - test for injection (SQL, path traversal)"))

    if "jku" in header:
        issues.append(("WARNING", f"JKU header present: {header['jku']} - test for SSRF"))

    if "jwk" in header:
        issues.append(("WARNING", "Embedded JWK - test for key injection"))

    if "x5u" in header:
        issues.append(("WARNING", f"x5u header present: {header['x5u']} - test for SSRF"))

    return issues


def analyze_payload(payload):
    """Analyze JWT payload for issues."""
    issues = []
    now = int(time.time())

    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            issues.append(("INFO", f"Token expired at {time.ctime(exp)}"))
        else:
            remaining = exp - now
            if remaining > 86400 * 30:
                issues.append(("WARNING", f"Token expires in {remaining // 86400} days - long-lived token"))
            else:
                issues.append(("INFO", f"Token expires in {remaining // 3600}h {(remaining % 3600) // 60}m"))
    else:
        issues.append(("WARNING", "No expiration (exp) claim - token never expires"))

    if "iat" in payload:
        iat = payload["iat"]
        age = now - iat
        issues.append(("INFO", f"Issued {age // 3600}h {(age % 3600) // 60}m ago"))

    if "nbf" in payload:
        nbf = payload["nbf"]
        if nbf > now:
            issues.append(("INFO", f"Token not valid until {time.ctime(nbf)}"))

    if "sub" in payload:
        issues.append(("INFO", f"Subject: {payload['sub']}"))

    if "admin" in payload or "role" in payload or "is_admin" in payload:
        issues.append(("WARNING", "Authorization claims in JWT - test for privilege escalation"))
        for key in ("admin", "is_admin", "role", "roles", "permissions"):
            if key in payload:
                issues.append(("INFO", f"  {key}: {payload[key]}"))

    sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
    for key in sensitive_keys:
        if key in payload:
            issues.append(("CRITICAL", f"Sensitive data in payload: {key}"))

    return issues


def main():
    parser = argparse.ArgumentParser(description="JWT token analyzer")
    parser.add_argument("token", help="JWT token to analyze")
    args = parser.parse_args()

    token = args.token.strip()

    print(f"[*] Analyzing JWT token...")
    print(f"[*] Token length: {len(token)} characters\n")

    try:
        header, payload, signature = decode_jwt(token)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to decode JWT: {e}", file=sys.stderr)
        sys.exit(1)

    print("=== Header ===")
    print(json.dumps(header, indent=2))

    print("\n=== Payload ===")
    print(json.dumps(payload, indent=2))

    print(f"\n=== Signature ===")
    print(f"  {signature[:40]}..." if len(signature) > 40 else f"  {signature}")
    if not signature or signature == "":
        print("  [CRITICAL] Empty signature!")

    print("\n=== Analysis ===")
    header_issues = analyze_header(header)
    payload_issues = analyze_payload(payload)

    all_issues = header_issues + payload_issues
    for severity, msg in all_issues:
        print(f"  [{severity}] {msg}")

    critical = sum(1 for s, _ in all_issues if s == "CRITICAL")
    warnings = sum(1 for s, _ in all_issues if s == "WARNING")
    print(f"\n[*] Summary: {critical} critical, {warnings} warnings, {len(all_issues)} total findings")


if __name__ == "__main__":
    main()
