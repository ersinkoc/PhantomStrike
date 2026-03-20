#!/usr/bin/env python3
"""Analyze SSL/TLS configuration of a target host."""
import argparse
import datetime
import hashlib
import socket
import ssl
import sys


WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}
PROTOCOLS = [
    ("SSLv2", getattr(ssl, "PROTOCOL_SSLv2", None), "CRITICAL"),
    ("SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None), "CRITICAL"),
    ("TLSv1.0", None, "HIGH"),
    ("TLSv1.1", None, "MEDIUM"),
    ("TLSv1.2", None, "OK"),
    ("TLSv1.3", None, "OK"),
]


def parse_target(target):
    """Parse target into host and port."""
    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    if ":" in target:
        parts = target.rsplit(":", 1)
        return parts[0], int(parts[1])
    return target, 443


def get_cert_info(host, port, timeout):
    """Connect and retrieve certificate information."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                peer_cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                return cert, peer_cert, protocol, cipher
    except Exception as e:
        print(f"[!] SSL connection failed: {e}", file=sys.stderr)
        sys.exit(1)


def check_protocol(host, port, timeout, proto_name):
    """Check if a specific protocol version is supported."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if proto_name == "TLSv1.0":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif proto_name == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif proto_name == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif proto_name == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        else:
            return False

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False


def get_cipher_list(host, port, timeout):
    """Get the list of supported ciphers."""
    ciphers = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                shared = ssock.shared_ciphers()
                if shared:
                    ciphers = shared
    except Exception:
        pass
    return ciphers


def grade_ssl(issues):
    """Calculate an SSL grade based on findings."""
    if any(s == "CRITICAL" for s, _ in issues):
        return "F"
    highs = sum(1 for s, _ in issues if s == "HIGH")
    meds = sum(1 for s, _ in issues if s == "MEDIUM")
    if highs >= 2:
        return "D"
    if highs == 1:
        return "C"
    if meds >= 2:
        return "B-"
    if meds == 1:
        return "B"
    return "A"


def main():
    parser = argparse.ArgumentParser(description="SSL/TLS configuration analyzer")
    parser.add_argument("target", help="Target host[:port] (default port 443)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Connection timeout")
    args = parser.parse_args()

    host, port = parse_target(args.target)
    print(f"[*] SSL/TLS Analyzer - Target: {host}:{port}\n")

    cert_bin, cert_info, protocol, cipher = get_cert_info(host, port, args.timeout)
    issues = []

    # Certificate details
    print("=== Certificate Details ===\n")
    subject = dict(x[0] for x in cert_info.get("subject", ()))
    issuer = dict(x[0] for x in cert_info.get("issuer", ()))

    cn = subject.get("commonName", "N/A")
    issuer_cn = issuer.get("commonName", "N/A")
    issuer_org = issuer.get("organizationName", "N/A")

    print(f"  Common Name:    {cn}")
    print(f"  Issuer:         {issuer_cn} ({issuer_org})")
    print(f"  Serial Number:  {cert_info.get('serialNumber', 'N/A')}")

    # SAN
    san_list = []
    for san_type, san_value in cert_info.get("subjectAltName", ()):
        san_list.append(san_value)
    if san_list:
        print(f"  SANs:           {', '.join(san_list[:10])}")
        if len(san_list) > 10:
            print(f"                  ... and {len(san_list) - 10} more")

    # Validity
    not_before = cert_info.get("notBefore", "")
    not_after = cert_info.get("notAfter", "")
    print(f"  Valid From:     {not_before}")
    print(f"  Valid Until:    {not_after}")

    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            days_left = (expiry - now).days
            if days_left < 0:
                print(f"  [CRITICAL] Certificate EXPIRED {abs(days_left)} days ago")
                issues.append(("CRITICAL", "Certificate expired"))
            elif days_left < 30:
                print(f"  [HIGH] Certificate expires in {days_left} days")
                issues.append(("HIGH", f"Certificate expires in {days_left} days"))
            elif days_left < 90:
                print(f"  [MEDIUM] Certificate expires in {days_left} days")
                issues.append(("MEDIUM", f"Certificate expires in {days_left} days"))
            else:
                print(f"  [OK] {days_left} days until expiry")
        except ValueError:
            pass

    # Self-signed check
    if subject == issuer:
        print(f"  [HIGH] Certificate appears to be self-signed")
        issues.append(("HIGH", "Self-signed certificate"))

    # Fingerprint
    sha256 = hashlib.sha256(cert_bin).hexdigest()
    print(f"  SHA-256:        {sha256[:32]}...")

    # Current connection
    print(f"\n=== Connection ===\n")
    print(f"  Protocol: {protocol}")
    print(f"  Cipher:   {cipher[0] if cipher else 'N/A'}")
    print(f"  Bits:     {cipher[2] if cipher else 'N/A'}")

    # Protocol support
    print(f"\n=== Protocol Support ===\n")
    for proto_name, _, severity in PROTOCOLS:
        supported = check_protocol(host, port, args.timeout, proto_name)
        status = "supported" if supported else "not supported"
        if supported and severity in ("CRITICAL", "HIGH", "MEDIUM"):
            print(f"  [{severity}] {proto_name}: {status}")
            issues.append((severity, f"{proto_name} supported"))
        elif supported:
            print(f"  [OK]      {proto_name}: {status}")
        else:
            label = "OK" if severity in ("CRITICAL", "HIGH", "MEDIUM") else "INFO"
            print(f"  [{label}]      {proto_name}: {status}")

    # Cipher analysis
    print(f"\n=== Cipher Analysis ===\n")
    ciphers = get_cipher_list(host, port, args.timeout)
    weak_found = []
    if ciphers:
        for name, proto, bits in ciphers:
            is_weak = any(w.lower() in name.lower() for w in WEAK_CIPHERS)
            if is_weak:
                print(f"  [HIGH] Weak cipher: {name} ({bits} bits)")
                weak_found.append(name)
            elif bits and bits < 128:
                print(f"  [MEDIUM] Low-strength cipher: {name} ({bits} bits)")
                weak_found.append(name)
        if not weak_found:
            print(f"  [OK] {len(ciphers)} ciphers checked, no weak ciphers found")
        else:
            issues.append(("HIGH", f"{len(weak_found)} weak cipher(s) detected"))
    else:
        print("  [INFO] Could not enumerate server ciphers")

    # Hostname match
    print(f"\n=== Hostname Validation ===\n")
    hostname_match = host == cn or any(host == s for s in san_list) or any(
        s.startswith("*.") and host.endswith(s[1:]) for s in san_list
    )
    if hostname_match:
        print(f"  [OK] Hostname '{host}' matches certificate")
    else:
        print(f"  [HIGH] Hostname '{host}' does NOT match certificate CN or SANs")
        issues.append(("HIGH", "Hostname mismatch"))

    # Summary
    grade = grade_ssl(issues)
    print(f"\n{'='*50}")
    print(f"[*] Grade: {grade}")
    print(f"[*] Issues: {len(issues)}")
    for sev, msg in issues:
        print(f"    [{sev}] {msg}")
    if not issues:
        print(f"[*] No significant SSL/TLS issues found")


if __name__ == "__main__":
    main()
