#!/usr/bin/env python3
"""Comprehensive DNS record collector and security checker."""
import argparse
import json
import socket
import struct
import sys
import time


# DNS record type codes
RECORD_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33,
}


def build_dns_query(domain, qtype):
    """Build a raw DNS query packet."""
    transaction_id = struct.pack("!H", 0x1234)
    flags = struct.pack("!H", 0x0100)  # Standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)

    # Encode domain name
    qname = b""
    for label in domain.rstrip(".").split("."):
        qname += struct.pack("!B", len(label)) + label.encode()
    qname += b"\x00"

    qtype_bytes = struct.pack("!H", RECORD_TYPES.get(qtype, 1))
    qclass = struct.pack("!H", 1)  # IN class

    return transaction_id + flags + counts + qname + qtype_bytes + qclass


def parse_dns_name(data, offset):
    """Parse a DNS name from response data with pointer support."""
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode("ascii", errors="replace"))
            offset += length

    return ".".join(labels), original_offset if jumped else offset


def parse_dns_response(data, qtype_name):
    """Parse DNS response and extract records."""
    records = []
    if len(data) < 12:
        return records

    ancount = struct.unpack("!H", data[4:6])[0]
    offset = 12

    # Skip question section
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        offset += 1
    offset += 4  # Skip QTYPE and QCLASS

    # Parse answer records
    for _ in range(ancount):
        if offset >= len(data):
            break
        name, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]

        record = {"name": name, "type": qtype_name, "ttl": ttl}

        if rtype == 1 and rdlength == 4:  # A
            record["value"] = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlength == 16:  # AAAA
            record["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:  # CNAME
            cname, _ = parse_dns_name(data, offset - rdlength)
            record["value"] = cname
        elif rtype == 2:  # NS
            ns, _ = parse_dns_name(data, offset - rdlength)
            record["value"] = ns
        elif rtype == 15:  # MX
            priority = struct.unpack("!H", rdata[:2])[0]
            mx, _ = parse_dns_name(data, offset - rdlength + 2)
            record["value"] = f"{priority} {mx}"
        elif rtype == 16:  # TXT
            txt_parts = []
            i = 0
            while i < rdlength:
                txt_len = rdata[i]
                txt_parts.append(rdata[i+1:i+1+txt_len].decode("utf-8", errors="replace"))
                i += 1 + txt_len
            record["value"] = " ".join(txt_parts)
        elif rtype == 6:  # SOA
            mname, new_off = parse_dns_name(data, offset - rdlength)
            rname, new_off = parse_dns_name(data, new_off)
            if new_off + 20 <= offset:
                serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[new_off:new_off+20])
                record["value"] = f"{mname} {rname} (serial: {serial})"
            else:
                record["value"] = f"{mname} {rname}"
        else:
            record["value"] = rdata.hex()

        records.append(record)
        offset += rdlength

    return records


def dns_query(domain, qtype, nameserver="8.8.8.8", timeout=5):
    """Send a DNS query and parse the response."""
    query = build_dns_query(domain, qtype)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_response(data, qtype)
    except socket.timeout:
        return []
    except Exception:
        return []


def try_zone_transfer(domain, ns_server, timeout=10):
    """Attempt an AXFR zone transfer."""
    try:
        query = build_dns_query(domain, "A")
        # Modify for AXFR (type 252)
        query = query[:-4] + struct.pack("!HH", 252, 1)
        # TCP for zone transfer
        length_prefix = struct.pack("!H", len(query))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            ip = socket.gethostbyname(ns_server)
        except socket.gaierror:
            return False, []
        sock.connect((ip, 53))
        sock.send(length_prefix + query)
        data = sock.recv(65535)
        sock.close()
        if len(data) > 14:
            rcode = data[5] & 0x0F  # After 2-byte length prefix
            if rcode == 0:
                return True, ["Zone transfer may be possible"]
        return False, []
    except Exception:
        return False, []


def check_security_records(txt_records):
    """Check for SPF, DKIM, DMARC in TXT records."""
    issues = []
    has_spf = False
    has_dmarc = False

    for rec in txt_records:
        val = rec.get("value", "")
        if "v=spf1" in val:
            has_spf = True
            if "+all" in val:
                issues.append(("HIGH", "SPF uses +all (allows any sender)"))
            elif "~all" in val:
                issues.append(("MEDIUM", "SPF uses ~all (soft fail) - consider -all"))
        if "v=DMARC1" in val:
            has_dmarc = True
            if "p=none" in val:
                issues.append(("MEDIUM", "DMARC policy is 'none' (monitoring only)"))

    if not has_spf:
        issues.append(("HIGH", "No SPF record found - email spoofing possible"))
    if not has_dmarc:
        issues.append(("HIGH", "No DMARC record found - email authentication weak"))

    return issues


def main():
    parser = argparse.ArgumentParser(description="DNS reconnaissance tool")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-n", "--nameserver", default="8.8.8.8", help="DNS server to query")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Query timeout")
    parser.add_argument("--axfr", action="store_true", help="Attempt zone transfer")
    args = parser.parse_args()

    domain = args.target.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"[*] DNS Recon - Target: {domain}")
    print(f"[*] Nameserver: {args.nameserver}\n")

    all_records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    print("=== DNS Records ===\n")
    for rtype in record_types:
        records = dns_query(domain, rtype, args.nameserver, args.timeout)
        all_records[rtype] = records
        if records:
            print(f"  [{rtype}]")
            for rec in records:
                print(f"    {rec.get('value', 'N/A')}  (TTL: {rec.get('ttl', 'N/A')})")
            print()

    # Check DMARC specifically (it's at _dmarc.domain)
    dmarc_records = dns_query(f"_dmarc.{domain}", "TXT", args.nameserver, args.timeout)
    if dmarc_records:
        all_records["TXT"].extend(dmarc_records)
        print(f"  [DMARC]")
        for rec in dmarc_records:
            print(f"    {rec.get('value', 'N/A')}")
        print()

    # Zone transfer
    if args.axfr and all_records.get("NS"):
        print("=== Zone Transfer (AXFR) ===\n")
        for ns_rec in all_records["NS"]:
            ns_server = ns_rec.get("value", "").rstrip(".")
            if ns_server:
                success, data = try_zone_transfer(domain, ns_server, args.timeout)
                if success:
                    print(f"  [CRITICAL] Zone transfer ALLOWED on {ns_server}")
                else:
                    print(f"  [OK] Zone transfer denied on {ns_server}")
        print()

    # Email security analysis
    print("=== Email Security ===\n")
    security_issues = check_security_records(all_records.get("TXT", []) + dmarc_records)
    if security_issues:
        for severity, msg in security_issues:
            print(f"  [{severity}] {msg}")
    else:
        print(f"  [OK] SPF and DMARC records look good")

    # Summary
    total = sum(len(v) for v in all_records.values())
    print(f"\n{'='*50}")
    print(f"[*] Total records found: {total}")
    for rtype in record_types:
        count = len(all_records.get(rtype, []))
        if count:
            print(f"    {rtype}: {count}")
    sev_issues = [i for i in security_issues if i[0] in ("HIGH", "CRITICAL")]
    if sev_issues:
        print(f"[!] {len(sev_issues)} security issue(s) found")


if __name__ == "__main__":
    main()
