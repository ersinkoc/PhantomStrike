#!/usr/bin/env python3
"""DNS query logger: perform DNS queries and log all responses with TTL info."""
import argparse
import socket
import struct
import sys
import time

RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16,
                "SOA": 6, "PTR": 12, "SRV": 33, "CAA": 257}
RECORD_CLASSES = {"IN": 1}


def build_dns_query(domain, qtype):
    """Build a raw DNS query packet."""
    tid = struct.pack(">H", int(time.time() * 1000) % 65535)
    flags = struct.pack(">H", 0x0100)  # Standard query, recursion desired
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    header = tid + flags + counts

    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"

    qtype_val = RECORD_TYPES.get(qtype, 1)
    question = qname + struct.pack(">HH", qtype_val, 1)

    return header + question


def parse_name(data, offset):
    """Parse a DNS name with compression support."""
    parts = []
    jumped = False
    original_offset = offset
    max_jumps = 10
    jumps = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        offset += 1
        parts.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length

    name = ".".join(parts)
    return name, original_offset if jumped else offset


def parse_dns_response(data):
    """Parse DNS response packet."""
    if len(data) < 12:
        return None

    tid = struct.unpack(">H", data[0:2])[0]
    flags = struct.unpack(">H", data[2:4])[0]
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    nscount = struct.unpack(">H", data[8:10])[0]
    arcount = struct.unpack(">H", data[10:12])[0]

    rcode = flags & 0x0F
    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                   4: "NOTIMP", 5: "REFUSED"}

    result = {"id": tid, "rcode": rcode_names.get(rcode, f"RCODE:{rcode}"),
              "flags": flags, "questions": [], "answers": [], "authority": [], "additional": []}

    offset = 12

    # Parse questions
    for _ in range(qdcount):
        name, offset = parse_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype = struct.unpack(">H", data[offset:offset + 2])[0]
        qclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        offset += 4
        type_name = next((k for k, v in RECORD_TYPES.items() if v == qtype), str(qtype))
        result["questions"].append({"name": name, "type": type_name})

    # Parse resource records
    def parse_rrs(count, section):
        nonlocal offset
        for _ in range(count):
            if offset >= len(data):
                break
            name, offset = parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[offset:offset + 2])[0]
            rclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            ttl = struct.unpack(">I", data[offset + 4:offset + 8])[0]
            rdlength = struct.unpack(">H", data[offset + 8:offset + 10])[0]
            offset += 10
            rdata_raw = data[offset:offset + rdlength]
            offset += rdlength

            type_name = next((k for k, v in RECORD_TYPES.items() if v == rtype), str(rtype))
            rdata = ""

            if rtype == 1 and len(rdata_raw) == 4:  # A
                rdata = socket.inet_ntoa(rdata_raw)
            elif rtype == 28 and len(rdata_raw) == 16:  # AAAA
                rdata = socket.inet_ntop(socket.AF_INET6, rdata_raw)
            elif rtype in (2, 5, 12):  # NS, CNAME, PTR
                rdata, _ = parse_name(data, offset - rdlength)
            elif rtype == 15:  # MX
                pref = struct.unpack(">H", rdata_raw[0:2])[0]
                mx_name, _ = parse_name(data, offset - rdlength + 2)
                rdata = f"{pref} {mx_name}"
            elif rtype == 16:  # TXT
                rdata = rdata_raw[1:].decode("utf-8", errors="replace")
            elif rtype == 6:  # SOA
                mname, pos = parse_name(data, offset - rdlength)
                rname, pos = parse_name(data, pos)
                if pos + 20 <= len(data):
                    serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[pos:pos + 20])
                    rdata = f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
                else:
                    rdata = f"{mname} {rname}"
            else:
                rdata = rdata_raw.hex()

            section.append({"name": name, "type": type_name, "ttl": ttl, "data": rdata})

    parse_rrs(ancount, result["answers"])
    parse_rrs(nscount, result["authority"])
    parse_rrs(arcount, result["additional"])

    return result


def dns_query(domain, qtype, server, timeout):
    """Perform DNS query and return parsed response."""
    query = build_dns_query(domain, qtype)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        start = time.time()
        s.sendto(query, (server, 53))
        data, addr = s.recvfrom(4096)
        elapsed = time.time() - start
        s.close()
        result = parse_dns_response(data)
        if result:
            result["query_time_ms"] = round(elapsed * 1000, 2)
            result["server"] = server
        return result
    except socket.timeout:
        return {"error": "Timeout", "server": server}
    except Exception as e:
        return {"error": str(e), "server": server}


def main():
    ap = argparse.ArgumentParser(description="DNSLog-lite: DNS query logger with TTL info")
    ap.add_argument("target", help="Domain to query")
    ap.add_argument("-t", "--type", nargs="+", default=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"],
                    help="Record types to query")
    ap.add_argument("-n", "--nameserver", default="8.8.8.8", help="DNS server (default: 8.8.8.8)")
    ap.add_argument("--timeout", type=int, default=5, help="Query timeout")
    ap.add_argument("--all-ns", action="store_true", help="Query multiple DNS servers")
    ap.add_argument("--trace", action="store_true", help="Show authority and additional sections")
    args = ap.parse_args()

    domain = args.target.rstrip(".")
    servers = [args.nameserver]
    if args.all_ns:
        servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

    print(f"[*] DNSLog-Lite: DNS Query Logger")
    print(f"[*] Domain: {domain}")
    print(f"[*] Record types: {', '.join(args.type)}")
    print(f"[*] Nameserver(s): {', '.join(servers)}\n")

    all_records = []
    for server in servers:
        if len(servers) > 1:
            print(f"--- Server: {server} ---\n")

        for qtype in args.type:
            result = dns_query(domain, qtype, server, args.timeout)
            if "error" in result:
                print(f"  [{qtype:>5}] Error: {result['error']}")
                continue

            print(f"  [{qtype:>5}] Response: {result['rcode']} | Query time: {result['query_time_ms']}ms")

            if result["answers"]:
                for ans in result["answers"]:
                    ttl_str = f"TTL={ans['ttl']:>6}s"
                    data_str = ans["data"][:80]
                    print(f"         {ans['type']:>5} {ttl_str}  {ans['name']:<30} -> {data_str}")
                    all_records.append(ans)
            else:
                print(f"         (no records)")

            if args.trace:
                if result["authority"]:
                    print(f"         Authority:")
                    for ns in result["authority"]:
                        print(f"           {ns['type']:>5} TTL={ns['ttl']:>6}s  {ns['data'][:60]}")
                if result["additional"]:
                    print(f"         Additional:")
                    for ar in result["additional"]:
                        print(f"           {ar['type']:>5} TTL={ar['ttl']:>6}s  {ar['data'][:60]}")
            print()

    print(f"{'='*60}")
    print(f"[*] DNS LOG SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Domain: {domain}")
    print(f"  Total records: {len(all_records)}")

    by_type = {}
    for r in all_records:
        by_type.setdefault(r["type"], []).append(r)
    for t, records in sorted(by_type.items()):
        print(f"\n  {t} Records ({len(records)}):")
        for r in records:
            print(f"    {r['data'][:60]:<62} TTL={r['ttl']}s")

    # Security observations
    txt_records = by_type.get("TXT", [])
    has_spf = any("v=spf1" in r["data"] for r in txt_records)
    has_dmarc = any("v=DMARC1" in r["data"] for r in txt_records)
    if txt_records:
        print(f"\n  Security:")
        print(f"    SPF:   {'Found' if has_spf else 'MISSING'}")
        print(f"    DMARC: {'Found' if has_dmarc else 'MISSING'}")

    ttl_values = [r["ttl"] for r in all_records if r["ttl"] > 0]
    if ttl_values:
        print(f"\n  TTL Range: {min(ttl_values)}s - {max(ttl_values)}s (avg: {sum(ttl_values)//len(ttl_values)}s)")


if __name__ == "__main__":
    main()
