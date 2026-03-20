#!/usr/bin/env python3
"""ASN lookup: find ASN for IP, list IP ranges, org info. Uses BGPView and Team Cymru."""
import argparse
import json
import socket
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def cymru_lookup(ip, timeout):
    """Query Team Cymru via DNS TXT for ASN info."""
    result = {}
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            query = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # Use a simple DNS-over-TCP approach
            s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tcp.settimeout(timeout)
            s_tcp.connect(("8.8.8.8", 53))

            # Build DNS query
            import struct
            tid = 0x1234
            flags = 0x0100  # standard query
            header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
            qname = b""
            for part in query.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"
            question = qname + struct.pack(">HH", 16, 1)  # TXT record, IN class
            msg = header + question
            s_tcp.send(struct.pack(">H", len(msg)) + msg)
            resp_len = struct.unpack(">H", s_tcp.recv(2))[0]
            resp = s_tcp.recv(resp_len)
            s_tcp.close()

            # Parse TXT answer (rough parsing)
            txt = resp.decode("ascii", errors="replace")
            # Look for pipe-separated ASN data
            import re
            match = re.search(r"(\d+)\s*\|\s*([\d./]+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\S+)", txt)
            if match:
                result["asn"] = match.group(1)
                result["prefix"] = match.group(2)
                result["country"] = match.group(3)
                result["registry"] = match.group(4)
                result["allocated"] = match.group(5)
    except Exception:
        pass
    return result


def bgpview_asn_lookup(target, timeout):
    """Use BGPView API to look up ASN info."""
    results = {}
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{target}", timeout=timeout)
        if r.status_code == 200:
            data = r.json().get("data", {})
            prefixes = data.get("rir_allocation", {})
            results["ip"] = target
            results["rir"] = prefixes.get("rir_name", "")
            results["prefix"] = prefixes.get("prefix", "")
            results["country"] = prefixes.get("country_code", "")
            results["allocation_date"] = prefixes.get("date_allocated", "")
            ptr = data.get("ptr_record", "")
            results["ptr"] = ptr
            asn_list = []
            for prefix_info in data.get("prefixes", []):
                asn_info = prefix_info.get("asn", {})
                if asn_info:
                    asn_list.append({
                        "asn": asn_info.get("asn", ""),
                        "name": asn_info.get("name", ""),
                        "description": asn_info.get("description", ""),
                        "prefix": prefix_info.get("prefix", ""),
                        "country": asn_info.get("country_code", ""),
                    })
            results["asns"] = asn_list
    except Exception as e:
        results["error"] = str(e)
    return results


def bgpview_asn_prefixes(asn, timeout):
    """Get all prefixes for an ASN."""
    asn_num = asn.replace("AS", "").replace("as", "")
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=timeout)
        if r.status_code == 200:
            data = r.json().get("data", {})
            ipv4 = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
            ipv6 = [p["prefix"] for p in data.get("ipv6_prefixes", [])]
            return {"ipv4": ipv4, "ipv6": ipv6}
    except Exception:
        pass
    return {"ipv4": [], "ipv6": []}


def bgpview_asn_info(asn, timeout):
    """Get ASN details."""
    asn_num = asn.replace("AS", "").replace("as", "")
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn_num}", timeout=timeout)
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception:
        pass
    return {}


def bgpview_search(query, timeout):
    """Search for ASNs by organization name."""
    try:
        r = requests.get(f"https://api.bgpview.io/search?query_term={query}", timeout=timeout)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return data.get("asns", [])
    except Exception:
        pass
    return []


def resolve_target(target):
    """Resolve domain to IP if needed."""
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None


def main():
    ap = argparse.ArgumentParser(description="ASN Lookup: find ASN, IP ranges, org info")
    ap.add_argument("target", help="IP address, domain, or ASN (e.g., AS13335)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    ap.add_argument("--prefixes", action="store_true", help="List all prefixes for ASN")
    ap.add_argument("--search", action="store_true", help="Search by organization name")
    args = ap.parse_args()

    print(f"[*] ASN Lookup Tool")
    print(f"[*] Target: {args.target}\n")

    if args.search:
        print(f"[*] Searching for organization: {args.target}")
        results = bgpview_search(args.target, args.timeout)
        if results:
            print(f"  [+] Found {len(results)} ASN(s):\n")
            print(f"  {'ASN':<12} {'NAME':<30} {'COUNTRY':<8} {'DESCRIPTION'}")
            print(f"  {'-'*12} {'-'*30} {'-'*8} {'-'*30}")
            for asn in results[:20]:
                print(f"  AS{asn.get('asn',''):<9} {asn.get('name','')[:30]:<30} "
                      f"{asn.get('country_code',''):<8} {asn.get('description','')[:40]}")
        else:
            print("  [!] No results found")
        return

    if args.target.lower().startswith("as") and args.target[2:].isdigit():
        asn = args.target
        print(f"[*] Looking up ASN: {asn}")
        info = bgpview_asn_info(asn, args.timeout)
        if info:
            print(f"\n  ASN:           AS{info.get('asn', '')}")
            print(f"  Name:          {info.get('name', '')}")
            print(f"  Description:   {info.get('description_short', '')}")
            print(f"  Country:       {info.get('country_code', '')}")
            print(f"  Website:        {info.get('website', 'N/A')}")
            print(f"  Looking Glass: {info.get('looking_glass', 'N/A')}")
            email_contacts = info.get("email_contacts", [])
            if email_contacts:
                print(f"  Contacts:      {', '.join(email_contacts)}")
            abuse_contacts = info.get("abuse_contacts", [])
            if abuse_contacts:
                print(f"  Abuse:         {', '.join(abuse_contacts)}")

        if args.prefixes:
            print(f"\n[*] Fetching prefixes for {asn}...")
            prefixes = bgpview_asn_prefixes(asn, args.timeout)
            if prefixes["ipv4"]:
                print(f"\n  IPv4 Prefixes ({len(prefixes['ipv4'])}):")
                for p in prefixes["ipv4"]:
                    print(f"    {p}")
            if prefixes["ipv6"]:
                print(f"\n  IPv6 Prefixes ({len(prefixes['ipv6'])}):")
                for p in prefixes["ipv6"][:20]:
                    print(f"    {p}")
                if len(prefixes["ipv6"]) > 20:
                    print(f"    ... and {len(prefixes['ipv6']) - 20} more")
    else:
        ip = resolve_target(args.target)
        if not ip:
            print(f"[!] Cannot resolve: {args.target}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] IP: {ip}")
        print(f"\n[*] BGPView Lookup...")
        bgp = bgpview_asn_lookup(ip, args.timeout)
        if "error" in bgp:
            print(f"  [!] Error: {bgp['error']}")
        else:
            print(f"  PTR:        {bgp.get('ptr', 'N/A')}")
            print(f"  RIR:        {bgp.get('rir', 'N/A')}")
            print(f"  Prefix:     {bgp.get('prefix', 'N/A')}")
            print(f"  Country:    {bgp.get('country', 'N/A')}")
            if bgp.get("asns"):
                print(f"\n  Associated ASNs:")
                for a in bgp["asns"]:
                    print(f"    AS{a['asn']} - {a['name']} ({a['description'][:50]})")
                    print(f"      Prefix: {a['prefix']} | Country: {a['country']}")
                    if args.prefixes:
                        prefixes = bgpview_asn_prefixes(str(a["asn"]), args.timeout)
                        if prefixes["ipv4"]:
                            print(f"      All IPv4 ranges ({len(prefixes['ipv4'])}):")
                            for p in prefixes["ipv4"][:15]:
                                print(f"        {p}")
                            if len(prefixes["ipv4"]) > 15:
                                print(f"        ... and {len(prefixes['ipv4']) - 15} more")

        print(f"\n[*] Team Cymru Lookup...")
        cymru = cymru_lookup(ip, args.timeout)
        if cymru:
            print(f"  ASN:       {cymru.get('asn', 'N/A')}")
            print(f"  Prefix:    {cymru.get('prefix', 'N/A')}")
            print(f"  Country:   {cymru.get('country', 'N/A')}")
            print(f"  Registry:  {cymru.get('registry', 'N/A')}")
            print(f"  Allocated: {cymru.get('allocated', 'N/A')}")
        else:
            print("  [!] No Cymru data")

    print(f"\n{'='*50}")
    print(f"[*] ASN lookup complete")


if __name__ == "__main__":
    main()
