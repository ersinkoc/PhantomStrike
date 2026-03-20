#!/usr/bin/env python3
"""AD recon: check for common Active Directory misconfigs via LDAP/SMB queries."""
import argparse, socket, struct, sys

AD_PORTS = {
    88: "Kerberos", 135: "MSRPC", 139: "NetBIOS", 389: "LDAP", 445: "SMB",
    464: "Kerberos-Pwd", 636: "LDAPS", 3268: "GlobalCatalog", 3269: "GC-SSL",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 9389: "AD-WebSvc",
}

def scan_ad_ports(host, timeout=3):
    results = []
    for port, svc in AD_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            o = s.connect_ex((host, port)) == 0
            s.close()
            results.append((port, svc, o))
        except Exception:
            results.append((port, svc, False))
    return results

def check_smb(host, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 445))
        neg = (b"\x00\x00\x00\x85\xfe\x53\x4d\x42" + b"\x00" * 56 +
               b"\x24\x00\x02\x00\x01\x00\x00\x00" + b"\x00" * 28 + b"\x02\x02\x10\x02")
        s.send(neg)
        r = s.recv(4096)
        s.close()
        return {"accessible": True, "version": "SMB2+" if len(r) > 70 else "Unknown"}
    except Exception as e:
        return {"accessible": False, "error": str(e)}

def check_ldap(host, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 389))
        bind = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.send(bind)
        r = s.recv(4096)
        info = {"accessible": True, "anonymous_bind": b"\x0a\x01\x00" in r}
        search = (b"\x30\x25\x02\x01\x02\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00"
                  b"\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65"
                  b"\x63\x74\x43\x6c\x61\x73\x73\x30\x00")
        s.send(search)
        sr = s.recv(8192)
        s.close()
        strings, cur = [], []
        for b in sr:
            if 32 <= b < 127: cur.append(chr(b))
            else:
                if len(cur) >= 4: strings.append("".join(cur))
                cur = []
        for st in strings:
            if "DC=" in st or "dc=" in st: info["domain_dn"] = st; break
        info["strings"] = [st for st in strings if len(st) > 5]
        return info
    except Exception as e:
        return {"accessible": False, "error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Active Directory recon and security checker")
    parser.add_argument("target", help="Domain Controller IP or hostname")
    parser.add_argument("-t", "--timeout", type=float, default=5)
    args = parser.parse_args()
    print(f"[*] BloodHound-Lite - AD Recon\n[*] Target: {args.target}\n")
    try: ip = socket.gethostbyname(args.target); print(f"  Resolved: {ip}\n")
    except socket.gaierror: ip = args.target

    print("=== AD Service Discovery ===\n")
    ports = scan_ad_ports(ip, args.timeout)
    oc = 0
    for p, svc, o in ports:
        if o: print(f"  [+] {p:<6} {svc:<20} OPEN"); oc += 1
    if oc == 0: print("  [-] No AD services detected"); sys.exit(0)
    open_set = {p for p, _, o in ports if o}
    print(f"\n  Likely DC: {'Yes' if {88, 389, 445} & open_set else 'No'}")

    print("\n=== SMB Analysis ===\n")
    smb = check_smb(ip, args.timeout)
    if smb.get("accessible"): print(f"  [+] SMB: {smb.get('version','?')}")
    else: print(f"  [-] SMB: {smb.get('error','N/A')}")

    print("\n=== LDAP Analysis ===\n")
    ldap = check_ldap(ip, args.timeout)
    if ldap.get("accessible"):
        print(f"  [+] LDAP accessible")
        if ldap.get("anonymous_bind"): print(f"  [!!!] Anonymous bind ALLOWED")
        if ldap.get("domain_dn"): print(f"  [+] Domain: {ldap['domain_dn']}")
        for s in [x for x in ldap.get("strings", []) if any(k in x.lower() for k in ["dc=","domain","forest"])][:5]:
            print(f"  [*] {s}")
    else: print(f"  [-] LDAP: {ldap.get('error','N/A')}")

    print("\n=== Security Assessment ===\n")
    findings = []
    if 389 in open_set and 636 not in open_set: findings.append(("HIGH","LDAP without LDAPS"))
    if ldap.get("anonymous_bind"): findings.append(("CRITICAL","Anonymous LDAP bind allowed"))
    if 5985 in open_set: findings.append(("MEDIUM","WinRM HTTP exposed"))
    if 139 in open_set: findings.append(("MEDIUM","NetBIOS exposed"))
    if smb.get("accessible"): findings.append(("INFO","SMB accessible - check signing"))
    if 3268 in open_set: findings.append(("MEDIUM","Global Catalog exposed"))
    for sev, desc in findings:
        icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]","INFO":"[*]"}.get(sev,"[?]")
        print(f"  {icon} [{sev}] {desc}")
    print(f"\n{'='*50}\n[*] Open: {oc}/{len(AD_PORTS)} | Findings: {len(findings)}")

if __name__ == "__main__":
    main()
