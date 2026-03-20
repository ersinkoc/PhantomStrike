#!/usr/bin/env python3
"""Windows security checker: check common Windows misconfigs via network (SMB, null sessions, RDP)."""
import argparse
import socket
import struct
import sys
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WINDOWS_PORTS = {
    135: "MSRPC", 139: "NetBIOS-SSN", 445: "SMB", 3389: "RDP",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 389: "LDAP", 636: "LDAPS",
    88: "Kerberos", 464: "Kpasswd", 53: "DNS", 593: "HTTP-RPC",
    1433: "MSSQL", 3268: "GC-LDAP", 3269: "GC-LDAPS",
}


def check_port(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def check_smb(host, timeout):
    findings = []
    if not check_port(host, 445, timeout):
        return findings

    findings.append({"check": "SMB Port", "status": "OPEN", "severity": "INFO",
                     "detail": "Port 445/TCP is accessible"})

    # SMB negotiate
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 445))
        negotiate = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        negotiate += b"\x00" * 12 + b"\xff\xff\x00\x00\x00\x00\x00\x00"
        negotiate += b"\x00\x62\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        pkt = struct.pack(">I", len(negotiate)) + negotiate
        s.send(pkt)
        resp = s.recv(4096)
        s.close()

        if resp and resp[4:8] == b"\xffSMB":
            findings.append({"check": "SMBv1 Protocol", "status": "ENABLED", "severity": "HIGH",
                             "detail": "SMBv1 is enabled - vulnerable to EternalBlue (MS17-010), WannaCry"})
            if len(resp) > 39 and not (resp[39] & 0x08):
                findings.append({"check": "SMB Signing", "status": "NOT REQUIRED", "severity": "MEDIUM",
                                 "detail": "SMB signing is not required - relay attacks possible"})
        elif resp and resp[4:8] == b"\xfeSMB":
            findings.append({"check": "SMB Protocol", "status": "SMBv2+", "severity": "INFO",
                             "detail": "SMBv2+ negotiated (SMBv1 disabled)"})
            if len(resp) > 71:
                sec = struct.unpack("<H", resp[70:72])[0]
                if not (sec & 0x02):
                    findings.append({"check": "SMB Signing", "status": "NOT REQUIRED", "severity": "MEDIUM",
                                     "detail": "SMB signing not required on SMBv2+"})
    except Exception:
        pass

    # Null session
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 445))
        negotiate = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        negotiate += b"\x00" * 12 + b"\xff\xff\x00\x00\x00\x00\x00\x00"
        negotiate += b"\x00\x62\x00\x02NT LM 0.12\x00"
        pkt = struct.pack(">I", len(negotiate)) + negotiate
        s.send(pkt)
        resp = s.recv(4096)
        # Presence of a response indicates SMB is working
        if resp and len(resp) > 36:
            findings.append({"check": "SMB Null Session", "status": "NEEDS VERIFICATION", "severity": "MEDIUM",
                             "detail": "SMB responds to negotiate - test null session with smbclient"})
        s.close()
    except Exception:
        pass

    return findings


def check_rdp(host, timeout):
    findings = []
    if not check_port(host, 3389, timeout):
        return findings

    findings.append({"check": "RDP Port", "status": "OPEN", "severity": "INFO",
                     "detail": "Port 3389/TCP (RDP) is accessible"})

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 3389))
        # RDP negotiation request (without NLA)
        rdp_req = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
        s.send(rdp_req)
        resp = s.recv(4096)
        s.close()

        if resp:
            findings.append({"check": "RDP Service", "status": "ACTIVE", "severity": "INFO",
                             "detail": f"RDP responds ({len(resp)} bytes)"})
            if len(resp) > 11 and resp[0] == 0x03:
                # Check NLA support
                if resp[11] == 0x02:
                    findings.append({"check": "NLA Support", "status": "ENABLED", "severity": "INFO",
                                     "detail": "Network Level Authentication is supported"})
                elif resp[11] == 0x03:
                    findings.append({"check": "NLA Support", "status": "NOT REQUIRED", "severity": "MEDIUM",
                                     "detail": "NLA may not be required - brute force risk"})
            # Check for BlueKeep indicator
            rdp_req2 = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(timeout)
                s2.connect((host, 3389))
                s2.send(rdp_req2)
                resp2 = s2.recv(4096)
                s2.close()
                if resp2:
                    findings.append({"check": "RDP Security", "status": "CHECK", "severity": "MEDIUM",
                                     "detail": "Verify CVE-2019-0708 (BlueKeep) patches are applied"})
            except Exception:
                pass
    except Exception:
        pass

    return findings


def check_winrm(host, timeout):
    findings = []
    for port, scheme in [(5985, "http"), (5986, "https")]:
        if not check_port(host, port, timeout):
            continue
        findings.append({"check": f"WinRM ({scheme.upper()})", "status": "OPEN", "severity": "INFO",
                         "detail": f"Port {port}/TCP (WinRM-{scheme.upper()}) is accessible"})
        try:
            r = requests.post(f"{scheme}://{host}:{port}/wsman", timeout=timeout, verify=False,
                              headers={"Content-Type": "application/soap+xml"}, data="")
            if r.status_code in (401, 200, 403):
                findings.append({"check": "WinRM Service", "status": "ACTIVE", "severity": "MEDIUM",
                                 "detail": f"WinRM endpoint responds [{r.status_code}]"})
                if r.status_code == 401:
                    auth = r.headers.get("WWW-Authenticate", "")
                    findings.append({"check": "WinRM Auth", "status": "REQUIRED", "severity": "INFO",
                                     "detail": f"Auth methods: {auth[:60]}"})
        except Exception:
            pass
    return findings


def check_ldap(host, timeout):
    findings = []
    if not check_port(host, 389, timeout):
        return findings
    findings.append({"check": "LDAP Port", "status": "OPEN", "severity": "INFO",
                     "detail": "Port 389/TCP (LDAP) is accessible"})
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 389))
        # Basic LDAP bind with no credentials (anonymous bind)
        anon_bind = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.send(anon_bind)
        resp = s.recv(4096)
        s.close()
        if resp and len(resp) > 5:
            # Check result code in bind response
            if b"\x0a\x01\x00" in resp:  # resultCode: success
                findings.append({"check": "LDAP Anonymous Bind", "status": "ALLOWED", "severity": "HIGH",
                                 "detail": "Anonymous LDAP bind is permitted - information disclosure risk"})
            else:
                findings.append({"check": "LDAP Anonymous Bind", "status": "DENIED", "severity": "INFO",
                                 "detail": "Anonymous bind rejected"})
    except Exception:
        pass
    return findings


def check_mssql(host, timeout):
    findings = []
    if not check_port(host, 1433, timeout):
        return findings
    findings.append({"check": "MSSQL Port", "status": "OPEN", "severity": "MEDIUM",
                     "detail": "Port 1433/TCP (MSSQL) is accessible"})
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 1433))
        time.sleep(0.5)
        data = s.recv(4096)
        s.close()
        if data:
            banner = data.decode("utf-8", errors="replace")[:80]
            findings.append({"check": "MSSQL Banner", "status": "VISIBLE", "severity": "INFO",
                             "detail": f"Banner: {banner}"})
    except Exception:
        pass
    return findings


def check_kerberos(host, timeout):
    findings = []
    if not check_port(host, 88, timeout):
        return findings
    findings.append({"check": "Kerberos", "status": "OPEN", "severity": "INFO",
                     "detail": "Port 88/TCP (Kerberos) - indicates Active Directory Domain Controller"})
    return findings


def main():
    ap = argparse.ArgumentParser(description="WinPEAS-lite: Windows security checker via network")
    ap.add_argument("target", help="Target Windows host IP or hostname")
    ap.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout")
    ap.add_argument("--quick", action="store_true", help="Quick scan (SMB + RDP only)")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] WinPEAS-Lite: Windows Security Checker (Network)")
    print(f"[*] Target: {host} ({ip})\n")

    # Port scan
    print("[*] Scanning Windows service ports...")
    open_ports = []
    for port, svc in sorted(WINDOWS_PORTS.items()):
        if check_port(ip, port, args.timeout):
            open_ports.append((port, svc))
            print(f"  [+] {port:<6} {svc:<15} OPEN")
    if not open_ports:
        print("  [!] No Windows service ports found")
        return
    print()

    # Determine if it's a DC
    is_dc = any(p in (88, 389, 636, 3268) for p, _ in open_ports)
    if is_dc:
        print("[*] Possible Domain Controller detected (Kerberos/LDAP ports open)\n")

    all_findings = []

    print("[*] Running security checks...\n")

    print("  --- SMB Checks ---")
    smb_findings = check_smb(ip, args.timeout)
    for f in smb_findings:
        print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
    all_findings.extend(smb_findings)
    print()

    print("  --- RDP Checks ---")
    rdp_findings = check_rdp(ip, args.timeout)
    for f in rdp_findings:
        print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
    all_findings.extend(rdp_findings)
    print()

    if not args.quick:
        print("  --- WinRM Checks ---")
        winrm_findings = check_winrm(ip, args.timeout)
        for f in winrm_findings:
            print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
        all_findings.extend(winrm_findings)
        print()

        if is_dc:
            print("  --- LDAP Checks ---")
            ldap_findings = check_ldap(ip, args.timeout)
            for f in ldap_findings:
                print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
            all_findings.extend(ldap_findings)
            print()

            print("  --- Kerberos Checks ---")
            kerb_findings = check_kerberos(ip, args.timeout)
            for f in kerb_findings:
                print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
            all_findings.extend(kerb_findings)
            print()

        print("  --- MSSQL Checks ---")
        mssql_findings = check_mssql(ip, args.timeout)
        for f in mssql_findings:
            print(f"  [{f['severity']}] {f['check']}: {f['status']} - {f['detail']}")
        all_findings.extend(mssql_findings)
        print()

    print(f"{'='*60}")
    print(f"[*] WINDOWS SECURITY SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Host: {host} ({ip})")
    print(f"  Type: {'Domain Controller' if is_dc else 'Windows Host'}")
    print(f"  Open ports: {len(open_ports)}")

    non_info = [f for f in all_findings if f["severity"] != "INFO"]
    high = sum(1 for f in non_info if f["severity"] == "HIGH")
    med = sum(1 for f in non_info if f["severity"] == "MEDIUM")
    print(f"  Issues: {len(non_info)} ({high} HIGH, {med} MEDIUM)")

    if non_info:
        print(f"\n  Issues found:")
        for f in non_info:
            print(f"    [{f['severity']}] {f['check']}: {f['detail']}")


if __name__ == "__main__":
    main()
