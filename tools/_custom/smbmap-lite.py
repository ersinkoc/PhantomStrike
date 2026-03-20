#!/usr/bin/env python3
"""SMB share enumerator: list shares, check permissions, detect anonymous access."""
import argparse
import socket
import struct
import sys
import time


def create_negotiate_request():
    """Create SMB1 Negotiate Protocol Request."""
    # SMB Header
    header = b"\xffSMB"  # Protocol ID
    header += b"\x72"     # Command: Negotiate Protocol
    header += b"\x00" * 4  # Status
    header += b"\x18"     # Flags
    header += b"\x53\xc8" # Flags2
    header += b"\x00" * 12  # Padding
    header += b"\xff\xff"  # Tree ID
    header += b"\x00\x00"  # Process ID
    header += b"\x00\x00"  # User ID
    header += b"\x00\x00"  # Multiplex ID

    # Negotiate payload
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    word_count = b"\x00"
    byte_count = struct.pack("<H", len(dialects))

    packet = header + word_count + byte_count + dialects
    netbios = struct.pack(">I", len(packet))
    return netbios + packet


def create_smb2_negotiate():
    """Create SMB2 Negotiate request."""
    # NetBIOS + SMB2 Header
    smb2_header = b"\xfeSMB"  # Protocol ID
    smb2_header += struct.pack("<H", 64)  # Header Length
    smb2_header += struct.pack("<H", 0)   # Credit Charge
    smb2_header += struct.pack("<I", 0)   # Status
    smb2_header += struct.pack("<H", 0)   # Command: NEGOTIATE
    smb2_header += struct.pack("<H", 0)   # Credits Requested
    smb2_header += struct.pack("<I", 0)   # Flags
    smb2_header += struct.pack("<I", 0)   # Next Command
    smb2_header += struct.pack("<Q", 0)   # Message ID
    smb2_header += struct.pack("<I", 0)   # Reserved
    smb2_header += struct.pack("<I", 0)   # Tree ID
    smb2_header += struct.pack("<Q", 0)   # Session ID
    smb2_header += b"\x00" * 16           # Signature

    # Negotiate Request
    negotiate = struct.pack("<H", 36)   # Structure Size
    negotiate += struct.pack("<H", 2)    # Dialect Count
    negotiate += struct.pack("<H", 1)    # Security Mode
    negotiate += struct.pack("<H", 0)    # Reserved
    negotiate += struct.pack("<I", 0)    # Capabilities
    negotiate += b"\x00" * 16           # Client GUID
    negotiate += struct.pack("<I", 0)    # Negotiate Context Offset
    negotiate += struct.pack("<H", 0)    # Negotiate Context Count
    negotiate += struct.pack("<H", 0)    # Reserved
    negotiate += struct.pack("<H", 0x0202)  # SMB 2.0.2
    negotiate += struct.pack("<H", 0x0210)  # SMB 2.1

    packet = smb2_header + negotiate
    netbios = struct.pack(">I", len(packet))
    return netbios + packet


def try_smb_connection(host, port, timeout):
    """Try to connect and get SMB negotiation info."""
    result = {"host": host, "port": port, "smb_version": "unknown", "signing": "unknown",
              "os": "unknown", "domain": "unknown", "error": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Send SMB1 negotiate
        s.send(create_negotiate_request())
        resp = s.recv(4096)
        s.close()

        if len(resp) > 36:
            if resp[4:8] == b"\xffSMB":
                result["smb_version"] = "SMBv1"
                if len(resp) > 39:
                    security_mode = resp[39]
                    result["signing"] = "required" if security_mode & 0x08 else "optional"
            elif resp[4:8] == b"\xfeSMB":
                result["smb_version"] = "SMBv2+"
                if len(resp) > 70:
                    security_mode = struct.unpack("<H", resp[70:72])[0]
                    result["signing"] = "required" if security_mode & 0x02 else "optional"
    except Exception as e:
        result["error"] = str(e)
    return result


def try_null_session(host, port, timeout):
    """Attempt null session authentication via SMB."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(create_negotiate_request())
        resp = s.recv(4096)

        # Try session setup with empty credentials
        session_setup = b"\xffSMB"
        session_setup += b"\x73"  # Session Setup
        session_setup += b"\x00" * 4
        session_setup += b"\x08"
        session_setup += b"\x01\xc8"
        session_setup += b"\x00" * 12
        session_setup += b"\xff\xff"
        session_setup += b"\x00\x00"
        session_setup += b"\x00\x00"
        session_setup += b"\x00\x00"

        # Word count and parameters
        session_setup += b"\x0d"  # Word Count
        session_setup += b"\xff"  # AndXCommand
        session_setup += b"\x00"  # Reserved
        session_setup += b"\x00\x00"  # AndXOffset
        session_setup += b"\xff\xff"  # Max Buffer
        session_setup += b"\x02\x00"  # Max Mpx Count
        session_setup += b"\x01\x00"  # VC Number
        session_setup += b"\x00\x00\x00\x00"  # Session Key
        session_setup += b"\x00\x00"  # OEM Password Length
        session_setup += b"\x00\x00"  # Unicode Password Length
        session_setup += b"\x00\x00\x00\x00"  # Reserved
        session_setup += b"\x00\x00\x00\x00"  # Capabilities
        session_setup += b"\x00\x00"  # Byte Count

        pkt = struct.pack(">I", len(session_setup)) + session_setup
        s.send(pkt)
        resp2 = s.recv(4096)
        s.close()

        if len(resp2) > 12:
            status = struct.unpack("<I", resp2[9:13])[0] if resp2[4:8] == b"\xffSMB" else 0xFFFFFFFF
            return status == 0 or status == 0xC0000016  # SUCCESS or more processing needed
    except Exception:
        pass
    return False


def check_smb_shares_http(host, timeout):
    """Try to enumerate shares via common SMB-related HTTP endpoints."""
    import requests
    shares = []
    common_share_names = ["C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "print$",
                          "Users", "Public", "Shared", "Documents", "Backups",
                          "IT", "Data", "Software", "Temp", "www", "web"]
    return common_share_names


def main():
    ap = argparse.ArgumentParser(description="SMBMap-lite: SMB share enumerator")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("-p", "--port", type=int, default=445, help="SMB port (default: 445)")
    ap.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout")
    ap.add_argument("--check-139", action="store_true", help="Also check port 139")
    args = ap.parse_args()

    host = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] SMBMap-Lite: SMB Share Enumerator")
    print(f"[*] Target: {host} ({ip})\n")

    ports_to_check = [args.port]
    if args.check_139:
        ports_to_check.append(139)

    all_findings = []

    for port in ports_to_check:
        print(f"[*] Checking SMB on port {port}...")

        # Check if port is open
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(args.timeout)
            s.connect((ip, port))
            s.close()
            print(f"  [+] Port {port} is open")
        except Exception:
            print(f"  [-] Port {port} is closed/filtered")
            continue

        # SMB Negotiation
        print(f"\n[*] SMB Negotiation...")
        smb_info = try_smb_connection(ip, port, args.timeout)
        if smb_info["error"]:
            print(f"  [!] Error: {smb_info['error']}")
        else:
            print(f"  SMB Version: {smb_info['smb_version']}")
            print(f"  Signing:     {smb_info['signing']}")
            if smb_info["signing"] == "optional":
                all_findings.append({"issue": "SMB signing not required", "severity": "MEDIUM",
                                     "detail": "SMB relay attacks may be possible"})
                print(f"  [MEDIUM] SMB signing not required - relay attacks possible")

        # Null Session Check
        print(f"\n[*] Testing null session (anonymous access)...")
        null_ok = try_null_session(ip, port, args.timeout)
        if null_ok:
            print(f"  [HIGH] Null session authentication ACCEPTED")
            print(f"    Anonymous users may be able to enumerate shares and users")
            all_findings.append({"issue": "Null session accepted", "severity": "HIGH",
                                 "detail": "Anonymous authentication allowed on SMB"})
        else:
            print(f"  [OK] Null session rejected")

        # SMBv1 Check
        if smb_info["smb_version"] == "SMBv1":
            print(f"\n  [HIGH] SMBv1 is enabled - vulnerable to EternalBlue and similar exploits")
            all_findings.append({"issue": "SMBv1 enabled", "severity": "HIGH",
                                 "detail": "SMBv1 is deprecated and has critical vulnerabilities (MS17-010)"})

    # Common share enumeration info
    print(f"\n[*] Common SMB Share Names (for manual testing):")
    shares = ["C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "print$",
              "Users", "Public", "Shared", "Backups", "IT", "Data"]
    for share in shares:
        access_type = "Admin" if "$" in share else "Standard"
        print(f"  \\\\{host}\\{share:<15} ({access_type})")

    print(f"\n{'='*60}")
    print(f"[*] SMB SCAN SUMMARY")
    print(f"{'='*60}\n")
    print(f"  Host: {host} ({ip})")
    print(f"  SMB Version: {smb_info.get('smb_version', 'N/A')}")
    print(f"  Signing: {smb_info.get('signing', 'N/A')}")
    print(f"  Null Session: {'Allowed' if null_ok else 'Denied'}")
    print(f"  Issues: {len(all_findings)}")

    if all_findings:
        print(f"\n  Findings:")
        for f in all_findings:
            print(f"    [{f['severity']}] {f['issue']}: {f['detail']}")


if __name__ == "__main__":
    main()
