#!/usr/bin/env python3
"""Oracle DB checker: test TNS listener, check for default SIDs, version detection."""
import argparse, socket, struct, sys

SIDS = ["ORCL","XE","ORCLCDB","ORCLPDB1","PLSExtProc","PROD","DEV","TEST","STAGE","QA",
        "HR","FINANCE","SAP","APEX","DB11G","DB12C","DB19C","ORADB","FREE","FREEPDB1",
        "TESTDB","DEVDB","PRODDB","LIVE","BACKUP","REPORT"]

def build_tns(sid):
    cd = f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SID={sid})(CID=(PROGRAM=py)(HOST=scan)(USER=test))))"
    cb = cd.encode("ascii"); hl = 58; tl = hl + len(cb)
    pkt = struct.pack(">HH", tl, 0) + struct.pack("BB", 1, 0) + struct.pack(">H", 0)
    pkt += struct.pack(">HHHHHHHH", 314, 300, 0, 8192, 32767, 79, 0, 1)
    pkt += struct.pack(">HH", len(cb), hl) + struct.pack(">I", 0) + struct.pack("BB", 0x41, 0x41)
    pkt += b"\x00" * 20 + cb
    return pkt

def probe(host, port, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((host, port)); s.send(build_tns("ORCL")); r = s.recv(4096); s.close()
        if len(r) >= 8:
            t = r[4]
            return {2:"ACCEPT",4:"REFUSE",11:"RESEND"}.get(t, f"TYPE_{t}"), r
        return "UNKNOWN", r
    except socket.timeout: return "TIMEOUT", b""
    except ConnectionRefusedError: return "CLOSED", b""
    except Exception as e: return f"ERROR:{e}", b""

def check_sid(host, port, sid, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((host, port)); s.send(build_tns(sid)); r = s.recv(4096); s.close()
        if len(r) >= 8:
            if r[4] == 2: return True, "ACCEPTED"
            if r[4] == 4:
                rs = r.decode("ascii",errors="replace")
                if "12505" in rs or "unknown" in rs.lower(): return False, "Unknown SID"
                return True, "REFUSED (SID likely valid)"
        return False, "No response"
    except: return False, "Error"

def main():
    parser = argparse.ArgumentParser(description="Oracle DB scanner")
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p","--port", type=int, default=1521)
    parser.add_argument("--scan-ports", action="store_true")
    parser.add_argument("-t","--timeout", type=float, default=5)
    parser.add_argument("--sids", help="Custom SID list file")
    args = parser.parse_args()
    print(f"[*] Oracle Scanner\n[*] Target: {args.target}\n")
    open_ports = []
    ports = [1521,1522,1523,2483,2484] if args.scan_ports else [args.port]
    for port in ports:
        st, data = probe(args.target, port, args.timeout)
        if st not in ("CLOSED","TIMEOUT"):
            open_ports.append(port)
            print(f"  [+] Port {port}: TNS listener ({st})")
            d = data.decode("ascii",errors="replace")
            for m in ["VSNNUM=","Version "]:
                i = d.find(m)
                if i != -1: print(f"      Version: {d[i:i+30].split(')')[0]}"); break
        elif args.scan_ports: print(f"  [-] Port {port}: {st}")
    if not open_ports: print("[!] No TNS listeners"); sys.exit(0)
    port = open_ports[0]; sids = SIDS
    if args.sids:
        try:
            with open(args.sids) as f: sids = [l.strip() for l in f if l.strip()]
        except Exception as e: print(f"[!] {e}")
    print(f"\n[*] Enumerating {len(sids)} SIDs on port {port}...\n")
    valid = []
    for sid in sids:
        found, reason = check_sid(args.target, port, sid, args.timeout)
        if found: valid.append(sid); print(f"  [+] {sid} ({reason})")
    print(f"\n{'='*50}\n[*] Open ports: {open_ports}\n[*] Valid SIDs: {len(valid)}")
    for s in valid: print(f"    - {s}")
    if valid: print("[!] Test for default credentials")

if __name__ == "__main__":
    main()
