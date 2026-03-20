#!/usr/bin/env python3
"""Oracle TNS tool: send TNS commands, enumerate services and versions."""
import argparse, socket, struct, sys

CMDS = {"ping":"(CONNECT_DATA=(COMMAND=ping))","version":"(CONNECT_DATA=(COMMAND=version))",
        "status":"(CONNECT_DATA=(COMMAND=status))","services":"(CONNECT_DATA=(COMMAND=service_register_NSGR))",
        "debug":"(CONNECT_DATA=(COMMAND=debug))"}

def build_tns(data_str):
    d = data_str.encode("ascii"); hl = 58; tl = hl + len(d)
    pkt = struct.pack(">HH", tl, 0) + struct.pack("BB", 1, 0) + struct.pack(">H", 0)
    pkt += struct.pack(">HHHHHHHH", 314, 300, 0, 8192, 32767, 79, 0, 1)
    pkt += struct.pack(">HH", len(d), hl) + struct.pack(">I", 0) + struct.pack("BB", 0x41, 0x41)
    pkt += b"\x00" * 20 + d
    return pkt

def send_tns(host, port, data_str, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((host, port)); s.send(build_tns(data_str))
        resp = b""
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                resp += c
                if len(resp) >= 2 and len(resp) >= struct.unpack(">H", resp[:2])[0]: break
        except socket.timeout: pass
        s.close(); return resp
    except Exception as e: return None

def parse_resp(data):
    if not data or len(data) < 8: return {"type":"EMPTY","text":""}
    types = {1:"CONNECT",2:"ACCEPT",4:"REFUSE",5:"REDIRECT",6:"DATA",11:"RESEND"}
    ptype = types.get(data[4], f"UNK({data[4]})")
    decoded = data.decode("ascii", errors="replace")
    # Extract parenthesized content
    text_parts, depth, cur = [], 0, []
    for c in decoded:
        if c == "(": depth += 1; cur.append(c)
        elif c == ")": cur.append(c); depth -= 1
        elif depth > 0: cur.append(c)
        elif cur: text_parts.append("".join(cur)); cur = []
    if cur: text_parts.append("".join(cur))
    return {"type":ptype,"length":len(data),
            "text":" ".join(text_parts) if text_parts else decoded[8:60].strip()}

def main():
    parser = argparse.ArgumentParser(description="Oracle TNS command tool")
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p","--port", type=int, default=1521)
    parser.add_argument("-c","--command", default="version", choices=list(CMDS.keys())+["all","raw"])
    parser.add_argument("--raw", help="Raw connect data")
    parser.add_argument("-t","--timeout", type=float, default=10)
    args = parser.parse_args()
    print(f"[*] TNSCmd-Lite\n[*] Target: {args.target}:{args.port}\n")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(args.timeout)
        s.connect((args.target, args.port)); s.close(); print(f"[+] Port {args.port} open\n")
    except Exception as e: print(f"[!] Cannot connect: {e}"); sys.exit(1)
    cmds = [("raw", args.raw)] if args.raw else (list(CMDS.items()) if args.command == "all"
            else [(args.command, CMDS[args.command])])
    responded = 0
    for name, cmd_data in cmds:
        print(f"=== {name} ===")
        print(f"  Sending: {cmd_data[:70]}")
        resp = send_tns(args.target, args.port, cmd_data, args.timeout)
        if resp is None: print(f"  [-] No response"); continue
        p = parse_resp(resp)
        print(f"  Type: {p['type']} | Length: {p['length']}B")
        if p["text"]: print(f"  Content: {p['text'][:400]}")
        t = p.get("text","").lower()
        for marker in ["vsnnum=","version ","oracle","tnslsnr"]:
            if marker in t:
                i = t.find(marker); print(f"  [+] Version: {p['text'][i:i+50]}"); break
        responded += 1; print()
    print(f"{'='*60}\n[*] Commands: {len(cmds)} | Responses: {responded}")
    if responded: print("[*] TNS listener active")

if __name__ == "__main__":
    main()
