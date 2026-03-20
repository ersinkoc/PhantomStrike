#!/usr/bin/env python3
"""Binary pattern generator: create cyclic patterns for buffer overflow testing, calculate offsets."""
import argparse, string, struct, sys

def cyclic(length):
    pattern = []
    for a in string.ascii_uppercase:
        for b in string.ascii_lowercase:
            for c in string.digits:
                pattern.append(f"{a}{b}{c}")
                if len("".join(pattern)) >= length: return "".join(pattern)[:length]
    return "".join(pattern)[:length]

def find_offset(pattern, value):
    if isinstance(value, str) and not value.startswith("0x"):
        idx = pattern.find(value)
        if idx != -1: return idx
    try:
        val = int(value, 0) if isinstance(value, str) else int(value)
        for fmt in ["<I","<Q",">I"]:
            try:
                sz = 4 if fmt.endswith("I") else 8
                packed = struct.pack(fmt, val & (0xFFFFFFFF if sz==4 else 0xFFFFFFFFFFFFFFFF))
                search = packed.decode("ascii", errors="replace")
                idx = pattern.find(search)
                if idx != -1: return idx
            except: pass
    except: pass
    return -1

def gen_template(offset, arch="64"):
    pk = "struct.pack('<Q', addr)" if arch=="64" else "struct.pack('<I', addr)"
    return f'''#!/usr/bin/env python3
"""Exploit template - {offset}B overflow ({arch}-bit)"""
import struct
OFFSET = {offset}
RET_ADDR = 0xdeadbeef
payload = b"A" * OFFSET
payload += {pk.replace("addr","RET_ADDR")}
with open("payload.bin","wb") as f: f.write(payload)
print(f"Payload: {{len(payload)}} bytes")
'''

def hexdump(pattern, w=16):
    data = pattern.encode()
    for i in range(0, len(data), w):
        c = data[i:i+w]
        h = " ".join(f"{b:02x}" for b in c)
        a = "".join(chr(b) if 32<=b<127 else "." for b in c)
        print(f"  {i:08x}  {h:<{w*3}}  |{a}|")

def main():
    parser = argparse.ArgumentParser(description="Cyclic pattern generator for buffer overflow testing")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("create"); c.add_argument("length",type=int); c.add_argument("--hex",action="store_true")
    f = sub.add_parser("find"); f.add_argument("value"); f.add_argument("-l","--length",type=int,default=8192)
    t = sub.add_parser("template"); t.add_argument("offset",type=int); t.add_argument("--arch",choices=["32","64"],default="64")
    sub.add_parser("info")
    args = parser.parse_args()
    print("[*] GDB-PEDA-Lite\n")
    if args.command == "create":
        p = cyclic(args.length)
        if args.hex: hexdump(p)
        else:
            for i in range(0, len(p), 80): print(f"  {p[i:i+80]}")
        print(f"\n[*] Length: {len(p)} | First 4B (LE): 0x{struct.unpack('<I',p[:4].encode())[0]:08x}")
    elif args.command == "find":
        p = cyclic(args.length); off = find_offset(p, args.value)
        if off != -1:
            print(f"[+] Found! Value: {args.value} | Offset: {off} (0x{off:x})")
            print(f"[*] Payload: [padding({off}B)] + [ret_addr]")
        else: print(f"[-] '{args.value}' not found in {args.length}B pattern")
    elif args.command == "template":
        print(gen_template(args.offset, args.arch))
    elif args.command == "info":
        print("  x86_64 calling: rdi,rsi,rdx,rcx,r8,r9 | rax=syscall# | rsp=stack")
        print("  Syscalls: read=0 write=1 open=2 execve=59 mmap=9 mprotect=10")
        print("  Gadgets: pop rdi;ret | pop rsi;ret | pop rdx;ret | ret (align)")
        print("\n  Commands: create <len> | find <value> | template <offset> | info")
    else: parser.print_help()

if __name__ == "__main__":
    main()
