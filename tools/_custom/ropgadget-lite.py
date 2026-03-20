#!/usr/bin/env python3
"""ROP gadget finder: search binary for useful gadgets (ret, pop, syscall patterns)."""
import argparse, struct, sys

PAT_X86 = [(b"\xc3","ret"),(b"\x58\xc3","pop eax;ret"),(b"\x5b\xc3","pop ebx;ret"),
    (b"\x59\xc3","pop ecx;ret"),(b"\x5a\xc3","pop edx;ret"),(b"\x5e\xc3","pop esi;ret"),
    (b"\x5f\xc3","pop edi;ret"),(b"\x5d\xc3","pop ebp;ret"),(b"\x31\xc0\xc3","xor eax,eax;ret"),
    (b"\x31\xdb\xc3","xor ebx,ebx;ret"),(b"\x89\xe0\xc3","mov eax,esp;ret"),
    (b"\xff\xe0","jmp eax"),(b"\xff\xe4","jmp esp"),(b"\xff\xd0","call eax"),
    (b"\xcd\x80","int 0x80"),(b"\x0f\x05","syscall"),(b"\x0f\x34","sysenter"),
    (b"\x50\xc3","push eax;ret"),(b"\x89\xc1\xc3","mov ecx,eax;ret")]
PAT_X64 = [(b"\x41\x58\xc3","pop r8;ret"),(b"\x41\x59\xc3","pop r9;ret"),
    (b"\x41\x5e\xc3","pop r14;ret"),(b"\x41\x5f\xc3","pop r15;ret"),
    (b"\x48\x89\xc7\xc3","mov rdi,rax;ret"),(b"\x48\x31\xc0\xc3","xor rax,rax;ret"),
    (b"\x48\x31\xff\xc3","xor rdi,rdi;ret"),(b"\x48\x31\xf6\xc3","xor rsi,rsi;ret"),
    (b"\x48\x31\xd2\xc3","xor rdx,rdx;ret"),(b"\x5f\xc3","pop rdi;ret"),
    (b"\x5e\xc3","pop rsi;ret"),(b"\x5a\xc3","pop rdx;ret"),(b"\x58\xc3","pop rax;ret")]

def detect_arch(data):
    if data[:4] == b"\x7fELF": return "x86_64" if data[4] == 2 else "x86"
    if data[:2] == b"MZ" and len(data) > 64:
        pe = struct.unpack("<I", data[60:64])[0]
        if pe+6 <= len(data): return "x86_64" if struct.unpack("<H", data[pe+4:pe+6])[0]==0x8664 else "x86"
    return "unknown"

def find_gadgets(data, patterns, base=0, limit=500):
    gadgets = []
    for pat, desc in patterns:
        off = 0
        while len(gadgets) < limit:
            idx = data.find(pat, off)
            if idx == -1: break
            gadgets.append((base+idx, desc, pat.hex(), len(pat))); off = idx + 1
    return gadgets

def main():
    parser = argparse.ArgumentParser(description="ROP gadget finder")
    parser.add_argument("target", help="Binary file")
    parser.add_argument("-b","--base", type=lambda x:int(x,0), default=0x400000)
    parser.add_argument("-m","--max", type=int, default=500)
    args = parser.parse_args()
    print(f"[*] ROPGadget-Lite\n[*] File: {args.target}\n[*] Base: 0x{args.base:x}\n")
    try:
        with open(args.target,"rb") as f: data = f.read()
    except Exception as e: print(f"[!] {e}"); sys.exit(1)
    arch = detect_arch(data); print(f"[*] Arch: {arch}")
    pats = PAT_X86 + (PAT_X64 if arch == "x86_64" else [])
    gadgets = find_gadgets(data, pats, args.base, args.max)
    seen = set(); unique = []
    for g in gadgets:
        if g[1] not in seen: seen.add(g[1]); unique.append(g)
    print(f"[*] Found {len(gadgets)} ({len(unique)} unique)\n")
    print(f"{'ADDR':<18} {'GADGET':<30} {'BYTES'}")
    print(f"{'-'*18} {'-'*30} {'-'*16}")
    for addr, desc, ctx, sz in unique:
        print(f"0x{addr:016x} {desc:<30} {ctx[-sz*2:]}")
    # Chain suggestions
    need64 = {"pop rdi;ret","pop rsi;ret","pop rdx;ret","pop rax;ret","syscall"}
    need32 = {"pop eax;ret","pop ebx;ret","pop ecx;ret","pop edx;ret","int 0x80"}
    found = {g[1] for g in gadgets}
    for name, need in [("x86_64 execve",need64),("x86 execve",need32)]:
        match = found & need
        if len(match) >= 4:
            print(f"\n[+] Possible {name} chain ({len(match)}/{len(need)} gadgets)")
    print(f"\n{'='*50}\n[*] Total: {len(gadgets)} | Unique: {len(unique)}")

if __name__ == "__main__":
    main()
