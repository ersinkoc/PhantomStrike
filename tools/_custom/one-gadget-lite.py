#!/usr/bin/env python3
"""Binary constraint analyzer: find one-gadget-like patterns (execve/system calls) in binaries."""
import argparse, struct, sys

BINSH = [b"/bin/sh", b"/bin/bash", b"/bin/dash"]

def find_binsh(data):
    offsets = []
    for s in BINSH:
        idx = 0
        while True:
            idx = data.find(s, idx)
            if idx == -1: break
            offsets.append((idx, s.decode(errors="replace").strip("\x00"))); idx += 1
    return offsets

def find_candidates(data, base=0):
    candidates = []; binsh = find_binsh(data)
    if not binsh: return candidates
    # Find syscall locations
    sc_locs = []; idx = 0
    while True:
        idx = data.find(b"\x0f\x05", idx)
        if idx == -1: break
        sc_locs.append(idx); idx += 1
    # Check backward from each syscall
    for sc in sc_locs[:200]:
        ws = max(0, sc - 64); w = data[ws:sc+2]; constraints = []
        if b"\x48\xc7\xc0\x3b\x00\x00\x00" in w: constraints.append("rax=0x3b(execve)")
        if b"\x48\x31\xd2" in w or b"\x48\xc7\xc2\x00\x00\x00\x00" in w: constraints.append("rdx=NULL")
        if b"\x48\x31\xf6" in w or b"\x48\xc7\xc6\x00\x00\x00\x00" in w: constraints.append("rsi=NULL")
        if b"\x48\x8d\x3d" in w: constraints.append("rdi=ptr")
        if len(constraints) >= 2:
            for bo, bs in binsh:
                if -0x100000 < bo - sc < 0x100000:
                    constraints.append(f"/bin/sh@0x{bo:x}"); break
            candidates.append({"addr":base+ws,"constraints":constraints,
                               "bytes":w.hex()[:40],"type":"execve_syscall"})
    # Check lea rdi + call patterns
    for bo, bs in binsh:
        for i in range(max(0, bo-0x10000), min(len(data)-7, bo+0x10000)):
            if data[i:i+3] == b"\x48\x8d\x3d":
                rip_off = struct.unpack("<i", data[i+3:i+7])[0]
                if i + 7 + rip_off == bo:
                    nb = data[i+7:i+20]
                    if b"\xe8" in nb or b"\xff" in nb:
                        candidates.append({"addr":base+i,"constraints":[f"rdi->'{bs}'","call nearby"],
                                           "bytes":data[i:i+15].hex(),"type":"system_call"})
    return candidates

def main():
    parser = argparse.ArgumentParser(description="One-gadget constraint analyzer")
    parser.add_argument("target", help="Binary file (libc)")
    parser.add_argument("-b","--base", type=lambda x:int(x,0), default=0)
    parser.add_argument("-a","--all", action="store_true")
    args = parser.parse_args()
    print(f"[*] One-Gadget-Lite\n[*] File: {args.target}\n[*] Base: 0x{args.base:x}\n")
    try:
        with open(args.target, "rb") as f: data = f.read()
    except Exception as e: print(f"[!] {e}"); sys.exit(1)
    print(f"  Size: {len(data):,} bytes")
    binsh = find_binsh(data)
    print(f"  /bin/sh strings: {len(binsh)}")
    for o, s in binsh[:5]: print(f"    0x{o:x}: \"{s}\"")
    cands = find_candidates(data, args.base)
    print(f"\n[*] Found {len(cands)} candidates\n")
    shown = cands if args.all else cands[:15]
    for i, c in enumerate(shown):
        print(f"  [{i+1}] 0x{c['addr']:x} ({c['type']})")
        print(f"      Bytes: {c['bytes']}")
        print(f"      Constraints: {', '.join(c['constraints'])}\n")
    if cands: print(f"{'='*50}\n[*] Verify with debugger before use")
    else: print("[*] No one-gadget candidates found")

if __name__ == "__main__":
    main()
