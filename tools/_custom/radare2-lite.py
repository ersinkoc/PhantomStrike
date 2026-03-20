#!/usr/bin/env python3
"""Binary info extractor: read ELF/PE headers, find strings, detect packed binaries, security features."""
import argparse, math, os, struct, sys

ELF_TYPES = {0:"NONE",1:"REL",2:"EXEC",3:"DYN/PIE",4:"CORE"}
ELF_MACHINES = {3:"x86",40:"ARM",62:"x86-64",183:"AArch64",243:"RISC-V"}
PE_MACHINE = {0x14c:"i386",0x8664:"AMD64",0xaa64:"ARM64"}
PE_DLL_CHARS = {0x40:"ASLR",0x100:"DEP/NX",0x400:"NO_SEH",0x4000:"GUARD_CF"}

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

def extract_strings(data, minl=5):
    strs, cur = [], []
    for b in data:
        if 32 <= b < 127: cur.append(chr(b))
        else:
            if len(cur) >= minl: strs.append("".join(cur))
            cur = []
    if len(cur) >= minl: strs.append("".join(cur))
    return strs

def parse_elf(data):
    if len(data) < 64: return {"error":"Too small"}
    is64 = data[4] == 2; e = "<"
    info = {"format":"ELF","class":"ELF64" if is64 else "ELF32",
            "endian":"LE" if data[5]==1 else "BE"}
    et, em = struct.unpack(e+"HH", data[16:20])
    info["type"] = ELF_TYPES.get(et, f"?({et})"); info["machine"] = ELF_MACHINES.get(em, f"?({em})")
    if is64: info["entry"] = f"0x{struct.unpack(e+'Q', data[24:32])[0]:x}"
    else: info["entry"] = f"0x{struct.unpack(e+'I', data[24:28])[0]:x}"
    info["pie"] = et == 3
    phoff = struct.unpack(e+("Q" if is64 else "I"), data[(32 if is64 else 28):(40 if is64 else 32)])[0]
    phnum = struct.unpack(e+"H", data[(56 if is64 else 44):(58 if is64 else 46)])[0]
    phent = 56 if is64 else 32; info["nx"] = False; info["relro"] = False
    for i in range(phnum):
        off = phoff + i * phent
        if off + 4 > len(data): break
        pt = struct.unpack(e+"I", data[off:off+4])[0]
        if pt == 0x6474e551:
            fl = struct.unpack(e+"I", data[off+(4 if is64 else 24):off+(8 if is64 else 28)])[0]
            info["nx"] = (fl & 1) == 0
        if pt == 0x6474e552: info["relro"] = True
    return info

def parse_pe(data):
    if len(data) < 64: return {"error":"Too small"}
    pe = struct.unpack("<I", data[60:64])[0]
    if pe+24 > len(data) or data[pe:pe+4] != b"PE\x00\x00": return {"error":"Bad PE sig"}
    m = struct.unpack("<H", data[pe+4:pe+6])[0]
    ns = struct.unpack("<H", data[pe+6:pe+8])[0]
    info = {"format":"PE","machine":PE_MACHINE.get(m,f"?({m:#x})"),"sections":ns}
    magic = struct.unpack("<H", data[pe+24:pe+26])[0]
    info["pe_type"] = "PE32+" if magic == 0x20b else "PE32"
    info["entry"] = f"0x{struct.unpack('<I', data[pe+40:pe+44])[0]:x}"
    dco = pe + 24 + (70 if magic == 0x20b else 46)
    if dco + 2 <= len(data):
        dc = struct.unpack("<H", data[dco:dco+2])[0]
        info["security"] = [v for k,v in PE_DLL_CHARS.items() if dc & k]
    return info

def main():
    parser = argparse.ArgumentParser(description="Binary info extractor")
    parser.add_argument("target", help="Binary file")
    parser.add_argument("-s","--strings", action="store_true"); parser.add_argument("--min-str-len",type=int,default=6)
    args = parser.parse_args()
    print(f"[*] Radare2-Lite - Binary Info\n[*] File: {args.target}\n")
    try:
        with open(args.target, "rb") as f: data = f.read()
    except Exception as e: print(f"[!] {e}"); sys.exit(1)
    ent = entropy(data)
    print(f"  Size: {len(data):,} bytes\n  Entropy: {ent:.4f} {'(packed?)' if ent > 7.0 else ''}")
    if data[:4] == b"\x7fELF": info = parse_elf(data)
    elif data[:2] == b"MZ": info = parse_pe(data)
    else: print(f"  Unknown format (magic: {data[:4].hex()})"); return
    if "error" in info: print(f"  [!] {info['error']}"); return
    print(f"\n=== {info['format']} Header ===")
    for k, v in info.items():
        if k == "format": continue
        if isinstance(v, list): print(f"  {k}: {', '.join(str(x) for x in v) if v else 'None'}")
        elif isinstance(v, bool): print(f"  {'[+]' if v else '[-]'} {k}: {'Yes' if v else 'No'}")
        else: print(f"  {k}: {v}")
    packers = {b"UPX":"UPX",b"ASPack":"ASPack",b"Themida":"Themida",b"VMProtect":"VMProtect"}
    for sig, name in packers.items():
        if sig in data: print(f"\n  [!] Packer: {name}")
    if args.strings:
        strs = extract_strings(data, args.min_str_len)
        print(f"\n=== Strings ({len(strs)}) ===")
        for s in strs[:100]: print(f"  {s}")
        if len(strs) > 100: print(f"  ... +{len(strs)-100} more")

if __name__ == "__main__":
    main()
