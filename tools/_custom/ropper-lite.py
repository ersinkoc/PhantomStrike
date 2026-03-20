#!/usr/bin/env python3
"""Binary security checker: check NX, PIE, RELRO, stack canary, ASLR info from ELF/PE headers."""
import argparse, struct, sys

def check_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF": return {"error": "Not ELF"}
    is64 = data[4] == 2; e = "<"
    r = {"class": "ELF64" if is64 else "ELF32"}
    e_type = struct.unpack(e+"H", data[16:18])[0]
    r["PIE"] = e_type == 3
    if is64:
        phoff = struct.unpack(e+"Q", data[32:40])[0]; phent = 56
        phnum = struct.unpack(e+"H", data[56:58])[0]
    else:
        phoff = struct.unpack(e+"I", data[28:32])[0]; phent = 32
        phnum = struct.unpack(e+"H", data[44:46])[0]
    r["NX"] = False; r["RELRO"] = "None"; bind_now = False
    for i in range(phnum):
        off = phoff + i * phent
        if off + 8 > len(data): break
        pt = struct.unpack(e+"I", data[off:off+4])[0]
        if pt == 0x6474e551:  # GNU_STACK
            fl = struct.unpack(e+"I", data[off+(4 if is64 else 24):off+(8 if is64 else 28)])[0]
            r["NX"] = (fl & 1) == 0
        if pt == 0x6474e552: r["RELRO"] = "Partial"
        if pt == 2:  # DYNAMIC
            if is64: doff = struct.unpack(e+"Q", data[off+8:off+16])[0]; dsz = struct.unpack(e+"Q", data[off+32:off+40])[0]
            else: doff = struct.unpack(e+"I", data[off+4:off+8])[0]; dsz = struct.unpack(e+"I", data[off+16:off+20])[0]
            esz = 16 if is64 else 8; pos = doff
            while pos + esz <= min(doff + dsz, len(data)):
                dt = struct.unpack(e+("q" if is64 else "i"), data[pos:pos+(8 if is64 else 4)])[0]
                if dt in (24, 30): bind_now = True
                if dt == 0: break
                pos += esz
    if r["RELRO"] == "Partial" and bind_now: r["RELRO"] = "Full"
    r["Stack Canary"] = b"__stack_chk_fail" in data
    r["FORTIFY"] = b"_chk@" in data
    r["RPATH"] = b"rpath" in data.lower()
    return r

def check_pe(data):
    if len(data) < 64 or data[:2] != b"MZ": return {"error": "Not PE"}
    pe = struct.unpack("<I", data[60:64])[0]
    if pe + 24 > len(data) or data[pe:pe+4] != b"PE\x00\x00": return {"error": "Bad PE"}
    m = struct.unpack("<H", data[pe+4:pe+6])[0]
    r = {"class": "PE32+" if m == 0x8664 else "PE32"}
    magic = struct.unpack("<H", data[pe+24:pe+26])[0]
    dco = pe + 24 + (70 if magic == 0x20b else 46)
    if dco + 2 <= len(data):
        dc = struct.unpack("<H", data[dco:dco+2])[0]
        r["ASLR"] = bool(dc & 0x40); r["DEP/NX"] = bool(dc & 0x100)
        r["NO_SEH"] = bool(dc & 0x400); r["GUARD_CF"] = bool(dc & 0x4000)
        r["HIGH_ENTROPY_VA"] = bool(dc & 0x20)
    return r

def main():
    parser = argparse.ArgumentParser(description="Binary security checker")
    parser.add_argument("target", help="Binary file")
    args = parser.parse_args()
    print(f"[*] Ropper-Lite - Binary Security Checker\n[*] File: {args.target}\n")
    try:
        with open(args.target, "rb") as f: data = f.read()
    except Exception as e: print(f"[!] {e}"); sys.exit(1)
    print(f"  Size: {len(data):,} bytes")
    if data[:4] == b"\x7fELF": r = check_elf(data)
    elif data[:2] == b"MZ": r = check_pe(data)
    else: print("[!] Unknown format"); sys.exit(1)
    if "error" in r: print(f"[!] {r['error']}"); sys.exit(1)
    print(f"  Format: {r.pop('class')}\n\n=== Security Features ===\n")
    score = checks = 0
    for k, v in r.items():
        if isinstance(v, bool):
            bad = k in ("RPATH",)
            st = "Enabled" if v else "Disabled"
            icon = ("[!]" if v else "[+]") if bad else ("[+]" if v else "[-]")
            risk = " (RISK)" if (v and bad) or (not v and not bad) else ""
            print(f"  {icon} {k:<25}: {st}{risk}")
            score += (0 if v else 1) if bad else (1 if v else 0); checks += 1
        else:
            g = "[+]" if v == "Full" else "[-]" if v == "None" else "[~]"
            print(f"  {g} {k:<25}: {v}")
            score += (1 if v == "Full" else 0.5 if v == "Partial" else 0); checks += 1
    pct = (score/checks*100) if checks else 0
    grade = "A" if pct>=90 else "B" if pct>=70 else "C" if pct>=50 else "D" if pct>=30 else "F"
    print(f"\n{'='*50}\n[*] Score: {score:.1f}/{checks} ({pct:.0f}%) Grade: {grade}")

if __name__ == "__main__":
    main()
