#!/usr/bin/env python3
"""CTF binary setup: extract libc version, find gadgets, generate exploit template."""
import argparse, hashlib, os, struct, sys

ELF_MAGIC = b"\x7fELF"
LIBC_FUNCS = [b"system", b"execve", b"puts", b"printf", b"read", b"write",
              b"open", b"mmap", b"mprotect", b"malloc", b"free", b"exit",
              b"gets", b"fgets", b"scanf", b"strcpy", b"__stack_chk_fail"]

def analyze_binary(path):
    with open(path, "rb") as f: data = f.read()
    if data[:4] != ELF_MAGIC: return {"error": "Not ELF"}
    is64 = data[4] == 2; info = {"arch": "x86_64" if is64 else "x86", "bits": 64 if is64 else 32}
    e_type = struct.unpack("<H", data[16:18])[0]
    info["entry"] = struct.unpack("<Q" if is64 else "<I", data[24:24+(8 if is64 else 4)])[0]
    info["pie"] = e_type == 3; info["canary"] = b"__stack_chk_fail" in data
    info["nx"] = False; info["relro"] = "None"
    phoff = struct.unpack("<Q" if is64 else "<I", data[32:32+(8 if is64 else 4)])[0]
    phnum = struct.unpack("<H", data[56 if is64 else 44:58 if is64 else 46])[0]
    phent = 56 if is64 else 32
    for i in range(phnum):
        off = phoff + i * phent
        if off + 4 > len(data): break
        pt = struct.unpack("<I", data[off:off+4])[0]
        if pt == 0x6474e551:
            fl = struct.unpack("<I", data[off+4:off+8])[0] if is64 else struct.unpack("<I", data[off+24:off+28])[0]
            info["nx"] = (fl & 1) == 0
        if pt == 0x6474e552: info["relro"] = "Partial"
    info["imports"] = [f.decode() for f in LIBC_FUNCS if f in data]
    strs = []; cur = []
    for b in data:
        if 32 <= b < 127: cur.append(chr(b))
        else:
            if len(cur) >= 4: strs.append("".join(cur))
            cur = []
    info["interesting"] = [s for s in strs if any(k in s.lower() for k in ["flag","/bin/sh","password","shell"])][:5]
    return info

def analyze_libc(path):
    with open(path, "rb") as f: data = f.read()
    if data[:4] != ELF_MAGIC: return {"error": "Not ELF"}
    info = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16]}
    offsets = {}
    for fn in [b"/bin/sh", b"system", b"execve", b"exit", b"puts"]:
        idx = data.find(fn + b"\x00")
        if idx != -1: offsets[fn.decode()] = idx
    info["offsets"] = offsets
    bsh = data.find(b"/bin/sh\x00")
    if bsh != -1: info["binsh"] = bsh
    return info

def gen_template(bi, li=None):
    b = bi["bits"]; pk = f"struct.pack('<{'Q' if b==64 else 'I'}', addr)"
    t = f'''#!/usr/bin/env python3
"""Exploit template - {bi['arch']} ({b}-bit) PIE:{bi['pie']} NX:{bi['nx']} Canary:{bi['canary']}"""
import struct, socket
OFFSET = 0  # Find with cyclic pattern
'''
    if li and li.get("offsets"):
        for n, o in li["offsets"].items(): t += f'LIBC_{n.upper().replace("/","_")} = 0x{o:x}\n'
    t += f'\ndef p{b}(addr): return {pk}\n\ndef exploit():\n    payload = b"A" * OFFSET\n'
    t += f'    # payload += p{b}(gadget_addr)\n    with open("payload.bin","wb") as f: f.write(payload)\n'
    t += f'    print(f"Payload: {{len(payload)}} bytes")\n\nif __name__=="__main__": exploit()\n'
    return t

def main():
    parser = argparse.ArgumentParser(description="CTF binary setup and exploit template generator")
    parser.add_argument("target", help="Binary file"); parser.add_argument("--libc", help="Libc file")
    parser.add_argument("--template", action="store_true"); parser.add_argument("-o","--output",help="Output file")
    args = parser.parse_args()
    print("[*] PwnInit-Lite - CTF Binary Setup\n")
    if not os.path.isfile(args.target): print(f"[!] Not found: {args.target}"); sys.exit(1)
    bi = analyze_binary(args.target)
    if "error" in bi: print(f"[!] {bi['error']}"); sys.exit(1)
    print(f"=== {args.target} ===")
    for k in ["arch","bits","entry","pie","nx","canary","relro"]:
        v = bi[k]; v = f"0x{v:x}" if k=="entry" else v; print(f"  {k:>8}: {v}")
    print(f"  imports: {', '.join(bi['imports'][:10])}")
    if bi.get("interesting"): print(f"  notable: {bi['interesting']}")
    li = None
    if args.libc:
        li = analyze_libc(args.libc)
        if "error" not in li:
            print(f"\n=== {args.libc} (SHA:{li['sha256']}) ===")
            for n, o in li.get("offsets",{}).items(): print(f"  {n}: 0x{o:x}")
            if li.get("binsh"): print(f"  /bin/sh: 0x{li['binsh']:x}")
    if args.template:
        t = gen_template(bi, li)
        if args.output:
            with open(args.output,"w") as f: f.write(t)
            print(f"\n[*] Template -> {args.output}")
        else: print(f"\n{t}")
    print(f"\n{'='*50}\n[*] Next steps:")
    if not bi["canary"]: print("  - Find overflow offset with cyclic pattern")
    if not bi["nx"]: print("  - NX disabled: shellcode may work")
    elif "system" in bi["imports"]: print("  - ret2libc: system() is imported")
    if "gets" in bi["imports"]: print("  [!] gets() found - classic overflow target")

if __name__ == "__main__":
    main()
