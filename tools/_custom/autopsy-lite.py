#!/usr/bin/env python3
"""File analyzer: extract metadata, check signatures, detect embedded files, entropy analysis."""
import argparse, hashlib, math, os, sys

MAGIC = {b"\x89PNG\r\n\x1a\n":"PNG",b"\xff\xd8\xff":"JPEG",b"GIF89a":"GIF",b"PK\x03\x04":"ZIP/Office/APK",
         b"\x1f\x8b":"GZIP",b"7z\xbc\xaf\x27\x1c":"7-Zip",b"Rar!\x1a\x07":"RAR",b"\x7fELF":"ELF",
         b"MZ":"PE/DOS",b"%PDF":"PDF",b"\xd0\xcf\x11\xe0":"OLE2",b"SQLite format 3":"SQLite",
         b"RIFF":"RIFF",b"dex\n":"Android DEX"}
EMBED_SIGS = [(b"PK\x03\x04","ZIP"),(b"\x89PNG","PNG"),(b"\xff\xd8\xff","JPEG"),(b"%PDF","PDF"),
              (b"\x7fELF","ELF"),(b"MZ","PE"),(b"<script","Script"),(b"<?php","PHP")]

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

def identify(data):
    for m, d in MAGIC.items():
        if data[:len(m)] == m: return d
    if all(32<=b<127 or b in(9,10,13) for b in data[:512] if b!=0): return "ASCII text"
    return "Unknown binary"

def analyze(fp):
    try:
        with open(fp,"rb") as f: data = f.read()
    except Exception as e: return {"error":str(e)}
    r = {"name":os.path.basename(fp),"size":len(data),"type":identify(data)}
    r["md5"] = hashlib.md5(data).hexdigest(); r["sha256"] = hashlib.sha256(data).hexdigest()
    r["entropy"] = entropy(data)
    r["assessment"] = "HIGH (encrypted/packed)" if r["entropy"]>7 else "MEDIUM" if r["entropy"]>5 else "LOW"
    chunk = max(1, len(data)//16)
    r["emap"] = [entropy(data[i*chunk:(i+1)*chunk]) for i in range(16) if data[i*chunk:(i+1)*chunk]]
    embedded = []
    for sig, desc in EMBED_SIGS:
        off = 16
        while len(embedded) < 15:
            idx = data.find(sig, off)
            if idx <= 0: break
            embedded.append(f"{desc}@0x{idx:x}"); off = idx + len(sig)
    r["embedded"] = embedded
    if data[:4] == b"\x89PNG":
        iend = data.find(b"IEND")
        if iend != -1 and iend+12 < len(data): r["appended"] = f"{len(data)-iend-12}B after IEND"
    elif data[:2] == b"\xff\xd8":
        eoi = data.find(b"\xff\xd9")
        if eoi != -1 and eoi+2 < len(data): r["appended"] = f"{len(data)-eoi-2}B after EOI"
    strs = []; cur = []
    for b in data[:262144]:
        if 32<=b<127: cur.append(chr(b))
        else:
            if len(cur)>=6: strs.append("".join(cur))
            cur = []
    r["interesting"] = [s for s in strs if any(k in s.lower() for k in
        ["password","secret","key","token","api","http","flag{"])][:10]
    r["total_strings"] = len(strs)
    return r

def main():
    parser = argparse.ArgumentParser(description="File analyzer")
    parser.add_argument("target", help="File or directory"); parser.add_argument("--depth",type=int,default=1)
    args = parser.parse_args()
    print(f"[*] Autopsy-Lite - File Analyzer\n[*] Target: {args.target}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            if r.replace(args.target,"").count(os.sep) >= args.depth: dirs.clear(); continue
            for f in fns: files.append(os.path.join(r, f))
    for fp in files[:50]:
        r = analyze(fp)
        if "error" in r: print(f"--- {fp}: ERROR: {r['error']}\n"); continue
        print(f"--- {r['name']} ---")
        print(f"  Type: {r['type']} | Size: {r['size']:,}B")
        print(f"  MD5: {r['md5']} | SHA256: {r['sha256']}")
        print(f"  Entropy: {r['entropy']:.4f} - {r['assessment']}")
        print(f"  Map: [{' '.join(f'{e:.1f}' for e in r['emap'])}]")
        if r.get("appended"): print(f"  [!] Appended: {r['appended']}")
        if r["embedded"]: print(f"  [!] Embedded: {', '.join(r['embedded'][:5])}")
        if r["interesting"]: print(f"  [!] Strings: {r['interesting'][:5]}")
        print(f"  Strings: {r['total_strings']}\n")

if __name__ == "__main__":
    main()
