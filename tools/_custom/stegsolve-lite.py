#!/usr/bin/env python3
"""Steganography detector: check image files for hidden data (LSB, metadata, appended data, entropy)."""
import argparse, math, os, struct, sys

STEG_TOOLS = [b"steghide",b"openstego",b"stegano",b"outguess",b"jphide",b"camouflage"]

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

def analyze_lsb(data):
    if len(data) < 100: return "Insufficient data", 0.5
    bits = [b & 1 for b in data[:10000]]
    ratio = sum(bits) / len(bits)
    dev = abs(ratio - 0.5)
    if dev < 0.01: return "SUSPICIOUS - unusually uniform (possible steg)", ratio
    elif dev < 0.05: return "Normal distribution", ratio
    return "Skewed (likely natural)", ratio

def extract_lsb(data, n=256):
    bits = [b & 1 for b in data[:n*8]]
    result = bytearray()
    for i in range(0, len(bits)-7, 8):
        v = 0
        for j in range(8): v = (v << 1) | bits[i+j]
        result.append(v)
    return bytes(result)

def check_png(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n": return []
    f = ["[*] PNG detected"]; pos = 8; chunks = []
    while pos < len(data) - 4:
        if pos+8 > len(data): break
        ln = struct.unpack(">I", data[pos:pos+4])[0]
        ct = data[pos+4:pos+8].decode("ascii",errors="replace")
        chunks.append((ct, ln, pos)); pos += 12 + ln
    f.append(f"  Chunks: {', '.join(c[0] for c in chunks)}")
    for ct, ln, off in chunks:
        if ct in ("tEXt","iTXt","zTXt"):
            t = data[off+8:off+8+min(ln,100)].decode("utf-8",errors="replace")
            f.append(f"  [!] Text chunk ({ct}): {t[:80]}")
        if ct == "IEND":
            after = len(data) - (off+12+ln)
            if after > 0:
                f.append(f"  [!] {after}B after IEND (hidden data!)")
                f.append(f"      Preview: {data[off+12+ln:off+12+ln+32].hex()}")
    return f

def check_jpeg(data):
    if data[:3] != b"\xff\xd8\xff": return []
    f = ["[*] JPEG detected"]
    eoi = data.rfind(b"\xff\xd9")
    if eoi != -1 and eoi+2 < len(data):
        app = len(data) - eoi - 2
        if app > 0:
            f.append(f"  [!] {app}B after EOI (hidden data!)")
            f.append(f"      Preview: {data[eoi+2:eoi+34].hex()}")
    if b"\xff\xfe" in data[:1000]:
        idx = data.find(b"\xff\xfe")
        cl = struct.unpack(">H", data[idx+2:idx+4])[0]
        f.append(f"  [!] Comment: {data[idx+4:idx+4+min(cl,80)].decode('utf-8',errors='replace')}")
    return f

def main():
    parser = argparse.ArgumentParser(description="Steganography detector")
    parser.add_argument("target", help="Image file or directory")
    parser.add_argument("--lsb-extract", action="store_true")
    parser.add_argument("--deep", action="store_true")
    args = parser.parse_args()
    print(f"[*] StegSolve-Lite\n[*] Target: {args.target}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for f in os.listdir(args.target):
            fp = os.path.join(args.target, f)
            if os.path.isfile(fp): files.append(fp)
    for fp in files[:30]:
        try:
            with open(fp, "rb") as f: data = f.read()
        except Exception as e: print(f"[!] {fp}: {e}"); continue
        print(f"=== {os.path.basename(fp)} ({len(data):,}B) ===")
        print(f"  Entropy: {entropy(data):.4f}")
        for line in check_png(data) + check_jpeg(data): print(line)
        px = data[min(100,len(data)):]
        assess, ratio = analyze_lsb(px)
        print(f"  LSB ratio: {ratio:.4f} - {assess}")
        if args.lsb_extract and len(px) > 64:
            lsb = extract_lsb(px)
            print(f"  LSB data: {''.join(chr(b) if 32<=b<127 else '.' for b in lsb[:64])}")
        for t in STEG_TOOLS:
            if t in data.lower(): print(f"  [!] Tool signature: {t.decode()}")
        if args.deep:
            ch = max(1, len(data)//10)
            print(f"  Entropy map: {' '.join(f'{entropy(data[i*ch:(i+1)*ch]):.2f}' for i in range(10))}")
        print()

if __name__ == "__main__":
    main()
