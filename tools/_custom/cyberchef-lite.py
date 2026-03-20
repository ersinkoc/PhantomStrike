#!/usr/bin/env python3
"""Data transformer: encode/decode base64, hex, URL, ROT13, hash calculator, JWT decode."""
import argparse, base64, hashlib, json, sys, urllib.parse

OPS = ["b64encode","b64decode","hexencode","hexdecode","urlencode","urldecode",
       "rot13","md5","sha1","sha256","sha512","jwt-decode","analyze","all-hashes"]

def rot13(d):
    r = []
    for c in d:
        if "a"<=c<="z": r.append(chr((ord(c)-97+13)%26+97))
        elif "A"<=c<="Z": r.append(chr((ord(c)-65+13)%26+65))
        else: r.append(c)
    return "".join(r)

def all_hashes(d):
    b = d.encode()
    return "\n".join(f"  {a.upper():>8}: {getattr(hashlib,a)(b).hexdigest()}"
                     for a in ["md5","sha1","sha256","sha512"])

def jwt_decode(t):
    parts = t.strip().split(".")
    if len(parts) < 2: return "Not a valid JWT"
    out = []
    for i, label in enumerate(["Header","Payload"]):
        try:
            padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
            parsed = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8",errors="replace"))
            out.append(f"  {label}: {json.dumps(parsed, indent=4)}")
        except Exception as e: out.append(f"  {label}: Error - {e}")
    if len(parts) == 3: out.append(f"  Signature: {parts[2][:40]}...")
    return "\n".join(out)

def auto_analyze(d):
    r = [f"[*] Auto-analysis:\n  Length: {len(d)}\n  Hex: {d[:20].encode().hex()}..."]
    try:
        p = d + "=" * (4 - len(d) % 4) if len(d) % 4 else d
        dec = base64.b64decode(p)
        if all(32<=b<127 or b in(9,10,13) for b in dec): r.append(f"  [+] Base64: {dec.decode()[:80]}")
    except: pass
    try:
        c = d.replace("0x","").replace(" ","").replace("\\x","")
        if all(x in "0123456789abcdefABCDEF" for x in c) and len(c)%2==0 and len(c)>4:
            dec = bytes.fromhex(c).decode("utf-8",errors="replace")
            if all(32<=ord(x)<127 or x in"\t\n\r" for x in dec): r.append(f"  [+] Hex: {dec[:80]}")
    except: pass
    if "%" in d: r.append(f"  [+] URL: {urllib.parse.unquote(d)[:80]}")
    if d.count(".") == 2 and len(d) > 30: r.append(f"  [+] JWT:\n{jwt_decode(d)}")
    hl = len(d)
    if all(c in "0123456789abcdefABCDEF" for c in d):
        types = {32:"MD5",40:"SHA1",64:"SHA256",128:"SHA512"}
        if hl in types: r.append(f"  [+] Looks like {types[hl]}")
    r.append(f"\n{all_hashes(d)}")
    return "\n".join(r)

def main():
    parser = argparse.ArgumentParser(description="Data transformer")
    parser.add_argument("target", help="Input data or '-' for stdin")
    parser.add_argument("-o","--operation", default="analyze", choices=OPS)
    parser.add_argument("-f","--file", action="store_true")
    args = parser.parse_args()
    if args.target == "-": data = sys.stdin.read().strip()
    elif args.file:
        try:
            with open(args.target) as f: data = f.read().strip()
        except Exception as e: print(f"[!] {e}"); sys.exit(1)
    else: data = args.target
    print(f"[*] CyberChef-Lite - {args.operation}\n[*] Input ({len(data)} chars): {data[:60]}{'...'if len(data)>60 else ''}\n")
    ops = {
        "b64encode": lambda d: base64.b64encode(d.encode()).decode(),
        "b64decode": lambda d: base64.b64decode(d + "="*(4-len(d)%4) if len(d)%4 else d).decode("utf-8",errors="replace"),
        "hexencode": lambda d: d.encode().hex(),
        "hexdecode": lambda d: bytes.fromhex(d.replace("0x","").replace(" ","").replace("\\x","")).decode("utf-8",errors="replace"),
        "urlencode": lambda d: urllib.parse.quote(d, safe=""),
        "urldecode": lambda d: urllib.parse.unquote(d),
        "rot13": lambda d: rot13(d),
        "md5": lambda d: hashlib.md5(d.encode()).hexdigest(),
        "sha1": lambda d: hashlib.sha1(d.encode()).hexdigest(),
        "sha256": lambda d: hashlib.sha256(d.encode()).hexdigest(),
        "sha512": lambda d: hashlib.sha512(d.encode()).hexdigest(),
        "jwt-decode": lambda d: jwt_decode(d),
        "analyze": lambda d: auto_analyze(d),
        "all-hashes": lambda d: all_hashes(d),
    }
    try: print(f"=== Result ===\n{ops[args.operation](data)}")
    except Exception as e: print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
