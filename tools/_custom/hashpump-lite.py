#!/usr/bin/env python3
"""Hash analyzer: identify hash types, check against known weak hashes, rainbow table lookup."""
import argparse, hashlib, sys

HASH_TYPES = {32:[("MD5","Weak")],40:[("SHA1","Moderate")],64:[("SHA256","Strong")],
              128:[("SHA512","Strong")],56:[("SHA224","Strong")],96:[("SHA384","Strong")]}
COMMON_PWDS = ["password","123456","12345678","qwerty","abc123","letmein","admin","root",
               "toor","changeme","welcome","test","guest","default","oracle","mysql","postgres",
               "monkey","dragon","master","shadow","trustno1","iloveyou","superman","football"]
RAINBOW = {}

def build_rainbow():
    for p in COMMON_PWDS:
        b = p.encode()
        RAINBOW[hashlib.md5(b).hexdigest()] = ("MD5", p)
        RAINBOW[hashlib.sha1(b).hexdigest()] = ("SHA1", p)
        RAINBOW[hashlib.sha256(b).hexdigest()] = ("SHA256", p)

def identify(h):
    h = h.strip()
    if h.startswith("$2a$") or h.startswith("$2b$"): return [("bcrypt","Very strong")]
    if h.startswith("$6$"): return [("SHA512-crypt","Strong")]
    if h.startswith("$5$"): return [("SHA256-crypt","Strong")]
    if h.startswith("$1$"): return [("MD5-crypt","Weak")]
    if h.startswith("*") and len(h)==41: return [("MySQL 4.x/5.x","Moderate")]
    clean = h.replace("$","").replace("*","")
    if all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) in HASH_TYPES:
        return HASH_TYPES[len(clean)]
    return [("Unknown","N/A")]

def main():
    parser = argparse.ArgumentParser(description="Hash analyzer")
    parser.add_argument("target", help="Hash to analyze or string to hash (-g)")
    parser.add_argument("-g","--generate", action="store_true")
    parser.add_argument("-f","--file", help="File with hashes")
    parser.add_argument("-w","--wordlist", help="Custom wordlist")
    args = parser.parse_args()
    print("[*] HashPump-Lite - Hash Analyzer")
    build_rainbow()
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                for line in f:
                    p = line.strip()
                    if p:
                        b = p.encode()
                        RAINBOW[hashlib.md5(b).hexdigest()] = ("MD5",p)
                        RAINBOW[hashlib.sha1(b).hexdigest()] = ("SHA1",p)
                        RAINBOW[hashlib.sha256(b).hexdigest()] = ("SHA256",p)
            print(f"[*] Loaded wordlist: {args.wordlist}")
        except Exception as e: print(f"[!] {e}")
    if args.generate:
        print(f"[*] Hashes for: {args.target}\n")
        for a in ["md5","sha1","sha224","sha256","sha384","sha512"]:
            print(f"  {a.upper():>8}: {getattr(hashlib,a)(args.target.encode()).hexdigest()}")
        return
    hashes = []
    if args.file:
        try:
            with open(args.file) as f: hashes = [l.strip() for l in f if l.strip()]
        except Exception as e: print(f"[!] {e}"); sys.exit(1)
    else: hashes = [args.target]
    print(f"[*] Analyzing {len(hashes)} hash(es)\n")
    cracked = 0
    for h in hashes:
        print(f"  Hash: {h}")
        for name, strength in identify(h):
            icon = "[!]" if strength == "Weak" else "[*]"
            print(f"  {icon} Type: {name} | Strength: {strength}")
        r = RAINBOW.get(h.strip().lower())
        if r:
            print(f"  [!!!] CRACKED ({r[0]}): {r[1]}"); cracked += 1
        else: print(f"  [-] Not in rainbow table ({len(RAINBOW)} entries)")
        print()
    print(f"{'='*50}\n[*] Analyzed: {len(hashes)} | Cracked: {cracked}")
    if cracked: print("[!] Weak passwords - change immediately")

if __name__ == "__main__":
    main()
