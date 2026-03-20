#!/usr/bin/env python3
"""Memory/process analyzer: scan files for suspicious activity and injected code patterns."""
import argparse, math, os, sys

SUSPICIOUS = [b"cmd.exe",b"/bin/sh",b"/bin/bash",b"powershell",b"mimikatz",b"CreateRemoteThread",
              b"VirtualAllocEx",b"WriteProcessMemory",b"LoadLibraryA",b"GetProcAddress",
              b"WinExec",b"ShellExecute",b"URLDownloadToFile",b"meterpreter",b"beacon",b"cobalt"]
SHELLCODE = [(b"\x90"*8,"NOP sled"),(b"\xcc"*4,"INT3 sled"),(b"\x31\xc0\x50\x68","x86 shellcode"),
             (b"\x48\x31\xc0","x64 shellcode"),(b"\xeb\xfe","Infinite loop"),(b"\xff\xe4","JMP ESP")]

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

def scan_file(fp):
    findings = []
    try:
        with open(fp, "rb") as f: data = f.read()
    except Exception as e: return [f"  [!] Cannot read: {e}"]
    findings.append(f"  Size: {len(data):,} bytes")
    pe_count = data.count(b"MZ"); elf_count = data.count(b"\x7fELF")
    if pe_count > 1: findings.append(f"  [!] Multiple PE headers: {pe_count}")
    if elf_count > 1: findings.append(f"  [!] Multiple ELF headers: {elf_count}")
    hi_ent = sum(1 for i in range(0, min(len(data), 1048576), 4096)
                 if entropy(data[i:i+4096]) > 7.5)
    if hi_ent: findings.append(f"  [!] High entropy chunks: {hi_ent} (encryption/packing?)")
    findings.append(f"  Entropy: {entropy(data[:1048576]):.4f}/8.0")
    found = [s.decode(errors="replace") for s in SUSPICIOUS if s.lower() in data.lower()]
    if found: findings.append(f"  [!] Suspicious strings ({len(found)}): {', '.join(found[:8])}")
    for pat, desc in SHELLCODE:
        idx = data.find(pat)
        if idx != -1: findings.append(f"  [!] {desc} at 0x{idx:x}")
    null_run = mx = 0
    for b in data[:1048576]:
        if b == 0: null_run += 1; mx = max(mx, null_run)
        else: null_run = 0
    if mx > 512: findings.append(f"  [!] Null region: {mx}B (code cave?)")
    if b"UPX" in data: findings.append("  [!] UPX packed")
    return findings

def main():
    parser = argparse.ArgumentParser(description="Memory/process analyzer")
    parser.add_argument("target", help="File or directory")
    parser.add_argument("-d","--depth",type=int,default=2)
    args = parser.parse_args()
    print(f"[*] Volatility-Lite\n[*] Target: {args.target}\n")
    files = []
    if os.path.isfile(args.target): files.append(args.target)
    elif os.path.isdir(args.target):
        for r, dirs, fns in os.walk(args.target):
            if r.replace(args.target,"").count(os.sep) >= args.depth: dirs.clear(); continue
            for f in fns:
                fp = os.path.join(r, f)
                if os.path.getsize(fp) > 0: files.append(fp)
    print(f"[*] Scanning {len(files)} file(s)...\n")
    total = susp = 0
    for fp in files[:100]:
        findings = scan_file(fp)
        has = any("[!]" in f for f in findings)
        if has: susp += 1; total += sum(1 for f in findings if "[!]" in f)
        print(f"--- {fp} ---")
        for line in findings: print(line)
        print()
    print(f"{'='*60}\n[*] Scanned: {len(files)} | Suspicious: {susp} | Findings: {total}")

if __name__ == "__main__":
    main()
