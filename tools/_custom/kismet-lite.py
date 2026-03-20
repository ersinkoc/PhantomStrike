#!/usr/bin/env python3
"""Network discovery: active network scan, detect devices on local network."""
import argparse, socket, sys, time

PORTS = {22:"SSH",53:"DNS",80:"HTTP",443:"HTTPS",445:"SMB",3389:"RDP",
         8080:"HTTP-Proxy",5900:"VNC",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8443:"HTTPS-Alt"}
SCAN_PORTS = [80,443,22,445,139,8080,3389,53,21,25,3306,5432,8443]

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def tcp_ping(host, port, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        r = s.connect_ex((host, port)); s.close(); return r == 0
    except: return False

def discover(ip, timeout=0.5):
    for port in SCAN_PORTS:
        if tcp_ping(ip, port, timeout): return True, [port]
    return False, []

def scan_ports(ip, timeout=1.0):
    return [(p, PORTS[p]) for p in PORTS if tcp_ping(ip, p, timeout)]

def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return None

def guess_os(ports):
    ps = {p for p, _ in ports}
    if 3389 in ps or 445 in ps: return "Windows"
    if 22 in ps and 80 not in ps: return "Linux/Unix"
    if 80 in ps or 443 in ps: return "Web Server"
    if 53 in ps: return "DNS Server"
    return "Unknown"

def main():
    parser = argparse.ArgumentParser(description="Network discovery scanner")
    parser.add_argument("target", nargs="?", help="Network or 'auto'")
    parser.add_argument("-t","--timeout", type=float, default=0.5)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--range", help="IP range e.g. 1-50")
    args = parser.parse_args()
    print("[*] Kismet-Lite - Network Discovery\n")
    lip = get_local_ip(); print(f"  Local IP: {lip}")
    if not args.target or args.target == "auto":
        base = ".".join(lip.split(".")[:3])
    else:
        base = ".".join(args.target.split("/")[0].split(".")[:3])
    if args.range:
        s, e = args.range.split("-"); ips = [f"{base}.{i}" for i in range(int(s),int(e)+1)]
    else:
        ips = [f"{base}.{i}" for i in range(1, 255)]
    print(f"  Network: {base}.0/24\n  Scanning {len(ips)} hosts (timeout: {args.timeout}s)\n")
    found = []; start = time.time()
    for i, ip in enumerate(ips):
        alive, ports = discover(ip, args.timeout)
        if alive:
            hostname = reverse_dns(ip)
            if args.deep: ports_info = scan_ports(ip, args.timeout * 2)
            else: ports_info = [(p, PORTS.get(p,"?")) for p in ports]
            os_g = guess_os(ports_info)
            found.append({"ip":ip,"hostname":hostname,"ports":ports_info,"os":os_g})
            hn = f" ({hostname})" if hostname else ""
            ps = ",".join(f"{p}/{n}" for p,n in ports_info[:5])
            print(f"  [+] {ip}{hn} - {os_g} [{ps}]")
        if (i+1) % 50 == 0:
            print(f"  ... {(i+1)*100//len(ips)}% - {len(found)} hosts")
    elapsed = time.time() - start
    print(f"\n{'='*60}\n[*] Done in {elapsed:.1f}s | Found: {len(found)}/{len(ips)}")
    if found:
        print(f"\n  {'IP':<18} {'HOST':<25} {'OS':<15} PORTS")
        for h in found:
            hn = h["hostname"] or ""
            ps = ",".join(str(p) for p,_ in h["ports"][:4])
            print(f"  {h['ip']:<18} {hn:<25} {h['os']:<15} {ps}")

if __name__ == "__main__":
    main()
