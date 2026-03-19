# Port Scanning Strategy

## Overview
Port scanning identifies open network ports, running services, and their versions on target hosts. It is the foundation for vulnerability assessment, revealing the attack surface available for exploitation. Effective scanning balances thoroughness with stealth, adapting speed and technique to the engagement's rules of engagement.

## Classification
- **MITRE ATT&CK:** T1046 (Network Service Discovery)
- **Phase:** Reconnaissance / Scanning
- **Risk Level:** Active (generates network traffic to target)
- **Prerequisites:** Target IP addresses or ranges, authorized scope, rules of engagement

## Detection Methodology

### 1. Host Discovery
Determine which hosts are alive before port scanning:
- ICMP echo (ping sweep): fast but often blocked by firewalls
- TCP SYN to common ports (80, 443): reliable through most firewalls
- ARP scan on local networks: fastest and most reliable on LAN
- UDP probes (DNS 53, SNMP 161): catches hosts blocking TCP/ICMP

### 2. TCP Connect Scan
Full TCP three-way handshake. Reliable but logged by target systems.
- Use when you lack raw socket privileges (non-root)
- Logged in application and system logs
- Slower than SYN scan due to full connection setup

### 3. TCP SYN Scan (Half-Open)
Send SYN, receive SYN-ACK (open) or RST (closed), send RST. Never completes the handshake.
- Requires root/admin privileges for raw sockets
- Faster and stealthier than connect scan
- Less likely to be logged by applications (no complete connection)
- Default nmap scan type when run as root

### 4. UDP Scan
Send UDP packets and analyze responses:
- No response: open or filtered (ambiguous)
- ICMP Port Unreachable: closed
- UDP response: open (confirmed)
- Significantly slower than TCP scanning
- Critical for finding DNS, SNMP, TFTP, NTP, DHCP services

### 5. Version Detection
After discovering open ports, probe for service versions:
- Banner grabbing: read service banners on connection
- Protocol-specific probes: HTTP, SSH, FTP, SMTP version strings
- SSL/TLS certificate inspection for application identification
- Map versions to known CVEs for vulnerability assessment

### 6. OS Fingerprinting
Identify the target operating system:
- TCP/IP stack behavior analysis (TTL, window size, flags)
- Active fingerprinting: send crafted packets, analyze responses
- Passive fingerprinting: analyze traffic characteristics
- Combine with service version data for accuracy

### 7. Timing Strategies
Adjust scan speed based on engagement requirements:
```
T0 (Paranoid):   5 min between probes  — IDS evasion, very slow
T1 (Sneaky):     15 sec between probes — IDS evasion
T2 (Polite):     0.4 sec between probes — reduced load
T3 (Normal):     default timing          — standard scan
T4 (Aggressive): faster timing           — reliable networks
T5 (Insane):     0.3 sec timeout         — fast networks only
```

### 8. IDS/IPS Evasion Techniques
- **Fragmentation:** Split packets into fragments to evade signature detection
- **Decoy scanning:** Mix real scan with decoy source IPs
- **Idle scan:** Use zombie host to scan target indirectly
- **Source port manipulation:** Use trusted source ports (53, 80, 443)
- **Timing adjustment:** Slow down scan to avoid rate-based detection
- **Custom packet crafting:** Modify TCP flags, TTL, window size

## Tool Usage

### nmap
```bash
# Host discovery (ping sweep)
nmap -sn 10.0.0.0/24 -oG alive_hosts.gnmap

# TCP SYN scan top 1000 ports (default, requires root)
nmap -sS -T4 target.com -oA scan_results

# Full TCP port scan (all 65535 ports)
nmap -sS -p- -T4 target.com -oA full_scan

# TCP connect scan (non-root)
nmap -sT -T4 target.com -oA connect_scan

# UDP scan (top 100 UDP ports)
nmap -sU --top-ports 100 -T4 target.com -oA udp_scan

# Version detection and default scripts
nmap -sV -sC -T4 target.com -oA version_scan

# Aggressive scan (version + OS + scripts + traceroute)
nmap -A -T4 target.com -oA aggressive_scan

# OS fingerprinting
nmap -O --osscan-guess target.com -oA os_scan

# Vulnerability scanning with NSE scripts
nmap --script vuln target.com -oA vuln_scan

# Specific NSE script categories
nmap --script "http-*" -p 80,443,8080 target.com
nmap --script "smb-vuln-*" -p 445 target.com
nmap --script "ssl-*" -p 443 target.com

# IDS evasion with fragmentation and decoys
nmap -sS -f -D RND:5 -T2 target.com -oA stealth_scan

# Source port manipulation
nmap -sS --source-port 53 -T4 target.com

# Scan from file of targets
nmap -sS -T4 -iL targets.txt -oA batch_scan

# Output all formats (normal, XML, grepable)
nmap -sV -sC -T4 target.com -oA results
# Produces: results.nmap, results.xml, results.gnmap
```

### masscan
```bash
# Fast scan of all ports (internet-scale speed)
masscan -p0-65535 10.0.0.0/24 --rate=10000 -oL results.txt

# Specific ports with banner grabbing
masscan -p80,443,8080,8443 10.0.0.0/24 --banners --rate=5000 -oJ results.json

# Top ports scan
masscan -p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 \
  10.0.0.0/24 --rate=1000 -oG results.gnmap

# With source port and adapter
masscan -p0-65535 target.com --rate=5000 --source-port 61000

# Exclude hosts
masscan -p0-65535 10.0.0.0/24 --excludefile exclusions.txt --rate=10000
```

### rustscan
```bash
# Fast port discovery then nmap for details
rustscan -a target.com -- -sV -sC

# Custom port range
rustscan -a target.com -r 1-65535 -- -A

# Multiple targets
rustscan -a 10.0.0.1,10.0.0.2,10.0.0.3 -- -sV

# Adjust batch size for speed control
rustscan -a target.com -b 4500 -- -sV -sC

# Timeout adjustment
rustscan -a target.com --timeout 3000 -- -sV

# Scan from file
rustscan -a targets.txt -- -sV
```

### zmap
```bash
# Single port scan across a subnet
zmap -p 80 10.0.0.0/24 -o results.txt

# With bandwidth limit
zmap -p 443 10.0.0.0/24 -B 10M -o results.txt

# Multiple ports (run separately per port)
zmap -p 22 10.0.0.0/24 -o ssh_hosts.txt
zmap -p 80 10.0.0.0/24 -o http_hosts.txt

# Output metadata
zmap -p 80 10.0.0.0/24 -O json -o results.json
```

## Output Analysis Tips
- **Service correlation:** Match open ports to expected services. Unexpected ports (e.g., 4444, 31337) may indicate backdoors or malware.
- **Version mapping:** Cross-reference detected versions against CVE databases. Outdated versions are primary targets.
- **Port grouping patterns:** Common combinations reveal infrastructure type:
  - 80/443: Web server
  - 22/80/443: Linux web server
  - 135/139/445/3389: Windows host
  - 21/22/80/443/3306: LAMP stack
  - 80/443/8080/8443: Application server / reverse proxy
- **Filtered vs closed:** Filtered ports indicate firewall protection. Closed ports mean the host is reachable but no service is listening.
- **Rate limiting detection:** If scan results are inconsistent between runs, the target may be rate-limiting or dropping suspicious traffic.
- **nmap XML parsing:** Use `nmap -oX` output for automated processing. Parse with `xmlstarlet` or Python `xml.etree`.
- **masscan to nmap pipeline:** Use masscan for fast port discovery, then nmap for detailed version/script scanning on discovered ports only.

## Evidence Collection
- Complete scan results in multiple formats (XML, grepable, JSON)
- Open port summary with service versions and OS detection
- Notable findings (unusual ports, outdated services, known vulnerable versions)
- Scan parameters used (timing, technique, scope)
- Network diagram or host inventory from scan data
- Screenshots of service banners or login pages on discovered ports
- Comparison with previous scans if available (new ports, changed services)
