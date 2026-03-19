# Network Scanning Methodology

## Overview
Network scanning is the process of systematically probing a target network to discover live hosts, open ports, running services, and operating system details. It is the foundational phase of any penetration test or security assessment, providing the intelligence needed to identify attack surfaces. Effective scanning balances thoroughness with stealth, adapting techniques to the engagement scope and rules of engagement.

## Classification
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **MITRE ATT&CK:** T1046 (Network Service Scanning), T1040 (Network Sniffing), T1018 (Remote System Discovery), T1016 (System Network Configuration Discovery)
- **CVSS Base:** Informational (scanning itself), findings vary

## Detection Methodology

### 1. Host Discovery
Determine which hosts are alive on the target network:
```bash
# ICMP echo (ping sweep)
nmap -sn 10.10.10.0/24

# ARP discovery (local subnet only, most reliable)
nmap -sn -PR 10.10.10.0/24
arp-scan --localnet

# TCP SYN discovery (bypasses ICMP-blocking firewalls)
nmap -sn -PS22,80,443,445 10.10.10.0/24

# TCP ACK discovery
nmap -sn -PA80,443 10.10.10.0/24

# UDP discovery
nmap -sn -PU53,161 10.10.10.0/24

# Combined discovery (most thorough)
nmap -sn -PE -PS22,80,443,445,3389 -PA80,443 -PU53,161 10.10.10.0/24

# No ping (assume all hosts are up)
nmap -Pn 10.10.10.0/24

# ICMP timestamp and address mask
nmap -sn -PP -PM 10.10.10.0/24

# List scan (DNS resolution only, no packets sent)
nmap -sL 10.10.10.0/24
```

### 2. Port Scanning Techniques
Identify open ports on discovered hosts:
```bash
# TCP SYN scan (default, fast, stealthy, requires root)
nmap -sS 10.10.10.50

# TCP Connect scan (no root required, full TCP handshake)
nmap -sT 10.10.10.50

# UDP scan (slow but essential for DNS, SNMP, TFTP)
nmap -sU 10.10.10.50

# Combined TCP + UDP
nmap -sS -sU 10.10.10.50

# FIN/NULL/Xmas scans (firewall evasion)
nmap -sF 10.10.10.50    # FIN scan
nmap -sN 10.10.10.50    # NULL scan
nmap -sX 10.10.10.50    # Xmas scan

# ACK scan (map firewall rules, find filtered/unfiltered ports)
nmap -sA 10.10.10.50

# Window scan (ACK variant, can detect open ports through some firewalls)
nmap -sW 10.10.10.50

# SCTP scans
nmap -sY 10.10.10.50    # SCTP INIT scan
nmap -sZ 10.10.10.50    # SCTP COOKIE-ECHO scan

# Idle scan (stealth via zombie host)
nmap -sI zombie-host:80 10.10.10.50
```

### 3. Port Range Selection
```bash
# Top 100 ports
nmap --top-ports 100 10.10.10.50

# Top 1000 ports (default)
nmap 10.10.10.50

# All 65535 ports
nmap -p- 10.10.10.50

# Specific ports
nmap -p 22,80,443,445,3389 10.10.10.50

# Port range
nmap -p 1-1024 10.10.10.50

# Common service ports for pentesting
nmap -p 21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,27017 10.10.10.50
```

### 4. Service Detection and Version Scanning
```bash
# Service version detection
nmap -sV 10.10.10.50

# Aggressive version detection
nmap -sV --version-intensity 5 10.10.10.50

# Light version detection (faster)
nmap -sV --version-light 10.10.10.50

# Version detection with all probes
nmap -sV --version-all 10.10.10.50

# Banner grabbing alternative
nmap -sV --script=banner 10.10.10.50
```

### 5. OS Fingerprinting
```bash
# OS detection
nmap -O 10.10.10.50

# Aggressive OS detection
nmap -O --osscan-guess 10.10.10.50

# Combined service + OS detection
nmap -sV -O 10.10.10.50

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A 10.10.10.50
```

### 6. NSE (Nmap Scripting Engine)
```bash
# Default scripts
nmap -sC 10.10.10.50

# Specific script category
nmap --script=vuln 10.10.10.50
nmap --script=safe 10.10.10.50
nmap --script=auth 10.10.10.50
nmap --script=discovery 10.10.10.50

# Specific scripts
nmap --script=http-title,http-headers 10.10.10.50
nmap --script=smb-enum-shares,smb-enum-users 10.10.10.50
nmap --script=ssl-heartbleed,ssl-poodle 10.10.10.50

# Vulnerability scanning
nmap --script=vuln -p 80,443 10.10.10.50
nmap --script=smb-vuln-* 10.10.10.50

# Script with arguments
nmap --script=http-brute --script-args http-brute.path=/admin 10.10.10.50

# Wildcard scripts
nmap --script="http-*" 10.10.10.50
nmap --script="smb-*" 10.10.10.50
```

### 7. Scan Timing and Performance
```bash
# Timing templates
nmap -T0 10.10.10.50    # Paranoid (IDS evasion)
nmap -T1 10.10.10.50    # Sneaky
nmap -T2 10.10.10.50    # Polite
nmap -T3 10.10.10.50    # Normal (default)
nmap -T4 10.10.10.50    # Aggressive
nmap -T5 10.10.10.50    # Insane (fastest)

# Custom timing
nmap --min-rate 1000 10.10.10.50              # Minimum packets per second
nmap --max-retries 2 10.10.10.50              # Limit retransmissions
nmap --host-timeout 300s 10.10.10.50          # Skip slow hosts
nmap --scan-delay 1s 10.10.10.50              # Delay between probes
nmap --max-parallelism 10 10.10.10.50         # Limit parallel probes
```

### 8. Firewall/IDS Evasion
```bash
# Fragment packets
nmap -f 10.10.10.50
nmap --mtu 24 10.10.10.50

# Decoy scan
nmap -D RND:5 10.10.10.50
nmap -D 10.10.10.1,10.10.10.2,ME 10.10.10.50

# Source port manipulation
nmap --source-port 53 10.10.10.50
nmap --source-port 80 10.10.10.50

# Spoof MAC address
nmap --spoof-mac 0 10.10.10.50              # Random MAC
nmap --spoof-mac Dell 10.10.10.50           # Vendor prefix

# Data length padding
nmap --data-length 50 10.10.10.50

# Bad checksum (test for firewall/IDS)
nmap --badsum 10.10.10.50
```

## Tool Usage

### masscan
```bash
# Fast full port scan
masscan 10.10.10.0/24 -p 1-65535 --rate 10000

# Common ports
masscan 10.10.10.0/24 -p 21,22,80,443,445,3389 --rate 5000

# Output to file for nmap follow-up
masscan 10.10.10.0/24 -p 1-65535 --rate 10000 -oL masscan_output.txt

# Banner grabbing
masscan 10.10.10.0/24 -p 80,443 --banners --rate 5000

# Exclude hosts
masscan 10.10.10.0/24 -p 1-65535 --rate 10000 --excludefile exclude.txt
```

### RustScan
```bash
# Fast port discovery, then hand off to nmap
rustscan -a 10.10.10.50 -- -sC -sV

# Custom port range
rustscan -a 10.10.10.50 -r 1-65535 -- -sC -sV

# Multiple targets
rustscan -a 10.10.10.50,10.10.10.51,10.10.10.52 -- -sC -sV

# Adjust batch size and timeout
rustscan -a 10.10.10.50 -b 1000 -t 2000 -- -A

# Scan from file
rustscan -a targets.txt -- -sV
```

### Recommended Scan Strategy
```bash
# Phase 1: Fast host discovery
nmap -sn -PE -PS22,80,443,445 10.10.10.0/24 -oG hosts.gnmap

# Phase 2: Fast port scan with masscan/rustscan
masscan -iL live_hosts.txt -p 1-65535 --rate 10000 -oL ports.txt

# Phase 3: Detailed nmap scan on discovered ports
nmap -sC -sV -O -p <discovered_ports> -iL live_hosts.txt -oA detailed_scan

# Phase 4: Targeted vulnerability scanning
nmap --script=vuln -p <open_ports> -iL live_hosts.txt -oA vuln_scan

# Phase 5: UDP scan on common ports
nmap -sU --top-ports 50 -iL live_hosts.txt -oA udp_scan
```

### Output Formats
```bash
# Nmap output formats
nmap -oN normal.txt 10.10.10.50        # Normal output
nmap -oX output.xml 10.10.10.50        # XML output
nmap -oG greppable.txt 10.10.10.50     # Greppable output
nmap -oA all_formats 10.10.10.50       # All formats at once

# Parse nmap XML
xsltproc output.xml -o report.html
```

## Remediation
1. **Minimize attack surface** -- close unnecessary ports and disable unused services
2. **Firewall rules** -- implement default-deny inbound policies with explicit allow rules
3. **Network segmentation** -- isolate sensitive systems into separate network zones
4. **IDS/IPS deployment** -- detect and block port scanning activity
5. **Rate limiting** -- throttle connection attempts to prevent fast scanning
6. **Port knocking / SPA** -- hide services behind port knock sequences or Single Packet Authorization
7. **Service hardening** -- remove version banners, disable unnecessary features
8. **Regular scanning** -- perform internal scanning to identify unauthorized services before attackers do

## Evidence Collection
When documenting network scanning findings:
- Complete list of discovered hosts with IP addresses and hostnames
- Open ports and services on each host with version information
- OS fingerprinting results
- Network topology diagram based on scan results
- Nmap XML output files for reproducibility
- Notable findings (unexpected services, outdated versions, default credentials)
- Scan parameters used (timing, technique, scope)
- Any scan detection or blocking observed
