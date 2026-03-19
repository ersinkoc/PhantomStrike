# PCI-DSS Compliance Testing

## Overview
PCI-DSS (Payment Card Industry Data Security Standard) compliance testing validates that organizations handling cardholder data meet the security requirements defined by the PCI Security Standards Council. This guide covers penetration testing methodology aligned to PCI-DSS v4.0 requirements, focusing on cardholder data environment (CDE) scoping, network segmentation validation, and requirement-specific testing procedures.

## Classification
- **Framework:** PCI-DSS v4.0 (effective March 2024)
- **Testing Type:** Compliance-driven penetration testing
- **Scope:** Cardholder Data Environment (CDE) and connected systems
- **Frequency:** Annual penetration test, quarterly vulnerability scans (ASV)

## Methodology

### 1. CDE Scoping and Segmentation Validation
```
Step 1: Identify all systems that store, process, or transmit cardholder data
Step 2: Map data flows — card entry to processor, storage locations, logs
Step 3: Identify network segmentation controls (firewalls, VLANs, ACLs)
Step 4: Validate segmentation effectiveness from outside the CDE

# Test segmentation from non-CDE network
nmap -sS -p- <CDE_subnet> --source-port 53
nmap -sU -p 53,161,162,500 <CDE_subnet>

# Test from DMZ to CDE
nmap -Pn -sS -p 1-65535 <CDE_hosts>

# Test from wireless network to CDE
# Connect to guest/corporate wireless, attempt CDE access

# Document all in-scope systems and segmentation controls
```

### 2. Requirement 1 — Network Security Controls
```
# Test firewall/router rule sets
# Verify deny-all default policy
nmap -sS -p- <firewall_external_ip>

# Test for unnecessary open ports
nmap -sS -sV -p- <CDE_hosts>

# Verify inbound and outbound filtering
# Test egress from CDE to internet
curl -v http://example.com  # from CDE host
ncat -v <external_ip> 443   # from CDE host

# Verify personal firewall on mobile/remote devices accessing CDE
# Verify NSC (Network Security Control) configuration review process
```

### 3. Requirement 2 — Secure Configurations
```
# Test for default credentials
hydra -L defaults_users.txt -P defaults_pass.txt <target> ssh
hydra -L defaults_users.txt -P defaults_pass.txt <target> http-get /admin

# Check for default SNMP community strings
nmap -sU -p 161 --script snmp-brute <CDE_hosts>

# Verify system hardening
# CIS Benchmark compliance scanning
# Check unnecessary services, protocols, daemons

# Test wireless access points
# Default SSIDs, WEP encryption, weak WPA keys
airodump-ng wlan0
# Scan for rogue access points near CDE
```

### 4. Requirement 3 — Protect Stored Account Data
```
# Search for stored cardholder data (PANs)
# Check databases, files, logs, backups, memory

# PAN detection patterns (Luhn-validated)
# Visa: 4[0-9]{12,18}
# Mastercard: 5[1-5][0-9]{14} or 2[2-7][0-9]{14}
# Amex: 3[47][0-9]{13}
# Discover: 6(?:011|5[0-9]{2})[0-9]{12}

grep -rE '4[0-9]{12,18}|5[1-5][0-9]{14}|3[47][0-9]{13}' /var/log/ /tmp/ /var/www/

# Check for full track data, CVV, PIN storage (must NEVER be stored)
# Verify PAN masking in displays (show only first 6 / last 4)
# Verify encryption of stored PANs — check algorithm and key management

# Test database access controls to cardholder data tables
# Verify encryption key rotation procedures
```

### 5. Requirement 4 — Protect Data in Transit
```
# Test TLS on all CDE communication channels
testssl.sh <CDE_host>:443
sslyze --regular <CDE_host>:443

# Verify no cleartext transmission of PANs
# Monitor network traffic for unencrypted card data
tcpdump -i eth0 -A | grep -iE '[0-9]{13,19}'

# Test internal CDE-to-CDE communication encryption
# Check for plaintext protocols: HTTP, FTP, Telnet, SMTP without TLS

# Verify email/messaging encryption for any PAN transmission
# Check for PANs in unencrypted chat, email, or ticketing systems
```

### 6. Requirement 5 — Malware Protection
```
# Verify anti-malware on all CDE systems
# Check for current signatures and real-time scanning
# Test detection with EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt

# Verify anti-malware cannot be disabled by users
# Check phishing/email protection on systems handling card data
```

### 7. Requirement 6 — Secure Development
```
# Web application security testing (if custom payment application)
# Full OWASP Top 10 testing on payment-facing applications
# Test input validation on card entry forms
# Test for XSS, SQLi, CSRF on payment pages

# Verify patch management — check for unpatched vulnerabilities
nmap -sV --script vuln <CDE_hosts>
nuclei -l cde_targets.txt -t cves/

# Test for public-facing application protections (WAF or code review)
```

### 8. Requirement 7 — Restrict Access
```
# Test role-based access control on CDE systems
# Verify least privilege — users only access what they need
# Test for privilege escalation from non-CDE user to CDE access

# Check for shared/group accounts accessing cardholder data
# Verify access is revoked for terminated employees
# Test administrative access controls and logging
```

### 9. Requirement 8 — Identify Users
```
# Test authentication mechanisms on CDE systems
# Verify unique IDs for all users (no shared accounts)
# Test password policy: minimum 12 chars (v4.0), complexity, history

# Test MFA on all non-console administrative access to CDE
# Test MFA on all remote access to CDE
# Verify account lockout after 10 failed attempts (reset after 30 min)

hydra -l admin -P passwords.txt <CDE_host> ssh -t 4
# Observe lockout behavior
```

### 10. Requirement 10 — Log and Monitor
```
# Verify audit logging on all CDE systems
# Check that logs capture: user access, actions, timestamps, success/fail
# Verify log integrity (tamper detection, centralized logging)

# Test time synchronization across CDE systems
# Verify log retention (12 months minimum, 3 months immediately available)

# Check for security event alerting
# Trigger test events and verify alert generation
```

### 11. Requirement 11 — Regular Testing
```
# Quarterly internal and external vulnerability scans
nessus_scan <CDE_targets>    # Internal scan
# ASV scan for external-facing systems

# Annual penetration test covering:
# - Network layer testing (internal and external)
# - Application layer testing
# - Segmentation validation

# Wireless analyzer scan
airodump-ng wlan0  # Detect unauthorized wireless APs

# File integrity monitoring (FIM) validation
# Modify a critical system file, verify FIM alert
```

### 12. Requirement 12 — Organizational Policies
```
# Verify incident response plan exists and is tested
# Check that security awareness training covers cardholder data handling
# Review service provider agreements for PCI compliance requirements
# Verify risk assessment is performed annually
```

## Cardholder Data Detection Tools
```bash
# PANhunter — scan filesystems for card numbers
# Custom grep with Luhn validation
grep -rEn '([0-9]{4}[\s-]?){3}[0-9]{1,7}' /path/to/search/

# Memory analysis for card data
strings /proc/<pid>/mem | grep -E '[0-9]{13,19}'

# Database scanning
# Query for columns likely containing PANs
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%card%' OR column_name LIKE '%pan%'
  OR column_name LIKE '%account%' OR column_name LIKE '%number%';

# Network capture analysis
tshark -r capture.pcap -Y "data" -T fields -e data | xxd -r -p | grep -oE '[0-9]{13,19}'
```

## Segmentation Testing Procedure
```
1. From each non-CDE segment, attempt to reach each CDE system:
   - Full TCP port scan (1-65535)
   - UDP scan on common ports
   - Test all protocols (not just TCP/IP)

2. From wireless networks (guest and corporate):
   - Attempt to access CDE VLANs
   - Test for VLAN hopping

3. From internet-facing DMZ:
   - Verify only required ports accessible to CDE
   - Test for pivot paths through DMZ to CDE

4. Document all segmentation test results with:
   - Source network/host
   - Destination CDE host
   - Ports/protocols tested
   - Result (blocked/allowed)
```

## Remediation
1. **Minimize CDE scope** — use tokenization, P2PE, and network segmentation
2. **Encrypt stored PANs** — AES-256 with proper key management per Requirement 3
3. **Enforce TLS 1.2+** on all CDE communications — disable SSL, TLS 1.0/1.1
4. **Implement MFA** on all remote and administrative access to CDE
5. **Deploy file integrity monitoring** on critical system files and configurations
6. **Maintain patch currency** — critical patches within 30 days
7. **Restrict outbound traffic** from CDE to only required destinations
8. **Never store CVV, full track data, or PIN** post-authorization
9. **Implement centralized logging** with tamper detection and 12-month retention

## Evidence Collection
- Network diagrams showing CDE boundaries and segmentation controls
- Segmentation test results with source/destination/port/result matrix
- Vulnerability scan reports (internal and ASV external)
- Screenshots of cardholder data found in unauthorized locations
- TLS configuration test results for all CDE endpoints
- Authentication and access control test results
- Compliance gap matrix mapping each finding to PCI-DSS requirement
