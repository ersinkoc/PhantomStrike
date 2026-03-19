# DNS Enumeration

## Overview
DNS enumeration extracts detailed information about a target's DNS infrastructure including subdomains, mail servers, name servers, IP address mappings, and service records. DNS is the backbone of internet infrastructure, and thorough enumeration reveals the full scope of a target's network, hosting architecture, and potential attack vectors like zone transfers and cache poisoning.

## Classification
- **MITRE ATT&CK:** T1590.002 (DNS), T1596.001 (DNS/Passive DNS)
- **Phase:** Reconnaissance
- **Risk Level:** Low to Medium (DNS queries are expected traffic)
- **Prerequisites:** Target domain name

## Detection Methodology

### 1. DNS Record Types
Query all relevant record types for comprehensive enumeration:

| Record | Purpose | Security Value |
|--------|---------|----------------|
| **A** | IPv4 address mapping | Identify hosting infrastructure |
| **AAAA** | IPv6 address mapping | Find dual-stack hosts, sometimes less protected |
| **MX** | Mail server | Email infrastructure, spoofing targets |
| **NS** | Authoritative nameservers | DNS infrastructure, delegation attacks |
| **CNAME** | Canonical name (alias) | Subdomain takeover candidates |
| **TXT** | Text records | SPF, DKIM, DMARC, domain verification tokens |
| **SOA** | Start of Authority | Zone admin email, serial numbers |
| **SRV** | Service records | Internal service discovery (LDAP, SIP, XMPP) |
| **PTR** | Reverse DNS | Hostname discovery from IP ranges |
| **CAA** | Certificate Authority Authorization | Allowed CAs for the domain |
| **NAPTR** | Naming Authority Pointer | VoIP and SIP infrastructure |

### 2. Zone Transfer (AXFR)
Attempt to download the complete DNS zone file:
- Misconfigured DNS servers may allow zone transfers to any requestor
- Reveals all DNS records in the zone (complete subdomain listing)
- Check all authoritative nameservers (primary and secondary)
- Zone transfers are the most impactful DNS misconfiguration finding

### 3. Reverse DNS Enumeration
Map IP addresses back to hostnames:
- Identify the target's IP range from known A records
- Query PTR records for each IP in the range
- Reveals hostnames not discoverable through forward DNS
- Useful for finding internal naming conventions and hidden services

### 4. DNS Brute Force
Systematically resolve potential subdomains:
- Use curated wordlists (SecLists DNS lists)
- Detect wildcard responses before brute forcing
- Use multiple DNS resolvers for reliability
- Increase wordlist size based on initial findings

### 5. Cache Snooping
Query DNS caches to determine which domains have been recently resolved:
- Non-recursive query to caching resolvers
- Reveals which external services the target uses
- Identifies internal domain names cached by recursive resolvers
- Can indicate partnerships, vendors, and tools in use

### 6. Wildcard Detection
Identify domains configured with wildcard DNS responses:
- Query a random, non-existent subdomain
- If it resolves, the domain uses wildcard DNS
- Record the wildcard IP(s) to filter from brute force results
- Wildcard domains complicate subdomain enumeration but may indicate CDN usage

### 7. SPF, DKIM, and DMARC Analysis
Extract email security configuration:
- **SPF (TXT record):** Reveals authorized email sending servers and IP ranges
- **DKIM (TXT record):** Validates email signatures, reveals selector names
- **DMARC (TXT record):** Email authentication policy, reporting addresses
- Misconfigured email records enable email spoofing attacks

### 8. DNSSEC Validation
Check for DNSSEC deployment:
- Query DNSKEY, DS, RRSIG records
- Incomplete DNSSEC deployment may enable cache poisoning
- NSEC/NSEC3 zone walking can enumerate all domains

## Tool Usage

### dig
```bash
# Query all record types
dig target.com ANY +noall +answer

# Specific record types
dig target.com A +short
dig target.com AAAA +short
dig target.com MX +short
dig target.com NS +short
dig target.com TXT +short
dig target.com SOA +short
dig target.com CNAME +short
dig target.com SRV +short
dig target.com CAA +short

# Zone transfer attempt
dig @ns1.target.com target.com AXFR

# Attempt zone transfer on all nameservers
for ns in $(dig target.com NS +short); do
  echo "Trying AXFR on $ns..."
  dig @$ns target.com AXFR
done

# Reverse DNS lookup
dig -x 1.2.3.4 +short

# Reverse DNS for a range (class C)
for i in $(seq 1 254); do
  dig -x 10.0.0.$i +short
done

# SPF record
dig target.com TXT +short | grep "v=spf1"

# DMARC record
dig _dmarc.target.com TXT +short

# DKIM record (requires selector name)
dig selector1._domainkey.target.com TXT +short

# DNSSEC records
dig target.com DNSKEY +dnssec
dig target.com DS +short

# DNS cache snooping (non-recursive query)
dig @resolver.target.com www.google.com A +norecurse

# Trace DNS resolution path
dig target.com +trace

# Query specific nameserver
dig @8.8.8.8 target.com A +short
```

### host
```bash
# Basic lookup
host target.com

# Specific record type
host -t MX target.com
host -t NS target.com
host -t TXT target.com
host -t CNAME www.target.com

# Zone transfer
host -l target.com ns1.target.com

# Reverse lookup
host 1.2.3.4

# Verbose output
host -v target.com
```

### dnsrecon
```bash
# Standard enumeration (A, AAAA, SOA, NS, MX, SRV, TXT)
dnsrecon -d target.com -t std

# Zone transfer attempt
dnsrecon -d target.com -t axfr

# DNS brute force
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse lookup for IP range
dnsrecon -r 10.0.0.0/24 -t rvl

# Cache snooping
dnsrecon -d target.com -t snoop -D domains.txt -n resolver.target.com

# SRV record enumeration
dnsrecon -d target.com -t srv

# Google enumeration
dnsrecon -d target.com -t goo

# DNSSEC zone walking
dnsrecon -d target.com -t zonewalk

# Output to multiple formats
dnsrecon -d target.com -t std -j output.json
dnsrecon -d target.com -t std -c output.csv
dnsrecon -d target.com -t std -x output.xml

# Comprehensive scan (all enumeration types)
dnsrecon -d target.com -t std,axfr,brt,srv -D wordlist.txt -j full_results.json
```

### dnsenum
```bash
# Standard enumeration with brute force
dnsenum target.com

# With custom wordlist and threads
dnsenum --dnsserver 8.8.8.8 --enum -f wordlist.txt --threads 10 target.com

# Save results
dnsenum target.com -o results.xml

# Limit recursion
dnsenum --noreverse target.com

# With subdomains wordlist
dnsenum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt target.com

# Verbose mode
dnsenum -v target.com
```

### fierce
```bash
# Basic DNS reconnaissance
fierce --domain target.com

# With custom wordlist
fierce --domain target.com --subdomain-file wordlist.txt

# Specify DNS server
fierce --domain target.com --dns-servers 8.8.8.8

# Wide scan (expand IP ranges found)
fierce --domain target.com --wide

# Custom range for reverse lookups
fierce --domain target.com --range 10.0.0.0/24

# Connect scan on discovered hosts
fierce --domain target.com --connect

# Delay between queries
fierce --domain target.com --delay 1
```

## Output Analysis Tips
- **Zone transfer success is critical:** If AXFR succeeds, you have the complete DNS zone. Report this as a high-severity finding and analyze every record.
- **MX record analysis:** MX records reveal email providers (Google Workspace, Microsoft 365, self-hosted). This informs phishing and email security testing.
- **SPF record parsing:** Overly permissive SPF records (e.g., `+all`, `~all` without DMARC enforcement) enable email spoofing.
- **CNAME chains:** Follow CNAME chains to their final resolution. Dangling CNAMEs pointing to unclaimed services are subdomain takeover candidates.
- **NS record delegation:** Check if nameservers are self-hosted or third-party. Third-party DNS providers may have different security postures.
- **SRV records:** SRV records for `_ldap`, `_kerberos`, `_sip`, `_xmpp` reveal internal service architecture not intended for public consumption.
- **SOA email:** The SOA record contains the zone administrator's email (with `.` instead of `@`), which is a valid contact for the domain.
- **TTL analysis:** Very low TTLs may indicate load balancing or CDN usage. Very high TTLs indicate static infrastructure.
- **IPv6 discovery:** AAAA records sometimes point to hosts with less restrictive firewall rules than their IPv4 counterparts.

## Evidence Collection
- Complete DNS record dump for all queried record types
- Zone transfer results (if successful) with severity rating
- SPF, DKIM, and DMARC analysis with spoofing feasibility assessment
- Reverse DNS results for target IP ranges
- Subdomain brute force results with resolution status
- DNSSEC configuration status and any weaknesses
- Nameserver infrastructure summary
- Cache snooping results revealing third-party service usage
- CNAME records with subdomain takeover risk assessment
- Tools used and DNS servers queried
