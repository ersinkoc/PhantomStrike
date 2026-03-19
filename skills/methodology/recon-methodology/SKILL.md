# Reconnaissance Methodology

## Overview
Reconnaissance is the foundational phase of any security assessment. A structured approach moving from passive to active techniques maximizes information gathering while managing detection risk. This guide defines a repeatable methodology for target scoping, passive and active reconnaissance, information correlation, and tool chaining to build a comprehensive attack surface map.

## Methodology

### Phase 1: Target Scoping and Seed Collection
```
1. Define scope boundaries
   - In-scope domains, IP ranges, subsidiaries
   - Out-of-scope systems and restrictions
   - Rules of engagement (passive only vs active permitted)

2. Collect seed information
   - Primary domain(s) and known IP ranges
   - Organization name, subsidiaries, acquisitions
   - ASN numbers
   - Known technology stack

3. Create project structure
mkdir -p recon/{passive,active,osint,output}
echo "target.com" > recon/scope.txt
```

### Phase 2: Passive Reconnaissance
No direct interaction with target systems.

#### 2a. Domain and DNS Intelligence
```bash
# Subdomain enumeration (passive sources)
subfinder -d target.com -all -o recon/passive/subdomains_subfinder.txt
amass enum -passive -d target.com -o recon/passive/subdomains_amass.txt
assetfinder --subs-only target.com > recon/passive/subdomains_assetfinder.txt

# Merge and deduplicate
cat recon/passive/subdomains_*.txt | sort -u > recon/passive/all_subdomains.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS history and zone transfers (passive lookup)
# SecurityTrails, VirusTotal, DNSDumpster

# Reverse DNS on known IP ranges
# Identify additional domains hosted on same infrastructure
```

#### 2b. OSINT and Data Gathering
```bash
# Search engine dorking
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"
# "target.com" filetype:sql | filetype:log | filetype:conf

# GitHub/GitLab reconnaissance
# Search for organization repositories and leaked secrets
# "target.com" password OR secret OR api_key OR token

# Shodan/Censys queries
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,org,hostnames
censys search "target.com" --index-type hosts

# Email harvesting
theHarvester -d target.com -b all -f recon/osint/emails.html

# Leaked credentials
# Check HaveIBeenPwned API, breach databases
# Correlate discovered email addresses with breach data

# Wayback Machine — historical pages and endpoints
waybackurls target.com | sort -u > recon/passive/wayback_urls.txt
```

#### 2c. Technology Fingerprinting (Passive)
```bash
# Analyze public-facing technology from headers and content
# Wappalyzer, BuiltWith (browser extensions or API)

# Identify CDN, WAF, hosting provider
# Check response headers: Server, X-Powered-By, Via
# Check DNS for CDN CNAMEs (cloudfront, akamai, cloudflare)

# JavaScript library identification
# Analyze publicly accessible JS files for version strings
```

### Phase 3: Active Reconnaissance
Direct interaction with target systems (authorized only).

#### 3a. DNS Active Enumeration
```bash
# DNS brute force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o recon/active/dns_brute.txt

# DNS zone transfer attempt
dig axfr target.com @ns1.target.com

# DNS record enumeration
dig target.com ANY
dig target.com MX
dig target.com TXT
dig target.com NS
dig _dmarc.target.com TXT

# Resolve all discovered subdomains
cat recon/passive/all_subdomains.txt | dnsx -resp -o recon/active/resolved.txt
```

#### 3b. Network Discovery and Port Scanning
```bash
# Host discovery
nmap -sn <target_range> -oG recon/active/hosts_up.gnmap

# Port scanning — full TCP
nmap -sS -p- --min-rate 10000 -oA recon/active/full_tcp <target>

# Service version detection on open ports
nmap -sV -sC -p <open_ports> -oA recon/active/services <target>

# UDP scan (top ports)
nmap -sU --top-ports 100 -oA recon/active/udp <target>

# Masscan for fast large-range scanning
masscan -p1-65535 --rate 10000 -oL recon/active/masscan.txt <target_range>
```

#### 3c. Web Application Discovery
```bash
# HTTP probing on all resolved subdomains
cat recon/active/resolved.txt | httpx -title -status-code -tech-detect -o recon/active/web_alive.txt

# Screenshot all web applications
gowitness file -f recon/active/web_urls.txt -P recon/active/screenshots/

# Directory and file brute-forcing
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc 200,301,302,403 -o recon/active/dirs.json

# Virtual host discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs <default_size>

# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Technology fingerprinting (active)
whatweb https://target.com
wappalyzer-cli https://target.com
```

### Phase 4: Information Correlation and Attack Surface Mapping
```
1. Consolidate all findings into structured format:
   - Subdomain → IP → Open Ports → Services → Technologies
   - Build a spreadsheet or database of discovered assets

2. Identify high-value targets:
   - Admin panels and login pages
   - API endpoints
   - Legacy/development systems
   - Systems running outdated software
   - Cloud storage (S3 buckets, Azure blobs)

3. Correlate information:
   - Cross-reference subdomains with IP ranges (shared hosting detection)
   - Map technologies to known CVEs
   - Link email addresses to social media profiles
   - Identify trust relationships between systems

4. Prioritize targets:
   - Internet-facing with known vulnerabilities
   - Authentication pages (brute-force, credential stuffing)
   - File upload functionality
   - API endpoints without authentication
   - Legacy systems with outdated frameworks
```

## Tool Chaining Pipelines
```bash
# Full passive-to-active pipeline
subfinder -d target.com -silent | \
  dnsx -silent -resp | \
  httpx -silent -title -status-code -tech-detect | \
  tee recon/output/full_pipeline.txt

# Subdomain → port scan → service detect
subfinder -d target.com -silent | \
  dnsx -silent -a -resp-only | \
  naabu -p - -silent | \
  httpx -silent -title

# URL collection → parameter discovery
cat recon/passive/wayback_urls.txt | \
  grep "=" | \
  uro | \
  qsreplace "FUZZ" | \
  sort -u > recon/output/parameterized_urls.txt
```

## Output Organization
```
recon/
├── scope.txt                    # In-scope targets
├── passive/
│   ├── subdomains_*.txt         # Subdomain sources
│   ├── all_subdomains.txt       # Merged subdomains
│   └── wayback_urls.txt         # Historical URLs
├── active/
│   ├── resolved.txt             # DNS resolution results
│   ├── full_tcp.nmap            # Port scan results
│   ├── services.nmap            # Service detection
│   ├── web_alive.txt            # Live web applications
│   ├── dirs.json                # Directory brute-force
│   └── screenshots/             # Web app screenshots
├── osint/
│   ├── emails.html              # Harvested emails
│   └── github_findings.txt      # Code repository leaks
└── output/
    ├── attack_surface.csv       # Consolidated asset inventory
    └── full_pipeline.txt        # Tool chain output
```

## Remediation
1. **Minimize public attack surface** — remove unnecessary subdomains and services
2. **Implement DNS best practices** — disable zone transfers, use DNSSEC
3. **Remove sensitive data from public repositories** — rotate exposed credentials
4. **Restrict directory listings and default pages** — return 404 for non-existent paths
5. **Monitor for new asset exposure** — continuous subdomain monitoring
6. **Remove metadata from public documents** — strip author, path, version info
7. **Enforce consistent security baselines** — apply to all discovered systems including forgotten assets

## Evidence Collection
- Complete subdomain enumeration results with resolution status
- Port scan results mapped to services and versions
- Screenshots of all discovered web applications
- Technology stack identification per host
- Discovered credentials or sensitive data in public sources
- Network diagram showing discovered infrastructure relationships
- Attack surface summary with prioritized target list
