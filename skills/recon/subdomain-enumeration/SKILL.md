# Subdomain Enumeration

## Overview
Subdomain enumeration is the process of discovering valid subdomains for a target domain. It expands the attack surface by revealing hidden services, development environments, staging servers, and forgotten infrastructure that may contain vulnerabilities. This is typically the first step in external reconnaissance.

## Classification
- **MITRE ATT&CK:** T1596 (Search Open Technical Databases), T1590.002 (DNS)
- **Phase:** Reconnaissance
- **Risk Level:** Passive (no direct target interaction) to Active (DNS brute force)
- **Prerequisites:** Target domain name, authorized scope confirmation

## Detection Methodology

### 1. Passive Enumeration
Gather subdomains without sending traffic to the target. Sources include:
- **Certificate Transparency (crt.sh):** Query CT logs for issued certificates
- **SecurityTrails:** Historical DNS records and subdomain database
- **VirusTotal:** Passive DNS and URL dataset
- **Wayback Machine:** Historical URLs from web archives
- **Shodan:** Banner data containing hostnames
- **Censys:** Certificate and host search
- **Common Crawl:** Web crawl data index
- **DNS Dumpster:** Free subdomain enumeration service
- **RapidDNS:** Passive DNS database

### 2. Active DNS Brute Force
Send DNS queries to resolve potential subdomains against the target's authoritative nameservers:
- Use curated wordlists (SecLists, Assetnote)
- Start with small lists (1K-5K), escalate to large (100K+) if warranted
- Detect and handle wildcard DNS responses before brute forcing
- Use high-performance resolvers (massdns) for large wordlists

### 3. Permutation and Alteration
Generate variations of known subdomains to find related hosts:
- Prefix/suffix: `dev-`, `staging-`, `-api`, `-v2`
- Word swap: `app` to `application`, `mail` to `email`
- Number increment: `server1` to `server2`, `server3`
- Hyphenation: `devapi` to `dev-api`, `dev.api`

### 4. Recursive Enumeration
For each discovered subdomain, repeat enumeration:
- Sub-subdomains: `internal.dev.target.com`
- Multi-level: `api.staging.internal.target.com`

### 5. Validation and Filtering
After discovery, validate results:
- Resolve all found subdomains to IP addresses
- Filter out wildcard responses (compare against random subdomain)
- Check HTTP/HTTPS response on ports 80, 443, 8080, 8443
- Identify CDN, WAF, or third-party hosted subdomains
- Group by IP address to identify shared hosting

## Tool Usage

### subfinder
```bash
# Basic enumeration using all passive sources
subfinder -d target.com -o subdomains.txt

# Verbose with all sources and recursive
subfinder -d target.com -all -recursive -o subdomains.txt

# Use specific sources only
subfinder -d target.com -sources crtsh,securitytrails,virustotal -o subdomains.txt

# Multiple domains from file
subfinder -dL domains.txt -o subdomains.txt

# JSON output for parsing
subfinder -d target.com -json -o subdomains.json

# Silent mode (clean output, one per line)
subfinder -d target.com -silent
```

### amass
```bash
# Passive enumeration only
amass enum -passive -d target.com -o subdomains.txt

# Active enumeration with brute force
amass enum -active -brute -d target.com -o subdomains.txt

# Full enumeration with DNS resolution
amass enum -d target.com -ip -o subdomains.txt

# Use specific config file with API keys
amass enum -d target.com -config amass_config.yaml -o subdomains.txt

# Intel mode (discover related domains)
amass intel -d target.com -whois

# Track changes over time
amass track -d target.com -dir ./amass_output
```

### findomain
```bash
# Basic enumeration
findomain -t target.com -o

# Unique output with resolution
findomain -t target.com -r -u subdomains.txt

# Monitor mode (continuous)
findomain -t target.com --monitoring-flag

# Multiple targets
findomain -f domains.txt -r -u all_subdomains.txt
```

### dnsrecon (brute force mode)
```bash
# DNS brute force with wordlist
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Standard enumeration
dnsrecon -d target.com -t std

# Zone transfer attempt
dnsrecon -d target.com -t axfr

# Output to JSON
dnsrecon -d target.com -t brt -D wordlist.txt -j output.json
```

### altdns (permutation)
```bash
# Generate permutations from known subdomains
altdns -i known_subdomains.txt -o permutations.txt -w words.txt

# Generate and resolve
altdns -i known_subdomains.txt -o permutations.txt -w words.txt -r -s resolved.txt
```

### massdns (high-speed resolution)
```bash
# Resolve subdomain list at scale
massdns -r resolvers.txt -t A -o S subdomains.txt > resolved.txt

# JSON output
massdns -r resolvers.txt -t A -o J subdomains.txt > resolved.json

# With rate limiting to avoid resolver bans
massdns -r resolvers.txt -t A -o S -s 500 subdomains.txt > resolved.txt
```

### Manual crt.sh query
```bash
# Query Certificate Transparency logs via curl
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Include expired certificates
curl -s "https://crt.sh/?q=%.target.com&output=json&exclude=expired" | jq -r '.[].name_value' | sort -u
```

## Output Analysis Tips
- **Wildcard detection:** If a random subdomain (e.g., `xyzrandomstring123.target.com`) resolves, the domain uses wildcard DNS. Filter results matching the wildcard IP.
- **IP clustering:** Group subdomains by resolved IP to identify infrastructure segments and prioritize targets.
- **Cloud identification:** Check if IPs belong to AWS, Azure, GCP, or CDN ranges. Cloud-hosted subdomains may have different attack vectors (subdomain takeover).
- **Status code analysis:** After HTTP probing, focus on non-standard responses (401, 403, 500) as they often indicate internal or misconfigured services.
- **Subdomain takeover candidates:** Look for CNAME records pointing to unclaimed services (GitHub Pages, Heroku, S3, Azure, etc.).
- **Historical comparison:** Compare current results with Wayback Machine data to find decommissioned but still-resolving subdomains.

## Evidence Collection
- Complete list of discovered subdomains with resolution status
- IP address mappings and hosting provider identification
- HTTP response codes and page titles for live subdomains
- Subdomain takeover candidates with CNAME evidence
- Tools used, wordlists selected, and source APIs queried
- Timestamp and scope confirmation for the enumeration
- Screenshot or response body for notable discoveries
