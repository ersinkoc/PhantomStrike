# OSINT Reconnaissance

## Overview
Open Source Intelligence (OSINT) reconnaissance gathers publicly available information about a target organization, its employees, infrastructure, and technology stack. This intelligence shapes the attack strategy by revealing email patterns, organizational structure, exposed credentials, and potential social engineering vectors. All data is collected from public sources without direct target interaction.

## Classification
- **MITRE ATT&CK:** T1593 (Search Open Websites/Domains), T1589 (Gather Victim Identity Information), T1591 (Gather Victim Org Information)
- **Phase:** Reconnaissance
- **Risk Level:** Passive (public data sources only)
- **Prerequisites:** Target organization name, domain, or key personnel

## Detection Methodology

### 1. Email Harvesting
Discover email addresses associated with the target:
- Search engine scraping (Google, Bing, Yahoo, Baidu)
- LinkedIn employee discovery and email pattern inference
- Hunter.io, Phonebook.cz, EmailHippo lookups
- Document metadata extraction (PDF, DOCX, XLSX, PPTX)
- GitHub commit email addresses
- Mailing list archives and forum posts

### 2. Social Media Intelligence
Profile the organization and employees through social media:
- LinkedIn: employee roles, technologies, job postings (tech stack hints)
- Twitter/X: developer discussions, incident disclosures, tool mentions
- GitHub/GitLab: public repos, contributor profiles, code comments
- Stack Overflow: employee questions revealing internal tech
- Reddit: subreddit mentions, employee posts
- Glassdoor: reviews hinting at internal infrastructure

### 3. Employee Discovery
Map the organizational structure:
- LinkedIn company page and employee enumeration
- Email pattern discovery (first.last@, f.last@, firstl@)
- Role identification (IT admins, developers, executives)
- Org chart reconstruction from public sources
- Contractor and vendor relationship mapping

### 4. Technology Stack Identification
Determine technologies in use:
- Job postings mentioning specific technologies
- Wappalyzer/BuiltWith for web technology detection
- DNS records (mail servers, SPF, DMARC reveal email providers)
- SSL certificate details (issuer, SAN entries)
- HTTP response headers (Server, X-Powered-By, X-AspNet-Version)
- JavaScript library fingerprinting

### 5. Breached Credential Lookup
Search for compromised credentials (authorized use only):
- Have I Been Pwned (HIBP) API for email breach status
- DeHashed, LeakCheck, IntelX for credential databases
- Paste sites (Pastebin, Ghostbin) for leaked data
- Dark web monitoring services (authorized only)
- Password reuse analysis across breaches

### 6. Google Dorking
Use search engine operators for targeted discovery:
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
"target.com" filetype:sql
"target.com" filetype:env
"@target.com" password
```

### 7. Shodan and Internet-Wide Scanning Data
Query pre-scanned internet data:
- Shodan: open ports, banners, vulnerabilities, screenshots
- Censys: certificate search, host enumeration
- ZoomEye, FOFA: Chinese search engines with broad coverage
- BinaryEdge: Internet scanning data

### 8. Domain WHOIS and Registration Data
Extract registration information:
- Registrant name, email, organization, phone
- Registration and expiration dates
- Historical WHOIS changes (DomainTools, WhoisXML)
- Related domains through shared registrant data
- Reverse WHOIS for discovering other owned domains

## Tool Usage

### theHarvester
```bash
# Comprehensive email and subdomain harvest
theHarvester -d target.com -b all -l 500

# Specific sources
theHarvester -d target.com -b google,bing,linkedin,crtsh

# DNS brute force included
theHarvester -d target.com -b all -c -l 500

# Output to HTML report
theHarvester -d target.com -b all -f report.html

# Screenshot discovered hosts
theHarvester -d target.com -b all -s

# Search for specific person
theHarvester -d target.com -b linkedin -l 200
```

### sherlock
```bash
# Search for username across social networks
sherlock targetuser --output results.txt

# Search multiple usernames
sherlock user1 user2 user3

# Specific sites only
sherlock targetuser --site github --site twitter --site linkedin

# Print found accounts only
sherlock targetuser --print-found

# Use Tor for anonymity
sherlock targetuser --tor

# CSV output
sherlock targetuser --csv
```

### spiderfoot
```bash
# Start SpiderFoot web UI
spiderfoot -l 127.0.0.1:5001

# CLI scan with all modules
spiderfoot -s target.com -t all -o output.csv

# Specific module types
spiderfoot -s target.com -t EMAILADDR,PHONE_NUMBER,SOCIAL_MEDIA

# Passive only (no active scanning)
spiderfoot -s target.com -m sfp_dnsresolve,sfp_crt,sfp_whois -o output.csv

# Scan a person
spiderfoot -s "John Smith" -t HUMAN_NAME
```

### Shodan CLI
```bash
# Search for target organization
shodan search "org:Target Corp"

# Search by hostname
shodan search "hostname:target.com"

# Get host details
shodan host 1.2.3.4

# Search for specific service
shodan search "hostname:target.com port:22"

# Count results
shodan count "hostname:target.com"

# Download results
shodan download results "hostname:target.com"
shodan parse --fields ip_str,port,org results.json.gz
```

### WHOIS lookup
```bash
# Standard WHOIS query
whois target.com

# Reverse WHOIS (find related domains)
# Use amass intel for reverse WHOIS
amass intel -whois -d target.com

# Historical WHOIS (requires SecurityTrails API)
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: YOUR_API_KEY"
```

### HIBP breach check
```bash
# Check email against breaches (API v3)
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: YOUR_KEY" \
  -H "user-agent: PhantomStrike"
```

## Output Analysis Tips
- **Email pattern confirmation:** Once 3-5 emails are found, deduce the pattern (first.last@, flast@) and generate a full employee email list.
- **High-value targets:** Prioritize IT administrators, DevOps engineers, and security personnel for targeted attacks.
- **Credential correlation:** Cross-reference breached emails with discovered employees. Password reuse is common.
- **Technology decisions:** Job postings are the most reliable OSINT source for internal technology stack (databases, frameworks, cloud providers).
- **WHOIS privacy:** If WHOIS is private, use historical WHOIS or reverse WHOIS on known registrant emails.
- **Social media opsec failures:** Developers often post screenshots or terminal output revealing internal hostnames, IP ranges, or tool configurations.
- **Shodan correlation:** Match Shodan results with discovered subdomains to find services not visible through standard web scanning.

## Evidence Collection
- Harvested email addresses with source attribution
- Employee list with roles and social media profiles
- Technology stack summary with discovery sources
- Breached credential findings (redact actual passwords)
- WHOIS records and domain registration history
- Shodan/Censys findings with open services
- Google dorking results with exact queries used
- Screenshots of significant public disclosures
- Organizational chart reconstruction
