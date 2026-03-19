# Subdomain Takeover Testing

## Overview
Subdomain takeover occurs when a subdomain's DNS record (typically a CNAME) points to an external service that has been deprovisioned or was never claimed. An attacker can register the abandoned resource on the external service and serve arbitrary content on the victim's subdomain. This enables phishing with a legitimate domain, cookie theft across the parent domain, and bypass of domain-based security controls.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-668 (Exposure of Resource to Wrong Sphere)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 6.1 - 8.8

## Detection Methodology

### 1. Enumerate Subdomains
```bash
# Passive enumeration
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com -o subdomains.txt
assetfinder --subs-only target.com >> subdomains.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS brute force
gobuster dns -d target.com -w /usr/share/wordlists/subdomains-top1million-5000.txt
puredns bruteforce wordlist.txt target.com

# Historical records
waybackurls target.com | unfurl domains | sort -u
```

### 2. Identify Dangling CNAME Records
```bash
# Check DNS records for each subdomain
while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    # Check if CNAME target resolves
    ip=$(dig +short "$cname" 2>/dev/null)
    if [ -z "$ip" ]; then
      echo "[DANGLING] $sub → $cname (NO RESOLUTION)"
    else
      echo "[ACTIVE] $sub → $cname → $ip"
    fi
  fi
done < subdomains.txt
```

### 3. Cloud Service Fingerprinting
Check if the CNAME points to a known service and whether the resource is claimable:

**AWS S3:**
```bash
# CNAME: subdomain.target.com → bucket-name.s3.amazonaws.com
curl -s http://subdomain.target.com
# Response: <Code>NoSuchBucket</Code>
# → Create bucket with matching name to takeover

# Verify
aws s3 ls s3://bucket-name 2>&1 | grep "NoSuchBucket"
```

**AWS CloudFront:**
```bash
# CNAME → xyz.cloudfront.net
curl -s http://subdomain.target.com
# Response: "The request could not be satisfied" / "Bad Request"
# → Create CloudFront distribution with subdomain as alternate CNAME
```

**GitHub Pages:**
```bash
# CNAME → username.github.io
curl -s http://subdomain.target.com
# Response: "There isn't a GitHub Pages site here."
# → Create repo, add CNAME file with subdomain.target.com
```

**Heroku:**
```bash
# CNAME → appname.herokuapp.com
curl -s http://subdomain.target.com
# Response: "No such app" or Heroku 404
# → Create Heroku app with matching name, add custom domain
```

**Azure:**
```bash
# CNAME → appname.azurewebsites.net / appname.cloudapp.net
curl -s http://subdomain.target.com
# → Create Azure resource with matching name
```

**Shopify:**
```bash
# CNAME → shops.myshopify.com
curl -s http://subdomain.target.com
# Response: "Sorry, this shop is currently unavailable."
```

**Other services to check:**
```
Fastly:         → [name].fastly.net
Pantheon:       → [name].pantheonsite.io
Zendesk:        → [name].zendesk.com
Readme.io:      → [name].readme.io
Ghost:          → [name].ghost.io
Surge.sh:       → [name].surge.sh
Bitbucket:      → [name].bitbucket.io
WordPress.com:  → [name].wordpress.com
Tumblr:         → domains.tumblr.com
Unbounce:       → unbouncepages.com
Feedpress:      → redirect.feedpress.me
Cargo:          → subdomain.cargocollective.com
```

### 4. Fingerprint Response Patterns
```bash
# Known takeover indicators in HTTP response
curl -s http://subdomain.target.com | grep -iE \
  "(NoSuchBucket|no such app|there isn't a github|not found.*heroku|
   domain not configured|this shop is currently unavailable|
   project not found|the request could not be satisfied|
   fastly error|unknown domain|nxdomain)"
```

### 5. NS Delegation Takeover
```bash
# Check if NS records point to expired/available nameservers
dig NS subdomain.target.com +short
# If NS points to a domain that can be registered → full DNS takeover
whois ns-domain.com  # Check availability
```

### 6. MX Record Takeover
```bash
# Check if MX records point to unclaimed services
dig MX subdomain.target.com +short
# If MX points to deprovisioned service → email interception
```

### 7. Verification Process
Before reporting, verify the takeover is possible:
```
1. Confirm CNAME or A record points to external service
2. Confirm the external resource is unclaimed/deprovisioned
3. Attempt to claim the resource on the external service
4. Serve a benign proof file (e.g., takeover-poc.txt with your handle)
5. Verify the file is accessible via the subdomain
6. Document everything, then release the resource
```

## Tool Usage
```bash
# Subjack - automated subdomain takeover detection
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v

# Nuclei subdomain takeover templates
nuclei -l subdomains.txt -t http/takeovers/ -batch

# can-i-take-over-xyz (reference for service fingerprints)
# https://github.com/EdOverflow/can-i-take-over-xyz

# dnsreaper
dnsreaper scan -d target.com

# CNAME check pipeline
cat subdomains.txt | dnsx -cname -resp-only | sort -u

# tko-subs
tko-subs -domains subdomains.txt -data providers-data.csv

# Full pipeline
subfinder -d target.com -silent | dnsx -cname -resp-only -silent \
  | sort -u > cnames.txt
```

## Remediation
1. **Remove stale DNS records** -- delete CNAME/A records when deprovisioning external services
2. **DNS record inventory** -- maintain an authoritative list of all DNS records and their purpose
3. **Automated monitoring** -- continuously scan for dangling records using CI/CD or scheduled jobs
4. **Verify before deprovision** -- remove DNS records first, then deprovision the service
5. **Domain validation** -- use service-specific domain verification (TXT records) where available
6. **Wildcard DNS caution** -- avoid wildcard records that resolve for any subdomain
7. **Cookie scoping** -- avoid setting cookies on the parent domain if subdomains are delegated to third parties
8. **CSP restrictions** -- limit which subdomains can load scripts/frames

## Evidence Collection
- Subdomain name and full DNS resolution chain (CNAME, A records)
- External service the CNAME points to
- Evidence that the resource is unclaimed (error page, HTTP response)
- Service-specific fingerprint match
- Proof of takeover (benign file served via the subdomain)
- Screenshot of content served on the subdomain
- Cookie scope impact assessment (can attacker set cookies for parent domain?)
- Timeline of when the DNS record was created vs when the service was deprovisioned
