# Email Harvesting

## Overview
Email harvesting collects email addresses associated with a target organization from public sources. Discovered emails enable targeted phishing, password spraying, credential stuffing against breached databases, and social engineering attacks. Email patterns also reveal organizational naming conventions useful for generating comprehensive employee email lists.

## Classification
- **MITRE ATT&CK:** T1589.002 (Email Addresses), T1598 (Phishing for Information)
- **Phase:** Reconnaissance
- **Risk Level:** Passive (public source queries only)
- **Prerequisites:** Target domain name, organization name

## Detection Methodology

### 1. Search Engine Enumeration
Mine search engines for email addresses in indexed pages:
- Google: `"@target.com"`, `site:target.com email`, `"target.com" filetype:pdf`
- Bing: `"@target.com"`, `site:target.com "contact"`
- Yahoo, DuckDuckGo, Yandex for broader coverage
- Search for common email page patterns: contact pages, team pages, press releases
- Paginate through results (search engines limit initial results)

### 2. Document Metadata Extraction
Extract author emails and metadata from public documents:
- PDF documents: author field, producer, custom properties
- Microsoft Office (DOCX, XLSX, PPTX): author, last modified by, company
- Images (EXIF): photographer email, copyright notice
- Tools: `exiftool`, `metagoofil`, `FOCA`
- Download documents from target website and job boards
- Search for documents: `site:target.com filetype:pdf OR filetype:docx`

### 3. Social Media Mining
Extract emails from social media platforms:
- LinkedIn profiles and company pages (public profiles)
- Twitter/X bios and tweets mentioning `@target.com`
- GitHub commit history (`git log --format='%ae'`)
- Stack Overflow profiles and answers
- Forum signatures and mailing list archives
- Speaker bios from conference talk listings

### 4. Website Crawling
Spider the target website for email references:
- Contact pages, about pages, team pages, footer sections
- HTML source code comments
- JavaScript files containing email addresses
- Linked PDFs and downloadable documents
- Privacy policy and terms of service pages
- Press release and news sections
- Job listing pages (hiring manager contacts)

### 5. Breach Database Correlation
Cross-reference discovered emails with known breaches:
- Have I Been Pwned (HIBP) API for breach status
- Identify which breaches exposed target employees
- Determine credential exposure scope (password, hash, personal data)
- Assess organizational breach impact
- Note: only use authorized breach lookup services

### 6. Email Pattern Inference
Deduce the organization's email format from known addresses:
- Common patterns:
  - `first.last@target.com` (most common)
  - `flast@target.com`
  - `firstl@target.com`
  - `first_last@target.com`
  - `first@target.com`
  - `last.first@target.com`
- Validate pattern using mail server verification (SMTP VRFY, RCPT TO)
- Generate full employee email list from LinkedIn employee names

### 7. Email Validation
Verify that discovered emails are deliverable:
- DNS MX record check (domain accepts email)
- SMTP connection test (without sending email)
- SMTP RCPT TO verification (if server supports it)
- Catch-all detection (does the server accept all addresses)
- Note: aggressive validation may alert the target

## Tool Usage

### theHarvester
```bash
# Harvest emails from all sources
theHarvester -d target.com -b all -l 500

# Specific sources for email focus
theHarvester -d target.com -b google,bing,linkedin,yahoo,baidu

# Deep search with DNS brute force
theHarvester -d target.com -b all -c -l 1000

# Output to file
theHarvester -d target.com -b all -f harvest_results

# HTML report
theHarvester -d target.com -b all -f report.html

# Search specific source
theHarvester -d target.com -b linkedin -l 300

# Include Shodan results
theHarvester -d target.com -b shodan

# Limit results per source
theHarvester -d target.com -b google -l 200 -S 0
```

### hunter.io API
```bash
# Domain search (find all emails for domain)
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY" \
  | jq '.data.emails[].value'

# Email finder (find specific person's email)
curl -s "https://api.hunter.io/v2/email-finder?domain=target.com&first_name=John&last_name=Doe&api_key=YOUR_KEY" \
  | jq '.data.email'

# Email verification
curl -s "https://api.hunter.io/v2/email-verifier?email=john@target.com&api_key=YOUR_KEY" \
  | jq '.data.status'

# Get email count for domain
curl -s "https://api.hunter.io/v2/email-count?domain=target.com" \
  | jq '.data'

# Bulk domain search with pagination
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&limit=100&offset=0&api_key=YOUR_KEY"
```

### phonebook.cz
```bash
# Query phonebook.cz via IntelX API
curl -s "https://2.intelx.io/phonebook/search" \
  -H "x-key: YOUR_API_KEY" \
  -d '{"term":"target.com","buckets":[],"lookuplevel":0,"maxresults":100,"timeout":0,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}'

# Manual browser query (no API required)
# Navigate to https://phonebook.cz and search for @target.com
# Export results as CSV/JSON
```

### metagoofil (document metadata)
```bash
# Download and extract metadata from documents
metagoofil -d target.com -t pdf,docx,xlsx,pptx -l 100 -o ./downloads -f results.html

# Extract from specific file types
metagoofil -d target.com -t pdf -l 50 -o ./pdfs

# Increase search depth
metagoofil -d target.com -t pdf,docx -l 200 -o ./docs -f report.html
```

### exiftool (metadata extraction)
```bash
# Extract metadata from downloaded files
exiftool -r ./downloads/ | grep -i "author\|email\|creator\|producer"

# JSON output for parsing
exiftool -json ./downloads/*.pdf | jq '.[].Author'

# Extract all metadata fields
exiftool -a -u ./downloads/document.pdf
```

### SMTP email verification
```bash
# Check MX records
dig +short MX target.com

# Manual SMTP verification (use responsibly)
# Connect to mail server
ncat mail.target.com 25
# EHLO test.com
# MAIL FROM:<test@test.com>
# RCPT TO:<user@target.com>
# Response 250 = exists, 550 = does not exist

# Automated with smtp-user-enum
smtp-user-enum -M RCPT -U users.txt -D target.com -t mail.target.com
```

## Output Analysis Tips
- **Pattern validation:** Once you have 5+ confirmed emails, the naming pattern is reliable. Generate the full list using employee names from LinkedIn.
- **Role-based emails:** Addresses like `admin@`, `support@`, `info@`, `security@`, `it@` are high-value targets for social engineering and service account attacks.
- **Breach prioritization:** Employees found in breaches with password exposure are prime targets for credential stuffing on corporate services (VPN, OWA, SSO).
- **Catch-all domains:** If the mail server accepts all addresses (catch-all), SMTP verification is unreliable. Rely on other confirmation methods.
- **Document metadata gold:** Document metadata often reveals internal usernames, system names, and software versions alongside email addresses.
- **Deduplication:** Combine results from all sources and deduplicate. Different sources may format the same email differently (case, aliases).
- **Temporal analysis:** Recent emails (from current job postings, recent press releases) are more likely to be active accounts.

## Evidence Collection
- Complete email list with source attribution for each address
- Email naming pattern analysis and confidence level
- Breach correlation results per email (redact passwords)
- Document metadata findings (authors, internal usernames)
- MX record configuration and mail server identification
- Email validation results (verified, unverifiable, catch-all)
- Total email count and organizational coverage estimate
- Tools used and data sources queried
