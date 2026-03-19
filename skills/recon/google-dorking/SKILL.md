# Google Dorking

## Overview
Google dorking uses advanced search operators to discover sensitive information, exposed files, misconfigured services, and hidden pages indexed by Google. By crafting precise queries, testers can locate admin panels, credential files, directory listings, database dumps, and other high-value targets without directly interacting with the target infrastructure.

## Classification
- **MITRE ATT&CK:** T1593.002 (Search Engines)
- **Phase:** Reconnaissance
- **Risk Level:** Passive (queries Google, not the target directly)
- **Prerequisites:** Target domain name, organization name, or IP range

## Detection Methodology

### 1. Core Search Operators
Master these operators for precision targeting:

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Restrict to domain | `site:target.com` |
| `inurl:` | Search URL path | `inurl:admin` |
| `intitle:` | Search page title | `intitle:"index of"` |
| `intext:` | Search body text | `intext:"password"` |
| `filetype:` | Search file type | `filetype:pdf` |
| `ext:` | File extension | `ext:sql` |
| `cache:` | Google cached version | `cache:target.com` |
| `link:` | Pages linking to URL | `link:target.com` |
| `related:` | Similar sites | `related:target.com` |
| `info:` | Page information | `info:target.com` |
| `-` | Exclude term | `site:target.com -www` |
| `""` | Exact phrase | `"database error"` |
| `*` | Wildcard | `site:*.target.com` |
| `OR` / `|` | Boolean OR | `filetype:pdf OR filetype:docx` |
| `before:` | Date restriction | `before:2024-01-01` |
| `after:` | Date restriction | `after:2023-01-01` |

### 2. Sensitive File Discovery
Find configuration files, backups, and credentials:
```
site:target.com filetype:env
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:conf
site:target.com filetype:bak
site:target.com filetype:cfg
site:target.com filetype:ini
site:target.com filetype:xml intext:"password"
site:target.com filetype:yaml
site:target.com filetype:json intext:"api_key"
site:target.com filetype:csv intext:"email"
site:target.com ext:pem OR ext:key OR ext:crt
site:target.com filetype:xls intext:"password"
site:target.com filetype:doc intext:"confidential"
"target.com" filetype:sql "INSERT INTO"
"target.com" filetype:env "DB_PASSWORD"
```

### 3. Admin Panel Discovery
Locate administrative interfaces:
```
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:administrator
site:target.com inurl:dashboard
site:target.com inurl:cpanel
site:target.com inurl:wp-admin
site:target.com inurl:phpmyadmin
site:target.com intitle:"admin" inurl:login
site:target.com inurl:manage
site:target.com inurl:portal
site:target.com inurl:console
site:target.com inurl:webmail
```

### 4. Exposed Databases and Storage
Find database interfaces and data stores:
```
site:target.com inurl:phpmyadmin
site:target.com intitle:"phpMyAdmin" "Welcome to phpMyAdmin"
site:target.com inurl:adminer
site:target.com intitle:"MongoDB" inurl:28017
site:target.com intitle:"Elasticsearch" inurl:9200
site:target.com inurl:_kibana
site:target.com intitle:"Redis" inurl:info
site:target.com intitle:"MinIO" inurl:login
site:target.com inurl:graphql intitle:"GraphiQL"
```

### 5. Directory Listings
Find open directory indexes:
```
site:target.com intitle:"index of"
site:target.com intitle:"index of /" "parent directory"
site:target.com intitle:"index of" "backup"
site:target.com intitle:"index of" ".git"
site:target.com intitle:"index of" "wp-content"
site:target.com intitle:"directory listing"
site:target.com intitle:"index of" inurl:ftp
```

### 6. Login Pages
Discover authentication endpoints:
```
site:target.com inurl:login
site:target.com inurl:signin
site:target.com inurl:auth
site:target.com inurl:sso
site:target.com intitle:"login" inurl:https
site:target.com inurl:oauth
site:target.com inurl:saml
site:target.com inurl:forgot-password
site:target.com inurl:register
site:target.com inurl:signup
```

### 7. Error Messages and Debug Information
Find pages leaking technical details:
```
site:target.com "Fatal error" "on line"
site:target.com "Warning:" "mysql_" OR "mysqli_"
site:target.com "Traceback (most recent call last)"
site:target.com "Stack Trace" "System.Web"
site:target.com "Error 500" OR "Internal Server Error"
site:target.com intext:"DEBUG" intext:"True"
site:target.com "Exception in thread" "java.lang"
site:target.com "syntax error" "unexpected"
site:target.com "Warning: include" OR "Warning: require"
site:target.com "ORA-" site:target.com (Oracle errors)
site:target.com "You have an error in your SQL syntax"
```

### 8. Exposed Documents and Data
Find leaked internal documents:
```
site:target.com filetype:pdf "confidential"
site:target.com filetype:pdf "internal use only"
site:target.com filetype:docx "not for distribution"
site:target.com filetype:xlsx "employee"
site:target.com filetype:pptx "roadmap"
site:target.com filetype:pdf "network diagram"
site:target.com filetype:pdf "pentest" OR "assessment"
"target.com" filetype:pdf "salary" OR "compensation"
```

### 9. Infrastructure Discovery
Map network and cloud resources:
```
site:target.com inurl:vpn
site:target.com inurl:remote
site:target.com inurl:citrix
site:target.com inurl:rdweb
site:target.com intitle:"Outlook Web App"
site:target.com intitle:"Cisco" inurl:webvpn
site:*.target.com -www -mail
site:target.com inurl:jenkins
site:target.com inurl:grafana
site:target.com inurl:prometheus
site:target.com intitle:"GitLab"
```

### 10. API and Developer Resources
Find API documentation and endpoints:
```
site:target.com inurl:api
site:target.com inurl:swagger
site:target.com inurl:openapi
site:target.com intitle:"API Documentation"
site:target.com inurl:docs inurl:api
site:target.com inurl:graphql
site:target.com filetype:json inurl:api
site:target.com inurl:postman
site:target.com intitle:"API Reference"
```

## Tool Usage

### Manual Google searching
```
# Perform queries directly in Google search
# Use Incognito/Private mode to avoid personalization
# Paginate through results (Google limits to ~300 results per query)
# Use Google Advanced Search (google.com/advanced_search) for complex queries
# Rotate queries to avoid CAPTCHA rate limiting
```

### Automated dorking with googler
```bash
# Command-line Google search
googler -n 50 "site:target.com filetype:pdf"

# JSON output
googler -n 100 --json "site:target.com inurl:admin"

# With specific country Google
googler -c us -n 50 "site:target.com filetype:env"
```

### GHDB (Google Hacking Database)
```bash
# Use exploit-db.com/google-hacking-database for pre-built dorks
# Categories: Files containing passwords, Sensitive directories,
#             Web server detection, Vulnerable servers,
#             Error messages, Sensitive online shopping info

# Adapt GHDB entries to target:
# Generic: intitle:"index of" "parent directory"
# Targeted: site:target.com intitle:"index of" "parent directory"
```

### DorkSearch / Pagodo
```bash
# pagodo - automate Google dorking
pagodo -d target.com -g dorks.txt -l 100 -o results.json

# Use with curated dork lists from GHDB
```

## Output Analysis Tips
- **Rate limiting:** Google will CAPTCHA or block after too many queries. Space queries apart (5-10 second intervals), use VPN rotation, or split searches across sessions.
- **Cache for deleted content:** Use `cache:` operator to view Google's cached version of pages that have been removed or updated. This often reveals previously exposed sensitive data.
- **Operator stacking:** Combine operators for precision: `site:target.com inurl:admin filetype:php intitle:login` narrows results significantly.
- **Negative operators:** Use `-` to exclude known pages and focus on anomalies: `site:target.com -www -blog -docs` reveals hidden subdomains.
- **Date filtering:** Use `before:` and `after:` to find recently indexed pages or historical content that may have been misconfigured.
- **Results verification:** Always verify Google results by visiting the actual page. Some results may be outdated or no longer accessible.
- **Alternative search engines:** If Google results are limited, try Bing (`site:target.com`), DuckDuckGo, Yandex, and Baidu for different indexed content.
- **Document download priority:** Prioritize downloading found PDFs, DOCX, and XLSX files for metadata extraction (author names, internal paths, software versions).

## Evidence Collection
- Complete list of dork queries executed with result counts
- URLs of discovered sensitive files and admin panels
- Downloaded sensitive documents with metadata extraction results
- Screenshots of exposed directory listings and error pages
- Login page URLs with technology identification
- API documentation endpoints discovered
- Cached page content for removed sensitive data
- Summary of information exposure severity per finding
