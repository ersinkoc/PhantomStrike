# Directory and File Bruteforcing

## Overview
Directory and file bruteforcing discovers hidden endpoints, configuration files, backup archives, admin panels, and unlinked resources on web servers. By systematically requesting paths from wordlists, this technique reveals content not accessible through normal navigation, often exposing sensitive data or administrative interfaces.

## Classification
- **MITRE ATT&CK:** T1595.003 (Wordlist Scanning), T1083 (File and Directory Discovery)
- **Phase:** Reconnaissance / Scanning
- **Risk Level:** Medium (generates significant HTTP traffic, may trigger alerts)
- **Prerequisites:** Target URL, HTTP access, appropriate wordlists

## Detection Methodology

### 1. Wordlist Selection
Choose wordlists appropriate to the target technology:
- **General purpose:** `raft-medium-directories.txt`, `directory-list-2.3-medium.txt` (SecLists)
- **Technology-specific:**
  - PHP: `PHP.fuzz.txt`, common PHP file patterns
  - ASP.NET: `IIS.fuzz.txt`, `.aspx` / `.ashx` / `.asmx` patterns
  - Java: `spring-boot.txt`, `/WEB-INF/`, `/META-INF/` paths
  - Node.js: `nodejs.txt`, `.env`, `package.json` paths
  - Python/Django: `django.txt`, `flask.txt` patterns
- **CMS-specific:** WordPress, Drupal, Joomla-targeted wordlists
- **API paths:** `api-endpoints.txt`, versioned API paths (`/api/v1/`, `/api/v2/`)
- **Backup files:** `backup-files.txt`, common backup extensions (.bak, .old, .orig, .swp)
- **Custom wordlists:** Build from `robots.txt`, `sitemap.xml`, JavaScript files, and initial crawl results

### 2. Extension Fuzzing
Append file extensions to wordlist entries:
- Common web: `.html`, `.htm`, `.php`, `.asp`, `.aspx`, `.jsp`, `.py`
- Configuration: `.conf`, `.config`, `.cfg`, `.ini`, `.yaml`, `.yml`, `.json`, `.xml`, `.toml`
- Backup/temp: `.bak`, `.backup`, `.old`, `.orig`, `.save`, `.swp`, `.tmp`, `~`
- Archives: `.zip`, `.tar.gz`, `.rar`, `.7z`, `.gz`, `.sql.gz`
- Source code: `.git`, `.svn`, `.env`, `.htaccess`, `web.config`
- Logs: `.log`, `.txt`, `.out`

### 3. Recursive Scanning
When directories are discovered, scan recursively into them:
- Set maximum recursion depth to avoid infinite loops (3-5 levels typical)
- Focus recursive scanning on high-value directories (`/admin/`, `/api/`, `/backup/`, `/config/`)
- Adjust wordlist for subdirectory context (use smaller lists for deeper levels)

### 4. Virtual Host Discovery
Brute force virtual hostnames on the same IP:
- Send requests with different `Host` headers
- Compare response size/content against baseline to identify valid vhosts
- Check for both HTTP and HTTPS on each discovered vhost
- Common patterns: `admin.target.com`, `dev.target.com`, `staging.target.com`, `internal.target.com`

### 5. Parameter Discovery
Find hidden URL parameters on known endpoints:
- Brute force GET/POST parameter names
- Test for debug parameters (`debug=1`, `test=1`, `verbose=true`)
- API parameter enumeration

### 6. Response Filtering
Eliminate false positives through intelligent filtering:
- Filter by response status code (exclude 404, focus on 200, 301, 302, 403)
- Filter by response size (exclude common error page sizes)
- Filter by word count or line count in response body
- Filter by response content (exclude pages containing "not found" text)
- Watch for custom 404 pages that return HTTP 200

## Tool Usage

### ffuf
```bash
# Basic directory brute force
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# With extension fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.conf

# Filter by status code
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# Filter out specific response sizes (custom 404 pages)
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 4242

# Filter by word count
ffuf -u https://target.com/FUZZ -w wordlist.txt -fw 12

# Recursive scanning
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3

# Virtual host discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs 4242

# POST parameter fuzzing
ffuf -u https://target.com/login -X POST -d "username=admin&FUZZ=test" -w params.txt -fs 4242

# GET parameter discovery
ffuf -u "https://target.com/page?FUZZ=value" -w params.txt -fs 4242

# Two-position fuzzing (directory + extension)
ffuf -u https://target.com/FUZZ1FUZZ2 -w wordlist.txt:FUZZ1 -w extensions.txt:FUZZ2

# With authentication
ffuf -u https://target.com/FUZZ -w wordlist.txt -H "Cookie: session=abc123"
ffuf -u https://target.com/FUZZ -w wordlist.txt -H "Authorization: Bearer TOKEN"

# Rate limiting
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 100

# JSON output
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json

# Auto-calibration (auto-detect and filter error responses)
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac
```

### gobuster
```bash
# Directory mode
gobuster dir -u https://target.com -w wordlist.txt -t 50

# With extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,html,txt,bak

# Status code filter
gobuster dir -u https://target.com -w wordlist.txt -s 200,301,302,403

# DNS subdomain brute force
gobuster dns -d target.com -w subdomains.txt -t 50

# Virtual host enumeration
gobuster vhost -u https://target.com -w subdomains.txt

# With authentication cookie
gobuster dir -u https://target.com -w wordlist.txt -c "session=abc123"

# Expanded mode (show full URL)
gobuster dir -u https://target.com -w wordlist.txt -e

# Output to file
gobuster dir -u https://target.com -w wordlist.txt -o results.txt

# With custom User-Agent
gobuster dir -u https://target.com -w wordlist.txt -a "Mozilla/5.0"

# Wildcard detection and forcing
gobuster dir -u https://target.com -w wordlist.txt --wildcard
```

### feroxbuster
```bash
# Default recursive scan
feroxbuster -u https://target.com -w wordlist.txt

# With extensions and threads
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt -t 100

# Set recursion depth
feroxbuster -u https://target.com -w wordlist.txt --depth 3

# Filter by status code
feroxbuster -u https://target.com -w wordlist.txt -C 404,403

# Filter by response size
feroxbuster -u https://target.com -w wordlist.txt -S 4242

# Auto-filter and smart mode
feroxbuster -u https://target.com -w wordlist.txt --smart --auto-filter

# JSON output
feroxbuster -u https://target.com -w wordlist.txt -o results.json --json

# With proxy (Burp Suite)
feroxbuster -u https://target.com -w wordlist.txt -p http://127.0.0.1:8080

# Resume interrupted scan
feroxbuster --resume-from state.json

# Extract links from responses and add to scan
feroxbuster -u https://target.com -w wordlist.txt --extract-links
```

### dirb
```bash
# Basic scan with default wordlist
dirb https://target.com

# Custom wordlist
dirb https://target.com /usr/share/seclists/Discovery/Web-Content/common.txt

# With extensions
dirb https://target.com -X .php,.html,.txt

# With authentication
dirb https://target.com -H "Cookie: session=abc123"

# Ignore specific status code
dirb https://target.com -N 403

# Case-insensitive search
dirb https://target.com -z 200

# Output to file
dirb https://target.com -o results.txt
```

### dirsearch
```bash
# Basic scan
dirsearch -u https://target.com

# With extensions
dirsearch -u https://target.com -e php,html,txt,bak

# Recursive scan
dirsearch -u https://target.com -r -R 3

# Custom wordlist
dirsearch -u https://target.com -w wordlist.txt

# Exclude status codes
dirsearch -u https://target.com --exclude-status 404,403

# JSON output
dirsearch -u https://target.com --format json -o results.json

# With proxy
dirsearch -u https://target.com --proxy http://127.0.0.1:8080

# Threads and delay
dirsearch -u https://target.com -t 50 --delay 0.1
```

## Output Analysis Tips
- **Custom 404 detection:** Before scanning, request a known-nonexistent path (e.g., `/thispagedoesnotexist12345`) and note the response size and status code. Filter that size from results.
- **403 responses are valuable:** Forbidden responses confirm the path exists. Attempt bypass techniques: path traversal (`../`), URL encoding, adding trailing slash, changing HTTP method, header manipulation.
- **Backup file priority:** Files like `.bak`, `.old`, `web.config.bak`, `.env` often contain credentials, database connection strings, or API keys.
- **Source control exposure:** Discovery of `/.git/`, `/.svn/`, `/.hg/` allows full source code recovery using tools like `git-dumper` or `svn-extractor`.
- **Rate limit awareness:** If responses become inconsistent or start returning 429 status codes, reduce scan speed. Implement delays between requests.
- **Technology-driven wordlists:** After fingerprinting the technology stack, switch to technology-specific wordlists for higher hit rates.
- **API versioning:** If `/api/v1/` is found, always check `/api/v2/`, `/api/v3/`, and `/api/internal/` since older or internal API versions often lack security controls.

## Evidence Collection
- Complete directory/file listing with HTTP status codes and response sizes
- Notable discoveries: admin panels, config files, backup archives, source code
- Wordlists used and scan parameters (threads, extensions, filters)
- Content of discovered sensitive files (redact credentials)
- Screenshots of admin panels or exposed interfaces
- Virtual host discovery results with response differentiation
- Tool output in parseable format (JSON) for cross-referencing
