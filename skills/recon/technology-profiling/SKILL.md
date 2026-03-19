# Technology Stack Profiling

## Overview
Technology stack profiling identifies the complete set of technologies powering a target application, including programming languages, frameworks, databases, web servers, third-party components, JavaScript libraries, and their specific versions. Accurate profiling enables targeted vulnerability research, exploit selection, and attack planning based on known weaknesses in each identified technology.

## Classification
- **MITRE ATT&CK:** T1592.004 (Client Configurations), T1592.002 (Software)
- **Phase:** Reconnaissance
- **Risk Level:** Low (passive analysis and minimal HTTP requests)
- **Prerequisites:** Target URL, HTTP/HTTPS access

## Detection Methodology

### 1. Language Detection
Identify the server-side programming language:
- **File extensions:** `.php`, `.asp`, `.aspx`, `.jsp`, `.py`, `.rb`, `.pl`
- **Response headers:** `X-Powered-By: PHP/8.2`, `X-AspNet-Version`
- **Session cookies:** `PHPSESSID` (PHP), `JSESSIONID` (Java), `ASP.NET_SessionId` (.NET), `connect.sid` (Node.js), `_rails_session` (Ruby on Rails)
- **Default error pages:** Each language has distinct error formatting
- **URL patterns:** path-based routing (modern frameworks) vs. query string routing
- **Case sensitivity:** case-sensitive paths suggest Linux/Apache/Nginx

### 2. Framework Version Detection
Pinpoint the exact framework and version:
- **HTTP headers:** `X-Powered-By: Express`, `X-Django-Version`
- **HTML meta tags:** `<meta name="generator" content="WordPress 6.5">`
- **Default files:** `/web.config` (ASP.NET), `/.htaccess` (Apache), `/manage.py` (Django)
- **Static asset paths:** `/static/admin/` (Django), `/_next/` (Next.js), `/assets/` (Rails)
- **JavaScript globals:** `__NEXT_DATA__` (Next.js), `__NUXT__` (Nuxt), `Drupal.settings`
- **API response structure:** GraphQL introspection, REST error formats
- **CHANGELOG/VERSION files:** Many CMS expose version files at known paths

### 3. Database Fingerprinting
Determine the database backend:
- **Error messages:** SQL syntax errors reveal database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Default ports:** 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 1521 (Oracle), 27017 (MongoDB), 6379 (Redis)
- **Connection strings in source:** JDBC URLs, MongoDB URIs, Redis URLs
- **ORM indicators:** SQLAlchemy (Python), ActiveRecord (Ruby), Hibernate (Java), Entity Framework (.NET), Prisma/Sequelize (Node.js)
- **Admin interfaces:** phpMyAdmin (MySQL), pgAdmin (PostgreSQL), Adminer (multi-DB), Mongo Express (MongoDB)

### 4. Third-Party Component Identification
Discover external services and integrations:
- **CDN detection:** Cloudflare (`cf-ray` header), Akamai, Fastly, AWS CloudFront
- **Analytics:** Google Analytics (`UA-` or `G-` tracking ID), Mixpanel, Segment
- **Payment:** Stripe.js, PayPal SDK, Square includes
- **Authentication:** Auth0, Okta, Firebase Auth
- **Error tracking:** Sentry DSN, Rollbar, Bugsnag
- **Chat/Support:** Intercom, Zendesk, Drift widget
- **Marketing:** HubSpot, Marketo, Pardot tracking scripts
- **Maps:** Google Maps API key exposure

### 5. JavaScript Library Detection
Identify client-side libraries and their versions:
- **Direct file references:** `jquery-3.6.0.min.js`, `react.production.min.js`
- **CDN URLs:** `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`
- **Bundle analysis:** Webpack chunk names, source maps
- **Global variables:** `jQuery.fn.jquery`, `React.version`, `angular.version`
- **Package managers:** `package.json`, `yarn.lock`, `package-lock.json` exposure
- **Known vulnerable versions:** Cross-reference with Snyk, npm audit, retire.js databases

### 6. Web Server and Proxy Detection
Identify the HTTP server stack:
- **Server header:** `Apache/2.4.52`, `nginx/1.22.0`, `Microsoft-IIS/10.0`
- **Response behavior:** trailing slash handling, case sensitivity, directory listing style
- **Default error pages:** each server has distinctive 404/500 pages
- **Proxy indicators:** `Via` header, `X-Forwarded-For`, `X-Cache`, `X-Varnish`
- **Load balancer detection:** Response variation across requests, sticky session cookies

### 7. Infrastructure and Hosting Detection
Determine where the application is hosted:
- **IP WHOIS:** Identify hosting provider (AWS, Azure, GCP, DigitalOcean)
- **ASN lookup:** Map IP to autonomous system number and organization
- **Cloud metadata:** Response headers indicating cloud services
- **SSL certificate issuer:** Let's Encrypt (likely Linux), DigiCert (enterprise), AWS ACM (AWS-hosted)
- **DNS providers:** Route 53 (AWS), Cloud DNS (GCP), Azure DNS

## Tool Usage

### Wappalyzer CLI
```bash
# Using the npm package
npx wappalyzer https://target.com

# Pretty-printed output
npx wappalyzer https://target.com --pretty

# Multiple URLs
npx wappalyzer https://target.com https://app.target.com --pretty

# JSON output for automated processing
npx wappalyzer https://target.com > tech_profile.json

# Using webtech (alternative Wappalyzer-compatible CLI)
webtech -u https://target.com
webtech -u https://target.com --json
webtech -ul urls.txt --json
```

### BuiltWith (API)
```bash
# BuiltWith API query
curl -s "https://api.builtwith.com/v21/api.json?KEY=YOUR_KEY&LOOKUP=target.com" \
  | jq '.Results[].Result.Paths[].Technologies[]'

# Free tier: basic technology detection
curl -s "https://api.builtwith.com/free1/api.json?KEY=YOUR_KEY&LOOKUP=target.com"

# Extract specific technology categories
curl -s "https://api.builtwith.com/v21/api.json?KEY=YOUR_KEY&LOOKUP=target.com" \
  | jq '.Results[].Result.Paths[].Technologies[] | select(.Categories[] | contains("Web Server"))'
```

### retire.js
```bash
# Scan a website for vulnerable JavaScript libraries
retire --js --jspath /path/to/js/files

# Scan a URL
retire --js --jsuri https://target.com/js/

# Scan node_modules
retire --node --path /path/to/project

# JSON output
retire --js --jspath /path/to/js/ --outputformat json --outputpath results.json

# Verbose mode
retire --js --jspath /path/to/js/ --verbose

# Scan from URL list
retire --js --jsuri https://target.com/static/js/main.js
retire --js --jsuri https://target.com/static/js/vendor.js
```

### httpx (technology detection)
```bash
# Tech detection with httpx
httpx -l urls.txt -tech-detect -json -o results.json

# Full profiling
httpx -l urls.txt -tech-detect -status-code -title -server \
  -content-type -follow-redirects -json -o profile.json

# Header extraction
httpx -l urls.txt -include-response-header -json -o headers.json

# Favicon hash (for Shodan correlation)
httpx -l urls.txt -favicon -hash md5 -json -o favicon.json

# Content-Length and response time
httpx -l urls.txt -content-length -response-time -json
```

### Manual profiling techniques
```bash
# Inspect response headers
curl -sI https://target.com | grep -i "server\|powered\|version\|x-"

# Check for exposed package files
curl -s https://target.com/package.json 2>/dev/null | jq '.dependencies'
curl -s https://target.com/composer.json 2>/dev/null | jq '.require'
curl -s https://target.com/Gemfile 2>/dev/null
curl -s https://target.com/requirements.txt 2>/dev/null
curl -s https://target.com/pom.xml 2>/dev/null

# Check for source maps
curl -sI https://target.com/static/js/main.js | grep -i "sourcemap"
curl -s https://target.com/static/js/main.js.map 2>/dev/null | head -c 200

# Check known CMS paths
curl -s -o /dev/null -w "%{http_code}" https://target.com/wp-login.php
curl -s -o /dev/null -w "%{http_code}" https://target.com/administrator/
curl -s -o /dev/null -w "%{http_code}" https://target.com/user/login
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/login

# Extract JavaScript library versions from page source
curl -s https://target.com | grep -oP 'jquery[.-][\d.]+'
curl -s https://target.com | grep -oP 'react[.-][\d.]+'
curl -s https://target.com | grep -oP 'angular[.-][\d.]+'
curl -s https://target.com | grep -oP 'bootstrap[.-][\d.]+'

# Check robots.txt for technology hints
curl -s https://target.com/robots.txt
```

## Output Analysis Tips
- **Version to CVE mapping:** Every identified version should be cross-referenced with CVE databases (NVD, Snyk, GitHub Advisories). Even minor version differences can determine vulnerability.
- **End-of-life software:** Check if detected versions are past their end-of-life date. EOL software receives no security patches and is a guaranteed finding.
- **JavaScript library vulnerabilities:** retire.js and Snyk databases track known vulnerable client-side libraries. Common findings include outdated jQuery, Angular 1.x, and Bootstrap 3.x.
- **Source map exposure:** Exposed `.map` files allow full source code reconstruction. Check for `//# sourceMappingURL=` in JavaScript bundles.
- **Package file exposure:** `package.json`, `composer.json`, `Gemfile`, and `requirements.txt` reveal exact dependency versions. These are high-priority findings.
- **Technology inconsistencies:** Mismatched technologies (e.g., ASP.NET header on a Linux server) may indicate reverse proxy setups or header spoofing.
- **Deprecated frameworks:** Detection of deprecated frameworks (AngularJS 1.x, Python 2, Ruby 2.x) indicates a maintenance-deprived application likely to have unpatched vulnerabilities.
- **Build artifacts:** Webpack stats, next-data, and similar build artifacts can reveal internal API routes, environment variables, and application structure.
- **Third-party service exposure:** Analytics IDs (Google Analytics UA-codes), Sentry DSNs, and API keys in client-side code can reveal organizational information or be directly exploitable.

## Evidence Collection
- Complete technology stack matrix (component, version, status, known CVEs)
- HTTP response headers from primary endpoints
- JavaScript library inventory with version and vulnerability status
- Database technology identification with detection method
- Third-party service integrations with exposed identifiers
- Package/dependency file contents if publicly accessible
- Source map availability assessment
- End-of-life and deprecated technology findings
- Infrastructure hosting details (cloud provider, CDN, DNS)
- Tool output in JSON format for automated vulnerability correlation
- Recommendations prioritized by severity and exploitability
