# OWASP Top 10 (2021) Testing Guide

## Overview
The OWASP Top 10 is the industry-standard reference for the most critical web application security risks. This guide provides a structured testing methodology for each category, mapping risks to specific tools, techniques, and verification steps. Use this as a comprehensive checklist during web application penetration tests to ensure complete coverage.

## A01:2021 - Broken Access Control

### Risk Rating
- **Prevalence:** 94% of applications tested
- **CWE Mapped:** CWE-200, CWE-201, CWE-352, CWE-639, CWE-862, CWE-863

### Testing Methodology
```
1. IDOR Testing
   - Enumerate resource IDs (sequential, UUID, encoded)
   - Access resources as different users — swap tokens/sessions
   - Test horizontal access: User A accessing User B data
   - Test vertical access: regular user accessing admin functions

2. Privilege Escalation
   - Modify role/permission parameters in requests
   - Access admin endpoints with regular user credentials
   - Test forced browsing to restricted pages (/admin, /debug, /config)

3. CORS Misconfiguration
   - Send request with Origin: https://evil.com — check reflected origin
   - Test for Access-Control-Allow-Credentials: true with wildcard origin

4. Directory Traversal
   - Test path parameters with ../../etc/passwd
   - Test file download endpoints with path manipulation
```

**Tools:** Burp Suite (Autorize extension), ffuf, custom scripts for IDOR automation

## A02:2021 - Cryptographic Failures

### Risk Rating
- **CWE Mapped:** CWE-259, CWE-327, CWE-328, CWE-330, CWE-331

### Testing Methodology
```
1. Transport Security
   - Test for TLS version support (TLS 1.0/1.1 should be disabled)
   - Check cipher suite strength — reject weak ciphers (RC4, DES, export)
   - Verify HSTS header with long max-age and includeSubDomains
   - Test for mixed content (HTTPS page loading HTTP resources)

2. Data at Rest
   - Check for sensitive data in plaintext (database, config files, logs)
   - Verify password hashing algorithm (bcrypt/scrypt/argon2, not MD5/SHA1)
   - Check for hardcoded encryption keys in source code

3. Weak Cryptography
   - Identify use of deprecated algorithms (MD5, SHA1, DES, RC4)
   - Check for ECB mode in block ciphers
   - Verify random number generation uses CSPRNG
```

**Tools:** testssl.sh, sslyze, nmap ssl-enum-ciphers, Burp Scanner

## A03:2021 - Injection

### Risk Rating
- **CWE Mapped:** CWE-79 (XSS), CWE-89 (SQLi), CWE-73, CWE-77, CWE-78

### Testing Methodology
```
1. SQL Injection — test all input points with ' " ; -- payloads
2. XSS — inject <script>alert(1)</script> and event handler payloads
3. Command Injection — test with ; | ` $() in system-interacting parameters
4. LDAP Injection — test with * )( | payloads on directory lookups
5. Template Injection — test with {{7*7}} ${7*7} payloads
6. Header Injection — test CRLF injection in redirect/header-reflected params
```

**Tools:** sqlmap, XSStrike, Commix, Burp Scanner, tplmap

## A04:2021 - Insecure Design

### Testing Methodology
```
1. Business Logic Flaws
   - Test purchase flows for price manipulation
   - Test multi-step processes for step-skipping
   - Test rate limiting on critical functions (login, OTP, registration)

2. Missing Security Controls
   - Check for CAPTCHA on brute-forceable forms
   - Verify account lockout mechanisms
   - Test password reset flow for token predictability

3. Threat Modeling Review
   - Identify trust boundaries and data flow
   - Verify security controls at each boundary
   - Check for race conditions in concurrent operations
```

**Tools:** Burp Intruder, custom scripts, Turbo Intruder

## A05:2021 - Security Misconfiguration

### Testing Methodology
```
1. Default Configurations
   - Test for default credentials on admin interfaces
   - Check for default error pages revealing framework/version
   - Test for unnecessary HTTP methods (PUT, DELETE, TRACE)

2. Cloud/Server Misconfig
   - S3 bucket permissions, Azure blob access
   - Directory listing enabled
   - Unnecessary features enabled (WebDAV, status pages)

3. HTTP Headers
   - Verify: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy
   - Check for missing Referrer-Policy, Permissions-Policy
   - Verify cookie flags: Secure, HttpOnly, SameSite
```

**Tools:** Nikto, nuclei, curl, SecurityHeaders.com, ScoutSuite (cloud)

## A06:2021 - Vulnerable and Outdated Components

### Testing Methodology
```
1. Component Identification
   - Fingerprint web server, application framework, JavaScript libraries
   - Check package manifests (package.json, pom.xml, requirements.txt)
   - Identify client-side libraries via source/headers (jQuery, Angular version)

2. Vulnerability Lookup
   - Search CVE databases for identified component versions
   - Cross-reference with exploit databases (ExploitDB, GitHub advisories)
   - Run dependency scanners against project manifests

3. Verification
   - Confirm exploitability of discovered CVEs in context
   - Test known exploit PoCs against target components
```

**Tools:** retire.js, npm audit, OWASP Dependency-Check, Snyk, nuclei CVE templates

## A07:2021 - Identification and Authentication Failures

### Testing Methodology
```
1. Password Policy
   - Test minimum length, complexity, common password rejection
   - Test for username enumeration via error messages or timing

2. Session Management
   - Verify session ID entropy and length
   - Test session fixation — does session change after login?
   - Test session timeout and logout invalidation
   - Check for concurrent session controls

3. Multi-Factor Authentication
   - Test for MFA bypass via direct API calls
   - Check if MFA can be disabled without re-authentication
   - Test backup code generation and validation
```

**Tools:** Burp Suite, Hydra, custom wordlists, jwt_tool

## A08:2021 - Software and Data Integrity Failures

### Testing Methodology
```
1. Deserialization
   - Identify serialized data in parameters, cookies, headers
   - Test Java (ysoserial), PHP (phpggc), .NET (ysoserial.net)
   - Check Content-Type headers for serialization formats

2. CI/CD Pipeline
   - Check for unsigned code deployments
   - Verify dependency integrity (checksums, lockfiles)
   - Test for dependency confusion attacks

3. Auto-Update Mechanisms
   - Verify update source authentication
   - Check for integrity verification of downloaded updates
```

**Tools:** ysoserial, phpggc, Burp Java Deserialization Scanner

## A09:2021 - Security Logging and Monitoring Failures

### Testing Methodology
```
1. Logging Coverage
   - Verify authentication events are logged (login, failure, lockout)
   - Check that access control failures generate alerts
   - Test if injection attempts trigger monitoring

2. Log Integrity
   - Test for log injection — inject CRLF or log format strings
   - Verify logs are tamper-protected (append-only, separate storage)
   - Check log rotation and retention policies

3. Alerting
   - Trigger brute-force attack — verify alert generation
   - Test if anomalous access patterns are detected
```

**Tools:** Manual testing, Burp Intruder (for triggering alerts)

## A10:2021 - Server-Side Request Forgery (SSRF)

### Testing Methodology
```
1. Identify SSRF Vectors
   - URL parameters that fetch remote resources
   - File import functions (URL-based)
   - Webhook configurations, PDF generators
   - API integrations that accept URLs

2. Exploitation
   - Access internal services: http://127.0.0.1, http://169.254.169.254
   - Port scanning internal network via response timing/content
   - Access cloud metadata endpoints (AWS, GCP, Azure)
   - Use bypass techniques: IP encoding, DNS rebinding, redirects

3. Impact Assessment
   - Cloud credential theft via metadata service
   - Internal service access and data exfiltration
   - Remote code execution via internal services
```

**Tools:** Burp Collaborator, SSRFmap, interactsh

## Comprehensive Testing Checklist
```
[ ] A01 — IDOR tested on all resource endpoints
[ ] A01 — Forced browsing to admin/config paths
[ ] A01 — CORS policy validated
[ ] A02 — TLS configuration scanned
[ ] A02 — Sensitive data storage reviewed
[ ] A03 — All input points tested for injection
[ ] A04 — Business logic flaws assessed
[ ] A04 — Rate limiting verified
[ ] A05 — Default credentials tested
[ ] A05 — Security headers checked
[ ] A06 — Components identified and CVEs checked
[ ] A07 — Authentication and session management tested
[ ] A07 — Username enumeration tested
[ ] A08 — Deserialization points tested
[ ] A09 — Logging coverage verified
[ ] A10 — SSRF vectors tested with internal targets
```

## Evidence Collection
- Map each finding to its OWASP Top 10 category for report clarity
- Include CWE identifiers alongside each finding
- Document proof-of-concept for each exploited vulnerability
- Note which automated tools detected vs missed each finding
- Record severity based on actual impact in context, not generic CVSS alone
