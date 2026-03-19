# Mobile API Security Testing

## Overview
Mobile API security testing focuses on intercepting and analyzing the communication between mobile applications and their backend servers. This includes bypassing transport protections, discovering undocumented API endpoints, testing authentication and authorization mechanisms, and identifying data exposure in API responses. Mobile APIs often have weaker security than web counterparts due to assumptions about client-side control.

## Classification
- **CWE:** CWE-319 (Cleartext Transmission), CWE-200 (Exposure of Sensitive Information), CWE-306 (Missing Authentication for Critical Function)
- **OWASP Mobile:** M3 (Insecure Communication), M1 (Improper Platform Usage)
- **OWASP API:** API1-API10 (OWASP API Security Top 10)
- **CVSS Base:** 5.0 - 9.8 (Medium to Critical)

## Methodology

### 1. Traffic Interception Setup
```bash
# Configure mitmproxy as transparent proxy
mitmproxy --mode regular --listen-port 8080

# Install mitmproxy CA certificate on device
# Android: Push cert to /system/etc/security/cacerts/ (rooted)
# iOS: Install via http://mitm.it in Safari, trust in Settings

# Burp Suite setup
# Configure Proxy listener on all interfaces, port 8080
# Export CA cert and install on device
# Set device Wi-Fi proxy to <host_ip>:8080

# For HTTP/2 and gRPC traffic
mitmproxy --mode regular --set http2=true
```

### 2. Certificate Pinning Bypass
Bypass pinning to enable traffic interception:
```bash
# Android — Frida
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# Android — objection
objection -g com.target.app explore
android sslpinning disable

# iOS — objection
objection -g com.target.app explore
ios sslpinning disable

# Android — patch network_security_config.xml
# Decompile APK, modify config to trust user-installed CAs, repackage
```

```xml
<!-- Permissive network_security_config.xml -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

### 3. API Endpoint Discovery
```bash
# Extract endpoints from decompiled source
grep -rEi "https?://|/api/|/v[0-9]/" jadx_output/
grep -rEi "\.get\(|\.post\(|\.put\(|\.delete\(" jadx_output/

# Monitor all traffic and map endpoints
mitmdump -w traffic.flow
# Parse captured traffic for unique endpoints
mitmproxy --mode regular -s endpoint_logger.py

# Identify API framework (REST, GraphQL, gRPC)
# Check for API documentation endpoints
# /swagger.json, /openapi.json, /api-docs, /graphql
curl https://api.target.com/swagger.json
curl https://api.target.com/graphql -d '{"query":"{ __schema { types { name } } }"}'

# Brute-force API paths
ffuf -u https://api.target.com/api/v1/FUZZ -w api_wordlist.txt -mc 200,201,401,403
```

### 4. Authentication Testing
```bash
# Token analysis
# Decode JWT tokens — check claims, algorithm, expiration
echo "<jwt_token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Test token expiration enforcement
# 1. Capture valid token
# 2. Wait for stated expiration
# 3. Replay request with expired token

# Test token revocation
# 1. Authenticate and capture token
# 2. Logout or change password
# 3. Replay request with old token

# Test weak authentication
# - Default credentials on API endpoints
# - API key in URL parameter (visible in logs)
# - Bearer token not validated per-request
# - Missing authentication on admin endpoints
```

### 5. Authorization Testing (BOLA/IDOR)
```bash
# Test Broken Object Level Authorization
# 1. Authenticate as User A, capture request for resource
GET /api/v1/users/1001/profile
Authorization: Bearer <user_a_token>

# 2. Change resource ID, keep same token
GET /api/v1/users/1002/profile
Authorization: Bearer <user_a_token>

# 3. Test across all resource endpoints
# /api/v1/orders/{id}
# /api/v1/documents/{id}
# /api/v1/messages/{id}

# Test Broken Function Level Authorization
# 1. Capture admin endpoint from decompiled source
# 2. Call admin functions with regular user token
POST /api/v1/admin/users
Authorization: Bearer <regular_user_token>
```

### 6. Data Exposure Analysis
```bash
# Capture and analyze API responses for excessive data
# Look for:
# - Internal IDs, database fields
# - Other users' PII in list responses
# - Debug information in error responses
# - Server internals (stack traces, versions)
# - Sensitive fields not needed by mobile client

# mitmproxy script to flag sensitive data
mitmdump -s sensitive_data_detector.py

# Check response headers for information leakage
# X-Powered-By, Server, X-Debug, X-Request-Id
```

### 7. Input Validation Testing
```bash
# Test parameter tampering via proxy
# Modify price, quantity, role, status fields in requests

# Test mass assignment
# Add extra fields to POST/PUT requests
POST /api/v1/users/profile
{"name": "Test", "role": "admin", "is_verified": true}

# Test rate limiting
# Send rapid requests to authentication endpoints
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://api.target.com/api/v1/auth/login \
    -d '{"user":"admin","pass":"attempt'$i'"}';
done

# Test file upload endpoints
# Send oversized files, wrong content types, polyglot files
```

### 8. API Versioning and Deprecation
```bash
# Test for older, less-secure API versions
curl https://api.target.com/api/v1/users  # Current
curl https://api.target.com/api/v0/users  # Legacy
curl https://api.target.com/v1/users      # Alternate path

# Older versions may lack:
# - Rate limiting
# - Input validation
# - Authentication on certain endpoints
# - Security patches
```

## Tool Usage

### mitmproxy
```bash
# Interactive proxy
mitmproxy --mode regular -p 8080

# Dump traffic to file
mitmdump -w capture.flow -p 8080

# Replay captured requests
mitmdump -r capture.flow --set replay_kill_extra=true

# Filter specific domains
mitmproxy --mode regular -p 8080 --set intercept="~d api.target.com"

# Script to modify requests on the fly
mitmdump -s modify_headers.py -p 8080
```

### Frida for API inspection
```javascript
// Hook network calls to log all requests
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function(url) {
        console.log("URL: " + url);
        return this.$init(url);
    };
});

// Intercept OkHttp requests
Java.perform(function() {
    var Builder = Java.use("okhttp3.Request$Builder");
    Builder.build.implementation = function() {
        var req = this.build();
        console.log("OkHttp: " + req.url().toString());
        return req;
    };
});
```

### Burp Suite
```
# Mobile testing configuration
1. Proxy → Options → Add listener on all interfaces
2. Install CA cert on device
3. Configure device proxy
4. Use Scanner for automated API testing
5. Use Intruder for IDOR/BOLA testing across ID ranges
6. Use Repeater for manual request manipulation
```

## Remediation
1. **Implement certificate pinning** with pin rotation strategy and backup pins
2. **Use OAuth 2.0 / OpenID Connect** with short-lived access tokens and refresh token rotation
3. **Enforce object-level authorization** — validate resource ownership on every request
4. **Minimize API response data** — return only fields the client needs
5. **Implement rate limiting** — per-user, per-endpoint, with exponential backoff
6. **Validate all input server-side** — never trust client-side validation
7. **Deprecate old API versions** — enforce migration, disable legacy endpoints
8. **Use TLS 1.2+** with strong cipher suites; disable cleartext traffic
9. **Log and monitor API access** — detect anomalous patterns, credential stuffing

## Evidence Collection
- mitmproxy/Burp traffic captures showing intercepted requests and responses
- Screenshots of sensitive data in API responses (PII, tokens, internal data)
- BOLA/IDOR test results showing unauthorized data access with different user IDs
- API endpoint map with authentication and authorization requirements
- Rate limiting test results showing missing or insufficient throttling
- Decompiled source showing hardcoded API keys or endpoint paths
