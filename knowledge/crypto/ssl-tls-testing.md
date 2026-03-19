# SSL/TLS Testing Guide

## Overview

SSL/TLS configuration directly impacts confidentiality and integrity of communications.
Testing identifies weak cipher suites, protocol vulnerabilities, certificate issues, and
missing security headers.

## Protocol Version Testing

### Check Supported Versions
```bash
# Test specific protocol versions
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3
# SSLv3 (should be disabled)
openssl s_client -connect target.com:443 -ssl3
```

### Findings Severity
- SSLv2/SSLv3 enabled: **Critical** (POODLE, DROWN)
- TLS 1.0 enabled: **High** (BEAST, Lucky13)
- TLS 1.1 enabled: **Medium** (deprecated)
- TLS 1.2 without 1.3: **Low/Info**
- TLS 1.3 only: **Best practice**

## Cipher Suite Analysis

### Enumerate Ciphers
```bash
# Using nmap
nmap --script ssl-enum-ciphers -p 443 target.com
# Using testssl.sh (comprehensive)
testssl.sh target.com:443
# Using openssl to test specific cipher
openssl s_client -connect target.com:443 -cipher RC4-SHA
```

### Weak Ciphers to Flag
- NULL ciphers (no encryption)
- EXPORT ciphers (40/56-bit keys)
- RC4 stream cipher
- DES/3DES (SWEET32 attack)
- CBC-mode ciphers with TLS 1.0 (BEAST)
- Ciphers without forward secrecy (RSA key exchange)

## Certificate Validation

### Check Certificate Details
```bash
# View full certificate chain
openssl s_client -connect target.com:443 -showcerts
# Check certificate dates
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates
# Check Subject Alternative Names
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
# Verify certificate chain
openssl verify -CAfile chain.pem server.pem
```

### Certificate Issues
- Self-signed certificates in production
- Expired or not-yet-valid certificates
- Wildcard certificates on public-facing services
- Weak signature algorithms (SHA-1, MD5)
- Key size below 2048 bits (RSA) or 256 bits (ECDSA)
- Missing intermediate certificates (incomplete chain)
- Certificate transparency log absence

## Known Vulnerabilities

### Heartbleed (CVE-2014-0160)
```bash
nmap -p 443 --script ssl-heartbleed target.com
```

### POODLE (SSLv3)
```bash
testssl.sh --poodle target.com:443
```

### ROBOT (RSA padding oracle)
```bash
python3 robot-detect.py -p 443 target.com
```

### CRIME/BREACH (TLS compression)
```bash
testssl.sh --crime target.com:443
```

## HSTS (HTTP Strict Transport Security)

### Check HSTS Header
```bash
curl -sI https://target.com | grep -i strict-transport
```

### HSTS Requirements
- `Strict-Transport-Security` header present
- `max-age` at least 31536000 (1 year)
- `includeSubDomains` directive
- HSTS preload list submission for critical domains

## Tools
- **testssl.sh** - comprehensive TLS testing (`testssl.sh --full target.com`)
- **sslyze** - fast TLS scanner (`sslyze target.com`)
- **nmap ssl scripts** - ssl-enum-ciphers, ssl-heartbleed, ssl-poodle
- **SSL Labs** - online TLS assessment (ssllabs.com)
- **CipherScan** - Mozilla cipher suite analysis

## Remediation
- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
- Enable TLS 1.2 and TLS 1.3 only
- Use strong cipher suites with forward secrecy (ECDHE/DHE)
- Use RSA keys of 2048+ bits or ECDSA 256+ bits
- Implement HSTS with long max-age and includeSubDomains
- Enable OCSP stapling for revocation checking
- Configure proper certificate chains (include intermediates)
- Automate certificate renewal (Let's Encrypt / ACME)
