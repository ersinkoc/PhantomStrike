# Certificate Attack Testing

## Overview
Certificate attack testing evaluates the security of X.509 certificate implementations and PKI infrastructure. This includes testing for self-signed certificates, expired certificates, hostname mismatches, certificate transparency abuse, man-in-the-middle attacks using rogue certificates, and CA compromise scenarios. Weaknesses in certificate handling can enable traffic interception, identity spoofing, and complete breakdown of trust in encrypted communications.

## Classification
- **CWE:** CWE-295 (Improper Certificate Validation), CWE-296 (Improper Following of a Certificate's Chain of Trust), CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-298 (Improper Validation of Certificate Expiration), CWE-299 (Improper Check for Certificate Revocation)
- **OWASP:** A02:2021 - Cryptographic Failures, A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.9 - 9.1 (Medium to Critical)
- **MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1588.004 (Obtain Capabilities: Digital Certificates)

## Detection Methodology

### 1. Self-Signed Certificate Detection
```bash
# Check if certificate is self-signed (issuer == subject)
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -issuer -subject

# Verify certificate chain
openssl s_client -connect target.com:443 -showcerts </dev/null 2>/dev/null

# Check against system trust store
openssl s_client -connect target.com:443 -CAfile /etc/ssl/certs/ca-certificates.crt
```

**Risks of self-signed certificates:**
- No third-party validation of identity
- Users conditioned to accept security warnings
- Trivial MITM with another self-signed certificate
- No revocation mechanism

### 2. Expired Certificate Testing
```bash
# Check validity dates
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -dates

# Check if expired
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -checkend 0

# Check expiring within 30 days
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -checkend 2592000
```

**Test scenarios:**
- Currently expired certificates still being served
- Certificates expiring within 30/60/90 days (operational risk)
- Not-yet-valid certificates (notBefore in the future)
- Applications that ignore expiration errors

### 3. Hostname Mismatch Testing
```bash
# Extract CN and SAN entries
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject:"
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

**Check for:**
- Certificate CN/SAN does not match the accessed hostname
- Wildcard certificate scope (*.example.com does not match example.com or sub.sub.example.com)
- IP address access when certificate only covers domain names
- Internal hostnames exposed in SAN entries (information disclosure)
- Applications that skip hostname verification

### 4. Certificate Chain Validation
```bash
# Retrieve full chain
openssl s_client -connect target.com:443 -showcerts </dev/null 2>/dev/null

# Verify chain
openssl verify -CAfile ca-bundle.crt -untrusted intermediate.crt server.crt
```

**Issues to identify:**
- Missing intermediate certificates (incomplete chain)
- Wrong ordering of certificates in the chain
- Untrusted root CA
- Cross-signed certificate confusion
- Chain length exceeding path length constraints

### 5. Weak Cryptographic Parameters
```bash
# Check key size and signature algorithm
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -E "(Public-Key|Signature Algorithm)"
```

**Flag as weak:**
- RSA keys < 2048 bits
- DSA keys (deprecated for TLS)
- SHA-1 signature algorithm (collision attacks demonstrated)
- MD5 signature algorithm (trivially broken)
- ECDSA with curves < 256 bits

### 6. Certificate Transparency (CT) Abuse
```
Certificate Transparency logs record all publicly issued certificates.

Reconnaissance via CT logs:
- Enumerate subdomains from CT log entries
- Discover internal/staging hostnames inadvertently exposed
- Identify shadow IT certificates
- Track certificate issuance patterns

Tools:
- https://crt.sh/?q=%25.target.com
- https://censys.io/certificates
- https://transparencyreport.google.com/https/certificates
```

```bash
# Query crt.sh for subdomains
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u

# Monitor for unauthorized certificate issuance
# Set up CT log monitoring via certspotter, Facebook CT monitor, or Google CT monitor
```

### 7. MITM with Rogue Certificates
Testing whether applications properly reject rogue certificates:

```bash
# Generate rogue CA
openssl req -x509 -newkey rsa:4096 -keyout rogue-ca.key -out rogue-ca.crt \
  -days 365 -nodes -subj "/CN=Rogue CA"

# Generate rogue server certificate signed by rogue CA
openssl req -newkey rsa:2048 -keyout rogue-server.key -out rogue-server.csr \
  -nodes -subj "/CN=target.com"
openssl x509 -req -in rogue-server.csr -CA rogue-ca.crt -CAkey rogue-ca.key \
  -CAcreateserial -out rogue-server.crt -days 365

# Set up MITM proxy with rogue cert
mitmproxy --certs target.com=rogue-server.crt --cert-passphrase=""

# Use Bettercap for network-level MITM
bettercap -T target_ip -X --proxy --proxy-cert rogue-server.crt \
  --proxy-key rogue-server.key
```

**Test whether client applications:**
- Accept certificates signed by untrusted CAs
- Accept certificates with wrong hostname
- Accept expired certificates without warning
- Implement certificate pinning that prevents rogue certs
- Log or alert on certificate validation failures

### 8. Certificate Revocation Testing
```bash
# Check CRL distribution point
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A3 "CRL Distribution"

# Check OCSP responder URL
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -ocsp_uri

# Manual OCSP check
openssl ocsp -issuer issuer.crt -cert server.crt \
  -url http://ocsp.responder.com -resp_text

# Check OCSP stapling support
openssl s_client -connect target.com:443 -status </dev/null 2>/dev/null | \
  grep -A5 "OCSP Response"
```

**Issues:**
- No CRL or OCSP endpoint configured
- OCSP responder unreachable or returning errors
- Revoked certificates still accepted by application
- No OCSP stapling (clients may soft-fail and accept revoked certs)

### 9. CA Compromise Scenarios
```
Assess impact if a trusted CA is compromised:
- Can rogue certificates be issued for any domain?
- Is Certificate Transparency monitoring in place to detect unauthorized issuance?
- Are CAA DNS records configured to restrict which CAs can issue certificates?
- Is certificate pinning deployed to reject unauthorized CA-signed certificates?
- What is the revocation response plan?

Check CAA records:
  dig CAA target.com
  Expected: 0 issue "letsencrypt.org" (restrict to specific CA)
```

## Tool Usage

### certigo
```bash
# Inspect certificate from server
certigo connect target.com:443

# Inspect local certificate file
certigo dump certificate.pem
```

### sslyze (Certificate Focus)
```bash
# Certificate information and chain validation
sslyze --certinfo target.com
```

### Nmap NSE
```bash
# SSL certificate details
nmap --script ssl-cert -p 443 target.com

# Check for known bad certificates
nmap --script ssl-known-key -p 443 target.com
```

## Remediation
1. **Use certificates from trusted CAs** -- never use self-signed certs in production
2. **Automate certificate renewal** -- use ACME/Let's Encrypt to prevent expiration
3. **Validate hostname strictly** -- ensure CN/SAN match in all client applications
4. **Use SHA-256 or stronger signatures** -- retire SHA-1 and MD5 signed certificates
5. **Deploy Certificate Transparency monitoring** -- detect unauthorized certificate issuance
6. **Configure CAA DNS records** -- restrict which CAs can issue certificates for your domains
7. **Implement certificate pinning** in mobile and high-security applications
8. **Enable OCSP stapling** -- ensure reliable revocation checking
9. **Maintain complete certificate chains** -- serve all intermediates from the server
10. **Monitor certificate expiration** proactively with automated alerts at 90/60/30 days
11. **Enforce minimum key sizes** -- RSA 2048+, ECDSA 256+

## Evidence Collection
When documenting certificate attack findings:
- Full certificate details (issuer, subject, CN, SAN, validity, key size, signature algorithm)
- Certificate chain with trust path analysis
- Specific validation failures (self-signed, expired, hostname mismatch)
- CT log entries revealing sensitive subdomains or shadow infrastructure
- Client behavior when presented with rogue or invalid certificates
- CAA record presence and configuration
- Revocation status and OCSP/CRL availability
- Screenshots of browser/application warnings (or lack thereof)
- Impact assessment considering the sensitivity of interceptable data
