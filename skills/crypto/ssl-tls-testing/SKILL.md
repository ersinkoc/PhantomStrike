# SSL/TLS Security Testing

## Overview
SSL/TLS security testing evaluates the transport layer encryption protecting network communications. Testing covers protocol versions, cipher suite selection, certificate validation, known protocol vulnerabilities (BEAST, POODLE, CRIME, BREACH, Heartbleed), HSTS configuration, and certificate pinning implementation. Weaknesses in TLS configuration can lead to eavesdropping, data tampering, and man-in-the-middle attacks.

## Classification
- **CWE:** CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext Transmission), CWE-326 (Inadequate Encryption Strength), CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **OWASP:** A02:2021 - Cryptographic Failures
- **CVSS Base:** 4.3 - 9.1 (Medium to Critical)
- **MITRE ATT&CK:** T1557.002 (ARP Cache Poisoning), T1040 (Network Sniffing)

## Detection Methodology

### 1. Protocol Version Testing
Identify supported TLS/SSL versions:
```
Insecure (should be disabled):
- SSL 2.0 — critically broken, must never be used
- SSL 3.0 — vulnerable to POODLE
- TLS 1.0 — deprecated, vulnerable to BEAST
- TLS 1.1 — deprecated, weak ciphers

Acceptable:
- TLS 1.2 — secure with proper cipher suites
- TLS 1.3 — preferred, strongest security
```

### 2. Cipher Suite Analysis
```
Weak/broken ciphers to flag:
- NULL ciphers — no encryption at all
- EXPORT ciphers — intentionally weakened (40/56-bit)
- DES / 3DES — small block size, Sweet32 attack
- RC4 — multiple biases, broken for TLS
- MD5 MAC — collision attacks
- Anonymous DH — no authentication, trivial MITM
- Static RSA key exchange — no forward secrecy

Strong configuration:
- ECDHE or DHE key exchange (forward secrecy)
- AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305
- SHA-256 or SHA-384 MAC (or AEAD)
- TLS 1.2 minimum, TLS 1.3 preferred
```

### 3. Known Protocol Vulnerabilities

**BEAST (CVE-2011-3389):**
- Affects TLS 1.0 with CBC ciphers
- Chosen-plaintext attack on CBC IV predictability
- Mitigated by TLS 1.1+ or RC4 (but RC4 is also broken)

**POODLE (CVE-2014-3566):**
- Attacks SSL 3.0 CBC padding
- Recovers plaintext byte-by-byte
- TLS variant exists for implementations with non-deterministic padding

**CRIME (CVE-2012-4929):**
- Exploits TLS-level compression
- Recovers session cookies by observing compressed ciphertext size
- Mitigated by disabling TLS compression

**BREACH:**
- Exploits HTTP-level compression (gzip/deflate)
- Recovers secrets from HTTP response bodies
- Harder to mitigate — requires application-level changes

**Heartbleed (CVE-2014-0160):**
- OpenSSL memory disclosure via TLS heartbeat extension
- Leaks server memory including private keys and session data
- Affects OpenSSL 1.0.1 through 1.0.1f

**DROWN (CVE-2016-0800):**
- Cross-protocol attack using SSLv2 to decrypt TLS sessions
- Requires SSLv2 support on any server sharing the same key

**ROBOT (Return Of Bleichenbacher's Oracle Threat):**
- Bleichenbacher-style padding oracle on RSA key exchange
- Allows decryption of recorded TLS sessions

**Renegotiation vulnerabilities:**
- Client-initiated renegotiation → DoS vector
- Insecure renegotiation (CVE-2009-3555) → plaintext injection

### 4. HSTS (HTTP Strict Transport Security)
```
Check for:
- Strict-Transport-Security header presence
- max-age value (minimum 31536000 / 1 year recommended)
- includeSubDomains directive
- preload directive and HSTS preload list registration
- Missing HSTS allows SSL stripping attacks (sslstrip)
```

### 5. Certificate Validation
```
Check for:
- Self-signed certificates
- Expired or not-yet-valid certificates
- Hostname mismatch (CN/SAN vs actual hostname)
- Weak signature algorithm (MD5, SHA-1)
- Short RSA keys (< 2048 bits)
- Certificate chain completeness (missing intermediates)
- Certificate revocation (CRL/OCSP)
- Certificate Transparency (CT) log presence
```

### 6. Certificate Pinning
```
- HPKP header (deprecated but still encountered)
- Application-level pinning (mobile apps, thick clients)
- Test if pinning can be bypassed with a proxy CA
- Check pin-sha256 values match expected certificates
```

## Tool Usage

### testssl.sh
```bash
# Full scan
testssl.sh https://target.com

# Specific checks
testssl.sh --protocols https://target.com
testssl.sh --ciphers https://target.com
testssl.sh --vulnerabilities https://target.com
testssl.sh --headers https://target.com
testssl.sh --server-defaults https://target.com

# Output formats
testssl.sh --json-pretty --html https://target.com

# Test specific port/service
testssl.sh --starttls smtp target.com:25
testssl.sh target.com:8443

# Check certificate chain
testssl.sh --cert --certtext https://target.com

# Parallel scanning
testssl.sh --parallel --file=targets.txt
```

### sslyze
```bash
# Full scan
sslyze target.com

# Specific scans
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 target.com
sslyze --certinfo target.com
sslyze --heartbleed target.com
sslyze --openssl_ccs target.com
sslyze --robot target.com
sslyze --reneg target.com
sslyze --compression target.com
sslyze --fallback target.com
sslyze --early_data target.com

# JSON output
sslyze --json_out=results.json target.com

# Multiple targets
sslyze --targets_in=hosts.txt
```

### sslscan
```bash
# Standard scan
sslscan target.com

# Show certificate details
sslscan --show-certificate target.com

# Test specific port
sslscan target.com:8443

# STARTTLS
sslscan --starttls-smtp target.com:25
sslscan --starttls-ftp target.com:21

# No colour (for logging)
sslscan --no-colour target.com > results.txt

# XML output
sslscan --xml=results.xml target.com
```

### Nmap NSE Scripts
```bash
# Enumerate ciphers
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for Heartbleed
nmap --script ssl-heartbleed -p 443 target.com

# Check for POODLE
nmap --script ssl-poodle -p 443 target.com

# Certificate info
nmap --script ssl-cert -p 443 target.com

# CCS injection
nmap --script ssl-ccs-injection -p 443 target.com
```

### OpenSSL Manual Testing
```bash
# Test specific protocol version
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3

# Test specific cipher
openssl s_client -connect target.com:443 -cipher 'RC4-SHA'

# Show certificate chain
openssl s_client -connect target.com:443 -showcerts

# Check certificate expiry
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

# Check OCSP stapling
openssl s_client -connect target.com:443 -status
```

## Remediation
1. **Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1** -- enforce TLS 1.2 minimum
2. **Use strong cipher suites only** -- ECDHE + AES-GCM or ChaCha20-Poly1305
3. **Enable forward secrecy** -- prefer ECDHE key exchange
4. **Deploy HSTS** with `max-age=31536000; includeSubDomains; preload`
5. **Use 2048-bit+ RSA keys** or 256-bit+ ECDSA keys
6. **Disable TLS compression** to prevent CRIME
7. **Patch OpenSSL** and keep TLS libraries current
8. **Configure proper certificate chains** with all intermediates
9. **Enable OCSP stapling** for efficient revocation checking
10. **Disable client-initiated renegotiation** to prevent DoS

## Evidence Collection
When documenting SSL/TLS findings:
- Full testssl.sh or sslyze output as baseline
- List of supported protocol versions with assessment
- Complete cipher suite list with weak entries highlighted
- Certificate chain details (issuer, validity, key size, signature algorithm)
- Specific vulnerability scan results (Heartbleed, POODLE, ROBOT, etc.)
- Missing security headers (HSTS, HPKP)
- Server software and TLS library version if disclosed
- Impact assessment considering data sensitivity and exposure
