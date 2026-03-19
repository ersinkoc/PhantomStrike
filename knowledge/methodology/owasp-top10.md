# OWASP Top 10 (2021)

## A01:2021 — Broken Access Control
Moving up from #5, 94% of applications were tested for some form of broken access control. Notable CWEs include CWE-200, CWE-201, CWE-352.

**Testing approach:**
- Test for IDOR (Insecure Direct Object Reference) by modifying IDs in URLs/API calls
- Check for missing function-level access control on admin endpoints
- Test CORS misconfiguration
- Verify JWT token scope enforcement

**Tools:** Burp Suite, ffuf, nuclei (access-control templates)

## A02:2021 — Cryptographic Failures
Previously known as Sensitive Data Exposure. Focus is on failures related to cryptography.

**Testing approach:**
- Check for data transmitted in cleartext (HTTP, FTP, SMTP)
- Verify TLS configuration (testssl.sh, sslyze)
- Check for weak/deprecated algorithms (MD5, SHA1, DES)
- Look for hardcoded secrets and API keys

**Tools:** testssl.sh, sslyze, trufflehog, detect-secrets

## A03:2021 — Injection
SQL, NoSQL, OS, LDAP injection. XSS is now part of this category.

**Testing approach:**
- Test all user inputs for SQL injection (sqlmap)
- Test for command injection via parameter manipulation
- Check for LDAP injection on authentication forms
- Test for template injection (SSTI)

**Tools:** sqlmap, commix, dalfox, nuclei

## A04:2021 — Insecure Design
A new category focusing on design flaws vs implementation bugs.

**Testing approach:**
- Review threat models and data flow diagrams
- Check for missing rate limiting on sensitive operations
- Verify business logic constraints (e.g., negative quantities)
- Test for race conditions in financial operations

## A05:2021 — Security Misconfiguration
Including XML External Entities (XXE).

**Testing approach:**
- Check for default credentials
- Scan for unnecessary services and open ports
- Verify security headers (X-Frame-Options, CSP, HSTS)
- Test for directory listing and verbose error messages

**Tools:** nikto, nuclei, nmap scripts

## A06:2021 — Vulnerable and Outdated Components
Check dependencies for known CVEs.

**Testing approach:**
- Run dependency vulnerability scans
- Check component versions against NVD/CVE databases
- Verify components are actively maintained

**Tools:** trivy, grype, snyk, npm audit

## A07:2021 — Identification and Authentication Failures
Previously Broken Authentication.

**Testing approach:**
- Test for credential stuffing resistance
- Check password policy enforcement
- Verify MFA implementation
- Test session management (fixation, timeout, rotation)

**Tools:** hydra, medusa, burp intruder

## A08:2021 — Software and Data Integrity Failures
New category. Focuses on assumptions about software updates, CI/CD pipelines.

**Testing approach:**
- Check for unsigned/unverified updates
- Verify CI/CD pipeline security
- Test deserialization vulnerabilities

## A09:2021 — Security Logging and Monitoring Failures
Expanded from Insufficient Logging & Monitoring.

**Testing approach:**
- Verify that login failures are logged
- Check that high-value transactions create audit trails
- Test alerting thresholds

## A10:2021 — Server-Side Request Forgery (SSRF)
New category. Increasing incidence with cloud services.

**Testing approach:**
- Test URL parameters that fetch remote resources
- Check for cloud metadata endpoint access (169.254.169.254)
- Test for DNS rebinding attacks

**Tools:** nuclei (ssrf templates), burp collaborator
