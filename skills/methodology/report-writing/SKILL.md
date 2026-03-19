# Penetration Test Report Writing

## Overview
The penetration test report is the primary deliverable of any security assessment. A well-structured report communicates findings to both technical and executive audiences, provides actionable remediation guidance, and serves as a record of the security posture at a point in time. This guide covers report structure, finding format, severity rating, evidence presentation, and best practices for clear and effective security reporting.

## Methodology

### Report Structure

#### 1. Cover Page
```
- Report title (e.g., "External Penetration Test Report")
- Client organization name
- Assessment date range
- Report version and date
- Classification level (Confidential, Restricted)
- Assessor organization name and contact
- Report distribution list
```

#### 2. Executive Summary (1-2 pages)
```
Target audience: C-suite, board members, non-technical stakeholders

Content:
- Purpose and scope of the assessment (1 paragraph)
- Overall risk rating (Critical/High/Medium/Low)
- Key findings summary (3-5 bullet points, business impact focus)
- Strategic recommendations (prioritized, actionable)
- Positive observations (security strengths identified)

Writing guidelines:
- No technical jargon — translate to business risk
- Use concrete impact statements:
  BAD:  "SQL injection was found in the login form"
  GOOD: "An attacker could bypass authentication and access all customer
         records, including payment information for 50,000 accounts"
- Include a risk summary table or chart
- Keep to 1-2 pages maximum
```

#### 3. Scope and Methodology
```
- Scope definition (targets, IP ranges, applications, exclusions)
- Testing type (black box, gray box, white box)
- Testing methodology (OWASP, PTES, NIST SP 800-115)
- Rules of engagement (testing window, rate limits, restrictions)
- Tools used (categorized by function)
- Credentials provided (if gray/white box)
- Limitations and constraints encountered
```

#### 4. Findings Summary Table
```
ID   Title                          Severity   CVSS   Status
───  ─────────────────────────────  ────────   ────   ──────
F01  SQL Injection in Login Form    Critical   9.8    Open
F02  Default Admin Credentials      Critical   9.1    Open
F03  Missing TLS on Internal API    High       7.5    Open
F04  Stored XSS in User Profile     High       7.2    Open
F05  Directory Listing Enabled      Medium     5.3    Open
F06  Missing Security Headers       Low        3.1    Open
F07  Verbose Error Messages         Info       0.0    Open
```

#### 5. Detailed Findings

### Finding Format Template
```
## F01: [Finding Title]

### Severity
- Rating: Critical / High / Medium / Low / Informational
- CVSS v3.1 Score: X.X (Vector String)
- CWE: CWE-XXX (Name)
- OWASP: Category reference

### Affected Assets
- https://target.com/login (POST parameter: username)
- Internal IP: 10.0.1.50

### Description
Clear explanation of the vulnerability:
- What the vulnerability is
- Where it exists in the application
- Why it is a security risk

### Impact
Business-focused impact statement:
- What an attacker could achieve
- What data is at risk
- Potential regulatory implications
- Estimated blast radius

### Proof of Concept
Step-by-step reproduction:
1. Navigate to https://target.com/login
2. Enter the following in the username field: ' OR 1=1--
3. Observe: authentication is bypassed, admin dashboard displayed

[Screenshot with sensitive data redacted]

### Remediation
Primary fix:
- Implement parameterized queries for all database interactions

Additional recommendations:
- Deploy WAF rules as defense-in-depth measure
- Implement input validation (whitelist approach)
- Apply least-privilege database permissions

### References
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQLi Prevention: https://cheatsheetseries.owasp.org/...
```

#### 6. Positive Observations
```
Document security strengths:
- Effective controls that prevented exploitation
- Well-implemented security features
- Good security practices observed
- This section builds credibility and goodwill

Example:
- Strong TLS configuration with HSTS on all external endpoints
- Effective rate limiting prevented brute-force attacks
- Comprehensive logging observed on authentication events
```

#### 7. Appendices
```
Appendix A: Tool Output (sanitized scan results, raw data)
Appendix B: Testing Logs (timeline of testing activities)
Appendix C: Remediation Priority Matrix
Appendix D: Glossary of Terms
Appendix E: Retesting Results (if applicable)
```

### Severity Rating Guidelines

#### Rating Criteria
```
Critical (CVSS 9.0-10.0):
- Remote code execution
- Authentication bypass affecting all users
- Full database compromise
- Access to production secrets/keys
- Requires immediate action

High (CVSS 7.0-8.9):
- Significant data exposure
- Privilege escalation
- Stored XSS affecting many users
- Sensitive data in transit without encryption
- Requires action within 30 days

Medium (CVSS 4.0-6.9):
- Limited data exposure
- CSRF on sensitive functions
- Information disclosure aiding further attacks
- Missing security controls (defense-in-depth)
- Requires action within 90 days

Low (CVSS 0.1-3.9):
- Minor information disclosure
- Missing non-critical security headers
- Verbose error messages
- Best practice deviations
- Address in next release cycle

Informational (CVSS 0.0):
- Observations and recommendations
- Best practice suggestions
- No direct security impact
```

### Evidence Presentation Best Practices

#### Screenshots
```
Guidelines:
- Annotate with arrows, boxes, and labels highlighting the finding
- Redact sensitive data (PII, real credentials, internal IPs if external report)
- Include browser URL bar to show the target
- Use sequential numbering matching proof-of-concept steps
- Capture full context — not just the vulnerability, but its impact
- Use consistent formatting (borders, sizing)
```

#### Request/Response Evidence
```
Include sanitized HTTP requests and responses:

REQUEST:
POST /api/v1/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin' OR 1=1--", "password": "anything"}

RESPONSE:
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "success", "token": "eyJhbG...", "role": "admin"}

Highlight:
- The injected payload in the request
- The successful authentication in the response
- Any sensitive data returned
```

#### Tool Output
```
- Include relevant excerpts, not full scan dumps
- Highlight the key finding in the output
- Provide context for non-obvious tool output
- Link tool output to the finding it supports
```

### Writing Best Practices
```
1. Be precise and factual
   - State what was found, not what might exist
   - Distinguish between confirmed and suspected vulnerabilities

2. Be consistent
   - Use the same severity criteria throughout
   - Apply the same finding format for every issue
   - Use consistent terminology

3. Be actionable
   - Every finding must have a remediation recommendation
   - Recommendations should be specific, not generic
   - Include code examples or configuration snippets where helpful

4. Know your audience
   - Executive summary: business risk language
   - Technical findings: precise technical detail
   - Remediation: developer-friendly guidance

5. Maintain objectivity
   - Report facts, not opinions
   - Avoid inflammatory language
   - Present risk without exaggeration

6. Protect confidentiality
   - Classify the report appropriately
   - Redact data that could aid an attacker if the report leaks
   - Follow data handling agreements with the client
```

### Remediation Priority Matrix
```
Priority    Criteria                               Timeline
────────    ─────────────────────────────────────   ──────────
P1          Critical severity, actively exploited   24-48 hours
P2          Critical/High severity, exploitable     1-2 weeks
P3          High/Medium severity                    30-60 days
P4          Medium/Low severity                     60-90 days
P5          Low/Informational                       Next release
```

## Remediation
1. **Use a standardized template** for all reports to ensure consistency
2. **Peer review all reports** before delivery — technical accuracy and readability
3. **Tailor language to audience** — separate executive and technical sections clearly
4. **Include remediation verification** — offer retesting to confirm fixes
5. **Version control reports** — track changes between draft and final versions
6. **Deliver securely** — encrypted email, secure file sharing, not plaintext email
7. **Provide a findings tracker** — spreadsheet or ticketing system for remediation tracking

## Evidence Collection
- All screenshots annotated and organized by finding
- HTTP request/response pairs for each exploited vulnerability
- Tool output excerpts supporting each finding
- Testing activity timeline with timestamps
- Scope confirmation documentation (emails, signed agreements)
- Chain of custody for any sensitive data accessed during testing
