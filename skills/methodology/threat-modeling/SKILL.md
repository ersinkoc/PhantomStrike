# Threat Modeling

## Overview
Threat modeling is a structured approach to identifying, quantifying, and addressing security threats to a system. By analyzing architecture, data flows, and trust boundaries, threat modeling reveals potential attack vectors before they are exploited. This guide covers STRIDE and DREAD methodologies, attack tree construction, data flow diagramming, and integration of threat modeling outputs into security testing.

## Methodology

### Phase 1: System Decomposition

#### 1a. Define Scope and Assets
```
1. Identify the system under analysis
   - Application name, version, deployment model
   - Business purpose and critical functions
   - Regulatory requirements (PCI, HIPAA, GDPR)

2. Enumerate assets
   - Authentication credentials and tokens
   - Customer PII and financial data
   - Business logic and intellectual property
   - API keys and service account credentials
   - Encryption keys and certificates
   - Audit logs and monitoring data

3. Identify entry points
   - Web interfaces (forms, file uploads, APIs)
   - Network services (SSH, RDP, database ports)
   - IPC mechanisms (shared memory, message queues)
   - Physical interfaces (USB, serial, NFC)
   - Third-party integrations (OAuth, webhooks, APIs)
```

#### 1b. Data Flow Diagrams (DFDs)
```
DFD Elements:
┌──────────┐     Represents external entities (users, systems)
│  Entity  │     outside the system boundary
└──────────┘

(  Process  )    Represents a process that transforms data

══════════════   Represents a data store (database, file)
  Data Store
══════════════

─────────────>   Represents data flow between elements

─ ─ ─ ─ ─ ─ ─   Trust boundary — security context changes here

DFD Levels:
- Level 0 (Context): System as single process, all external entities
- Level 1 (High-level): Major subsystems and data flows
- Level 2 (Detailed): Individual components and interactions

Example Level 1:
  [User] ──HTTPS──> (Web Server) ──SQL──> ═══DB═══
                         │
                    ─ ─ ─│─ ─ ─  Trust Boundary
                         │
                    (Auth Service) ──LDAP──> [Directory]
```

#### 1c. Trust Boundary Identification
```
Common trust boundaries:
- Internet ↔ DMZ
- DMZ ↔ Internal network
- Application tier ↔ Database tier
- User context ↔ Admin context
- Client-side ↔ Server-side
- Authenticated ↔ Unauthenticated
- Internal service ↔ Third-party service
- Container ↔ Host
- VPC ↔ VPC (cloud environments)

For each boundary, document:
- What data crosses this boundary?
- What authentication/authorization is enforced?
- What validation is performed?
- What encryption protects data in transit?
```

### Phase 2: STRIDE Threat Identification

#### STRIDE Categories
```
Category                  Property Violated    Example Threats
────────────────────────  ──────────────────   ───────────────────────
S — Spoofing              Authentication       Session hijacking, credential theft
T — Tampering             Integrity            SQL injection, parameter manipulation
R — Repudiation           Non-repudiation      Log deletion, missing audit trail
I — Information Disclosure Confidentiality     Data leakage, error messages
D — Denial of Service     Availability         Resource exhaustion, logic bombs
E — Elevation of Privilege Authorization       Privilege escalation, IDOR
```

#### STRIDE-per-Element Analysis
```
Apply STRIDE to each DFD element type:

DFD Element          Applicable STRIDE
──────────────────   ──────────────────
External Entity      S, R
Data Flow            T, I, D
Data Store           T, R, I, D
Process              S, T, R, I, D, E

For each element + applicable category, ask:
"How could an attacker [Spoof/Tamper/etc.] this [element]?"

Example — Web API Process:
  S: Attacker forges JWT token to impersonate another user
  T: Attacker modifies request parameters to alter business logic
  R: Actions performed without adequate audit logging
  I: API returns excessive data in error responses
  D: Attacker sends malformed requests causing resource exhaustion
  E: Regular user accesses admin API endpoints (broken access control)
```

### Phase 3: DREAD Risk Scoring

```
Score each threat on a scale of 1-10 for each factor:

Factor                    Description
─────────────────────     ──────────────────────────────────────
D — Damage Potential      How severe is the damage if exploited?
R — Reproducibility       How easily can the attack be reproduced?
E — Exploitability        How easy is it to launch the attack?
A — Affected Users        How many users are impacted?
D — Discoverability       How easy is the vulnerability to find?

Risk Score = (D + R + E + A + D) / 5

Rating Scale:
  1-3:   Low risk
  4-6:   Medium risk
  7-9:   High risk
  10:    Critical risk

Example Scoring — SQL Injection on Login:
  Damage:          9  (full database access)
  Reproducibility: 8  (consistently exploitable)
  Exploitability:  7  (automated tools available)
  Affected Users:  10 (all users)
  Discoverability: 8  (standard testing finds it)
  Score: (9+8+7+10+8)/5 = 8.4 → High
```

### Phase 4: Attack Tree Construction

```
Attack trees decompose a threat goal into sub-goals:

Root Goal: Steal Customer Data
├── [OR] Exploit Web Application
│   ├── [OR] SQL Injection
│   │   ├── [AND] Find injectable parameter
│   │   └── [AND] Bypass WAF rules
│   ├── [OR] Broken Access Control
│   │   ├── [AND] Enumerate user IDs
│   │   └── [AND] Access other users' data
│   └── [OR] Exploit File Upload
│       ├── [AND] Upload web shell
│       └── [AND] Execute commands
├── [OR] Compromise Credentials
│   ├── [OR] Phishing attack
│   ├── [OR] Credential stuffing
│   └── [OR] Brute force weak passwords
├── [OR] Exploit Network
│   ├── [OR] Man-in-the-middle attack
│   └── [OR] Exploit unpatched services
└── [OR] Insider Threat
    ├── [OR] Malicious administrator
    └── [OR] Compromised employee device

For each leaf node, annotate:
- Required attacker skill level
- Required access (network, physical, authenticated)
- Estimated effort and cost
- Available tools and techniques
- Corresponding MITRE ATT&CK technique
```

### Phase 5: Mapping Threats to Security Tests

```
Threat → Test Mapping:

STRIDE Threat                    Security Test
──────────────────────────────   ─────────────────────────────────
Spoofing: Token forgery          JWT attack testing (none alg, weak secret)
Tampering: Parameter manip       Input validation, mass assignment testing
Repudiation: No audit trail      Log review, forensic readiness check
Info Disclosure: Error messages   Fuzzing, error handling review
DoS: Resource exhaustion          Rate limit testing, stress testing
Elevation: IDOR                  Access control testing across roles

Generate test cases from each identified threat:
1. Create test case per threat
2. Define pass/fail criteria
3. Map to tools and techniques
4. Assign to testing phase (recon, exploitation, post-exploit)
```

## Automated Threat Modeling Tools
```
Microsoft Threat Modeling Tool
- DFD-based, generates STRIDE threats automatically
- Produces report with threats and mitigations
- Best for Windows/.NET applications

OWASP Threat Dragon
- Open source, web-based
- Create DFDs and identify threats
- Export threat model as JSON

pytm (Python Threat Modeling)
- Define system as Python code
- Automatically generates threats based on STRIDE
- Produces DFDs, sequence diagrams, reports

threatspec
- Code annotation-based threat modeling
- Document threats as comments in source code
- Generates reports from codebase annotations

IriusRisk
- Automated threat modeling platform
- Library of threat patterns
- Integration with JIRA, DevOps pipelines
```

```python
# pytm example
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("Web Application Threat Model")
internet = Boundary("Internet")
dmz = Boundary("DMZ")
internal = Boundary("Internal Network")

user = Actor("User")
user.inBoundary = internet

web = Server("Web Server")
web.inBoundary = dmz

db = Datastore("Database")
db.inBoundary = internal
db.isEncryptedAtRest = True

user_to_web = Dataflow(user, web, "HTTPS Request")
user_to_web.protocol = "HTTPS"

web_to_db = Dataflow(web, db, "SQL Query")
web_to_db.protocol = "SQL"

tm.process()
```

## Remediation
1. **Integrate threat modeling into SDLC** — perform at design phase, update at each release
2. **Address high-risk threats first** — use DREAD scores or risk matrices to prioritize
3. **Implement controls at trust boundaries** — authentication, validation, encryption
4. **Validate mitigations through testing** — every identified threat should have a test case
5. **Maintain living threat models** — update as architecture evolves
6. **Automate where possible** — use pytm or Threat Dragon in CI/CD pipelines
7. **Cross-reference with ATT&CK** — map threats to known adversary techniques

## Evidence Collection
- Data flow diagrams at all levels (L0, L1, L2) for the system
- STRIDE analysis table with all identified threats per element
- DREAD scores for each threat with justification
- Attack trees showing decomposed threat scenarios
- Threat-to-test mapping showing security test coverage
- Residual risk register for accepted threats
- Threat model version history showing evolution over time
