# NIST Cybersecurity Framework Testing

## Overview
The NIST Cybersecurity Framework (CSF) provides a structured approach to managing cybersecurity risk through five core functions: Identify, Protect, Detect, Respond, and Recover. This guide maps specific security tests and penetration testing activities to NIST controls, enabling assessors to validate an organization's security posture against the framework and identify gaps in implementation.

## Classification
- **Framework:** NIST CSF v2.0 (February 2024) / NIST SP 800-53 Rev. 5
- **Testing Type:** Control validation and gap assessment
- **Applicability:** All organizations, mandatory for US federal agencies

## Methodology

### Function 1: Identify (ID)

#### ID.AM — Asset Management
```
Tests:
- Enumerate all network-connected assets (authorized and unauthorized)
  nmap -sn <network_ranges> -oA id_am_discovery

- Compare discovered assets against CMDB/asset inventory
  # Identify shadow IT, rogue devices, forgotten systems

- Identify all software installed on in-scope systems
  # Compare against approved software inventory

- Map data flows across organizational boundaries
  # Identify where sensitive data is stored, processed, transmitted

- Verify asset criticality classifications
  # Confirm that high-value assets have appropriate protections

Validation:
[ ] Hardware inventory is complete and accurate
[ ] Software inventory covers all installed applications
[ ] Network topology is documented and current
[ ] Data flow diagrams exist for sensitive data
[ ] Asset criticality ratings are assigned and reviewed
```

#### ID.RA — Risk Assessment
```
Tests:
- Conduct vulnerability scanning across all asset classes
  nessus_scan --policy "Full Scan" -T <all_assets>
  openvas-cli --scan-all <target_ranges>

- Identify threats relevant to organization's sector
- Review threat intelligence feeds for targeted threats
- Validate risk register against actual security posture

Validation:
[ ] Vulnerability management program produces regular scans
[ ] Threat intelligence is consumed and acted upon
[ ] Risk register is maintained and reviewed quarterly
[ ] Risk tolerance levels are defined by leadership
```

#### ID.GV — Governance
```
Tests:
- Review security policies for completeness and currency
- Verify policy awareness among staff (interview/quiz)
- Confirm regulatory requirements are identified and mapped
- Validate roles and responsibilities are documented

Validation:
[ ] Security policy exists and is approved by management
[ ] Roles and responsibilities are clearly defined
[ ] Legal/regulatory requirements are identified
[ ] Governance processes include cybersecurity risk
```

### Function 2: Protect (PR)

#### PR.AC — Access Control
```
Tests:
- Test authentication mechanisms
  hydra -L users.txt -P passwords.txt <target> ssh
  # Test password policy enforcement
  # Test MFA implementation and bypass resistance

- Validate least privilege implementation
  # Escalation testing — can regular users access admin functions?
  # Test RBAC/ABAC enforcement

- Test network access controls
  nmap -sS -p- <segmented_network> # from unauthorized segment
  # Verify VPN authentication and authorization
  # Test wireless network access controls

- Verify remote access security
  # Test VPN split tunneling configuration
  # Validate remote session timeout

Validation:
[ ] Identities and credentials are managed for all users
[ ] Physical access to assets is controlled
[ ] Remote access is managed and secured
[ ] Access permissions follow least privilege
[ ] Network integrity is protected (segmentation, monitoring)
```

#### PR.DS — Data Security
```
Tests:
- Verify data-at-rest encryption
  # Check database encryption (TDE, column-level)
  # Check file system encryption (BitLocker, LUKS, FileVault)
  # Search for unencrypted sensitive data

- Verify data-in-transit encryption
  testssl.sh <target>:443
  # Test internal communication channels
  # Check for cleartext protocols (FTP, Telnet, HTTP)

- Test data loss prevention controls
  # Attempt to exfiltrate test data via email, USB, cloud storage
  # Verify DLP rule effectiveness

- Validate data disposal procedures
  # Verify secure deletion of decommissioned media

Validation:
[ ] Data-at-rest is protected with encryption
[ ] Data-in-transit is protected with TLS/encryption
[ ] Assets are managed through removal, transfer, disposition
[ ] Adequate capacity is maintained for availability
[ ] Data integrity is verified (checksums, signing)
[ ] Development/test environments use sanitized data
```

#### PR.IP — Information Protection
```
Tests:
- Review baseline configurations (CIS Benchmarks)
  # Scan systems against hardening standards

- Validate change management process
  # Verify that changes require approval and documentation

- Test backup and recovery
  # Verify backup integrity, encryption, access controls
  # Test restoration procedure and timing

- Verify vulnerability management cycle
  # Confirm scan frequency, patch timelines, exception process

Validation:
[ ] Configuration baselines are established and maintained
[ ] System Development Life Cycle includes security
[ ] Change management processes exist and are followed
[ ] Backups are performed, tested, and protected
[ ] Physical operating environment policies are met
[ ] Data is destroyed according to policy
[ ] Protection processes are continuously improved
```

### Function 3: Detect (DE)

#### DE.CM — Continuous Monitoring
```
Tests:
- Validate network monitoring coverage
  # Generate test traffic and verify detection
  nmap -sS -p 1-1000 <monitored_host>
  # Verify IDS/IPS alerting

- Test endpoint detection and response (EDR)
  # Execute benign test payloads (atomic red team tests)
  # Verify detection and alerting

- Validate log collection and SIEM
  # Verify log sources are feeding SIEM
  # Test correlation rules with simulated events
  # Check log retention meets requirements

- Test physical security monitoring
  # Verify badge access logging, camera coverage

Validation:
[ ] Network is monitored for anomalies and attacks
[ ] Physical environment is monitored
[ ] Personnel activity is monitored for anomalies
[ ] Malicious code is detected
[ ] Unauthorized devices are detected
[ ] External service provider activity is monitored
[ ] Monitoring for unauthorized access is performed
```

#### DE.AE — Anomaly and Event Detection
```
Tests:
- Verify baseline network behavior is established
- Test anomaly detection with deviation from baseline
  # Unusual data transfer volumes
  # Connections to uncommon destinations
  # Off-hours access patterns

- Validate event correlation across sources
  # Multi-stage attack simulation
  # Lateral movement detection

- Test alert prioritization and triage process

Validation:
[ ] Baseline of network operations is established
[ ] Detected events are analyzed for attack targets/methods
[ ] Event data is aggregated and correlated from multiple sources
[ ] Impact of events is determined
[ ] Incident alert thresholds are established
```

### Function 4: Respond (RS)

#### RS.RP — Response Planning
```
Tests:
- Tabletop exercise for incident response
  # Simulate ransomware scenario
  # Simulate data breach notification
  # Simulate insider threat scenario

- Test communication plans
  # Verify escalation paths work
  # Test out-of-band communication channels

- Validate forensic readiness
  # Verify forensic tool availability
  # Test evidence collection procedures
  # Check chain of custody documentation

Validation:
[ ] Incident response plan is established and tested
[ ] Communication plan includes all stakeholders
[ ] Forensic capabilities are available
[ ] Lessons learned process exists
[ ] Response plan is updated based on lessons learned
```

### Function 5: Recover (RC)

#### RC.RP — Recovery Planning
```
Tests:
- Test disaster recovery procedures
  # Verify RTO/RPO can be met
  # Test failover to backup systems
  # Validate data restoration from backups

- Verify business continuity plans
  # Test alternate processing locations
  # Verify critical function continuation

- Validate communication during recovery
  # Test notification to customers, partners, regulators

Validation:
[ ] Recovery plan is established and exercised
[ ] Recovery plan incorporates lessons learned
[ ] Recovery activities are communicated to stakeholders
[ ] Public relations and reputation management is planned
[ ] Recovery plans are updated after testing
```

## NIST SP 800-53 Control Mapping
```
NIST CSF Function    Key SP 800-53 Controls
─────────────────    ──────────────────────
Identify             RA-3, RA-5, PM-5, CM-8
Protect              AC-2, AC-3, AC-17, SC-8, SC-28
Detect               SI-4, AU-6, IR-4
Respond              IR-1, IR-4, IR-5, IR-6, IR-8
Recover              CP-2, CP-4, CP-10
```

## Tool Mapping by Function
```
Identify:  nmap, Nessus, OpenVAS, Qualys, asset discovery tools
Protect:   CIS-CAT, Lynis, testssl.sh, Prowler (cloud), ScoutSuite
Detect:    Atomic Red Team, MITRE Caldera, detection lab tools
Respond:   Velociraptor, GRR, forensic toolkits
Recover:   Backup validation tools, DR orchestration
```

## Remediation
1. **Complete asset inventory** — deploy continuous discovery and maintain CMDB accuracy
2. **Implement defense in depth** — layer controls across all Protect subcategories
3. **Deploy comprehensive monitoring** — ensure visibility across network, endpoint, and cloud
4. **Test incident response regularly** — conduct tabletop and live exercises quarterly
5. **Validate recovery capabilities** — test backups and DR plans under realistic conditions
6. **Map controls to framework** — maintain a current mapping of security controls to NIST CSF
7. **Measure maturity** — use NIST CSF tiers (Partial, Risk Informed, Repeatable, Adaptive)

## Evidence Collection
- Asset inventory comparison (discovered vs documented)
- Control implementation status per NIST CSF subcategory
- Vulnerability scan results mapped to Identify function gaps
- Access control test results demonstrating Protect function effectiveness
- Detection capability test results with true positive/false negative rates
- Incident response exercise reports and lessons learned
- Recovery test results with measured RTO/RPO against targets
- Maturity tier assessment per function with supporting evidence
