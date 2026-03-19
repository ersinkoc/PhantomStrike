# MITRE ATT&CK Framework Integration

## Overview
The MITRE ATT&CK framework is a knowledge base of adversary tactics, techniques, and procedures (TTPs) observed in real-world attacks. This guide maps penetration testing activities to ATT&CK techniques, enables adversary emulation planning, supports detection engineering validation, and provides a structured approach to measuring technique coverage across the attack lifecycle.

## Classification
- **Framework:** MITRE ATT&CK Enterprise v15 / Mobile / ICS
- **Application:** Adversary emulation, detection validation, coverage analysis
- **Matrices:** Enterprise (Windows, Linux, macOS, Cloud, Network, Containers)

## Methodology

### Tactic-to-Tool Mapping

#### TA0043 — Reconnaissance
```
Technique                        Tools
────────────────────────────     ─────────────────────────────
T1595 — Active Scanning          nmap, masscan, naabu
T1592 — Gather Victim Host Info  Shodan, Censys, nmap -sV
T1589 — Gather Victim Identity   theHarvester, LinkedIn, OSINT
T1591 — Gather Victim Org Info   OSINT, Maltego, Recon-ng
T1593 — Search Open Websites     Google dorking, GitHub search
T1596 — Search Open Databases    Shodan, Censys, crt.sh
T1597 — Search Closed Sources    Breach databases, dark web
```

#### TA0042 — Resource Development
```
T1583 — Acquire Infrastructure   Cloud providers, domain registrars
T1587 — Develop Capabilities     Metasploit, custom payloads
T1588 — Obtain Capabilities      ExploitDB, GitHub PoCs
T1585 — Establish Accounts       Social media, email providers
T1608 — Stage Capabilities       Web hosting, C2 infrastructure
```

#### TA0001 — Initial Access
```
T1190 — Exploit Public-Facing    sqlmap, nuclei, Metasploit
T1078 — Valid Accounts           Hydra, credential stuffing tools
T1566 — Phishing                 Gophish, SET, King Phisher
T1133 — External Remote Svcs     VPN/RDP testing, nmap
T1189 — Drive-by Compromise      BeEF, custom exploit pages
T1195 — Supply Chain Compromise  Dependency confusion tools
```

#### TA0002 — Execution
```
T1059 — Command/Script Interp    PowerShell, bash, Python payloads
T1203 — Exploitation for Client  Browser exploits, document macros
T1204 — User Execution           Phishing payloads, HTA, LNK files
T1047 — WMI                      wmic, Impacket wmiexec
T1053 — Scheduled Task/Job       schtasks, cron, at
```

#### TA0003 — Persistence
```
T1053 — Scheduled Task/Job       schtasks, crontab
T1136 — Create Account           net user, useradd
T1547 — Boot/Logon Autostart     Registry run keys, startup folders
T1543 — Create/Modify Sys Proc   Service creation, systemd units
T1505 — Server Software Comp     Web shells (ASPX, PHP, JSP)
T1098 — Account Manipulation     Azure AD, AWS IAM modifications
```

#### TA0004 — Privilege Escalation
```
T1068 — Exploitation for Priv    Linux kernel exploits, Windows LPE
T1548 — Abuse Elevation Control  UAC bypass, sudo misconfig
T1134 — Access Token Manip       Token impersonation, Incognito
T1078 — Valid Accounts           Cached credentials, credential files
T1055 — Process Injection        DLL injection, process hollowing
```

#### TA0005 — Defense Evasion
```
T1027 — Obfuscated Files/Info    Packers, encoders, crypters
T1070 — Indicator Removal        Log clearing, timestomp
T1036 — Masquerading             Filename/extension spoofing
T1562 — Impair Defenses          Disable AV, tamper with EDR
T1218 — System Binary Proxy      LOLBins (mshta, certutil, rundll32)
```

#### TA0006 — Credential Access
```
T1003 — OS Credential Dumping    Mimikatz, secretsdump, pypykatz
T1110 — Brute Force              Hydra, Medusa, CrackMapExec
T1555 — Credentials from Stores  Browser credential extraction
T1552 — Unsecured Credentials    Config files, scripts, environment vars
T1558 — Steal Kerberos Tickets   Rubeus, Impacket, GetUserSPNs
T1557 — Adversary-in-the-Middle  Responder, mitm6, Bettercap
```

#### TA0007 — Discovery
```
T1046 — Network Service Scan     nmap, masscan
T1082 — System Info Discovery    systeminfo, uname -a
T1083 — File and Dir Discovery   dir, find, ls
T1087 — Account Discovery        net user, ldapsearch, BloodHound
T1016 — System Network Config    ipconfig, ifconfig, route
T1018 — Remote System Discovery  ping sweep, net view, ARP
```

#### TA0008 — Lateral Movement
```
T1021 — Remote Services           PsExec, SSH, RDP, WinRM
T1091 — Replication Through       USB, shared drives
T1210 — Exploit Remote Services   EternalBlue, BlueKeep, Log4Shell
T1550 — Use Alternate Auth        Pass-the-Hash, Pass-the-Ticket
T1570 — Lateral Tool Transfer     SMB, SCP, certutil download
```

#### TA0009 — Collection
```
T1005 — Data from Local System    Manual file search, automated scripts
T1039 — Data from Network Share   SMB share enumeration
T1114 — Email Collection          Exchange, mail spool access
T1119 — Automated Collection      Scripts for bulk data gathering
T1560 — Archive Collected Data    7z, tar, zip for staging
```

#### TA0011 — Command and Control
```
T1071 — Application Layer Proto   HTTP/S, DNS C2 channels
T1572 — Protocol Tunneling        SSH tunnels, DNS tunneling
T1573 — Encrypted Channel         HTTPS, custom encrypted C2
T1105 — Ingress Tool Transfer     certutil, wget, curl, bitsadmin
T1090 — Proxy                     SOCKS, port forwarding, Chisel
```

#### TA0010 — Exfiltration
```
T1041 — Exfil Over C2 Channel     Standard C2 data transfer
T1048 — Exfil Over Alt Protocol   DNS, ICMP, SMTP exfiltration
T1567 — Exfil to Cloud Storage    S3, Google Drive, Dropbox upload
T1029 — Scheduled Transfer        Timed data exfiltration
T1537 — Transfer to Cloud Acct    Cross-account cloud transfer
```

#### TA0040 — Impact
```
T1486 — Data Encrypted for Impact Ransomware simulation (safe)
T1489 — Service Stop              Service disruption testing
T1529 — System Shutdown/Reboot    Availability impact assessment
T1531 — Account Access Removal    Account lockout testing
```

## Adversary Emulation Planning
```
1. Select adversary profile
   - Choose threat actor relevant to organization's sector
   - Reference ATT&CK Groups (APT28, APT29, Lazarus, FIN7, etc.)
   - Map their known techniques from ATT&CK Navigator

2. Build emulation plan
   - Sequence techniques following real attack chains
   - Initial Access → Execution → Persistence → Priv Esc → Lateral Movement
   - Include detection checkpoints at each phase

3. Execute with tooling
   - Atomic Red Team for individual technique testing
   - MITRE Caldera for automated adversary emulation
   - Manual testing for complex multi-step chains

4. Measure detection coverage
   - Record which techniques were detected vs missed
   - Identify gaps in visibility by tactic
   - Map gaps to specific data sources needed
```

### Atomic Red Team Execution
```bash
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Run specific technique test
Invoke-AtomicTest T1003.001  # OS Credential Dumping: LSASS Memory

# Run all tests for a tactic
Invoke-AtomicTest T1059 -TestNumbers 1,2,3

# Cleanup after testing
Invoke-AtomicTest T1003.001 -Cleanup
```

## Detection Engineering

### Data Source Mapping
```
To detect a technique, ensure the required data sources are collected:

Technique                    Required Data Sources
─────────────────────────    ──────────────────────────────────
T1003 — Credential Dump     Process monitoring, API monitoring, LSASS access
T1059 — Command Interp      Process creation, script block logging, command-line
T1021 — Remote Services     Authentication logs, network flow, process creation
T1547 — Boot Autostart      Registry monitoring, file creation, service creation
T1190 — Exploit Public App  Web server logs, IDS/IPS, WAF logs
```

### Detection Rule Development
```
For each ATT&CK technique:
1. Identify required log sources and telemetry
2. Develop detection logic (Sigma, YARA, Snort/Suricata rules)
3. Test detection against emulated technique
4. Measure true positive rate and false positive rate
5. Tune detection to minimize noise
6. Document in detection catalog with ATT&CK reference
```

## Coverage Analysis
```
1. Export current detections mapped to ATT&CK techniques
2. Overlay on ATT&CK Navigator heatmap
3. Identify coverage gaps by tactic and technique
4. Prioritize gaps based on:
   - Threat actor relevance to organization
   - Technique prevalence in real attacks
   - Feasibility of detection with current data sources
5. Develop roadmap to close highest-priority gaps
```

## Remediation
1. **Achieve full visibility** across all ATT&CK data sources relevant to your environment
2. **Prioritize detection by threat profile** — focus on techniques used by adversaries targeting your sector
3. **Layer detections across the kill chain** — do not rely on a single tactic for detection
4. **Test detections regularly** — use adversary emulation to validate detection rules
5. **Maintain detection-to-technique mapping** — update as ATT&CK framework evolves
6. **Implement preventive controls** for high-impact techniques that are hard to detect
7. **Share threat intelligence** — contribute and consume community detection content

## Evidence Collection
- ATT&CK Navigator heatmap showing technique coverage before and after testing
- Detection gap analysis with prioritized remediation roadmap
- Adversary emulation results with per-technique detection outcomes
- Log source inventory mapped to ATT&CK data sources
- Detection rule catalog with ATT&CK technique references
- Timeline of emulated attack chain with detection/miss annotations
