# Incident Response Checklist

## Overview

Incident response is the structured approach to handling security breaches and attacks.
This checklist guides an agent through the phases of identification, containment, eradication,
and recovery, with practical commands for evidence collection.

## Phase 1: Identification

### Confirm the Incident
- Validate alerts from SIEM/IDS/EDR - distinguish true positives from false positives
- Determine scope: which systems, users, and data are affected
- Classify severity: critical, high, medium, low
- Document the initial timeline of events

### Initial Evidence Collection (Linux)
```bash
# System snapshot
date && hostname && uname -a
# Current users and sessions
w && who && last -20
# Running processes (full command lines)
ps auxww --forest
# Network connections
ss -tlnp && ss -tunp
# Open files
lsof -i -P
# Recent file modifications (last 24 hours)
find / -mtime -1 -type f 2>/dev/null | head -100
# Check for unusual cron jobs
for user in $(cut -d: -f1 /etc/passwd); do crontab -u $user -l 2>/dev/null; done
```

### Initial Evidence Collection (Windows)
```powershell
# System info
systeminfo
Get-ComputerInfo
# Logged-in users
query user
# Running processes with command lines
Get-WmiObject Win32_Process | Select ProcessId,Name,CommandLine
# Network connections
netstat -ano
Get-NetTCPConnection | Where-Object State -eq 'Established'
# Recent event log entries
Get-EventLog -LogName Security -Newest 50
Get-EventLog -LogName System -Newest 50
# Scheduled tasks
schtasks /query /fo LIST /v
```

## Phase 2: Containment

### Short-Term Containment
- Isolate affected systems from the network (do NOT power off)
- Block attacker IPs at firewall/WAF
- Disable compromised user accounts
- Revoke compromised API keys and tokens

### Network Isolation Commands
```bash
# Linux - drop all traffic except management
iptables -I INPUT -s MANAGEMENT_IP -j ACCEPT
iptables -I OUTPUT -d MANAGEMENT_IP -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
# Block specific attacker IP
iptables -I INPUT -s ATTACKER_IP -j DROP
```

### Long-Term Containment
- Apply temporary patches or mitigations
- Redirect DNS for compromised domains
- Enable enhanced logging and monitoring on adjacent systems
- Create forensic images before remediation

## Phase 3: Eradication

### Malware Analysis
```bash
# Hash suspicious files
sha256sum /path/to/suspicious_file
# Check against VirusTotal
curl -s "https://www.virustotal.com/api/v3/files/SHA256_HASH" -H "x-apikey: API_KEY"
# Strings analysis
strings -a suspicious_file | less
# Check running processes for known malware indicators
ls -la /proc/*/exe 2>/dev/null | grep deleted
```

### Persistence Removal (Linux)
```bash
# Check and clean cron jobs
crontab -l && crontab -r
# Check systemd services
systemctl list-unit-files --type=service | grep enabled
# Check init scripts
ls -la /etc/init.d/ /etc/rc.local
# Check authorized SSH keys
find / -name "authorized_keys" -exec cat {} \;
# Check for rootkits
chkrootkit
rkhunter --check
```

### Persistence Removal (Windows)
```powershell
# Check autoruns (use Sysinternals Autoruns)
autorunsc -a * -c -h
# Check services
Get-Service | Where-Object {$_.Status -eq 'Running'}
# Check startup registry keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}
```

## Phase 4: Recovery

### System Restoration
- Rebuild compromised systems from known-good images
- Restore data from verified clean backups
- Reset all credentials (passwords, keys, tokens, certificates)
- Gradually reconnect systems to the network with monitoring

### Validation
- Verify systems are clean with updated AV/EDR scans
- Confirm no unauthorized access persists
- Test all restored services for proper functionality
- Monitor closely for 48-72 hours post-recovery

## Phase 5: Lessons Learned

### Post-Incident Activities
- Conduct timeline reconstruction with all evidence
- Write incident report with root cause analysis
- Identify security gaps that allowed the incident
- Update detection rules and playbooks
- Conduct tabletop exercises based on the incident

## Evidence Preservation

### Chain of Custody
```bash
# Create forensic disk image
dd if=/dev/sda of=/evidence/disk.img bs=4M status=progress
# Hash the image for integrity
sha256sum /evidence/disk.img > /evidence/disk.img.sha256
# Capture volatile memory
avml /evidence/memory.lime
# Package with timestamps
tar czf evidence_$(date +%Y%m%d_%H%M%S).tar.gz /evidence/
```

## Tools
- **Velociraptor** - endpoint visibility and forensic collection
- **KAPE** - Kroll artifact parser and extractor (Windows)
- **Volatility** - memory forensics framework
- **TheHive** - incident response platform
- **AVML** - Linux memory acquisition
- **Autoruns** - Windows persistence analysis (Sysinternals)
- **osquery** - cross-platform endpoint visibility

## Key Principles
- Preserve evidence before remediation - never modify original data
- Document every action taken with timestamps
- Maintain chain of custody for all evidence
- Communicate through established channels (assume attacker may monitor)
- Do not alert the attacker during investigation if possible
