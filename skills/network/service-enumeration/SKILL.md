# Service Enumeration Testing

## Overview
Service enumeration is the process of actively probing discovered network services to extract detailed information such as version numbers, supported features, user accounts, shares, databases, and configuration details. It goes beyond port scanning by deeply interrogating each service to identify potential misconfigurations, default credentials, and exploitable weaknesses. Thorough enumeration often reveals the path to initial access without needing sophisticated exploits.

## Classification
- **CWE:** CWE-200 (Exposure of Sensitive Information), CWE-16 (Configuration), CWE-284 (Improper Access Control)
- **MITRE ATT&CK:** T1046 (Network Service Scanning), T1087 (Account Discovery), T1135 (Network Share Discovery), T1069 (Permission Groups Discovery)
- **CVSS Base:** Informational to High (varies by service exposure)

## Detection Methodology

### 1. SMB Enumeration (TCP 139/445)
```bash
# Enumerate shares, users, groups, policies
enum4linux -a target
enum4linux-ng -A target

# List shares
smbclient -L //target -N
smbclient -L //target -U user%password
crackmapexec smb target -u '' -p '' --shares

# Connect to share
smbclient //target/share -N
smbclient //target/share -U user%password

# Enumerate with nmap
nmap --script=smb-enum-shares,smb-enum-users,smb-enum-groups,smb-os-discovery -p 445 target
nmap --script=smb-vuln-* -p 445 target

# SMB version detection
nmap --script=smb-protocols -p 445 target
nmap --script=smb2-security-mode -p 445 target

# Recursive file listing
smbmap -H target -u user -p password -R
crackmapexec smb target -u user -p password --spider share

# Null session check
rpcclient -U "" target -N
rpcclient -U "" target -N -c "enumdomusers"
rpcclient -U "" target -N -c "enumdomgroups"
rpcclient -U "" target -N -c "querydominfo"
```

### 2. FTP Enumeration (TCP 21)
```bash
# Anonymous login check
ftp target
# Username: anonymous, Password: (blank or email)

# Nmap FTP scripts
nmap --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p 21 target

# Banner grabbing
nc -nv target 21

# Brute force
hydra -L users.txt -P passwords.txt ftp://target
medusa -h target -U users.txt -P passwords.txt -M ftp

# Recursive directory listing
wget -r --no-passive ftp://anonymous:anon@target/
```

### 3. SSH Enumeration (TCP 22)
```bash
# Banner and algorithm enumeration
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 target

# SSH audit
ssh-audit target

# User enumeration (CVE-2018-15473, older OpenSSH)
python3 ssh_user_enum.py target -U users.txt

# Brute force
hydra -L users.txt -P passwords.txt ssh://target
crackmapexec ssh target -u users.txt -p passwords.txt

# Check for weak keys
nmap --script=ssh-publickey-acceptance -p 22 target
```

### 4. SMTP Enumeration (TCP 25/465/587)
```bash
# User enumeration via VRFY/EXPN/RCPT
smtp-user-enum -M VRFY -U users.txt -t target
smtp-user-enum -M EXPN -U users.txt -t target
smtp-user-enum -M RCPT -U users.txt -t target

# Nmap SMTP scripts
nmap --script=smtp-commands,smtp-enum-users,smtp-open-relay -p 25 target

# Manual SMTP interaction
nc -nv target 25
EHLO test.com
VRFY admin
EXPN admin

# Open relay test
nmap --script=smtp-open-relay -p 25 target
```

### 5. SNMP Enumeration (UDP 161/162)
```bash
# Community string brute force
onesixtyone -c community_strings.txt target
hydra -P community_strings.txt target snmp

# Walk SNMP tree
snmpwalk -c public -v2c target
snmpwalk -c public -v2c target 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -c public -v2c target 1.3.6.1.2.1.25.6.3.1.2  # Installed software
snmpwalk -c public -v2c target 1.3.6.1.4.1.77.1.2.25    # User accounts (Windows)
snmpwalk -c public -v2c target 1.3.6.1.2.1.6.13.1.3     # TCP open ports

# Nmap SNMP scripts
nmap --script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr -sU -p 161 target

# snmp-check (detailed info)
snmp-check target -c public
```

### 6. LDAP Enumeration (TCP 389/636)
```bash
# Anonymous bind enumeration
ldapsearch -x -H ldap://target -b "DC=corp,DC=local"
ldapsearch -x -H ldap://target -s base namingcontexts

# Authenticated LDAP search
ldapsearch -x -H ldap://target -D "user@corp.local" -w password -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Nmap LDAP scripts
nmap --script=ldap-rootdse,ldap-search -p 389 target

# windapsearch
windapsearch --dc target -d corp.local -u user -p password --da
windapsearch --dc target -d corp.local -u user -p password --users --full
windapsearch --dc target -d corp.local -u user -p password --computers
```

### 7. NFS Enumeration (TCP/UDP 2049)
```bash
# Show exported shares
showmount -e target

# Nmap NFS scripts
nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 target

# Mount NFS share
mkdir /tmp/nfs_mount
mount -t nfs target:/share /tmp/nfs_mount
mount -t nfs -o nolock target:/share /tmp/nfs_mount

# Check for root squashing
# If no_root_squash is set, root on client = root on NFS
```

### 8. RPC Enumeration (TCP 111/135)
```bash
# Linux RPC (portmapper)
rpcinfo -p target
nmap --script=rpc-grind,rpcinfo -p 111 target

# Windows RPC
rpcclient -U "" target -N
rpcclient -U user%password target
# Useful commands: enumdomusers, enumdomgroups, queryuser, lookupnames, lsaenumsid

# Impacket RPC tools
impacket-rpcdump target
impacket-samrdump target
impacket-lookupsid corp.local/user:password@target
```

### 9. MySQL Enumeration (TCP 3306)
```bash
# Remote login
mysql -h target -u root -p
mysql -h target -u root

# Nmap MySQL scripts
nmap --script=mysql-info,mysql-enum,mysql-databases,mysql-empty-password -p 3306 target

# Brute force
hydra -L users.txt -P passwords.txt target mysql
medusa -h target -U users.txt -P passwords.txt -M mysql

# Version detection
nmap -sV -p 3306 target
```

### 10. MSSQL Enumeration (TCP 1433)
```bash
# Impacket MSSQL client
impacket-mssqlclient sa:password@target
impacket-mssqlclient corp.local/user:password@target -windows-auth

# Nmap MSSQL scripts
nmap --script=ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info -p 1433 target

# Brute force
hydra -L users.txt -P passwords.txt target mssql
crackmapexec mssql target -u users.txt -p passwords.txt

# Enumerate with crackmapexec
crackmapexec mssql target -u sa -p password --local-auth -q "SELECT name FROM sys.databases"

# Enable xp_cmdshell for command execution
impacket-mssqlclient sa:password@target
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### 11. PostgreSQL Enumeration (TCP 5432)
```bash
# Remote login
psql -h target -U postgres
psql -h target -U postgres -d database_name

# Nmap PostgreSQL scripts
nmap --script=pgsql-brute -p 5432 target

# Brute force
hydra -L users.txt -P passwords.txt target postgres
medusa -h target -U users.txt -P passwords.txt -M postgres

# List databases (after login)
\l
# List tables
\dt
# Current user
SELECT current_user;
# Read files (superuser)
SELECT pg_read_file('/etc/passwd');
```

### 12. Redis Enumeration (TCP 6379)
```bash
# Connect (often no auth required)
redis-cli -h target
redis-cli -h target -a password

# Information gathering
redis-cli -h target INFO
redis-cli -h target CONFIG GET *
redis-cli -h target DBSIZE
redis-cli -h target CLIENT LIST

# Nmap Redis scripts
nmap --script=redis-info -p 6379 target

# Key enumeration
redis-cli -h target KEYS *
redis-cli -h target GET key_name
```

### 13. MongoDB Enumeration (TCP 27017)
```bash
# Connect without auth
mongosh --host target

# Nmap MongoDB scripts
nmap --script=mongodb-info,mongodb-databases -p 27017 target

# Enumerate databases and collections
mongosh --host target --eval "db.adminCommand('listDatabases')"
mongosh --host target --eval "db.getCollectionNames()"

# Brute force
nmap --script=mongodb-brute -p 27017 target
```

## Tool Usage

### Comprehensive Enumeration Approach
```bash
# AutoRecon (automated multi-service enumeration)
autorecon target

# Reconnoitre
reconnoitre -t target -o output_dir --services

# Legion (GUI-based)
legion

# nmapAutomator
./nmapAutomator.sh target All
```

## Remediation
1. **Disable anonymous access** -- require authentication on all services (SMB, FTP, LDAP, Redis, MongoDB)
2. **Remove default credentials** -- change all default usernames and passwords
3. **Restrict service exposure** -- bind services to specific interfaces, use firewall rules
4. **Disable unnecessary features** -- turn off SNMP if unused, disable SMTP VRFY/EXPN
5. **Enforce encryption** -- use TLS/SSL for all service communications
6. **Access control lists** -- restrict which hosts can connect to each service
7. **Audit service configurations** -- regularly review NFS exports, SMB shares, database permissions
8. **Version patching** -- keep all services updated to prevent known exploit attacks
9. **Logging and monitoring** -- enable authentication logs, detect brute force attempts

## Evidence Collection
When documenting service enumeration findings:
- Complete list of services with versions and configurations
- Shares, databases, or resources accessible without authentication
- User accounts discovered through enumeration
- Default or weak credentials found
- Sensitive data exposed through service misconfiguration
- SNMP community strings discovered
- Nmap and tool output files for each service
- Recommendations prioritized by severity and exploitability
