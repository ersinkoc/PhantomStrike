# Port Scanning Reference

## Common Service Ports

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Check for anonymous access |
| 22 | SSH | Check version, auth methods |
| 23 | Telnet | Cleartext, avoid in production |
| 25 | SMTP | Check for open relay |
| 53 | DNS | Zone transfer, amplification |
| 80 | HTTP | Web server |
| 110 | POP3 | Email retrieval |
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | Windows file sharing |
| 143 | IMAP | Email |
| 443 | HTTPS | Secure web |
| 445 | SMB | Windows shares, EternalBlue |
| 993 | IMAPS | Secure IMAP |
| 995 | POP3S | Secure POP3 |
| 1433 | MSSQL | Microsoft SQL Server |
| 1521 | Oracle | Oracle DB |
| 3306 | MySQL | MySQL/MariaDB |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL DB |
| 5900 | VNC | Virtual Network Computing |
| 6379 | Redis | In-memory store |
| 8080 | HTTP-Alt | Alternative web/proxy |
| 8443 | HTTPS-Alt | Alternative HTTPS |
| 27017 | MongoDB | NoSQL database |

## Nmap Scan Types

### TCP SYN Scan (default, requires root)
```bash
nmap -sS target
```

### TCP Connect Scan (no root needed)
```bash
nmap -sT target
```

### Service Version Detection
```bash
nmap -sV target
```

### OS Detection
```bash
nmap -O target
```

### Script Scan (default scripts)
```bash
nmap -sC target
```

### Comprehensive Scan
```bash
nmap -sS -sV -sC -O -p- -T4 target
```

### Vulnerability Scanning
```bash
nmap --script vuln target
```

## Output Interpretation
- **open**: Port is accepting connections
- **closed**: Port is accessible but no service listening
- **filtered**: Firewall blocking, cannot determine state
- **open|filtered**: Cannot determine between open and filtered
