# Reconnaissance Methodology

## Phase 1: Passive Reconnaissance

### Domain Information
- WHOIS lookup for registration details
- DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME)
- Reverse DNS lookups
- Certificate Transparency logs (crt.sh)

### Subdomain Enumeration
```bash
# Passive sources
subfinder -d target.com -all
amass enum -passive -d target.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### OSINT
- theHarvester for emails, hosts, names
- Shodan/Censys for exposed services
- Google dorks for sensitive files
- GitHub/GitLab for leaked credentials

## Phase 2: Active Reconnaissance

### Port Scanning
```bash
# Fast discovery
rustscan -a target.com --ulimit 5000 -- -sV

# Thorough scan
nmap -sS -sV -sC -O -p- target.com

# UDP scan (top ports)
nmap -sU --top-ports 100 target.com
```

### Web Fingerprinting
```bash
# Technology detection
whatweb target.com
httpx -u target.com -tech-detect

# WAF detection
wafw00f target.com
```

### Directory/File Discovery
```bash
# Fast fuzzing
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,403

# Recursive
feroxbuster -u https://target.com -w wordlist.txt --depth 3
```

## Phase 3: Vulnerability Identification

### Automated Scanning
```bash
# Multi-purpose scanner
nuclei -u target.com -severity critical,high,medium

# Web-specific
nikto -h target.com

# SSL/TLS
testssl.sh target.com
```

### Manual Testing Focus Areas
- Authentication mechanisms
- Authorization controls (IDOR, privilege escalation)
- Input validation (injection points)
- Session management
- Business logic flaws
- API security
