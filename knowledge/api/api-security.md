# API Security Testing Guide

## Overview

APIs (REST, GraphQL, gRPC) are primary attack surfaces for modern applications. Testing
covers authentication bypass, authorization flaws, injection, and business logic vulnerabilities.

## REST API Testing

### Reconnaissance
```bash
# Discover endpoints from OpenAPI/Swagger
curl https://target.com/swagger.json
curl https://target.com/api-docs
curl https://target.com/.well-known/openapi.json
# Fuzz for hidden endpoints
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/api-endpoints.txt -mc 200,301,403
```

### Authentication Bypass
- Test endpoints without Authorization header
- Try expired, malformed, or empty JWTs
- Check for JWT algorithm confusion (change RS256 to HS256)
- Test API key in URL parameter vs header
- Look for unauthenticated admin/debug endpoints

### JWT Attacks
```bash
# Decode JWT
echo "JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Test "none" algorithm
python3 jwt_tool.py TOKEN -X a
# Brute-force HMAC secret
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt
# Test key confusion (RS256 -> HS256)
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

### Authorization Testing (BOLA/IDOR)
```bash
# Test accessing other users' resources by changing IDs
curl -H "Authorization: Bearer USER_A_TOKEN" https://target.com/api/users/USER_B_ID
# Test sequential ID enumeration
for id in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} $id\n" \
    -H "Authorization: Bearer TOKEN" https://target.com/api/orders/$id
done
```

### Mass Assignment
```json
// Try adding privileged fields in request body
POST /api/users
{
  "name": "test",
  "email": "test@test.com",
  "role": "admin",
  "is_admin": true,
  "verified": true
}
```

## GraphQL Testing

### Introspection
```bash
# Full introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'
```

### Common GraphQL Attacks
- **Batching**: send multiple queries in one request to bypass rate limiting
- **Nested queries**: cause denial of service with deeply nested relationships
- **Field suggestions**: leak field names from error messages
- **Mutation abuse**: modify data through undocumented mutations

### GraphQL Tools
```bash
# InQL - Burp extension or standalone
inql -t https://target.com/graphql
# graphql-voyager for schema visualization
# Clairvoyance for schema recovery when introspection is disabled
clairvoyance -o schema.json https://target.com/graphql
```

## Rate Limiting Bypass
- Rotate IP addresses via headers: `X-Forwarded-For`, `X-Real-IP`
- Change case in URL paths (`/Api/Login` vs `/api/login`)
- Add query parameters (`/api/login?cachebust=1`)
- Use HTTP method override headers (`X-HTTP-Method-Override`)
- Unicode normalization tricks in parameters

## Input Validation
- SQL injection in filter/sort parameters
- NoSQL injection in JSON bodies (`{"$gt": ""}`)
- SSRF via URL parameters that fetch remote resources
- XXE in XML-accepting endpoints
- Command injection in file processing endpoints

## Tools
- **Burp Suite** - comprehensive API testing proxy
- **jwt_tool** - JWT analysis and attack toolkit
- **Postman/Insomnia** - API client for manual testing
- **ffuf** - endpoint fuzzing
- **Arjun** - HTTP parameter discovery
- **Kiterunner** - API endpoint discovery

## Remediation
- Implement proper authentication on all endpoints (no security by obscurity)
- Use authorization checks at the object level (prevent BOLA/IDOR)
- Validate and sanitize all input server-side
- Disable GraphQL introspection in production
- Implement rate limiting and request throttling
- Use allowlists for mass-assignment protection
- Return minimal error information to prevent information disclosure
