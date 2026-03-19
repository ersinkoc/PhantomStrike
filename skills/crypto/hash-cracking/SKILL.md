# Hash Cracking

## Overview
Hash cracking is the process of recovering plaintext passwords or data from their cryptographic hash representations. This encompasses hash identification, offline cracking using wordlists and rules, rainbow table lookups, GPU-accelerated attacks, and targeted approaches for common hash types including MD5, SHA family, bcrypt, NTLM, and NTLMv2. Hash cracking is essential for password auditing, credential recovery during penetration tests, and validating password policy enforcement.

## Classification
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort), CWE-328 (Use of Weak Hash), CWE-759 (Use of a One-Way Hash without a Salt), CWE-760 (Use of a One-Way Hash with a Predictable Salt)
- **OWASP:** A02:2021 - Cryptographic Failures, A07:2021 - Identification and Authentication Failures
- **CVSS Base:** 5.3 - 7.5 (Medium to High)
- **MITRE ATT&CK:** T1110.002 (Password Cracking)

## Hash Identification

### Common Hash Formats
```
MD5:           32 hex chars         → 5d41402abc4b2a76b9719d911017c592
SHA-1:         40 hex chars         → aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA-256:       64 hex chars         → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e...
SHA-512:       128 hex chars        → cf83e1357eefb8bd...
NTLM:          32 hex chars         → a4f49c406510bdca... (no salt, fast)
NTLMv2:        variable             → user::domain:challenge:hmac:blob
bcrypt:        $2a$/$2b$/$2y$ prefix → $2a$12$LJ3m4ys3Lg...
scrypt:        $scrypt$ prefix      → $scrypt$ln=17,r=8,p=1$...
Argon2:        $argon2id$ prefix    → $argon2id$v=19$m=65536,t=3,p=4$...
MySQL 4.1+:    *<40 hex>            → *6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
PostgreSQL MD5: md5 + 32 hex        → md535d41402abc4b2a76b9719d911017c592
MSSQL:         0x0100 prefix        → 0x0100...
LM:            32 hex chars         → aad3b435b51404eeaad3b435b51404ee (split 7+7)
descrypt:      13 chars             → rEK1ecacw.7.c
md5crypt:      $1$ prefix           → $1$salt$hash
sha256crypt:   $5$ prefix           → $5$rounds=5000$salt$hash
sha512crypt:   $6$ prefix           → $6$rounds=5000$salt$hash
Kerberos TGS:  $krb5tgs$23$*       → (Kerberoasting)
Kerberos AS-REP: $krb5asrep$23$    → (AS-REP roasting)
```

### Hash Identification Tools
```bash
# hashid
hashid '<hash_value>'
hashid -m '<hash_value>'    # show hashcat mode number

# hash-identifier (Python)
hash-identifier

# haiti
haiti '<hash_value>'

# Name-That-Hash
nth --text '<hash_value>'
```

## Hashcat Modes (Common)
```
Mode   Type                        Example
─────────────────────────────────────────────────────
0      MD5                         hashcat -m 0
100    SHA-1                       hashcat -m 100
1400   SHA-256                     hashcat -m 1400
1700   SHA-512                     hashcat -m 1700
1000   NTLM                       hashcat -m 1000
5600   NTLMv2                      hashcat -m 5600
3200   bcrypt                      hashcat -m 3200
500    md5crypt ($1$)              hashcat -m 500
1800   sha512crypt ($6$)           hashcat -m 1800
7400   sha256crypt ($5$)           hashcat -m 7400
13100  Kerberos TGS-REP (23)      hashcat -m 13100
18200  Kerberos AS-REP (23)       hashcat -m 18200
300    MySQL 4.1+                  hashcat -m 300
1731   MSSQL 2012/2014            hashcat -m 1731
3000   LM                         hashcat -m 3000
5500   NetNTLMv1                  hashcat -m 5500
16500  JWT (HS256)                hashcat -m 16500
11300  Bitcoin wallet             hashcat -m 11300
13400  KeePass                    hashcat -m 13400
```

## Tool Usage

### Hashcat
```bash
# Dictionary attack
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/dive.rule

# Brute force (mask attack)
hashcat -m 0 hashes.txt -a 3 '?a?a?a?a?a?a?a?a'     # 8 char all
hashcat -m 0 hashes.txt -a 3 '?u?l?l?l?l?d?d?d'      # Ullllddd pattern
hashcat -m 0 hashes.txt -a 3 '?d?d?d?d?d?d'           # 6 digit PIN

# Custom charset
hashcat -m 0 hashes.txt -a 3 -1 '?l?d' '?1?1?1?1?1?1?1?1'

# Combinator attack (word1 + word2)
hashcat -m 0 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Hybrid (wordlist + mask)
hashcat -m 0 hashes.txt -a 6 wordlist.txt '?d?d?d?d'   # word + 4 digits
hashcat -m 0 hashes.txt -a 7 '?d?d?d?d' wordlist.txt   # 4 digits + word

# GPU optimization
hashcat -m 1000 hashes.txt wordlist.txt -O -w 3         # optimized kernels, high workload

# Show cracked results
hashcat -m 0 hashes.txt --show

# Restore interrupted session
hashcat --restore

# Hashcat mask charsets:
# ?l = a-z, ?u = A-Z, ?d = 0-9, ?s = special, ?a = all, ?b = 0x00-0xff
```

### John the Ripper
```bash
# Auto-detect hash and crack
john hashes.txt

# Specify format
john --format=raw-md5 hashes.txt
john --format=raw-sha256 hashes.txt
john --format=nt hashes.txt
john --format=bcrypt hashes.txt
john --format=krb5tgs hashes.txt

# Wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Wordlist with rules
john --wordlist=wordlist.txt --rules=All hashes.txt
john --wordlist=wordlist.txt --rules=Jumbo hashes.txt
john --wordlist=wordlist.txt --rules=KoreLogic hashes.txt

# Incremental (brute force)
john --incremental hashes.txt
john --incremental=Digits hashes.txt

# Show cracked passwords
john --show hashes.txt

# List supported formats
john --list=formats

# Custom rules (john.conf)
# [List.Rules:CustomRule]
# Az"[0-9][0-9]"    → append two digits
# c                  → capitalize first letter
# $[!@#$%]           → append special character
```

### Rainbow Tables
```bash
# Generate rainbow tables with rtgen
rtgen md5 loweralpha-numeric 1 8 0 3800 33554432 0

# Sort tables
rtsort *.rt

# Crack with rcrack
rcrack /path/to/tables/ -h <hash_value>
rcrack /path/to/tables/ -l hashes.txt

# Online rainbow table lookup
# https://crackstation.net
# https://hashes.com
# https://cmd5.org
```

### Wordlist Generation
```bash
# CeWL — extract words from target website
cewl https://target.com -d 3 -m 5 -w custom_wordlist.txt

# CUPP — generate targeted wordlist from user profile
cupp -i    # interactive mode (name, birthday, pet, etc.)

# Crunch — generate all combinations
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt
crunch 6 6 -t @@%%^^ -o wordlist.txt    # pattern: 2 lower, 2 digit, 2 special

# Mentalist — GUI-based wordlist generator (chain transformations)

# Combine and deduplicate
sort -u wordlist1.txt wordlist2.txt > combined.txt
```

## GPU Cracking Performance (Approximate, Single RTX 4090)
```
MD5:          ~164 GH/s
NTLM:         ~300 GH/s
SHA-1:        ~27 GH/s
SHA-256:      ~11 GH/s
bcrypt ($2a$12): ~185 KH/s
scrypt:       ~2.4 MH/s
Argon2:       very slow (by design)
```

## Remediation
1. **Use strong adaptive hashing** -- bcrypt, scrypt, or Argon2id for passwords
2. **Use unique per-user salts** -- minimum 16 bytes, cryptographically random
3. **Set adequate cost factors** -- bcrypt cost 12+, Argon2 tuned to ~1 second
4. **Enforce strong password policies** -- minimum 12 characters, check against breach databases
5. **Implement account lockout and rate limiting** to slow online attacks
6. **Never use MD5, SHA-1, or unsalted hashes** for password storage
7. **Pepper passwords** -- add a server-side secret to the hash input
8. **Monitor for credential dumps** -- integrate with HaveIBeenPwned API
9. **Educate users** on passphrases and password managers

## Evidence Collection
When documenting hash cracking findings:
- Hash type identified and algorithm weakness classification
- Number of hashes obtained and source (database dump, SAM file, NTDS.dit)
- Number and percentage of hashes cracked within a time limit
- Cracking methodology used (wordlist, rules, brute force, rainbow tables)
- Time taken to crack with hardware specification noted
- Password complexity distribution of cracked passwords
- Weak password patterns discovered (company name + year, seasonal patterns)
- Recommendations mapped to specific password policy gaps
