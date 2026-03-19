# Password Cracking Methodology

## Overview

Password cracking is used to test password strength, recover credentials from captured hashes,
and validate password policies. This guide covers methodology, tools, and techniques.

## Hash Identification

### Common Hash Formats
| Hash Prefix / Pattern | Type | Hashcat Mode |
|----------------------|------|-------------|
| `$1$` | MD5crypt | 500 |
| `$2a$` / `$2b$` | bcrypt | 3200 |
| `$5$` | SHA-256crypt | 7400 |
| `$6$` | SHA-512crypt | 1800 |
| `$y$` | yescrypt | — |
| 32 hex chars | MD5 / NTLM | 0 / 1000 |
| 40 hex chars | SHA-1 | 100 |
| 64 hex chars | SHA-256 | 1400 |

### Identify Unknown Hashes
```bash
# Using hashid
hashid '$6$rounds=5000$salt$hash'
# Using haiti
haiti 'e99a18c428cb38d5f260853678922e03'
# Using hashcat's built-in
hashcat --identify hash.txt
```

## Hashcat

### Basic Usage
```bash
# Dictionary attack
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# Dictionary + rules
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
# Brute force (mask attack) - 8 char lowercase
hashcat -m 0 hashes.txt -a 3 ?l?l?l?l?l?l?l?l
# Combinator attack
hashcat -m 0 hashes.txt -a 1 wordlist1.txt wordlist2.txt
# Show cracked results
hashcat -m 0 hashes.txt --show
```

### Useful Mask Charsets
| Charset | Description |
|---------|-----------|
| `?l` | Lowercase a-z |
| `?u` | Uppercase A-Z |
| `?d` | Digits 0-9 |
| `?s` | Special characters |
| `?a` | All printable |

### Optimized Modes
```bash
# Use optimized kernels (faster, max 32 char passwords)
hashcat -m 1000 hashes.txt wordlist.txt -O
# Use workload profile (1=low, 2=default, 3=high, 4=nightmare)
hashcat -m 1000 hashes.txt wordlist.txt -w 3
```

## John the Ripper

### Basic Usage
```bash
# Auto-detect hash type
john hashes.txt
# Specify format
john --format=raw-sha256 hashes.txt
# Wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# With rules
john --wordlist=wordlist.txt --rules=All hashes.txt
# Show cracked passwords
john --show hashes.txt
```

### Extracting Hashes
```bash
# Linux shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt
# ZIP files
zip2john protected.zip > zip_hash.txt
# Office documents
office2john document.docx > office_hash.txt
# SSH keys
ssh2john id_rsa > ssh_hash.txt
# KeePass databases
keepass2john database.kdbx > keepass_hash.txt
```

## Rainbow Tables

### Usage with RainbowCrack
```bash
# Generate rainbow table
rtgen md5 loweralpha-numeric 1 8 0 3800 33554432 0
# Sort table
rtsort *.rt
# Crack hash
rcrack *.rt -h HASH_VALUE
```

### Limitations
- Defeated by salted hashes (bcrypt, SHA-512crypt)
- Large storage requirements
- Only useful for fast hash types (MD5, NTLM, SHA-1)

## Wordlist Generation

### Custom Wordlists
```bash
# CeWL - scrape target website for words
cewl https://target.com -d 3 -m 5 -w custom_wordlist.txt
# CUPP - generate targeted wordlist from personal info
cupp -i
# Crunch - pattern-based generation
crunch 8 8 -t @@@@%%%% -o wordlist.txt
# Combine and deduplicate
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
```

### Mutation Rules
- Append/prepend numbers and years (Password2024!)
- Leet speak substitutions (p@ssw0rd)
- Capitalize first letter, add special char at end
- Keyboard walks (qwerty123, zaq1@WSX)

## Attack Strategy Priority
1. **Common passwords** - rockyou, top 1000 lists
2. **Target-specific wordlist** - CeWL scrape + OSINT-derived terms
3. **Dictionary + rules** - best64, dive, OneRuleToRuleThemAll
4. **Hybrid attack** - wordlist + mask (e.g., `word?d?d?d?s`)
5. **Pure brute force** - last resort, only for short passwords

## Tools
- **Hashcat** - GPU-accelerated hash cracking
- **John the Ripper** - versatile CPU/GPU cracker
- **CeWL** - custom wordlist generator from websites
- **CUPP** - common user password profiler
- **haiti/hashid** - hash type identification

## Remediation
- Enforce minimum 12-character passwords with complexity requirements
- Use bcrypt, scrypt, or Argon2id for password storage (never MD5/SHA-1)
- Implement account lockout or progressive delays after failed attempts
- Deploy multi-factor authentication
- Check passwords against breach databases (HaveIBeenPwned API)
