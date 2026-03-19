# GitHub / Source Code Reconnaissance

## Overview
GitHub and source code reconnaissance searches public repositories for secrets, API keys, credentials, internal URLs, and configuration data accidentally committed by target organization employees. Developers frequently commit sensitive data to version control, and even deleted commits remain accessible through Git history. This technique is one of the highest-yield passive reconnaissance methods.

## Classification
- **MITRE ATT&CK:** T1593.003 (Code Repositories), T1552.004 (Private Keys)
- **Phase:** Reconnaissance
- **Risk Level:** Passive (public repository queries only)
- **Prerequisites:** Target organization name, domain, employee GitHub usernames

## Detection Methodology

### 1. Organization Repository Discovery
Locate repositories owned by or associated with the target:
- GitHub organization page: `github.com/orgname`
- Search repositories: `org:targetorg` in GitHub search
- Employee personal repos: search by known developer usernames
- Forked repositories from target organization
- Archived and deprecated repositories (often less maintained, more secrets)
- GitHub Pages sites: `targetorg.github.io`

### 2. Secret and Credential Scanning
Search for accidentally committed secrets:
- API keys: AWS, GCP, Azure, Stripe, Twilio, SendGrid, Slack
- Database credentials: connection strings, passwords in config files
- Private keys: SSH keys, TLS certificates, PGP keys
- OAuth tokens and refresh tokens
- JWT signing secrets
- Cloud service account JSON keys
- SMTP credentials
- Webhook URLs with embedded tokens

### 3. Common Secret Patterns
```
# AWS
AKIA[0-9A-Z]{16}                          # AWS Access Key ID
[0-9a-zA-Z/+]{40}                         # AWS Secret Access Key

# GCP
AIza[0-9A-Za-z\-_]{35}                    # Google API Key
"type": "service_account"                  # GCP Service Account JSON

# Azure
[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}  # Azure Client ID pattern

# Generic
password\s*=\s*['"][^'"]+['"]             # Hardcoded passwords
api[_-]?key\s*[:=]\s*['"][^'"]+['"]       # API keys
secret\s*[:=]\s*['"][^'"]+['"]            # Secret values
token\s*[:=]\s*['"][^'"]+['"]             # Token values
private[_-]?key                            # Private keys
-----BEGIN RSA PRIVATE KEY-----            # RSA private key
-----BEGIN OPENSSH PRIVATE KEY-----        # SSH private key
jdbc:mysql://                              # Database connection strings
mongodb(\+srv)?://[^/\s]+                  # MongoDB connection strings
postgres(ql)?://[^/\s]+                    # PostgreSQL connection strings
```

### 4. Internal URL and Infrastructure Discovery
Find references to internal systems:
- Internal hostnames and IP addresses in config files
- VPN endpoints, internal API URLs, staging/dev servers
- CI/CD pipeline configurations revealing infrastructure
- Docker compose files with service architecture
- Kubernetes manifests with service names and ports
- Terraform/CloudFormation templates with resource definitions

### 5. Code Pattern Analysis
Identify security-relevant code patterns:
- Authentication bypass logic or debug flags
- Commented-out security checks
- Hard-coded admin credentials
- SQL query construction (potential injection points)
- Insecure cryptographic implementations
- Disabled SSL/TLS verification
- Default or weak configurations
- TODO/FIXME comments mentioning security issues

### 6. Git History Mining
Examine commit history for previously exposed data:
- Deleted files that contained secrets
- Commits that "removed" credentials (still in history)
- Force-pushed branches with sensitive data
- Pull request diffs containing secrets in review
- Commit messages referencing security fixes or credential rotation

### 7. CI/CD Configuration Analysis
Extract information from pipeline configurations:
- `.github/workflows/*.yml` - GitHub Actions
- `.gitlab-ci.yml` - GitLab CI
- `Jenkinsfile` - Jenkins pipelines
- `.circleci/config.yml` - CircleCI
- `buildspec.yml` - AWS CodeBuild
- Environment variables and build secrets
- Deployment targets and production URLs
- Docker image names and registry URLs

## Tool Usage

### truffleHog
```bash
# Scan a repository for secrets (regex + entropy)
trufflehog git https://github.com/target/repo.git

# Scan entire GitHub organization
trufflehog github --org=targetorg

# Scan with JSON output
trufflehog git https://github.com/target/repo.git --json > results.json

# Scan local repository
trufflehog filesystem /path/to/repo

# Scan only recent commits
trufflehog git https://github.com/target/repo.git --since-commit=abc123

# Include branch scanning
trufflehog git https://github.com/target/repo.git --branch=main

# Scan with specific detectors
trufflehog git https://github.com/target/repo.git --detector="AWS,GCP,Azure"

# Verify found credentials (test if still valid)
trufflehog git https://github.com/target/repo.git --only-verified
```

### gitleaks
```bash
# Scan a repository
gitleaks detect --source /path/to/repo -v

# Scan remote repository
gitleaks detect --source https://github.com/target/repo.git -v

# JSON report output
gitleaks detect --source /path/to/repo -f json -r results.json

# Scan specific branch
gitleaks detect --source /path/to/repo --branch main

# Scan commits within range
gitleaks detect --source /path/to/repo --log-opts="HEAD~50..HEAD"

# Use custom rules
gitleaks detect --source /path/to/repo -c custom_rules.toml

# Scan staged changes only (pre-commit)
gitleaks protect --source /path/to/repo

# Verbose with commit details
gitleaks detect --source /path/to/repo -v --report-format json
```

### gitdorker
```bash
# Search GitHub for secrets using dork patterns
python3 gitdorker.py -t YOUR_GITHUB_TOKEN -d dorks.txt -q "target.com"

# Search specific organization
python3 gitdorker.py -t YOUR_GITHUB_TOKEN -d dorks.txt -q "org:targetorg"

# Custom dork list
python3 gitdorker.py -t YOUR_GITHUB_TOKEN -d custom_dorks.txt -q "target.com"

# Output to file
python3 gitdorker.py -t YOUR_GITHUB_TOKEN -d dorks.txt -q "target.com" -o results.txt
```

### GitHub Search (manual and API)
```bash
# GitHub code search (web or API)
# Search for domain references
# https://github.com/search?q=target.com&type=code

# API search for code
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/search/code?q=target.com+password" \
  | jq '.items[].html_url'

# Search for specific file types
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/search/code?q=org:targetorg+filename:.env" \
  | jq '.items[].html_url'

# Search for specific secrets patterns
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/search/code?q=org:targetorg+AKIA" \
  | jq '.items[].html_url'

# List organization repos
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/orgs/targetorg/repos?per_page=100" \
  | jq '.[].full_name'

# List organization members
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/orgs/targetorg/members" \
  | jq '.[].login'

# Get user's public repos
curl -s -H "Authorization: token YOUR_TOKEN" \
  "https://api.github.com/users/username/repos?per_page=100" \
  | jq '.[].full_name'
```

### GitHub Dork Queries (manual)
```
# Sensitive filenames in org
org:targetorg filename:.env
org:targetorg filename:credentials
org:targetorg filename:config.json password
org:targetorg filename:docker-compose.yml
org:targetorg filename:id_rsa
org:targetorg filename:.htpasswd
org:targetorg filename:wp-config.php

# Credential patterns
org:targetorg "password" extension:yml
org:targetorg "api_key" extension:json
org:targetorg "secret_key" extension:py
org:targetorg "AWS_ACCESS_KEY_ID"
org:targetorg "PRIVATE KEY"
org:targetorg "jdbc:mysql://"

# Domain references
"target.com" "password"
"target.com" "internal"
"target.com" "staging"
"target.com" extension:sql
```

## Output Analysis Tips
- **Verify before reporting:** Leaked credentials may have been rotated. Use `trufflehog --only-verified` to test if credentials are still active.
- **Git history depth:** Secrets removed in recent commits are still in Git history. Always scan the full commit history, not just the current state.
- **Fork analysis:** Forks of private repositories sometimes become public. Check if target organization repos have been forked and if forks expose additional branches or commits.
- **Employee personal repos:** Developers often have personal projects that reference employer infrastructure, use work credentials, or contain code from internal projects.
- **CI/CD files are goldmines:** GitHub Actions workflows, Dockerfiles, and compose files reveal the full deployment architecture, internal service names, and sometimes hardcoded secrets.
- **Rate limiting:** GitHub API has rate limits (5000 requests/hour authenticated, 60/hour unauthenticated). Use authenticated requests and pace your searches.
- **Gist search:** GitHub Gists are often overlooked. Search `gist.github.com` for target-related code snippets and configuration files.
- **Archive.org for deleted repos:** If a repository was deleted, it may still be cached in the Wayback Machine or other code archive services.

## Evidence Collection
- List of all discovered repositories associated with the target
- Verified leaked credentials with affected service identification
- Internal URLs and infrastructure references found in code
- CI/CD configuration files revealing deployment architecture
- Commit hashes and file paths for each finding
- Tool output in JSON format for automated processing
- Severity assessment per finding (active credential vs. rotated)
- Repository access levels (public, organization member access)
- Timeline of secret exposure (commit date to discovery date)
- Recommendations for credential rotation per finding
