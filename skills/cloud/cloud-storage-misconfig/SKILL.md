# Cloud Storage Misconfiguration Testing

## Overview
Cloud storage misconfiguration testing identifies publicly accessible or improperly secured storage resources across cloud providers. Misconfigured storage buckets and containers are one of the most common sources of data breaches, exposing sensitive files such as backups, credentials, PII, and proprietary data to unauthorized access.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.3 - 9.1 (High when sensitive data exposed)
- **MITRE ATT&CK:** T1530 (Data from Cloud Storage Object), T1619 (Cloud Storage Object Discovery)

## Detection Methodology

### 1. AWS S3 Public Bucket Testing
```bash
# Check bucket ACL for public grants
aws s3api get-bucket-acl --bucket <bucket>
# Red flags: Grantee with URI "http://acs.amazonaws.com/groups/global/AllUsers"
#            or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# Check bucket policy for public access
aws s3api get-bucket-policy --bucket <bucket>

# Check public access block settings
aws s3api get-public-access-block --bucket <bucket>

# Test anonymous listing
aws s3 ls s3://<bucket> --no-sign-request

# Test anonymous read
aws s3 cp s3://<bucket>/test.txt /tmp/ --no-sign-request

# Test anonymous upload
echo "test" > /tmp/upload-test.txt
aws s3 cp /tmp/upload-test.txt s3://<bucket>/upload-test.txt --no-sign-request

# Test anonymous delete
aws s3 rm s3://<bucket>/upload-test.txt --no-sign-request

# Brute-force bucket discovery
for word in $(cat wordlist.txt); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${word}.s3.amazonaws.com/")
  if [ "$status" != "404" ]; then
    echo "$word: HTTP $status"
  fi
done

# Check for bucket versioning (may expose deleted files)
aws s3api list-object-versions --bucket <bucket> --no-sign-request
```

### 2. Azure Blob Storage Public Access Testing
```bash
# List containers and check public access level
az storage container list --account-name <account> \
  --query '[].{Name:name,PublicAccess:properties.publicAccess}'

# Check account-level public access setting
az storage account show --name <account> \
  --query 'allowBlobPublicAccess'

# Test anonymous blob listing (container-level public access)
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

# Test anonymous blob read (blob-level public access)
curl "https://<account>.blob.core.windows.net/<container>/<blob>"

# Enumerate storage accounts via subdomain brute-force
for name in $(cat wordlist.txt); do
  result=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.blob.core.windows.net/")
  if [ "$result" != "000" ]; then
    echo "$name.blob.core.windows.net: HTTP $result"
  fi
done

# Check for SAS tokens in URLs (may be leaked in logs, referers)
# Pattern: ?sv=2020-08-04&ss=b&srt=sco&sp=rwdlacitfx&se=...&sig=...

# Check storage account network rules
az storage account show --name <account> \
  --query 'networkRuleSet.{DefaultAction:defaultAction,IpRules:ipRules}'
```

### 3. GCS (Google Cloud Storage) Permissions Testing
```bash
# Check bucket IAM bindings
gsutil iam get gs://<bucket>

# Check bucket ACLs
gsutil acl get gs://<bucket>

# Test anonymous listing
curl "https://storage.googleapis.com/storage/v1/b/<bucket>/o"

# Test anonymous read
curl "https://storage.googleapis.com/<bucket>/<object>"

# Check if allUsers or allAuthenticatedUsers has access
gsutil iam get gs://<bucket> | grep -E "(allUsers|allAuthenticatedUsers)"

# Check public access prevention setting
gsutil publicAccessPrevention get gs://<bucket>

# Brute-force bucket names
for word in $(cat wordlist.txt); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${word}/")
  if [ "$status" != "404" ]; then
    echo "$word: HTTP $status"
  fi
done
```

### 4. Cross-Provider Enumeration Patterns
Common naming conventions to test:
```
<company>-backup
<company>-dev
<company>-staging
<company>-prod
<company>-logs
<company>-data
<company>-assets
<company>-media
<company>-uploads
<company>-static
<company>-config
<company>-db-backup
<company>-internal
```

### 5. Sensitive File Discovery
After gaining listing access, search for high-value targets:
```
*.sql, *.bak             # Database backups
*.csv, *.xlsx             # Data exports
*.env, *.config, *.yml    # Configuration files
*.pem, *.key, *.p12      # Certificates and keys
*.tfstate                 # Terraform state (contains secrets)
*.git/                    # Git repositories
id_rsa, id_ed25519        # SSH keys
credentials, .aws/        # Cloud credentials
```

## Tool Usage

### cloud_enum
```bash
# Multi-cloud storage enumeration
cloud_enum -k <company> -l results.txt

# With custom wordlist
cloud_enum -k <company> -m wordlist.txt -l results.txt
```

### S3Scanner
```bash
# Scan a list of bucket names
s3scanner scan --bucket-file buckets.txt

# Dump accessible buckets
s3scanner dump --bucket <bucket-name>
```

### BlobHunter
```bash
# Scan Azure storage accounts for public blobs
python3 BlobHunter.py

# With specific subscription
python3 BlobHunter.py --subscription-id <sub-id>
```

### GCPBucketBrute
```bash
# Enumerate GCS buckets
python3 gcpbucketbrute.py -k <keyword> -w wordlist.txt
```

### Nuclei
```bash
# Use cloud misconfiguration templates
nuclei -u https://<bucket>.s3.amazonaws.com -t cloud/ -batch
nuclei -l targets.txt -t cloud/enum/ -batch
```

## Testing Checklist
- [ ] Anonymous listing (can unauthenticated users list objects?)
- [ ] Anonymous read (can unauthenticated users download objects?)
- [ ] Anonymous write/upload (can unauthenticated users upload objects?)
- [ ] Anonymous delete (can unauthenticated users delete objects?)
- [ ] Authenticated cross-account access (can other tenants access?)
- [ ] Versioning exposure (can deleted file versions be retrieved?)
- [ ] Logging enabled (are access logs being captured?)
- [ ] Encryption at rest (are objects encrypted?)
- [ ] Encryption in transit (is HTTPS enforced?)
- [ ] Lifecycle policies (are old objects being cleaned up?)

## Remediation
1. **AWS S3:** Enable S3 Block Public Access at the account level, use bucket policies with explicit deny for public access, enable default encryption, enable access logging, use VPC endpoints for internal access
2. **Azure Blob:** Set `allowBlobPublicAccess` to false at the account level, use Azure Private Endpoints, enforce HTTPS-only transfers, disable shared key access in favor of Entra ID authentication
3. **GCS:** Enable public access prevention at the organization level via Organization Policy, use uniform bucket-level access, apply IAM Conditions for fine-grained control, use VPC Service Controls
4. **General:** Implement cloud security posture management (CSPM), set up automated alerts for public storage creation, conduct regular audits, use infrastructure-as-code to enforce compliant configurations, classify data and apply appropriate controls per sensitivity level

## Evidence Collection
- Bucket/container listing output showing accessible objects
- Public access configuration settings (ACL, policy, IAM bindings)
- Sample files demonstrating data exposure (redact sensitive content)
- Account-level settings showing lack of public access prevention
- Network configuration showing unrestricted access
- Tool scan results with severity classifications
- Curl commands and HTTP responses proving anonymous access
