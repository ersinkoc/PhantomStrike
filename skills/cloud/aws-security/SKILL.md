# AWS Security Testing

## Overview
AWS security testing targets misconfigurations and vulnerabilities across Amazon Web Services infrastructure. Common attack surfaces include overly permissive IAM policies, publicly exposed S3 buckets, exploitable Lambda functions, EC2 instance metadata abuse, exposed RDS databases, and CloudTrail logging gaps that allow attackers to operate undetected.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-732 (Incorrect Permission Assignment)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.0 - 10.0 (varies by finding severity)
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1530 (Data from Cloud Storage), T1552.005 (Cloud Instance Metadata API)

## Detection Methodology

### 1. IAM Misconfiguration Analysis
Enumerate IAM users, roles, policies, and identify overly permissive configurations:
```bash
# List all IAM users and their policies
aws iam list-users
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <policy>

# List roles and their trust policies
aws iam list-roles
aws iam get-role --role-name <role>
aws iam list-attached-role-policies --role-name <role>

# Find policies with wildcard actions
aws iam get-policy-version --policy-arn <arn> --version-id <v>

# Check for access keys older than 90 days
aws iam list-access-keys --user-name <user>
aws iam get-access-key-last-used --access-key-id <key>
```

**Red flags:**
- Policies with `"Action": "*"` or `"Resource": "*"`
- Users with inline policies granting `iam:*` or `sts:AssumeRole` on `*`
- Roles with overly broad trust policies allowing cross-account assumption
- Access keys that have never been rotated

### 2. S3 Bucket Enumeration and Exploitation
```bash
# List all buckets and check ACLs
aws s3 ls
aws s3api get-bucket-acl --bucket <bucket>
aws s3api get-bucket-policy --bucket <bucket>
aws s3api get-public-access-block --bucket <bucket>

# Check for public access
aws s3api get-bucket-policy-status --bucket <bucket>

# Test anonymous access (unauthenticated)
aws s3 ls s3://<bucket> --no-sign-request
aws s3 cp s3://<bucket>/sensitive-file.txt . --no-sign-request

# Brute-force bucket names
for name in dev staging prod backup logs; do
  aws s3 ls s3://company-${name} --no-sign-request 2>/dev/null && echo "PUBLIC: company-${name}"
done
```

### 3. Lambda Function Abuse
```bash
# List functions and their configurations
aws lambda list-functions
aws lambda get-function --function-name <name>
aws lambda get-function-configuration --function-name <name>

# Extract environment variables (may contain secrets)
aws lambda get-function-configuration --function-name <name> \
  --query 'Environment.Variables'

# Check execution role permissions
aws lambda get-policy --function-name <name>

# Invoke function with crafted event
aws lambda invoke --function-name <name> \
  --payload '{"key":"value"}' output.json
```

### 4. EC2 Metadata Service Exploitation
```bash
# From a compromised EC2 instance — IMDSv1 (no token required)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl http://169.254.169.254/latest/user-data/

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Check if IMDSv1 is disabled
aws ec2 describe-instances --instance-id <id> \
  --query 'Reservations[].Instances[].MetadataOptions'
```

### 5. RDS Exposure Assessment
```bash
# List publicly accessible RDS instances
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Endpoint.Address]'

# Check security group rules allowing 0.0.0.0/0 on database ports
aws ec2 describe-security-groups --group-ids <sg-id> \
  --query 'SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]'

# Check for unencrypted instances
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier]'

# Check for automated backups disabled
aws rds describe-db-instances \
  --query 'DBInstances[?BackupRetentionPeriod==`0`].[DBInstanceIdentifier]'
```

### 6. CloudTrail Evasion Detection
```bash
# Check if CloudTrail is enabled in all regions
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail>

# Look for trails that exclude management events
aws cloudtrail get-event-selectors --trail-name <trail>

# Detect if logging was recently stopped
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging

# Check for multi-region trail
aws cloudtrail describe-trails \
  --query 'trailList[?IsMultiRegionTrail==`false`].TrailARN'
```

### 7. Privilege Escalation Paths
```bash
# Check if current user can create new IAM users or keys
aws iam simulate-principal-policy --policy-source-arn <user-arn> \
  --action-names iam:CreateUser iam:CreateAccessKey iam:AttachUserPolicy

# Check for PassRole + service abuse
aws iam simulate-principal-policy --policy-source-arn <user-arn> \
  --action-names iam:PassRole lambda:CreateFunction lambda:InvokeFunction

# Enumerate STS assume-role targets
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}'
```

## Tool Usage

### Prowler
```bash
# Full AWS security assessment
prowler aws

# Specific check categories
prowler aws --category iam
prowler aws --category s3
prowler aws --category logging

# Output in specific format
prowler aws -M json-ocsf -o ./results/

# Scan specific region
prowler aws --region us-east-1
```

### Pacu (AWS Exploitation Framework)
```bash
# Start Pacu session
pacu --new-session pentest

# Enumerate permissions
run iam__enum_permissions
run iam__enum_users_roles_policies_groups

# Privilege escalation
run iam__privesc_scan

# S3 enumeration
run s3__bucket_finder --brute-force

# Lambda exploitation
run lambda__enum

# EC2 enumeration
run ec2__enum
```

### enumerate-iam
```bash
# Enumerate permissions for a given set of credentials
enumerate-iam --access-key <AKIA...> --secret-key <secret>
```

### ScoutSuite
```bash
# Full AWS scan
scout aws

# Specific services
scout aws --services iam s3 ec2 rds lambda

# Generate report
scout aws --report-dir ./scout-report/
```

## Remediation
1. **IAM:** Apply least-privilege policies, enable MFA for all users, rotate access keys every 90 days, eliminate wildcard permissions
2. **S3:** Enable Block Public Access at the account level, use bucket policies with explicit deny, enable server-side encryption, enable access logging
3. **Lambda:** Remove secrets from environment variables (use Secrets Manager), restrict execution role permissions, validate all event inputs
4. **EC2:** Enforce IMDSv2, use VPC endpoints for metadata, apply instance profiles with minimal permissions
5. **RDS:** Disable public accessibility, use private subnets, enforce SSL connections, enable encryption at rest
6. **CloudTrail:** Enable multi-region trails, enable log file validation, ship logs to a separate account, monitor for StopLogging events
7. **General:** Enable GuardDuty, use AWS Config rules, implement SCPs at the organization level

## Evidence Collection
- IAM policy documents showing overly permissive access
- S3 bucket listing output demonstrating public access
- Extracted credentials from metadata service or Lambda environment variables (redact after documentation)
- CloudTrail gaps or disabled logging evidence
- RDS instances with public accessibility confirmation
- Privilege escalation chain documentation with step-by-step reproduction
- Screenshots of ScoutSuite/Prowler findings with severity ratings
