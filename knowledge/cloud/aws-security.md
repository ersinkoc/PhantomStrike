# AWS Security Testing Guide

## Overview

AWS environments present a large attack surface spanning identity management, storage, compute,
and serverless services. Misconfigurations are the most common root cause of cloud breaches.
This guide covers key areas an automated agent should test.

## S3 Bucket Misconfiguration

### Discovery
```bash
# Enumerate buckets from known domain
aws s3 ls
# Brute-force bucket names
python3 cloud_enum.py -k target-company
# Check for public access
aws s3api get-bucket-acl --bucket BUCKET_NAME
aws s3api get-bucket-policy --bucket BUCKET_NAME
```

### Common Issues
- Public read/write ACLs
- Overly permissive bucket policies allowing `s3:*` to `*`
- Missing S3 Block Public Access settings
- Hosting sensitive data (backups, logs, credentials) without encryption

## IAM Privilege Escalation

### Enumeration
```bash
# List attached policies for current user
aws iam list-attached-user-policies --user-name USERNAME
# Check for inline policies
aws iam list-user-policies --user-name USERNAME
# Enumerate roles we can assume
aws iam list-roles | jq '.Roles[].Arn'
```

### Escalation Vectors
- `iam:CreatePolicyVersion` - overwrite an existing policy with admin permissions
- `iam:AttachUserPolicy` / `iam:AttachRolePolicy` - attach AdministratorAccess
- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` - execute as privileged role
- `sts:AssumeRole` on overly permissive trust policies
- `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` - set console password for another user

## Lambda & Serverless

### Testing
```bash
# List functions
aws lambda list-functions --region us-east-1
# Get function code
aws lambda get-function --function-name FUNC_NAME
# Check environment variables for secrets
aws lambda get-function-configuration --function-name FUNC_NAME | jq '.Environment'
```

### Common Weaknesses
- Hardcoded credentials in environment variables
- Overly permissive execution roles (full admin)
- Event injection via untrusted input (API Gateway, S3 triggers)
- Missing function URL authentication

## EC2 Metadata Service

### SSRF to Metadata (IMDSv1)
```bash
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### IMDSv2 (Token-based)
```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

## Tools
- **Pacu** - AWS exploitation framework (`pacu --new-session target`)
- **ScoutSuite** - multi-cloud security auditing (`scout aws`)
- **Prowler** - AWS CIS benchmark checks (`prowler aws`)
- **CloudMapper** - network visualization and auditing
- **Enumerate-IAM** - brute-force IAM permissions

## Remediation
- Enable S3 Block Public Access at the account level
- Enforce IMDSv2 on all EC2 instances
- Apply least-privilege IAM policies; use IAM Access Analyzer
- Enable CloudTrail logging in all regions with log file validation
- Use AWS Config rules to detect and auto-remediate misconfigurations
- Rotate access keys regularly; prefer IAM roles over long-lived keys
