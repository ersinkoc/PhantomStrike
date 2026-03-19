# GCP Security Testing

## Overview
GCP security testing identifies misconfigurations and vulnerabilities across Google Cloud Platform infrastructure. Key attack surfaces include overly permissive IAM bindings, publicly accessible Cloud Storage buckets, Compute Engine metadata exploitation, service account impersonation, and insecure project configurations that allow lateral movement and privilege escalation.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.0 - 10.0 (varies by finding severity)
- **MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1530 (Data from Cloud Storage), T1552.005 (Cloud Instance Metadata API)

## Detection Methodology

### 1. IAM Policy Analysis
```bash
# List all IAM bindings for a project
gcloud projects get-iam-policy <project-id> --format=json

# Find bindings with allUsers or allAuthenticatedUsers
gcloud projects get-iam-policy <project-id> --format=json | \
  jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))'

# List custom roles and their permissions
gcloud iam roles list --project=<project-id>
gcloud iam roles describe <role-id> --project=<project-id>

# List service accounts
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy <sa-email>

# Check service account keys (should be minimal)
gcloud iam service-accounts keys list --iam-account=<sa-email>

# Test current permissions
gcloud auth list
gcloud projects list
```

**Red flags:**
- `roles/editor` or `roles/owner` granted broadly
- `allUsers` or `allAuthenticatedUsers` in IAM bindings
- Service accounts with user-managed keys
- Primitive roles used instead of predefined or custom roles

### 2. Cloud Storage Enumeration
```bash
# List all buckets in a project
gsutil ls

# Check bucket ACLs and IAM
gsutil iam get gs://<bucket>
gsutil acl get gs://<bucket>

# Check for public access
gsutil ls -L gs://<bucket> | grep -i "public"

# Test anonymous access
curl "https://storage.googleapis.com/<bucket>/"
curl "https://storage.googleapis.com/<bucket>/?prefix=&delimiter=/"

# Attempt to list objects without authentication
gsutil -o "Credentials:gs_oauth2_refresh_token=" ls gs://<bucket>

# Check bucket-level public access prevention
gsutil publicAccessPrevention get gs://<bucket>

# Check for uniform bucket-level access
gsutil uniformbucketlevelaccess get gs://<bucket>
```

### 3. Compute Engine Metadata Exploitation
```bash
# From a compromised GCE instance — query metadata server
# GCP requires the Metadata-Flavor header
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/"

# Get instance details
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"

# Get service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get service account scopes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Get project-level metadata (may contain startup scripts with secrets)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"

# Get instance startup script
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"

# Get SSH keys from metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
```

### 4. Service Account Impersonation
```bash
# Check if current identity can impersonate other service accounts
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy <target-sa-email> \
  --format=json | jq '.bindings[] | select(.role | contains("iam.serviceAccountTokenCreator"))'

# Generate an access token for another service account
gcloud auth print-access-token --impersonate-service-account=<target-sa-email>

# Use impersonated identity
gcloud compute instances list --impersonate-service-account=<target-sa-email>
gcloud storage ls --impersonate-service-account=<target-sa-email>

# Create a service account key (if permitted — high impact)
gcloud iam service-accounts keys create key.json \
  --iam-account=<sa-email>

# Activate stolen service account key
gcloud auth activate-service-account --key-file=key.json
```

### 5. Project Enumeration and Lateral Movement
```bash
# List accessible projects
gcloud projects list

# List organizations
gcloud organizations list

# List folders
gcloud resource-manager folders list --organization=<org-id>

# Enumerate resources across projects
for project in $(gcloud projects list --format="value(projectId)"); do
  echo "=== $project ==="
  gcloud compute instances list --project=$project 2>/dev/null
  gcloud sql instances list --project=$project 2>/dev/null
  gcloud functions list --project=$project 2>/dev/null
done

# Check for cross-project service account usage
gcloud projects get-iam-policy <project> --format=json | \
  jq '.bindings[].members[] | select(contains("serviceAccount:") and (contains("'$current_project'") | not))'

# Check enabled APIs (indicates what services are in use)
gcloud services list --project=<project-id>
```

### 6. Additional Service Checks
```bash
# Cloud SQL — check for public IPs
gcloud sql instances list --format="table(name,ipAddresses[].ipAddress,settings.ipConfiguration.authorizedNetworks)"

# Cloud Functions — list and inspect
gcloud functions list
gcloud functions describe <function> --format=json | jq '.environmentVariables'

# GKE clusters — check for public endpoints
gcloud container clusters list \
  --format="table(name,endpoint,masterAuthorizedNetworksConfig)"

# Firewall rules — find overly permissive rules
gcloud compute firewall-rules list \
  --format="table(name,direction,sourceRanges,allowed)" \
  --filter="sourceRanges=('0.0.0.0/0')"
```

## Tool Usage

### ScoutSuite
```bash
# Full GCP scan
scout gcp --project-id <project-id>

# Specific services
scout gcp --services iam cloudstorage computeengine cloudsql

# Generate HTML report
scout gcp --report-dir ./scout-gcp-report/
```

### gcp_enum
```bash
# Enumerate GCP resources with discovered credentials
python3 gcp_enum.py --project <project-id>

# Service-specific enumeration
python3 gcp_enum.py --project <project-id> --services compute,storage,iam

# Use with service account key file
python3 gcp_enum.py --key-file key.json
```

### gcloud CLI (Manual Testing)
```bash
# Test permissions with testIamPermissions API
gcloud asset search-all-iam-policies --scope=projects/<project-id>

# Audit log analysis
gcloud logging read "logName:cloudaudit.googleapis.com" --project=<project-id> --limit=100

# Check organization policies
gcloud org-policies list --project=<project-id>
```

## Remediation
1. **IAM:** Use predefined roles instead of primitive roles, never grant `allUsers` or `allAuthenticatedUsers` on sensitive resources, implement organization policy constraints, enforce service account key rotation
2. **Cloud Storage:** Enable uniform bucket-level access, set public access prevention at the organization level, use signed URLs for temporary access, enable Object Versioning and retention policies
3. **Compute Engine:** Use custom service accounts with minimal scopes, block project-wide SSH keys, restrict metadata API access from workloads, use Shielded VMs
4. **Service Accounts:** Minimize user-managed keys (prefer workload identity federation), restrict `iam.serviceAccountTokenCreator` role, disable unused service accounts, audit key creation events
5. **Network:** Apply VPC firewall rules with specific source ranges, use Private Google Access, enable VPC Flow Logs, use Cloud NAT instead of external IPs
6. **Logging:** Enable Data Access audit logs, export logs to a separate project, set up alerting on sensitive admin actions, use Security Command Center

## Evidence Collection
- IAM policy bindings showing excessive or public access grants
- Cloud Storage bucket configurations proving public access
- Metadata service output including tokens and startup scripts (redact tokens)
- Service account impersonation chain documentation
- Cross-project access paths identified
- ScoutSuite report findings with severity ratings
- Firewall rules showing unrestricted ingress from 0.0.0.0/0
