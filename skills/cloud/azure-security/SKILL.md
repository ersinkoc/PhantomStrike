# Azure Security Testing

## Overview
Azure security testing focuses on identifying misconfigurations and vulnerabilities across Microsoft Azure infrastructure. Key attack surfaces include Azure Active Directory (Entra ID) privilege escalation, managed identity abuse, storage account misconfiguration, Key Vault access control weaknesses, and insecure ARM template deployments.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-522 (Insufficiently Protected Credentials)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 5.0 - 10.0 (varies by finding severity)
- **MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1087.004 (Cloud Account Discovery), T1098 (Account Manipulation)

## Detection Methodology

### 1. Azure AD (Entra ID) Enumeration
```bash
# Enumerate tenant information
az account list
az account show
az ad user list --output table
az ad group list --output table
az ad app list --output table

# Find privileged role assignments
az role assignment list --all --output table
az role assignment list --role "Owner" --all
az role assignment list --role "Contributor" --all
az role assignment list --role "User Access Administrator" --all

# Enumerate service principals
az ad sp list --all --query '[].{Name:displayName,AppId:appId,Type:servicePrincipalType}'

# Check for guest users (potential external access)
az ad user list --filter "userType eq 'Guest'" --output table

# Find users with no MFA
# (Requires MS Graph API)
az rest --method GET \
  --uri 'https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails'
```

### 2. Managed Identity Exploitation
```bash
# From a compromised Azure VM — query IMDS for managed identity token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Token for Key Vault access
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Token for Microsoft Graph
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# Use stolen token with Azure CLI
az login --identity
az account show
az resource list

# Enumerate what the managed identity can access
az role assignment list --assignee <managed-identity-object-id> --all
```

### 3. Storage Account Misconfiguration
```bash
# List storage accounts
az storage account list --query '[].{Name:name,AllowBlobPublicAccess:allowBlobPublicAccess}'

# Check for public blob access
az storage container list --account-name <account> --auth-mode login \
  --query '[?properties.publicAccess!=`none`].{Name:name,Access:properties.publicAccess}'

# Attempt anonymous blob listing
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

# Check shared access signatures (SAS) exposure
az storage account show --name <account> \
  --query '{HTTPS:enableHttpsTrafficOnly,MinTLS:minimumTlsVersion,KeyAccess:allowSharedKeyAccess}'

# List storage access keys (if permitted)
az storage account keys list --account-name <account>

# Check for soft delete and versioning
az storage blob service-properties show --account-name <account> \
  --query '{SoftDelete:deleteRetentionPolicy,Versioning:isVersioningEnabled}'

# Enumerate file shares
az storage share list --account-name <account> --account-key <key>
```

### 4. Key Vault Security Assessment
```bash
# List Key Vaults
az keyvault list --output table

# Check access policies
az keyvault show --name <vault> --query 'properties.accessPolicies'

# Check network ACLs (should not be open to all)
az keyvault show --name <vault> \
  --query 'properties.networkAcls.{DefaultAction:defaultAction,IpRules:ipRules,VNetRules:virtualNetworkRules}'

# Check if RBAC authorization is used (preferred over access policies)
az keyvault show --name <vault> --query 'properties.enableRbacAuthorization'

# Attempt to list secrets, keys, certificates
az keyvault secret list --vault-name <vault>
az keyvault key list --vault-name <vault>
az keyvault certificate list --vault-name <vault>

# Read a secret value
az keyvault secret show --vault-name <vault> --name <secret-name>

# Check for soft-delete and purge protection
az keyvault show --name <vault> \
  --query '{SoftDelete:properties.enableSoftDelete,PurgeProtection:properties.enablePurgeProtection}'
```

### 5. ARM Template Analysis
```bash
# Export ARM templates for a resource group
az group export --name <resource-group> --output json > arm-template.json

# Look for hardcoded secrets in templates
grep -iE '(password|secret|key|token|connectionstring)' arm-template.json

# Check for insecure defaults
grep -i '"publicAccess"' arm-template.json
grep -i '"publicNetworkAccess"' arm-template.json
grep -i '"httpsOnly": false' arm-template.json

# Review deployment history for leaked parameters
az deployment group list --resource-group <rg>
az deployment group show --resource-group <rg> --name <deployment> \
  --query 'properties.parameters'

# Check for linked templates with SAS tokens in URLs
grep -i 'templateLink' arm-template.json
```

### 6. Subscription and Resource Enumeration
```bash
# Enumerate accessible subscriptions
az account list --all --output table

# List all resources in a subscription
az resource list --output table

# Find VMs and their configurations
az vm list --output table
az vm show --name <vm> --resource-group <rg>

# Check Network Security Groups for open rules
az network nsg list --output table
az network nsg rule list --nsg-name <nsg> --resource-group <rg> \
  --query '[?access==`Allow` && direction==`Inbound`].{Name:name,Port:destinationPortRange,Source:sourceAddressPrefix}'

# Find exposed public IPs
az network public-ip list --query '[].{Name:name,IP:ipAddress,Associated:ipConfiguration.id}'
```

## Tool Usage

### AzureHound
```bash
# Collect Azure AD and Azure RM data for BloodHound
azurehound list -t <tenant-id> --auth <method> -o azurehound-output.json

# Specific collections
azurehound list az-rm -t <tenant-id>
azurehound list az-ad -t <tenant-id>

# Import into BloodHound for attack path analysis
# Upload azurehound-output.json to BloodHound CE
```

### ROADtools
```bash
# Authenticate and gather Azure AD data
roadrecon auth --access-token <token>
roadrecon gather

# Launch GUI for exploration
roadrecon gui

# Dump database to explore policies, users, apps
roadrecon dump

# Enumerate application permissions and delegated grants
roadrecon plugin policies
```

### MicroBurst
```powershell
# Import module
Import-Module MicroBurst.psm1

# Enumerate storage accounts
Invoke-EnumerateAzureBlobs -Base <company>

# Enumerate subdomains
Invoke-EnumerateAzureSubDomains -Base <company>

# Check for exposed functions and web apps
Get-AzureDomainInfo -folder ./results -Verbose

# Run full suite
Invoke-AzureRmVMBulkCMD -Script "whoami" -ResourceGroup <rg>
```

## Remediation
1. **Azure AD:** Enforce MFA for all users, implement Conditional Access policies, minimize Global Administrator assignments, review guest access regularly
2. **Managed Identities:** Use user-assigned identities with minimal RBAC roles, avoid system-assigned identities where cross-resource scoping is needed, monitor token usage
3. **Storage Accounts:** Disable public blob access at the account level, use Azure Private Endpoints, enforce HTTPS-only, disable shared key access in favor of Entra ID auth, enable soft delete
4. **Key Vault:** Use RBAC authorization instead of access policies, enable purge protection and soft delete, restrict network access with private endpoints, audit access logs
5. **ARM Templates:** Use Azure Key Vault references for secrets in templates, never hardcode credentials, use template specs with versioning, enable deployment-level RBAC
6. **Network:** Restrict NSG rules to specific source IPs, use Azure Firewall or Application Gateway with WAF, disable direct RDP/SSH from internet

## Evidence Collection
- Azure AD role assignment listings showing excessive privileges
- Storage account configuration proving public access is enabled
- Managed identity token output showing accessible resources
- Key Vault access policy or secret values demonstrating exposure (redact actual secrets)
- ARM template excerpts with hardcoded credentials
- NSG rules showing unrestricted inbound access on sensitive ports
- AzureHound/BloodHound attack path graphs showing privilege escalation routes
