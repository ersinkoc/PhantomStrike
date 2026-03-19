# Container Registry Security Testing

## Overview
Container registry security testing identifies vulnerabilities in container image registries that can lead to unauthorized image access, image tampering, secret extraction from image layers, and supply chain compromise. Insecure registries expose organizations to image poisoning attacks, credential theft from embedded secrets, and the deployment of tampered or malicious containers across the infrastructure.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-494 (Download of Code Without Integrity Check), CWE-522 (Insufficiently Protected Credentials)
- **OWASP:** A05:2021 - Security Misconfiguration, A06:2021 - Vulnerable and Outdated Components, A08:2021 - Software and Data Integrity Failures
- **CVSS Base:** 5.0 - 9.8 (Critical for supply chain attacks)
- **MITRE ATT&CK:** T1525 (Implant Internal Image), T1608.003 (Install Digital Certificate), T1195.002 (Supply Chain Compromise: Software Supply Chain)

## Detection Methodology

### 1. Registry Discovery and Enumeration
```bash
# Scan for exposed Docker Registry (default port 5000)
nmap -p 5000,443,8080,8443 <target>

# Check Docker Registry API v2
curl -s https://<registry>/v2/
curl -s http://<registry>:5000/v2/

# Expected response for open registry:
# {"repositories":[...]} or {} with 200 OK

# List all repositories (catalog)
curl -s https://<registry>/v2/_catalog
curl -s http://<registry>:5000/v2/_catalog

# List tags for a repository
curl -s https://<registry>/v2/<repo>/tags/list

# Paginated catalog enumeration
curl -s "https://<registry>/v2/_catalog?n=100"
# Follow Link header for next page

# Check if authentication is required
curl -sv https://<registry>/v2/ 2>&1 | grep -i "www-authenticate"

# Test common credentials
curl -u admin:admin https://<registry>/v2/_catalog
curl -u admin:password https://<registry>/v2/_catalog
curl -u registry:registry https://<registry>/v2/_catalog
```

### 2. Unauthenticated Access Testing
```bash
# Attempt to pull images without authentication
docker pull <registry>/<repo>:<tag>

# Via API — get image manifest
curl -s https://<registry>/v2/<repo>/manifests/<tag>
curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://<registry>/v2/<repo>/manifests/<tag>

# Download image layers (blobs)
# First get the manifest to find layer digests
MANIFEST=$(curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://<registry>/v2/<repo>/manifests/<tag>)
echo $MANIFEST | jq '.layers[].digest'

# Download a specific layer
DIGEST=$(echo $MANIFEST | jq -r '.layers[0].digest')
curl -sL https://<registry>/v2/<repo>/blobs/$DIGEST -o layer.tar.gz

# Extract and examine layer contents
mkdir layer && tar xzf layer.tar.gz -C layer/
find layer/ -type f | head -50

# Check for anonymous push (write) access
# Create a test blob
echo "test" | docker build -t <registry>/test-push:latest -
docker push <registry>/test-push:latest
```

### 3. Image Tampering Detection
```bash
# Check if Docker Content Trust is enabled
echo $DOCKER_CONTENT_TRUST  # Should be "1"

# Verify image signatures (Notary)
docker trust inspect <registry>/<repo>:<tag>
notary list <registry>/<repo>

# Check image digest consistency
docker pull <registry>/<repo>:<tag>
docker inspect <registry>/<repo>:<tag> --format='{{.RepoDigests}}'

# Compare manifest digest with expected
DIGEST=$(curl -s -I -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://<registry>/v2/<repo>/manifests/<tag> | grep -i docker-content-digest | awk '{print $2}' | tr -d '\r')
echo "Manifest digest: $DIGEST"

# Cosign verification (sigstore)
cosign verify <registry>/<repo>:<tag> --key cosign.pub

# Check for image provenance (SLSA)
cosign verify-attestation <registry>/<repo>:<tag> --key cosign.pub

# Detect tag mutability (same tag pointing to different digests over time)
# Save current digest and compare later
curl -s -I -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://<registry>/v2/<repo>/manifests/<tag> | grep docker-content-digest
```

### 4. Secret Scanning in Image Layers
```bash
# Pull and save image
docker pull <registry>/<repo>:<tag>
docker save <registry>/<repo>:<tag> -o image.tar

# Extract all layers
mkdir -p image_analysis
tar xf image.tar -C image_analysis/
cd image_analysis

# Extract each layer
for layer in $(find . -name "layer.tar" -o -name "*.tar.gz"); do
  dir=$(dirname $layer)/extracted
  mkdir -p $dir
  tar xf $layer -C $dir 2>/dev/null
done

# Search for secrets in extracted layers
grep -rn "password\|secret\|api_key\|token\|AWS_ACCESS\|PRIVATE KEY" . 2>/dev/null
find . -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa" \
  -o -name "*.p12" -o -name "*.pfx" -o -name "credentials" -o -name "*.json" \
  2>/dev/null

# Check Dockerfile history for secrets passed via build args
docker history --no-trunc <registry>/<repo>:<tag> | grep -iE "(password|secret|key|token)"

# Use TruffleHog for automated secret scanning
trufflehog docker --image <registry>/<repo>:<tag>

# Use Trivy for secret detection
trivy image --scanners secret <registry>/<repo>:<tag>

# Check for embedded SSH keys
find . -name "authorized_keys" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

# Check for configuration files with credentials
find . -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.ini" \
  -o -name "*.cfg" -o -name "*.conf" 2>/dev/null | xargs grep -l "password\|secret" 2>/dev/null
```

### 5. Supply Chain Attack Vectors
```bash
# Check base image provenance
docker inspect <image:tag> --format='{{.Config.Labels}}'
docker inspect <image:tag> --format='{{index .Config.Labels "org.opencontainers.image.source"}}'

# Verify base image is from trusted source
# Check for typosquatting on base images
# e.g., "aIpine" instead of "alpine", "ubunty" instead of "ubuntu"

# Check for Dockerfile best practices
# - Uses specific tag (not :latest)
# - Uses official/verified base images
# - Multi-stage build to reduce attack surface
# - No ADD from remote URLs
# - No curl | sh patterns

# Scan for known vulnerable base images
trivy image <base-image:tag>
grype <base-image:tag>

# Check image creation timestamps (detect unexpected rebuilds)
docker inspect <image:tag> --format='{{.Created}}'

# Verify CI/CD pipeline produced the image
# Check build provenance attestations
cosign verify-attestation --type slsaprovenance <registry>/<repo>:<tag>
```

### 6. Cloud Registry-Specific Testing

#### AWS ECR
```bash
# List repositories
aws ecr describe-repositories

# Check repository policy (who can pull/push)
aws ecr get-repository-policy --repository-name <repo>

# Check for image scanning enabled
aws ecr describe-repositories --query 'repositories[].{Name:repositoryName,ScanOnPush:imageScanningConfiguration.scanOnPush}'

# Check lifecycle policies
aws ecr get-lifecycle-policy --repository-name <repo>

# Pull image without proper auth (test cross-account)
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
```

#### Azure ACR
```bash
# List registries
az acr list --output table

# Check admin user (should be disabled)
az acr show --name <registry> --query 'adminUserEnabled'

# Check network rules
az acr show --name <registry> --query 'networkRuleSet'

# List repositories and tags
az acr repository list --name <registry>
az acr repository show-tags --name <registry> --repository <repo>
```

#### GCP Artifact Registry / GCR
```bash
# List repositories
gcloud artifacts repositories list

# Check IAM policy
gcloud artifacts repositories get-iam-policy <repo> --location=<location>

# Check for public access
gcloud artifacts repositories describe <repo> --location=<location>

# List images
gcloud container images list --repository=gcr.io/<project>
```

## Tool Usage

### Trivy
```bash
# Comprehensive image scan (CVEs + secrets + misconfig)
trivy image <registry>/<repo>:<tag>
trivy image --scanners vuln,secret,misconfig <registry>/<repo>:<tag>

# Registry scan
trivy registry <registry>
```

### Skopeo
```bash
# Inspect remote image without pulling
skopeo inspect docker://<registry>/<repo>:<tag>

# Copy image between registries
skopeo copy docker://<source>/<repo>:<tag> docker://<dest>/<repo>:<tag>

# List tags
skopeo list-tags docker://<registry>/<repo>
```

### Docker Registry HTTP API
```bash
# Full enumeration script
REGISTRY="https://<target>"
for repo in $(curl -s $REGISTRY/v2/_catalog | jq -r '.repositories[]'); do
  echo "=== $repo ==="
  tags=$(curl -s $REGISTRY/v2/$repo/tags/list | jq -r '.tags[]' 2>/dev/null)
  for tag in $tags; do
    echo "  $tag"
    curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      $REGISTRY/v2/$repo/manifests/$tag | jq '.layers | length' 2>/dev/null
  done
done
```

### Notary / Cosign
```bash
# Verify image signatures
cosign verify <image> --key cosign.pub
notary list <registry>/<repo>

# Check for unsigned images in registry
# (Compare signed vs total images)
```

## Remediation
1. **Authentication:** Require authentication for all registry operations (pull and push), disable anonymous access, use short-lived tokens instead of static credentials
2. **Authorization:** Implement RBAC on repositories, restrict push access to CI/CD service accounts only, separate read and write permissions
3. **Image signing:** Enable Docker Content Trust or Cosign for image signing, enforce signature verification in admission controllers (Kyverno, OPA), use SLSA provenance attestations
4. **Secret prevention:** Scan images for secrets in CI/CD pipelines, use multi-stage builds to exclude secrets from final images, use .dockerignore to prevent accidental inclusion, never pass secrets via build args
5. **Vulnerability management:** Enable automatic image scanning, set policies to block deployment of images with critical CVEs, maintain a curated list of approved base images
6. **Network security:** Restrict registry access to trusted networks, use private endpoints, enforce TLS for all registry communication
7. **Immutable tags:** Use digest-based references instead of mutable tags, enable tag immutability where supported, maintain an image promotion workflow

## Evidence Collection
- Registry catalog listing showing accessible repositories without authentication
- Image manifest and layer download proof
- Secrets found in image layers (file paths and redacted content)
- Missing or invalid image signatures
- Registry configuration showing disabled authentication
- Docker history output revealing build-time secrets
- Vulnerability scan results from Trivy/Grype
- Supply chain analysis showing unverified base images or unsigned builds
- Cloud registry IAM policies showing overly permissive access
