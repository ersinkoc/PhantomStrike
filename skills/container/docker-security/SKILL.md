# Docker Security Testing

## Overview
Docker security testing identifies vulnerabilities and misconfigurations in container images, runtime configurations, and the Docker daemon that can lead to container escape, host compromise, privilege escalation, and data exposure. Testing covers image supply chain security, runtime isolation weaknesses, exposed Docker APIs, and capability/namespace misconfigurations.

## Classification
- **CWE:** CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control)
- **OWASP:** A05:2021 - Security Misconfiguration, A06:2021 - Vulnerable and Outdated Components
- **CVSS Base:** 6.0 - 10.0 (Critical for container escape)
- **MITRE ATT&CK:** T1610 (Deploy Container), T1611 (Escape to Host), T1613 (Container and Resource Discovery)

## Detection Methodology

### 1. Docker Image Scanning
```bash
# Scan image for known CVEs
trivy image <image:tag>
trivy image --severity HIGH,CRITICAL <image:tag>

# Scan with Grype
grype <image:tag>
grype <image:tag> --only-fixed

# Check image for secrets
trufflehog docker --image <image:tag>

# Inspect image layers for sensitive files
docker history --no-trunc <image:tag>
docker inspect <image:tag>

# Export and analyze image filesystem
docker save <image:tag> -o image.tar
tar xf image.tar
# Examine each layer for secrets, credentials, keys
find . -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa" -o -name "*.p12"

# Check if image runs as root
docker inspect <image:tag> --format='{{.Config.User}}'
# Empty or "0" or "root" = runs as root

# Check for SUID/SGID binaries in image
docker run --rm <image:tag> find / -perm -4000 -type f 2>/dev/null
docker run --rm <image:tag> find / -perm -2000 -type f 2>/dev/null
```

### 2. Container Runtime Configuration Audit
```bash
# Check if container is running privileged
docker inspect <container> --format='{{.HostConfig.Privileged}}'

# Check capabilities
docker inspect <container> --format='{{.HostConfig.CapAdd}}'
docker inspect <container> --format='{{.HostConfig.CapDrop}}'

# Check if PID namespace is shared with host
docker inspect <container> --format='{{.HostConfig.PidMode}}'

# Check network mode
docker inspect <container> --format='{{.HostConfig.NetworkMode}}'

# Check mounted volumes (look for sensitive host paths)
docker inspect <container> --format='{{json .Mounts}}' | jq

# Check security options (AppArmor, Seccomp, SELinux)
docker inspect <container> --format='{{.HostConfig.SecurityOpt}}'

# Check if read-only root filesystem
docker inspect <container> --format='{{.HostConfig.ReadonlyRootfs}}'

# List all running containers with key security settings
docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}'
for c in $(docker ps -q); do
  echo "=== $(docker inspect $c --format='{{.Name}}') ==="
  echo "Privileged: $(docker inspect $c --format='{{.HostConfig.Privileged}}')"
  echo "Caps Added: $(docker inspect $c --format='{{.HostConfig.CapAdd}}')"
  echo "PID Mode: $(docker inspect $c --format='{{.HostConfig.PidMode}}')"
  echo "Net Mode: $(docker inspect $c --format='{{.HostConfig.NetworkMode}}')"
done
```

### 3. Docker Socket Exposure
```bash
# Check if Docker socket is mounted into containers
docker inspect <container> --format='{{json .Mounts}}' | jq '.[] | select(.Source=="/var/run/docker.sock")'

# From inside a container — check for socket
ls -la /var/run/docker.sock

# Exploit mounted Docker socket to escape to host
# List containers on host
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# Create a privileged container with host filesystem mounted
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}' \
  http://localhost/containers/create

# Check for remotely exposed Docker API (TCP)
nmap -p 2375,2376 <target>
curl http://<target>:2375/version
curl http://<target>:2375/containers/json
```

### 4. Privilege Escalation from Within Container
```bash
# Check current capabilities
capsh --print 2>/dev/null || cat /proc/self/status | grep -i cap

# Check if running as root
id
whoami

# Check for writable sensitive paths
ls -la /proc/sysrq-trigger 2>/dev/null
ls -la /proc/kcore 2>/dev/null

# Check cgroup membership
cat /proc/1/cgroup

# Attempt to access host filesystem via /proc
ls -la /proc/1/root/  # If PID namespace is shared

# Check for available tools
which python python3 perl ruby gcc make curl wget nc 2>/dev/null

# Check kernel version for known exploits
uname -r
cat /proc/version
```

### 5. Namespace and Isolation Checks
```bash
# From the host — verify namespace isolation
# Check user namespace mapping
docker inspect <container> --format='{{.HostConfig.UsernsMode}}'

# Check IPC namespace
docker inspect <container> --format='{{.HostConfig.IpcMode}}'

# Check UTS namespace
docker inspect <container> --format='{{.HostConfig.UTSMode}}'

# Check cgroup parent
docker inspect <container> --format='{{.HostConfig.CgroupParent}}'

# Verify seccomp profile
docker inspect <container> --format='{{.HostConfig.SecurityOpt}}' | grep seccomp

# Check if container has no-new-privileges flag
docker inspect <container> --format='{{.HostConfig.SecurityOpt}}' | grep no-new-privileges
```

### 6. Docker Daemon Configuration Audit
```bash
# Check Docker daemon configuration
cat /etc/docker/daemon.json

# Key settings to verify:
# "userns-remap" — should be set for user namespace remapping
# "no-new-privileges" — should be true
# "icc" — inter-container communication should be false
# "live-restore" — should be true
# "userland-proxy" — should be false
# "log-driver" — should be configured for centralized logging
# "tls" — should be true for remote API

# Check Docker info for security features
docker info --format '{{json .SecurityOptions}}' | jq
docker info | grep -E "Storage Driver|Logging Driver|Cgroup|Security Options"

# Check for insecure registries
docker info | grep -A5 "Insecure Registries"
```

## Tool Usage

### Docker Bench Security
```bash
# Run CIS Docker Benchmark checks
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  docker/docker-bench-security
```

### Trivy
```bash
# Scan images
trivy image <image:tag>

# Scan filesystem
trivy fs /path/to/project

# Scan running container
trivy image --input image.tar

# Generate SBOM
trivy image --format spdx-json --output sbom.json <image:tag>
```

### Falco (Runtime Detection)
```bash
# Monitor container runtime behavior
falco -r /etc/falco/falco_rules.yaml

# Key rules to monitor:
# - Shell spawned in container
# - Sensitive file access
# - Network connections from container
# - Privilege escalation attempts
```

### Deepce (Container Escape)
```bash
# From inside a container
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
chmod +x deepce.sh
./deepce.sh

# With specific checks
./deepce.sh --no-network --no-enumeration
```

## Remediation
1. **Images:** Use minimal base images (distroless, Alpine), scan images in CI/CD, do not run as root (use USER directive), remove unnecessary SUID binaries, use multi-stage builds to exclude build tools
2. **Runtime:** Drop all capabilities and add only required ones (`--cap-drop ALL --cap-add <needed>`), never run `--privileged`, use read-only root filesystem, set memory and CPU limits
3. **Docker socket:** Never mount Docker socket into containers, use Docker-in-Docker with restricted access if needed, protect remote API with TLS mutual auth
4. **Namespaces:** Enable user namespace remapping, use separate PID/network/IPC namespaces per container, enforce `no-new-privileges` flag
5. **Daemon:** Enable content trust (image signing), disable inter-container communication by default, configure TLS for remote API, use seccomp and AppArmor profiles
6. **Monitoring:** Deploy runtime security tools (Falco, Sysdig), centralize container logs, alert on container escape indicators

## Evidence Collection
- Image scan results showing CVEs with severity ratings
- Container configuration showing privileged mode or dangerous capabilities
- Docker socket exposure proof (listing host containers from within)
- Sensitive files found in image layers (secrets, credentials, keys)
- Docker daemon configuration showing insecure settings
- Docker Bench Security report output
- Container escape proof-of-concept steps and output
- Network exposure of Docker API (port 2375/2376 accessible)
