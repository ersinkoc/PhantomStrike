# PhantomStrike Security Sandbox

Isolated execution environment for security testing tools.

## Architecture

```
┌─────────────────────────────────────────┐
│           PhantomStrike API            │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Docker Daemon (local)          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │  Nuclei │ │  Nmap   │ │ DalFox  │  │
│  │(sandbox)│ │(sandbox)│ │(sandbox)│  │
│  └─────────┘ └─────────┘ └─────────┘  │
└─────────────────────────────────────────┘
```

## Security Measures

1. **Network Isolation**: No outgoing connections (or restricted)
2. **Read-only Filesystem**: Container cannot modify itself
3. **Resource Limits**: CPU, memory, timeout
4. **No Privileges**: Run as non-root user
5. **Seccomp**: System call filtering
6. **AppArmor/SELinux**: Mandatory access control

## Tool Images

All images are built from official sources with hardening:

| Tool | Base | Size | Network |
|------|------|------|---------|
| nuclei | Alpine | ~50MB | Isolated |
| nmap | Alpine | ~30MB | Bridge |
| dalfox | Alpine | ~40MB | Isolated |
| testssl | Alpine | ~25MB | Bridge |
| gobuster | Alpine | ~20MB | Isolated |

## Building

```bash
make sandbox-build
make sandbox-push  # to private registry
```

## Testing

```bash
cd sandbox/nuclei
docker build -t phantomstrike/nuclei:test .
docker run --rm --network=none phantomstrike/nuclei:test -version
```
