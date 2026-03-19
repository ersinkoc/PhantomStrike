# gRPC Security Testing

## Overview
gRPC is a high-performance RPC framework using Protocol Buffers (protobuf) for serialization and HTTP/2 for transport. Its binary protocol, strongly typed schemas, and widespread use in microservice architectures introduce unique security challenges. Attackers can abuse server reflection to enumerate services, manipulate protobuf messages to bypass validation, exploit authentication gaps in inter-service communication, and target TLS misconfigurations. This skill covers comprehensive gRPC security assessment.

## Classification
- **CWE:** CWE-287 (Improper Authentication), CWE-284 (Improper Access Control), CWE-295 (Improper Certificate Validation), CWE-20 (Improper Input Validation), CWE-319 (Cleartext Transmission of Sensitive Information)
- **OWASP:** API2:2023 - Broken Authentication, API5:2023 - Broken Function Level Authorization, API8:2023 - Security Misconfiguration
- **CVSS Base:** 5.3 - 9.1 (Medium to Critical)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1040 (Network Sniffing)

## Detection Methodology

### 1. Service Discovery via Reflection
gRPC Server Reflection allows clients to query available services at runtime:
```bash
# Using grpcurl to list all services
grpcurl -plaintext target.com:50051 list

# List methods of a specific service
grpcurl -plaintext target.com:50051 list com.example.UserService

# Describe a service
grpcurl -plaintext target.com:50051 describe com.example.UserService

# Describe a message type
grpcurl -plaintext target.com:50051 describe com.example.UserRequest

# Full service description including all fields and types
grpcurl -plaintext target.com:50051 describe .
```

If reflection is disabled, test common service names:
```bash
# Try known/common service names
grpcurl -plaintext target.com:50051 list grpc.health.v1.Health
grpcurl -plaintext target.com:50051 list grpc.reflection.v1alpha.ServerReflection
```

### 2. Proto File Analysis
Obtain and analyze .proto files for attack surface mapping:
```bash
# Sources for .proto files
# - Public repositories (GitHub, GitLab)
# - Mobile app decompilation (APK/IPA)
# - Documentation endpoints
# - Server reflection output
# - Network traffic analysis (protobuf decoding)

# Compile proto files for testing
protoc --descriptor_set_out=services.pb --include_imports *.proto

# Use compiled descriptor with grpcurl
grpcurl -protoset services.pb target.com:50051 list
```

**What to look for in .proto files:**
- Admin/internal service definitions (AdminService, InternalService)
- Sensitive fields (password, token, secret, internal_id)
- Debug/test methods (Debug, Test, HealthCheck with verbose info)
- Privileged operations (DeleteAll, BulkUpdate, ImportData)
- Deprecated but still-defined methods

### 3. Authentication Bypass
```bash
# Request without authentication metadata
grpcurl -plaintext target.com:50051 com.example.UserService/GetUser \
  -d '{"id": 1}'

# Empty or null auth tokens
grpcurl -plaintext -H "authorization: Bearer " target.com:50051 \
  com.example.UserService/GetUser -d '{"id": 1}'

grpcurl -plaintext -H "authorization: Bearer null" target.com:50051 \
  com.example.UserService/GetUser -d '{"id": 1}'

# Expired token reuse
grpcurl -plaintext -H "authorization: Bearer <expired_token>" \
  target.com:50051 com.example.UserService/GetUser -d '{"id": 1}'

# Cross-service token usage
# Use token from ServiceA to access ServiceB

# API key in metadata
grpcurl -plaintext -H "x-api-key: test" target.com:50051 \
  com.example.AdminService/ListUsers -d '{}'

# Internal service impersonation
grpcurl -plaintext -H "x-internal-service: true" \
  -H "x-source-service: payment-service" \
  target.com:50051 com.example.InternalService/GetSecrets -d '{}'
```

### 4. Authorization Testing
```bash
# Access another user's data (BOLA)
grpcurl -plaintext -H "authorization: Bearer <user_a_token>" \
  target.com:50051 com.example.UserService/GetUser -d '{"id": 2}'

# Access admin methods as regular user
grpcurl -plaintext -H "authorization: Bearer <user_token>" \
  target.com:50051 com.example.AdminService/DeleteUser -d '{"id": 1}'

# Method-level authorization
# Test each method individually — authorization may be inconsistent
grpcurl -plaintext target.com:50051 com.example.UserService/ListAllUsers -d '{}'
grpcurl -plaintext target.com:50051 com.example.UserService/ExportData -d '{}'
```

### 5. Message Manipulation
```bash
# Type confusion — send unexpected field types
grpcurl -plaintext target.com:50051 com.example.UserService/UpdateUser \
  -d '{"id": 1, "role": 1}'        # int instead of enum
grpcurl -plaintext target.com:50051 com.example.UserService/UpdateUser \
  -d '{"id": 1, "role": "ADMIN"}'  # string instead of enum

# Unknown field injection
# Protobuf ignores unknown fields by default
grpcurl -plaintext target.com:50051 com.example.UserService/CreateUser \
  -d '{"name": "test", "isAdmin": true, "internalRole": "superadmin"}'

# Integer overflow
grpcurl -plaintext target.com:50051 com.example.OrderService/SetPrice \
  -d '{"id": 1, "price": -1}'
grpcurl -plaintext target.com:50051 com.example.OrderService/SetPrice \
  -d '{"id": 1, "price": 999999999999}'

# Repeated field abuse
grpcurl -plaintext target.com:50051 com.example.UserService/BulkCreate \
  -d '{"users": [' + '"name":"x"},' * 100000 + ']}'

# Oneof field confusion
# Set multiple fields in a oneof group simultaneously
```

### 6. TLS and Transport Security
```bash
# Test for plaintext (non-TLS) gRPC
grpcurl -plaintext target.com:50051 list
# If this succeeds, traffic is unencrypted

# Test TLS configuration
grpcurl target.com:443 list
# Check for: self-signed certs, expired certs, weak ciphers

# TLS with insecure skip verification
grpcurl -insecure target.com:443 list

# Check certificate details
echo | openssl s_client -connect target.com:443 -alpn h2 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates

# Test for mutual TLS (mTLS) enforcement
# Attempt connection without client certificate
grpcurl target.com:443 list
# If no mTLS required for internal services, lateral movement is possible
```

### 7. Denial of Service and Metadata Injection
```bash
# Large message payload
grpcurl -plaintext target.com:50051 com.example.UserService/CreateUser \
  -d '{"name": "'$(python3 -c "print('A'*10000000)"))'"}'

# Stream abuse: send continuous messages without closing; exhaust connections/memory
# Concurrent connection flooding; deadline/timeout manipulation with -max-time 3600

# Header injection via metadata
grpcurl -plaintext -H "x-custom: value\r\nX-Injected: malicious" \
  target.com:50051 com.example.UserService/GetUser -d '{"id": 1}'

# Metadata smuggling (x-forwarded-for, x-real-ip set to 127.0.0.1)
```

## Tool Usage

### grpcurl
```bash
# Primary tool for gRPC testing
# Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Basic service enumeration
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 describe

# Call a method with JSON data
grpcurl -plaintext -d '{"id": 1}' target.com:50051 com.example.UserService/GetUser

# With authentication
grpcurl -plaintext -H "authorization: Bearer TOKEN" -d '{}' \
  target.com:50051 com.example.UserService/ListUsers

# Server streaming
grpcurl -plaintext -d '{"query": "test"}' \
  target.com:50051 com.example.SearchService/StreamResults
```

### grpcui
```bash
# Web-based gRPC GUI (like Postman for gRPC)
grpcui -plaintext target.com:50051
# Opens browser with interactive interface for all services
```

### Burp Suite with gRPC
```
# Use Burp with gRPC-Web or HTTP/2
1. Configure Burp for HTTP/2 (Project Options -> HTTP)
2. Install gRPC-Web or protobuf decoder extensions
3. Intercept and modify protobuf payloads
```

### protoc (Protocol Buffer Compiler)
```bash
# Decode raw protobuf messages
protoc --decode_raw < message.bin

# Encode crafted messages
echo 'field1: "value"' | protoc --encode=MessageType -I. service.proto
```

## Remediation
1. **Disable reflection in production** -- only enable gRPC server reflection in development and staging environments
2. **Enforce TLS** -- require TLS for all gRPC communication; use mTLS for inter-service calls
3. **Per-method authentication** -- implement authentication interceptors that validate credentials for every RPC method
4. **Per-method authorization** -- enforce RBAC or ABAC at the interceptor level, not just at the service level
5. **Input validation** -- validate all message fields in application code; do not rely solely on protobuf type enforcement
6. **Message size limits** -- configure maximum send and receive message sizes (grpc.MaxRecvMsgSize, grpc.MaxSendMsgSize)
7. **Rate limiting** -- implement per-client rate limiting using interceptors
8. **Deadline enforcement** -- set and enforce maximum RPC deadlines server-side
9. **Secure metadata handling** -- sanitize and validate all metadata; reject unknown or suspicious headers
10. **Proto file security** -- treat .proto files as sensitive; do not expose them publicly

## Evidence Collection
- Service listing obtained via reflection (all services, methods, message types)
- Authentication bypass requests with successful responses
- Authorization test results showing cross-user or cross-role access
- Proto file contents revealing internal service architecture
- TLS configuration issues (plaintext, weak ciphers, missing mTLS)
- Message manipulation payloads that bypassed server-side validation
- Metadata injection attempts and their results
- DoS test results including response times under load
