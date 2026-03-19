# Mobile Application Security Testing Guide

## Overview

Mobile app security testing covers Android and iOS platforms, focusing on client-side
vulnerabilities, insecure data storage, network communication flaws, and backend API
weaknesses. Testing requires both static and dynamic analysis.

## Android Security Testing

### Static Analysis
```bash
# Decompile APK
apktool d target.apk -o target_decompiled
# Extract Java source (jadx)
jadx target.apk -d target_source
# Search for hardcoded secrets
grep -rn "api_key\|password\|secret\|token\|AWS" target_source/
# Check AndroidManifest.xml for misconfigurations
cat target_decompiled/AndroidManifest.xml
```

### Key Manifest Checks
- `android:debuggable="true"` - debuggable in production (Critical)
- `android:allowBackup="true"` - data extractable via adb backup
- Exported components without permission checks (activities, services, receivers)
- `android:usesCleartextTraffic="true"` - allows HTTP traffic
- Missing `android:networkSecurityConfig` - no certificate pinning

### Dynamic Analysis
```bash
# Install Frida server on rooted device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
# Bypass SSL pinning with Frida
frida -U -l ssl_pinning_bypass.js -f com.target.app
# Objection (Frida wrapper)
objection -g com.target.app explore
# Inside objection
android sslpinning disable
android root disable
```

### Data Storage Checks
```bash
# Check shared preferences (on rooted device)
adb shell cat /data/data/com.target.app/shared_prefs/*.xml
# Check SQLite databases
adb pull /data/data/com.target.app/databases/
sqlite3 database.db ".dump"
# Check for sensitive data in logs
adb logcat | grep -i "token\|password\|key"
```

## iOS Security Testing

### Static Analysis
```bash
# Decrypt IPA (on jailbroken device using frida-ios-dump)
python3 dump.py com.target.app
# Extract class information
class-dump-z decrypted.app > classes.txt
# Search for hardcoded strings
strings decrypted_binary | grep -i "api\|key\|secret\|password"
# Check Info.plist
plutil -p Info.plist
```

### Key Info.plist Checks
- `NSAppTransportSecurity` exceptions allowing HTTP
- Custom URL schemes that could be hijacked
- Missing `NSFaceIDUsageDescription` when using biometrics
- Enabled background modes that may leak data

### Dynamic Analysis
```bash
# Frida on jailbroken iOS
frida -U -l hook_script.js -f com.target.app
# Objection for iOS
objection -g com.target.app explore
# Inside objection
ios sslpinning disable
ios keychain dump
ios nsuserdefaults get
```

### Data Storage Checks
- Keychain entries (should use appropriate access control)
- NSUserDefaults (should not contain sensitive data)
- SQLite databases and Core Data stores
- Cache and temporary files
- Pasteboard/clipboard data leakage

## Common Mobile Vulnerabilities

### Insecure Communication
- Missing or bypassable SSL/TLS certificate pinning
- Sending sensitive data over HTTP
- Ignoring certificate validation errors
- Leaking data through system logs

### Insecure Authentication
- Weak local authentication (simple PIN, no biometric)
- Session tokens stored in plaintext
- Missing re-authentication for sensitive operations
- Client-side authentication bypass

### Reverse Engineering
- Lack of code obfuscation
- Debug symbols left in production builds
- Hardcoded API keys, tokens, and credentials
- Business logic exposed in client code

### Binary Protections
```bash
# Check for PIE (Position Independent Executable)
rabin2 -I binary | grep pic
# Check for stack canaries
rabin2 -I binary | grep canary
# Check for ARC (iOS)
otool -Iv binary | grep objc_release
```

## Network Interception Setup
```bash
# Set up Burp Suite proxy for mobile
# 1. Configure device proxy to BURP_IP:8080
# 2. Install Burp CA certificate on device
# Android: push to /system/etc/security/cacerts/
adb push burp_cert.pem /system/etc/security/cacerts/9a5ba575.0
# iOS: install profile via Safari, then trust in Settings
```

## Tools
- **Frida** - dynamic instrumentation toolkit
- **Objection** - runtime mobile exploration (Frida-based)
- **MobSF** - automated mobile security framework (static + dynamic)
- **apktool / jadx** - Android reverse engineering
- **Burp Suite** - traffic interception proxy
- **drozer** - Android security assessment framework
- **idb** - iOS app assessment tool

## Remediation
- Implement certificate pinning with backup pins
- Use Android Keystore / iOS Keychain for secret storage
- Enable code obfuscation (ProGuard/R8 for Android)
- Disable debugging and backup in production builds
- Validate all input on the server side, not just client
- Implement root/jailbreak detection (defense in depth, not sole control)
- Use secure communication for all API calls (TLS 1.2+)
- Apply OWASP Mobile Top 10 guidelines
