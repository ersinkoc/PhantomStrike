# iOS Security Testing

## Overview
iOS security testing involves analyzing IPA packages, inspecting binary protections, evaluating Keychain and Data Protection usage, testing URL scheme handlers, and bypassing client-side defenses such as jailbreak detection and certificate pinning. Despite the iOS sandbox model, vulnerabilities in data storage, transport security, and inter-app communication can lead to significant data exposure and authentication bypass.

## Classification
- **CWE:** CWE-312 (Cleartext Storage), CWE-295 (Improper Certificate Validation), CWE-939 (Improper Authorization in Handler for Custom URL Scheme)
- **OWASP Mobile:** M1-M10 (OWASP Mobile Top 10 2024)
- **CVSS Base:** 4.0 - 9.8 (Medium to Critical depending on finding)
- **MITRE ATT&CK Mobile:** T1409 (Access Stored Application Data), T1417 (Input Capture)

## Methodology

### 1. IPA Acquisition and Extraction
```bash
# Obtain IPA from jailbroken device
ssh root@<device_ip>
find /var/containers/Bundle/Application -name "*.app" | grep target

# Decrypt app binary (if encrypted)
# Using frida-ios-dump
python3 dump.py com.target.app

# Extract IPA contents
unzip target.ipa -d ipa_output
ls ipa_output/Payload/Target.app/
```

### 2. Binary Analysis
```bash
# Check binary protections
otool -hv Target                # Architecture
otool -l Target | grep -A4 LC_ENCRYPTION_INFO  # Encryption check
otool -l Target | grep PIE      # ASLR/PIE
otool -l Target | grep -i stack  # Stack canaries
otool -I -v Target | grep _objc_release  # ARC

# Class and method enumeration
class-dump Target > classes.h
class-dump -H Target -o headers/

# Search for interesting strings
strings Target | grep -iE "api|key|secret|password|token|http"

# Disassemble with Hopper
# Open binary in Hopper Disassembler for control flow analysis
# Look for authentication logic, crypto implementations, validation routines
```

### 3. Data Storage Testing
```bash
# Plist files (may contain tokens, settings)
find /var/mobile/Containers/Data/Application/<UUID> -name "*.plist"
plutil -p com.target.app.plist

# SQLite databases
find /var/mobile/Containers/Data/Application/<UUID> -name "*.db" -o -name "*.sqlite"
sqlite3 app.db ".tables" && sqlite3 app.db ".dump"

# NSUserDefaults
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.target.app.plist

# Caches and snapshots
ls /var/mobile/Containers/Data/Application/<UUID>/Library/Caches/
ls /var/mobile/Containers/Data/Application/<UUID>/Library/SplashBoard/Snapshots/

# Cookies
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Cookies/Cookies.binarycookies

# Check clipboard for sensitive data
# Use Frida to hook UIPasteboard
```

### 4. Keychain Analysis
```bash
# Dump Keychain items with objection
objection -g com.target.app explore
ios keychain dump

# Check Keychain protection classes
# kSecAttrAccessibleWhenUnlocked (reasonable)
# kSecAttrAccessibleAlways (INSECURE)
# kSecAttrAccessibleAfterFirstUnlock (acceptable for push tokens)
# kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly (strongest)

# Frida script to dump Keychain
frida -U -f com.target.app -l keychain_dump.js
```

### 5. Data Protection Classes
Verify files use appropriate protection levels:
```
NSFileProtectionComplete — encrypted when locked (best)
NSFileProtectionCompleteUnlessOpen — encrypted unless file handle open
NSFileProtectionCompleteUntilFirstUserAuthentication — encrypted until first unlock
NSFileProtectionNone — no protection (INSECURE)
```

```bash
# Check protection class of files
objection -g com.target.app explore
ios nsuserdefaults get
ios bundles list_frameworks
```

### 6. URL Scheme Testing
```bash
# Identify registered URL schemes
cat ipa_output/Payload/Target.app/Info.plist | grep -A5 CFBundleURLSchemes

# Test URL scheme handling
# On device Safari:
# targetapp://action?param=value
# targetapp://deeplink?url=http://evil.com
# targetapp://callback?token=stolen_token

# Test for URL scheme hijacking
# Verify if another app can register the same scheme

# Universal Links validation
cat ipa_output/Payload/Target.app/apple-app-site-association
```

### 7. Jailbreak Detection Bypass
```bash
# Objection automated bypass
objection -g com.target.app explore
ios jailbreak disable

# Common checks to bypass:
# - File existence: /Applications/Cydia.app, /bin/bash, /usr/sbin/sshd
# - URL scheme: cydia://
# - Sandbox integrity: writing outside sandbox
# - Dynamic library injection detection
# - Fork-based detection

# Frida bypass script
frida -U -f com.target.app -l jailbreak_bypass.js --no-pause
```

```javascript
// Frida jailbreak bypass example
var paths = ["/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd",
             "/etc/apt", "/private/var/lib/apt"];
Interceptor.attach(Module.findExportByName(null, "stat"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        for (var i = 0; i < paths.length; i++) {
            if (path.indexOf(paths[i]) !== -1) {
                Memory.writeUtf8String(args[0], "/nonexistent");
            }
        }
    }
});
```

### 8. Certificate Pinning Bypass
```bash
# Objection SSL pinning bypass
objection -g com.target.app explore
ios sslpinning disable

# Frida bypass for common frameworks
# NSURLSession, ATS, Alamofire, AFNetworking, TrustKit
frida -U -f com.target.app -l ios_ssl_bypass.js --no-pause

# SSL Kill Switch 2 (Cydia tweak for jailbroken devices)
# Install via Cydia: com.nablac0d3.sslkillswitch2
```

### 9. Runtime Manipulation with Frida
```javascript
// Hook Objective-C method
var className = "AuthenticationManager";
var methodName = "- validateCredentials:password:";
var hook = ObjC.classes[className][methodName];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        console.log("User: " + ObjC.Object(args[2]).toString());
        console.log("Pass: " + ObjC.Object(args[3]).toString());
    },
    onLeave: function(retval) {
        console.log("Result: " + retval);
        retval.replace(0x1); // Force return true
    }
});

// List all classes from the app bundle
ObjC.enumerateLoadedClasses({
    ownedBy: ObjC.classes.NSBundle.mainBundle(),
}, { onMatch: function(name) { console.log(name); },
     onComplete: function() {} });
```

## Tool Usage

### objection
```bash
# Attach to running app
objection -g com.target.app explore

# Useful commands
ios keychain dump                    # Dump keychain entries
ios plist cat <path>                 # Read plist files
ios cookies get                      # Get cookies
ios nsurlcredentialstorage dump      # Dump stored credentials
ios ui dump                          # Dump current UI hierarchy
ios bundles list_frameworks          # List loaded frameworks
ios hooking list classes             # List ObjC classes
ios hooking watch method "<class> <method>"  # Watch method calls
```

### class-dump
```bash
# Generate headers from binary
class-dump -H Target -o output_headers/
# Review headers for authentication, crypto, storage classes
grep -r "password\|secret\|token\|encrypt" output_headers/
```

## Remediation
1. **Use Keychain with strongest protection class** — `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
2. **Enable Data Protection** — `NSFileProtectionComplete` for sensitive files
3. **Implement App Transport Security** — enforce TLS 1.2+ with no exceptions
4. **Certificate pinning** with backup pins and graceful rotation strategy
5. **Validate URL scheme input** — sanitize all parameters, reject unexpected schemes
6. **Use Universal Links** instead of custom URL schemes where possible
7. **Clear sensitive data** from pasteboard, snapshots, and caches on background
8. **Implement binary protections** — PIE, ARC, stack canaries, code obfuscation
9. **Avoid logging sensitive data** — disable NSLog in production builds

## Evidence Collection
- Binary analysis output showing missing protections (no PIE, no ARC)
- Keychain dump showing tokens stored with weak protection classes
- Plist or database contents containing plaintext credentials
- URL scheme test results showing unvalidated deep link handling
- Frida console output demonstrating bypassed security controls
- Screenshots of sensitive data visible in app snapshots or caches
