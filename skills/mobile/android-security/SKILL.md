# Android Security Testing

## Overview
Android security testing involves analyzing APK packages, reverse engineering application logic, inspecting data storage practices, evaluating inter-process communication (IPC) mechanisms, and bypassing client-side protections such as certificate pinning and root detection. The goal is to identify vulnerabilities that could lead to data leakage, unauthorized access, or code execution on the device.

## Classification
- **CWE:** CWE-312 (Cleartext Storage), CWE-319 (Cleartext Transmission), CWE-927 (Improper Intent Handling)
- **OWASP Mobile:** M1-M10 (OWASP Mobile Top 10 2024)
- **CVSS Base:** 4.0 - 9.8 (Medium to Critical depending on finding)
- **MITRE ATT&CK Mobile:** T1407 (Download New Code at Runtime), T1409 (Access Stored Application Data)

## Methodology

### 1. APK Acquisition and Static Analysis
Obtain the APK and decompile for source review:
```bash
# Pull APK from device
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app/base.apk

# Decompile with apktool (resources + smali)
apktool d base.apk -o apk_output

# Decompile with jadx (Java source)
jadx -d jadx_output base.apk
jadx-gui base.apk
```

**Review targets:**
- `AndroidManifest.xml` — exported components, permissions, `android:debuggable`, `android:allowBackup`
- Hardcoded secrets — API keys, credentials, tokens in source or resources
- Embedded URLs — staging/dev endpoints, admin panels
- Cryptographic misuse — weak algorithms, hardcoded keys, ECB mode

### 2. Manifest and Component Analysis
```bash
# List exported activities, services, receivers, providers
aapt dump xmltree base.apk AndroidManifest.xml

# Check for dangerous configurations
# android:exported="true" without permission protection
# android:debuggable="true"
# android:allowBackup="true"
# android:usesCleartextTraffic="true"
```

### 3. Data Storage Testing
```bash
# Check shared preferences (plaintext XML)
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Check SQLite databases
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db ".tables" && sqlite3 app.db ".dump"

# Check for files on external storage
adb shell ls /sdcard/Android/data/com.target.app/

# Check for sensitive data in logs
adb logcat | grep -i "password\|token\|key\|secret"
```

### 4. IPC and Intent Testing
```bash
# Send intents to exported activities
adb shell am start -n com.target.app/.DeepLinkActivity -d "http://evil.com"

# Broadcast to exported receivers
adb shell am broadcast -a com.target.app.ACTION -e data "payload"

# Query exported content providers
adb shell content query --uri content://com.target.app.provider/users

# Test for intent injection / redirection
adb shell am start -n com.target.app/.WebViewActivity -e url "javascript:alert(1)"
```

### 5. WebView Security
Test for JavaScript injection and insecure WebView configurations:
```javascript
// Indicators of vulnerable WebView (in source)
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(obj, "Android");  // JS bridge
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

### 6. Certificate Pinning Bypass
```bash
# Frida script to bypass common pinning libraries
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Objection automated bypass
objection -g com.target.app explore
# Inside objection:
android sslpinning disable

# For OkHttp, TrustManager, network_security_config
# Use specialized Frida scripts targeting each implementation
```

### 7. Root Detection Bypass
```bash
# Objection bypass
objection -g com.target.app explore
android root disable

# Frida bypass for common checks
frida -U -f com.target.app -l root_bypass.js --no-pause

# Common checks to bypass:
# - su binary existence check
# - Build.TAGS contains "test-keys"
# - Installed packages (Magisk, SuperSU)
# - RootBeer library checks
# - SafetyNet/Play Integrity API
```

### 8. Dynamic Instrumentation with Frida
```javascript
// Hook a method and log arguments
Java.perform(function() {
    var targetClass = Java.use("com.target.app.AuthManager");
    targetClass.login.implementation = function(user, pass) {
        console.log("Username: " + user + " Password: " + pass);
        return this.login(user, pass);
    };
});

// Enumerate loaded classes
Java.perform(function() {
    Java.enumerateLoadedClasses({ onMatch: function(name) {
        if (name.includes("com.target")) console.log(name);
    }, onComplete: function() {} });
});
```

## Tool Usage

### MobSF (Mobile Security Framework)
```bash
# Run MobSF and upload APK for automated analysis
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK via http://localhost:8000 — produces static analysis report
```

### drozer
```bash
# Connect to agent on device
drozer console connect

# Enumerate attack surface
run app.package.attacksurface com.target.app

# List exported activities
run app.activity.info -a com.target.app

# Query content providers
run app.provider.query content://com.target.app.provider/users

# Test for SQL injection in content providers
run scanner.provider.injection -a com.target.app

# Test for path traversal in content providers
run scanner.provider.traversal -a com.target.app
```

### apktool + jadx
```bash
# Full decompile → modify → repack → sign
apktool d base.apk -o modified
# (edit smali/resources)
apktool b modified -o repackaged.apk
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore test.keystore repackaged.apk test
adb install repackaged.apk
```

## Remediation
1. **Disable backup and debugging** in production — `android:allowBackup="false"`, `android:debuggable="false"`
2. **Protect exported components** with signature-level permissions or set `android:exported="false"`
3. **Encrypt sensitive data** — use EncryptedSharedPreferences, SQLCipher, Android Keystore
4. **Implement certificate pinning** via `network_security_config.xml` with backup pins
5. **Validate all IPC inputs** — sanitize Intent extras, restrict Content Provider access
6. **Disable JavaScript in WebViews** unless required; never use `addJavascriptInterface` with untrusted content
7. **Use ProGuard/R8** for code obfuscation and remove debug logs
8. **Implement Play Integrity API** for device attestation (not as sole protection)
9. **Avoid storing secrets client-side** — use server-side session management

## Evidence Collection
- Screenshots of decompiled source showing hardcoded credentials or insecure configurations
- Exported `AndroidManifest.xml` with highlighted vulnerable attributes
- Frida console output showing intercepted credentials or bypassed protections
- SQLite database dumps containing sensitive plaintext data
- drozer output showing exploitable components and data exposure
- MobSF report summary with severity ratings
