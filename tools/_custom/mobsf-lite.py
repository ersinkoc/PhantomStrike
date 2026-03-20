#!/usr/bin/env python3
"""Mobile app analyzer: extract APK info, check Android security issues (permissions, exports)."""
import argparse, os, sys, zipfile

PERMS = {"android.permission.READ_SMS":"CRITICAL","android.permission.SEND_SMS":"CRITICAL",
    "android.permission.RECEIVE_SMS":"CRITICAL","android.permission.CAMERA":"HIGH",
    "android.permission.RECORD_AUDIO":"HIGH","android.permission.ACCESS_FINE_LOCATION":"HIGH",
    "android.permission.READ_CONTACTS":"HIGH","android.permission.READ_PHONE_STATE":"HIGH",
    "android.permission.INSTALL_PACKAGES":"CRITICAL","android.permission.BIND_DEVICE_ADMIN":"CRITICAL",
    "android.permission.SYSTEM_ALERT_WINDOW":"HIGH","android.permission.WRITE_SETTINGS":"HIGH",
    "android.permission.REQUEST_INSTALL_PACKAGES":"HIGH","android.permission.READ_CALL_LOG":"HIGH",
    "android.permission.WRITE_EXTERNAL_STORAGE":"MEDIUM","android.permission.INTERNET":"LOW",
    "android.permission.ACCESS_NETWORK_STATE":"LOW","android.permission.BLUETOOTH":"MEDIUM"}
SEC_PAT = [(b"http://","Insecure HTTP","MEDIUM"),(b"MODE_WORLD_READABLE","World-readable","HIGH"),
    (b"TrustAllCertificates","Cert bypass","CRITICAL"),(b"addJavascriptInterface","JS interface","HIGH"),
    (b"setAllowFileAccess(true)","WebView file access","HIGH"),(b"DexClassLoader","Dynamic loading","HIGH"),
    (b"SecretKeySpec","Hardcoded key?","HIGH"),(b'android:debuggable="true"',"Debug mode","CRITICAL"),
    (b'android:allowBackup="true"',"Backup allowed","MEDIUM"),(b'android:exported="true"',"Exported","MEDIUM"),
    (b"SQLiteDatabase","SQLite (check injection)","LOW")]

def analyze(filepath):
    r = {"info":{},"perms":[],"findings":[],"files":[]}
    try:
        with zipfile.ZipFile(filepath) as z:
            r["files"] = z.namelist(); r["info"]["total"] = len(r["files"])
            r["info"]["size"] = os.path.getsize(filepath)
            r["info"]["dex"] = any(f.endswith(".dex") for f in r["files"])
            r["info"]["manifest"] = "AndroidManifest.xml" in r["files"]
            r["info"]["cert"] = any(f.startswith("META-INF/") and f.endswith((".RSA",".DSA")) for f in r["files"])
            r["info"]["native"] = [f for f in r["files"] if f.endswith(".so")][:8]
            r["info"]["interesting"] = [f for f in r["files"] if any(
                k in f.lower() for k in ["config","secret","key","password","token",".json",".xml"])][:15]
            for name in r["files"]:
                if name.endswith((".dex",".xml",".smali")):
                    try:
                        data = z.read(name)
                        for pat, desc, sev in SEC_PAT:
                            if pat in data: r["findings"].append({"file":name,"issue":desc,"sev":sev})
                    except: pass
            if r["info"]["manifest"]:
                try:
                    md = z.read("AndroidManifest.xml")
                    for p in PERMS:
                        if p.encode() in md: r["perms"].append(p)
                except: pass
    except zipfile.BadZipFile: r["error"] = "Not a valid APK"
    except Exception as e: r["error"] = str(e)
    return r

def main():
    parser = argparse.ArgumentParser(description="Mobile app analyzer")
    parser.add_argument("target", help="APK file"); parser.add_argument("-v","--verbose",action="store_true")
    args = parser.parse_args()
    print(f"[*] MobSF-Lite\n[*] Target: {args.target}\n")
    if not os.path.isfile(args.target): print(f"[!] Not found"); sys.exit(1)
    r = analyze(args.target)
    if "error" in r: print(f"[!] {r['error']}"); sys.exit(1)
    i = r["info"]
    print(f"=== APK Info ===\n  Size: {i['size']:,}B | Files: {i['total']} | DEX: {i['dex']} | Cert: {i['cert']}")
    if i["native"]: print(f"  Native: {', '.join(os.path.basename(n) for n in i['native'][:5])}")
    if r["perms"]:
        print(f"\n=== Permissions ({len(r['perms'])}) ===")
        sev_ord = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        for p in sorted(r["perms"], key=lambda x: sev_ord.get(PERMS.get(x,"LOW"),3)):
            s = PERMS.get(p,"LOW"); icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(s,"[*]")
            print(f"  {icon} [{s}] {p}")
    if r["findings"]:
        seen = set(); unique = []
        for f in r["findings"]:
            k = f"{f['issue']}:{f['file']}"
            if k not in seen: seen.add(k); unique.append(f)
        print(f"\n=== Findings ({len(unique)}) ===")
        for f in unique[:20]:
            icon = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(f["sev"],"[*]")
            print(f"  {icon} [{f['sev']}] {f['issue']} in {f['file']}")
    if i.get("interesting"):
        print(f"\n=== Interesting Files ===")
        for f in i["interesting"][:10]: print(f"  {f}")
    print(f"\n{'='*50}\n[*] Risk indicators: {len(r['findings'])}")

if __name__ == "__main__":
    main()
