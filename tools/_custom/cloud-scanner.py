#!/usr/bin/env python3
"""Multi-cloud scanner: check S3 buckets, Azure blobs, GCP storage for public access."""
import argparse
import re
import sys
import xml.etree.ElementTree as ET

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PREFIXES = [
    "", "dev", "staging", "prod", "production", "test", "backup", "backups",
    "data", "assets", "static", "media", "uploads", "files", "logs",
    "public", "private", "internal", "images", "img", "cdn",
    "web", "www", "api", "app", "mobile", "docs", "documents",
    "db", "database", "archive", "archives", "temp", "tmp",
    "config", "configs", "configuration", "secrets", "keys",
    "deploy", "deployment", "release", "releases", "builds", "build",
    "ci", "cd", "jenkins", "artifacts", "packages", "dist",
]

BUCKET_SUFFIXES = [
    "", "-dev", "-staging", "-prod", "-backup", "-data", "-assets",
    "-public", "-private", "-logs", "-test", "-old", "-new",
]


def generate_names(base_name):
    """Generate bucket/container name variations."""
    names = set()
    clean = re.sub(r"[^a-z0-9-]", "", base_name.lower())
    parts = clean.split("-")

    for prefix in COMMON_PREFIXES:
        if prefix:
            names.add(f"{prefix}-{clean}")
            names.add(f"{clean}-{prefix}")
            names.add(f"{prefix}.{clean}")
        else:
            names.add(clean)

    for suffix in BUCKET_SUFFIXES:
        names.add(f"{clean}{suffix}")

    if len(parts) > 1:
        names.add("".join(parts))

    return sorted(names)[:80]  # Limit to prevent excessive requests


def check_s3_bucket(name, timeout):
    """Check if S3 bucket exists and is publicly accessible."""
    result = {"name": name, "provider": "AWS S3", "exists": False, "public": False, "items": []}

    # Check via HTTP
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]

    for url in urls:
        try:
            r = requests.get(url, timeout=timeout, verify=True)
            if r.status_code == 200:
                result["exists"] = True
                result["public"] = True
                result["url"] = url
                result["status"] = r.status_code
                # Try to parse listing
                try:
                    root = ET.fromstring(r.text)
                    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
                    keys = root.findall(".//s3:Key", ns) or root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                    if not keys:
                        keys = root.findall(".//Key")
                    for key in keys[:10]:
                        result["items"].append(key.text)
                except Exception:
                    pass
                return result
            elif r.status_code == 403:
                result["exists"] = True
                result["public"] = False
                result["url"] = url
                result["status"] = 403
                return result
            elif r.status_code == 301:
                # Bucket exists in different region
                result["exists"] = True
                result["public"] = False
                result["url"] = url
                result["status"] = 301
                result["redirect"] = r.headers.get("Location", "")
                return result
        except Exception:
            continue

    return result


def check_azure_blob(name, timeout):
    """Check if Azure Blob container is publicly accessible."""
    result = {"name": name, "provider": "Azure Blob", "exists": False, "public": False, "items": []}

    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            result["exists"] = True
            result["public"] = True
            result["url"] = url
            result["status"] = r.status_code
            try:
                root = ET.fromstring(r.text)
                for container in root.findall(".//Container/Name"):
                    result["items"].append(container.text)
            except Exception:
                pass
            return result
        elif r.status_code == 400:
            # Storage account exists but listing not allowed
            # Try known container names
            for container in ["$web", "public", "data", "assets", "uploads", "files", "media"]:
                blob_url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
                try:
                    r2 = requests.get(blob_url, timeout=timeout)
                    if r2.status_code == 200:
                        result["exists"] = True
                        result["public"] = True
                        result["url"] = blob_url
                        result["items"].append(f"Container: {container} (public)")
                        return result
                except Exception:
                    continue
            result["exists"] = True
            result["status"] = 400
        elif r.status_code in (403, 404):
            if r.status_code == 403:
                result["exists"] = True
                result["status"] = 403
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    return result


def check_gcp_bucket(name, timeout):
    """Check if GCP storage bucket is publicly accessible."""
    result = {"name": name, "provider": "GCP Storage", "exists": False, "public": False, "items": []}

    url = f"https://storage.googleapis.com/{name}/"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            result["exists"] = True
            result["public"] = True
            result["url"] = url
            result["status"] = r.status_code
            try:
                root = ET.fromstring(r.text)
                ns = {"gcs": "http://doc.s3.amazonaws.com/2006-03-01"}
                keys = root.findall(".//Key") or root.findall(".//{http://doc.s3.amazonaws.com/2006-03-01}Key")
                for key in keys[:10]:
                    result["items"].append(key.text)
            except Exception:
                pass
            return result
        elif r.status_code == 403:
            result["exists"] = True
            result["status"] = 403
        elif r.status_code == 404:
            pass  # Bucket doesn't exist
    except Exception:
        pass

    return result


def check_digitalocean_spaces(name, timeout):
    """Check DigitalOcean Spaces."""
    result = {"name": name, "provider": "DO Spaces", "exists": False, "public": False}
    regions = ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
    for region in regions:
        url = f"https://{name}.{region}.digitaloceanspaces.com/"
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                result["exists"] = True
                result["public"] = True
                result["url"] = url
                result["region"] = region
                return result
            elif r.status_code == 403:
                result["exists"] = True
                result["url"] = url
                result["region"] = region
                return result
        except Exception:
            continue
    return result


def main():
    ap = argparse.ArgumentParser(description="Cloud-Scanner: Multi-cloud public storage checker")
    ap.add_argument("target", help="Organization/domain name to generate bucket names from")
    ap.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout")
    ap.add_argument("--providers", nargs="+", default=["s3", "azure", "gcp"],
                    choices=["s3", "azure", "gcp", "do"], help="Cloud providers to check")
    ap.add_argument("--custom", nargs="+", help="Custom bucket names to check")
    ap.add_argument("--quick", action="store_true", help="Quick scan (fewer name variations)")
    args = ap.parse_args()

    base = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    base = base.split(".")[0] if "." in base else base

    print(f"[*] Cloud Scanner: Multi-Cloud Public Storage Checker")
    print(f"[*] Base name: {base}")
    print(f"[*] Providers: {', '.join(args.providers)}\n")

    names = args.custom if args.custom else generate_names(base)
    if args.quick:
        names = names[:20]

    print(f"[*] Testing {len(names)} name variations\n")

    all_findings = []
    provider_funcs = {
        "s3": ("AWS S3", check_s3_bucket),
        "azure": ("Azure Blob", check_azure_blob),
        "gcp": ("GCP Storage", check_gcp_bucket),
        "do": ("DigitalOcean Spaces", check_digitalocean_spaces),
    }

    for provider_key in args.providers:
        provider_name, check_fn = provider_funcs[provider_key]
        print(f"  === {provider_name} ===\n")

        found_any = False
        for name in names:
            result = check_fn(name, args.timeout)
            if result["exists"]:
                found_any = True
                status = "PUBLIC" if result["public"] else "EXISTS (private)"
                severity = "CRITICAL" if result["public"] else "INFO"
                print(f"  [{severity}] {name}")
                print(f"    Status: {status}")
                if result.get("url"):
                    print(f"    URL: {result['url']}")
                if result.get("items"):
                    print(f"    Items ({len(result['items'])}):")
                    for item in result["items"][:5]:
                        print(f"      - {item}")
                    if len(result["items"]) > 5:
                        print(f"      ... and {len(result['items']) - 5} more")
                all_findings.append(result)

        if not found_any:
            print(f"  [OK] No buckets found")
        print()

    print(f"{'='*60}")
    print(f"[*] CLOUD SCAN RESULTS")
    print(f"{'='*60}\n")

    public = [f for f in all_findings if f["public"]]
    private = [f for f in all_findings if f["exists"] and not f["public"]]

    print(f"  Names tested: {len(names) * len(args.providers)}")
    print(f"  Buckets found: {len(all_findings)}")
    print(f"  Publicly accessible: {len(public)}")
    print(f"  Private (exists): {len(private)}")

    if public:
        print(f"\n  [!!!] PUBLICLY ACCESSIBLE STORAGE:")
        for f in public:
            print(f"    [{f['provider']}] {f['name']}: {f.get('url', '')}")
            if f.get("items"):
                print(f"      Contains {len(f['items'])} visible item(s)")
        print(f"\n  [!] Public cloud storage can expose sensitive data!")
    else:
        print(f"\n  [OK] No publicly accessible storage found")


if __name__ == "__main__":
    main()
