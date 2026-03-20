#!/usr/bin/env python3
"""Scan for exposed Swagger/OpenAPI documentation endpoints."""
import argparse
import json
import sys
import requests

SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-ui/", "/swagger-ui.html", "/swagger-ui/index.html",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
    "/api-docs", "/api-docs/swagger.json",
    "/v2/api-docs", "/v3/api-docs",
    "/docs", "/docs/", "/redoc",
    "/api/swagger.json", "/api/openapi.json",
    "/api/docs", "/api/v1/docs",
    "/.well-known/openapi.json",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/api/swagger/ui", "/api/swagger-ui.html",
]


def scan_target(base_url, timeout):
    base_url = base_url.rstrip("/")
    found = []
    specs = []

    print(f"[*] Scanning {base_url} for Swagger/OpenAPI docs...\n")

    for path in SWAGGER_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                verify=False, headers={"User-Agent": "PhantomStrike/1.0"})
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                body = resp.text[:500]
                is_spec = False

                if "json" in content_type or "yaml" in content_type:
                    is_spec = True
                elif any(k in body.lower() for k in ['"openapi"', '"swagger"', "openapi:", "swagger:"]):
                    is_spec = True
                elif "swagger-ui" in body.lower() or "SwaggerUI" in body:
                    is_spec = False  # UI page, not spec

                tag = "SPEC" if is_spec else "UI/DOC"
                print(f"  [{tag}]  {path}")
                print(f"          Content-Type: {content_type}")
                print(f"          Size: {len(resp.content)} bytes")

                entry = {"path": path, "type": tag, "content_type": content_type,
                         "size": len(resp.content)}
                found.append(entry)

                if is_spec:
                    specs.append((path, resp.text))
                    try:
                        spec = json.loads(resp.text)
                        title = spec.get("info", {}).get("title", "N/A")
                        version = spec.get("info", {}).get("version", "N/A")
                        api_ver = spec.get("openapi", spec.get("swagger", "N/A"))
                        num_paths = len(spec.get("paths", {}))
                        print(f"          API: {title} v{version} (spec {api_ver})")
                        print(f"          Endpoints: {num_paths}")
                    except (json.JSONDecodeError, AttributeError):
                        pass
                print()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            continue

    print(f"[*] Scan complete: {len(found)} Swagger/OpenAPI resources found")
    if found:
        print("\n=== Findings ===")
        for f in found:
            print(f"  [{f['type']}] {f['path']} ({f['size']} bytes)")

    if not found:
        print("[*] No Swagger/OpenAPI documentation exposed.")

    return found


def main():
    parser = argparse.ArgumentParser(description="Swagger/OpenAPI scanner")
    parser.add_argument("target", help="Target base URL (e.g., http://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scan_target(target, args.timeout)


if __name__ == "__main__":
    main()
