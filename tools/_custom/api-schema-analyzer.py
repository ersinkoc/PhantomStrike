#!/usr/bin/env python3
"""API Schema Analyzer - Detect and analyze API schemas (OpenAPI, GraphQL, WSDL)"""
import argparse, requests, json, sys

SCHEMA_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api/docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/schema", "/api/spec", "/schema.json", "/spec.json",
    "/.well-known/openapi.json", "/api/openapi", "/docs/api",
    "/graphql", "/graphiql", "/api/graphql",
    "/wsdl", "/service.wsdl", "/?wsdl",
]

def main():
    parser = argparse.ArgumentParser(description="API Schema Analyzer")
    parser.add_argument("target", help="Target URL or hostname")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    print(f"[*] API Schema Analyzer - Target: {target}\n")

    found = []
    for path in SCHEMA_PATHS:
        url = f"{target}{path}"
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True,
                           headers={"Accept": "application/json"})
            if r.status_code == 200 and len(r.text) > 50:
                content_type = r.headers.get("content-type", "")
                if any(x in content_type for x in ["json", "yaml", "xml", "html"]):
                    found.append({"path": path, "status": r.status_code, "size": len(r.text),
                                "type": content_type.split(";")[0]})
                    print(f"  [FOUND] {path} ({r.status_code}, {len(r.text)} bytes, {content_type.split(';')[0]})")

                    # Try to parse as OpenAPI
                    try:
                        data = r.json()
                        if "openapi" in data or "swagger" in data:
                            version = data.get("openapi", data.get("swagger", "?"))
                            title = data.get("info", {}).get("title", "?")
                            paths = len(data.get("paths", {}))
                            print(f"    OpenAPI {version}: {title} ({paths} endpoints)")
                            for p in list(data.get("paths", {}).keys())[:10]:
                                methods = list(data["paths"][p].keys())
                                print(f"      {', '.join(m.upper() for m in methods)} {p}")
                    except:
                        pass
        except:
            pass

    print(f"\n=== Summary ===")
    print(f"Schemas found: {len(found)}")
    if not found:
        print("No API schemas detected.")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
