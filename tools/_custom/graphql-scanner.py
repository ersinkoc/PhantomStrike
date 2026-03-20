#!/usr/bin/env python3
"""Detect and introspect GraphQL endpoints."""
import argparse
import json
import sys
import requests

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/graphql/console",
    "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/v1/graphql",
    "/query", "/gql",
    "/graphql/schema", "/graphql/playground",
    "/altair", "/voyager",
    "/explorer",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

SIMPLE_QUERY = '{"query": "{ __typename }"}'


def check_endpoint(url, timeout):
    """Check if a URL is a GraphQL endpoint."""
    headers = {"Content-Type": "application/json", "User-Agent": "PhantomStrike/1.0"}
    try:
        resp = requests.post(url, data=SIMPLE_QUERY, headers=headers,
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    return True, data
            except (json.JSONDecodeError, ValueError):
                pass
        # Also try GET
        resp = requests.get(f"{url}?query={{__typename}}", headers=headers,
                            timeout=timeout, verify=False)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    return True, data
            except (json.JSONDecodeError, ValueError):
                pass
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        pass
    return False, None


def try_introspection(url, timeout):
    """Attempt GraphQL introspection."""
    headers = {"Content-Type": "application/json", "User-Agent": "PhantomStrike/1.0"}
    payload = json.dumps({"query": INTROSPECTION_QUERY})
    try:
        resp = requests.post(url, data=payload, headers=headers,
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                return True, data["data"]["__schema"]
    except Exception:
        pass
    return False, None


def scan_target(base_url, timeout):
    base_url = base_url.rstrip("/")
    found_endpoints = []

    print(f"[*] Scanning {base_url} for GraphQL endpoints...\n")

    for path in GRAPHQL_PATHS:
        url = f"{base_url}{path}"
        is_gql, data = check_endpoint(url, timeout)
        if is_gql:
            print(f"  [FOUND] GraphQL endpoint: {path}")
            entry = {"path": path, "url": url, "introspection": False}

            intro_ok, schema = try_introspection(url, timeout)
            if intro_ok:
                print(f"  [VULN]  Introspection ENABLED at {path}")
                entry["introspection"] = True
                types = schema.get("types", [])
                custom_types = [t for t in types
                                if not t["name"].startswith("__") and t["kind"] in ("OBJECT",)]
                print(f"          Query type: {schema.get('queryType', {}).get('name', 'N/A')}")
                mutation = schema.get("mutationType")
                if mutation:
                    print(f"          Mutation type: {mutation.get('name', 'N/A')}")
                    entry["has_mutations"] = True
                print(f"          Custom types: {len(custom_types)}")
                for t in custom_types[:10]:
                    fields = [f["name"] for f in (t.get("fields") or [])]
                    print(f"            - {t['name']}: {', '.join(fields[:5])}")
                if len(custom_types) > 10:
                    print(f"            ... and {len(custom_types) - 10} more")
            else:
                print(f"  [OK]    Introspection disabled at {path}")
            print()
            found_endpoints.append(entry)

    print(f"[*] Scan complete: {len(found_endpoints)} GraphQL endpoint(s) found")
    if any(e["introspection"] for e in found_endpoints):
        print("[!] WARNING: Introspection is enabled - information disclosure risk")

    return found_endpoints


def main():
    parser = argparse.ArgumentParser(description="GraphQL endpoint scanner")
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
