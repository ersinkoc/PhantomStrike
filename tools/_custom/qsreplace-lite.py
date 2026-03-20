#!/usr/bin/env python3
"""URL query string replacer: read URLs from stdin, replace param values with payloads."""
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def replace_params(url, payload, param_name=None, append=False):
    """Replace query string parameter values with payload."""
    parsed = urlparse(url)
    if not parsed.query:
        return []

    params = parse_qs(parsed.query, keep_blank_values=True)
    results = []

    if param_name:
        if param_name in params:
            new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            if append:
                new_params[param_name] = (new_params[param_name] or "") + payload
            else:
                new_params[param_name] = payload
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, urlencode(new_params), parsed.fragment))
            results.append(new_url)
    else:
        # Replace all params one at a time
        for param in params:
            new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            if append:
                new_params[param] = (new_params[param] or "") + payload
            else:
                new_params[param] = payload
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, urlencode(new_params), parsed.fragment))
            results.append(new_url)

    return results


def replace_all_params(url, payload):
    """Replace all parameter values at once."""
    parsed = urlparse(url)
    if not parsed.query:
        return None

    params = parse_qs(parsed.query, keep_blank_values=True)
    new_params = {k: payload for k in params}
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(new_params), parsed.fragment))


def replace_path_segments(url, payload):
    """Replace path segments with payload."""
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    results = []
    for i, part in enumerate(parts):
        if part:
            new_parts = list(parts)
            new_parts[i] = payload
            new_path = "/".join(new_parts)
            new_url = urlunparse((parsed.scheme, parsed.netloc, new_path,
                                  parsed.params, parsed.query, parsed.fragment))
            results.append(new_url)
    return results


def main():
    ap = argparse.ArgumentParser(
        description="QSReplace-lite: URL query string replacer. Reads URLs from stdin.",
        epilog="Example: cat urls.txt | python3 qsreplace-lite.py 'FUZZ'")
    ap.add_argument("payload", nargs="?", default="FUZZ", help="Payload to inject (default: FUZZ)")
    ap.add_argument("-p", "--param", help="Only replace specific parameter")
    ap.add_argument("-a", "--append", action="store_true", help="Append payload instead of replacing")
    ap.add_argument("--all", action="store_true", help="Replace all params simultaneously")
    ap.add_argument("--path", action="store_true", help="Also replace path segments")
    ap.add_argument("-i", "--input", help="Input file (default: stdin)")
    ap.add_argument("-u", "--unique", action="store_true", help="Deduplicate output URLs")
    ap.add_argument("--payloads-file", help="File with payloads (one per line), replaces each param with each payload")
    args = ap.parse_args()

    # Read URLs
    if args.input:
        try:
            with open(args.input, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Cannot read input file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("[*] QSReplace-Lite: URL query string replacer", file=sys.stderr)
            print("[*] Reading URLs from stdin (pipe URLs or use -i file)...", file=sys.stderr)
        urls = [line.strip() for line in sys.stdin if line.strip()]

    if not urls:
        print("[!] No URLs provided", file=sys.stderr)
        sys.exit(1)

    # Load payloads
    payloads = [args.payload]
    if args.payloads_file:
        try:
            with open(args.payloads_file, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Cannot read payloads file: {e}", file=sys.stderr)
            sys.exit(1)

    seen = set()
    output_count = 0

    for url in urls:
        if not url.startswith("http"):
            url = f"https://{url}"

        for payload in payloads:
            if args.all:
                result = replace_all_params(url, payload)
                if result:
                    if not args.unique or result not in seen:
                        seen.add(result)
                        print(result)
                        output_count += 1
            else:
                results = replace_params(url, payload, args.param, args.append)
                for r in results:
                    if not args.unique or r not in seen:
                        seen.add(r)
                        print(r)
                        output_count += 1

            if args.path:
                path_results = replace_path_segments(url, payload)
                for r in path_results:
                    if not args.unique or r not in seen:
                        seen.add(r)
                        print(r)
                        output_count += 1

    print(f"\n[*] Processed {len(urls)} URLs, generated {output_count} output URLs", file=sys.stderr)
    if args.unique:
        print(f"[*] Unique URLs: {len(seen)}", file=sys.stderr)


if __name__ == "__main__":
    main()
