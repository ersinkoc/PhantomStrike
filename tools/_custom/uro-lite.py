#!/usr/bin/env python3
"""URL deduplication/optimization: filter duplicate URLs, keep unique paths."""
import argparse
import re
import sys
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

STATIC_EXTENSIONS = {
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".avi", ".wmv", ".flv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar",
    ".gz", ".tar", ".7z", ".bmp", ".tif", ".tiff", ".webp", ".webm",
}

USELESS_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "_ga", "_gl", "__cf_chl_tk", "__cf_chl_jschl_tk__",
    "ref", "referrer", "source", "mc_cid", "mc_eid",
    "share", "shared", "timestamp", "t", "ts", "cb", "rand", "random",
    "_", "nocache", "cache_bust", "v", "ver", "version",
}


def normalize_url(url):
    """Normalize a URL for comparison."""
    parsed = urlparse(url)
    # Normalize scheme
    scheme = parsed.scheme.lower() or "https"
    # Normalize netloc
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    # Normalize path
    path = parsed.path.rstrip("/") or "/"
    # Remove fragments
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def get_url_signature(url, ignore_values=False):
    """Get a signature for URL deduplication."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = parsed.path.rstrip("/") or "/"

    if ignore_values:
        params = parse_qs(parsed.query, keep_blank_values=True)
        param_keys = tuple(sorted(params.keys()))
        return (netloc, path, param_keys)
    else:
        return (netloc, path, parsed.query)


def is_static_resource(url):
    """Check if URL points to a static resource."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def remove_tracking_params(url):
    """Remove known tracking/useless parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    filtered = {k: v for k, v in params.items() if k.lower() not in USELESS_PARAMS}
    new_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in filtered.items()})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, ""))


def is_similar_path(path1, path2):
    """Check if two paths are similar (differ only in IDs/numbers)."""
    parts1 = path1.strip("/").split("/")
    parts2 = path2.strip("/").split("/")
    if len(parts1) != len(parts2):
        return False
    for p1, p2 in zip(parts1, parts2):
        if p1 == p2:
            continue
        # Both are numeric or UUID-like
        if (re.match(r"^\d+$", p1) and re.match(r"^\d+$", p2)):
            continue
        if (re.match(r"^[a-f0-9-]{20,}$", p1, re.I) and re.match(r"^[a-f0-9-]{20,}$", p2, re.I)):
            continue
        return False
    return True


def get_path_pattern(path):
    """Convert path to pattern by replacing IDs with placeholders."""
    parts = path.strip("/").split("/")
    pattern_parts = []
    for part in parts:
        if re.match(r"^\d+$", part):
            pattern_parts.append("{id}")
        elif re.match(r"^[a-f0-9-]{20,}$", part, re.I):
            pattern_parts.append("{uuid}")
        elif re.match(r"^[a-f0-9]{32,64}$", part, re.I):
            pattern_parts.append("{hash}")
        else:
            pattern_parts.append(part)
    return "/".join(pattern_parts)


def main():
    ap = argparse.ArgumentParser(
        description="URO-lite: URL deduplication and optimization. Reads URLs from stdin.",
        epilog="Example: cat urls.txt | python3 uro-lite.py")
    ap.add_argument("-i", "--input", help="Input file (default: stdin)")
    ap.add_argument("-o", "--output", help="Output file (default: stdout)")
    ap.add_argument("--keep-static", action="store_true", help="Keep static resource URLs")
    ap.add_argument("--keep-tracking", action="store_true", help="Keep tracking parameters")
    ap.add_argument("--strict", action="store_true", help="Strict dedup: same path+param names = duplicate")
    ap.add_argument("--path-dedup", action="store_true", help="Deduplicate similar paths (e.g., /user/1 and /user/2)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show statistics")
    args = ap.parse_args()

    # Read URLs
    if args.input:
        try:
            with open(args.input, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Cannot read input: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("[*] URO-Lite: URL deduplication/optimization", file=sys.stderr)
            print("[*] Reading URLs from stdin (pipe URLs or use -i file)...", file=sys.stderr)
        urls = [line.strip() for line in sys.stdin if line.strip()]

    if not urls:
        print("[!] No URLs provided", file=sys.stderr)
        sys.exit(1)

    original_count = len(urls)
    filtered = []
    stats = {"static_removed": 0, "tracking_cleaned": 0, "duplicates_removed": 0, "path_deduped": 0}

    # Step 1: Basic cleanup
    for url in urls:
        if not url.startswith("http"):
            url = f"https://{url}"

        # Remove static resources
        if not args.keep_static and is_static_resource(url):
            stats["static_removed"] += 1
            continue

        # Clean tracking params
        if not args.keep_tracking:
            cleaned = remove_tracking_params(url)
            if cleaned != url:
                stats["tracking_cleaned"] += 1
            url = cleaned

        filtered.append(normalize_url(url))

    # Step 2: Deduplication
    seen_sigs = set()
    deduped = []
    for url in filtered:
        sig = get_url_signature(url, ignore_values=args.strict)
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            deduped.append(url)
        else:
            stats["duplicates_removed"] += 1

    # Step 3: Path pattern dedup
    if args.path_dedup:
        path_patterns = {}
        final = []
        for url in deduped:
            parsed = urlparse(url)
            pattern = get_path_pattern(parsed.path)
            key = (parsed.netloc, pattern, tuple(sorted(parse_qs(parsed.query).keys())))
            if key not in path_patterns:
                path_patterns[key] = url
                final.append(url)
            else:
                stats["path_deduped"] += 1
        deduped = final

    # Output
    out = open(args.output, "w") if args.output else sys.stdout
    for url in sorted(deduped):
        out.write(url + "\n")
    if args.output:
        out.close()

    # Stats
    if args.verbose or sys.stderr.isatty():
        print(f"\n[*] URO-Lite Statistics:", file=sys.stderr)
        print(f"  Input URLs:        {original_count}", file=sys.stderr)
        print(f"  Output URLs:       {len(deduped)}", file=sys.stderr)
        print(f"  Reduction:         {original_count - len(deduped)} ({((original_count - len(deduped)) / max(original_count, 1) * 100):.1f}%)", file=sys.stderr)
        print(f"  Static removed:    {stats['static_removed']}", file=sys.stderr)
        print(f"  Tracking cleaned:  {stats['tracking_cleaned']}", file=sys.stderr)
        print(f"  Duplicates:        {stats['duplicates_removed']}", file=sys.stderr)
        if args.path_dedup:
            print(f"  Path deduped:      {stats['path_deduped']}", file=sys.stderr)


if __name__ == "__main__":
    main()
