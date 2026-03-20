#!/usr/bin/env python3
"""Fingerprint technology stack of a target website."""
import argparse
import re
import sys
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADER_SIGNATURES = {
    "Server": {
        "Apache": ("Apache", "web_server"),
        "nginx": ("Nginx", "web_server"),
        "Microsoft-IIS": ("Microsoft IIS", "web_server"),
        "LiteSpeed": ("LiteSpeed", "web_server"),
        "Caddy": ("Caddy", "web_server"),
        "openresty": ("OpenResty", "web_server"),
        "Cloudflare": ("Cloudflare", "cdn"),
    },
    "X-Powered-By": {
        "PHP": ("PHP", "language"),
        "ASP.NET": ("ASP.NET", "framework"),
        "Express": ("Express.js", "framework"),
        "Next.js": ("Next.js", "framework"),
        "Servlet": ("Java Servlet", "framework"),
    },
}

COOKIE_SIGNATURES = {
    "PHPSESSID": ("PHP", "language", "high"),
    "JSESSIONID": ("Java", "language", "high"),
    "ASP.NET_SessionId": ("ASP.NET", "framework", "high"),
    "csrftoken": ("Django", "framework", "medium"),
    "laravel_session": ("Laravel", "framework", "high"),
    "_rails_session": ("Ruby on Rails", "framework", "high"),
    "ci_session": ("CodeIgniter", "framework", "high"),
    "CAKEPHP": ("CakePHP", "framework", "high"),
    "symfony": ("Symfony", "framework", "medium"),
    "wp_": ("WordPress", "cms", "medium"),
}

HTML_SIGNATURES = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', "WordPress", "cms", "high"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', "Drupal", "cms", "high"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "cms", "high"),
    (r'wp-content/', "WordPress", "cms", "high"),
    (r'wp-includes/', "WordPress", "cms", "high"),
    (r'/sites/default/files/', "Drupal", "cms", "medium"),
    (r'Drupal\.settings', "Drupal", "cms", "high"),
    (r'/media/jui/', "Joomla", "cms", "medium"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Shopify', "Shopify", "ecommerce", "high"),
    (r'cdn\.shopify\.com', "Shopify", "ecommerce", "high"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Hugo', "Hugo", "ssg", "high"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Jekyll', "Jekyll", "ssg", "high"),
    (r'__next', "Next.js", "framework", "medium"),
    (r'__nuxt', "Nuxt.js", "framework", "medium"),
    (r'__gatsby', "Gatsby", "framework", "medium"),
    (r'react-root|data-reactroot|_react', "React", "js_framework", "medium"),
    (r'ng-app|ng-controller|angular', "Angular", "js_framework", "medium"),
    (r'v-bind:|v-if|vue\.js|__vue', "Vue.js", "js_framework", "medium"),
    (r'jquery[./\-](\d[\d.]*)', "jQuery", "js_library", "high"),
    (r'bootstrap[./\-](\d[\d.]*)', "Bootstrap", "css_framework", "high"),
    (r'tailwindcss|tailwind', "Tailwind CSS", "css_framework", "medium"),
    (r'fonts\.googleapis\.com', "Google Fonts", "service", "high"),
    (r'google-analytics\.com|gtag/js', "Google Analytics", "analytics", "high"),
    (r'googletagmanager\.com', "Google Tag Manager", "analytics", "high"),
    (r'cloudflare', "Cloudflare", "cdn", "medium"),
    (r'recaptcha', "reCAPTCHA", "security", "medium"),
    (r'moment\.js|moment\.min\.js', "Moment.js", "js_library", "medium"),
    (r'lodash|underscore', "Lodash/Underscore", "js_library", "medium"),
]

CDN_HEADERS = {
    "cf-ray": ("Cloudflare", "cdn"),
    "x-cache": ("CDN Cache", "cdn"),
    "x-cdn": ("CDN", "cdn"),
    "x-amz": ("AWS", "cloud"),
    "x-azure": ("Azure", "cloud"),
    "x-goog": ("Google Cloud", "cloud"),
    "via": ("Proxy/CDN", "proxy"),
}


def fingerprint(url, timeout):
    """Perform technology fingerprinting."""
    detections = {}

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomStrike/1.0)"})
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    headers = resp.headers
    body = resp.text

    # Header analysis
    for hdr_name, sigs in HEADER_SIGNATURES.items():
        value = headers.get(hdr_name, "")
        if value:
            for pattern, (tech, cat) in sigs.items():
                if pattern.lower() in value.lower():
                    version = ""
                    v_match = re.search(r'[\d]+\.[\d.]+', value)
                    if v_match:
                        version = v_match.group()
                    key = tech
                    detections[key] = {"name": tech, "version": version, "category": cat, "confidence": "high", "source": f"header:{hdr_name}"}

    # CDN / security headers
    for hdr_pattern, (tech, cat) in CDN_HEADERS.items():
        for h in headers:
            if hdr_pattern.lower() in h.lower():
                detections[tech] = {"name": tech, "version": "", "category": cat, "confidence": "medium", "source": f"header:{h}"}

    # Cookie analysis
    cookies = resp.headers.get("Set-Cookie", "")
    raw_cookies = str(resp.cookies)
    for cookie_name, (tech, cat, conf) in COOKIE_SIGNATURES.items():
        if cookie_name.lower() in cookies.lower() or cookie_name.lower() in raw_cookies.lower():
            detections[tech] = {"name": tech, "version": "", "category": cat, "confidence": conf, "source": "cookie"}

    # HTML / body analysis
    for pattern, tech, cat, conf in HTML_SIGNATURES:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            if tech not in detections or detections[tech]["confidence"] != "high":
                detections[tech] = {"name": tech, "version": version, "category": cat, "confidence": conf, "source": "html_body"}

    # Security headers presence
    sec_headers = {"X-Frame-Options": False, "Content-Security-Policy": False,
                   "Strict-Transport-Security": False, "X-Content-Type-Options": False}
    for h in sec_headers:
        sec_headers[h] = h.lower() in [k.lower() for k in headers]

    return detections, sec_headers, resp.status_code, resp.url


def main():
    parser = argparse.ArgumentParser(description="Technology stack fingerprinter")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    print(f"[*] Tech Fingerprint - Target: {target}\n")

    detections, sec_headers, status, final_url = fingerprint(target, args.timeout)

    if final_url != target:
        print(f"[*] Redirected to: {final_url}")
    print(f"[*] Status: {status}\n")

    # Group by category
    categories = {}
    for tech, info in detections.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(info)

    cat_labels = {
        "web_server": "Web Server", "language": "Language", "framework": "Framework",
        "cms": "CMS", "js_framework": "JS Framework", "js_library": "JS Library",
        "css_framework": "CSS Framework", "cdn": "CDN/Proxy", "cloud": "Cloud Provider",
        "analytics": "Analytics", "ecommerce": "E-Commerce", "ssg": "Static Site Generator",
        "security": "Security", "service": "Service", "proxy": "Proxy",
    }

    print("=== Detected Technologies ===\n")
    for cat, items in sorted(categories.items()):
        label = cat_labels.get(cat, cat.title())
        print(f"  [{label}]")
        for item in items:
            ver_str = f" v{item['version']}" if item['version'] else ""
            print(f"    {item['name']}{ver_str} (confidence: {item['confidence']}, source: {item['source']})")
        print()

    print("=== Security Headers ===\n")
    for header, present in sec_headers.items():
        status_str = "present" if present else "MISSING"
        marker = "OK" if present else "WARN"
        print(f"  [{marker}] {header}: {status_str}")

    print(f"\n{'='*50}")
    print(f"[*] Technologies detected: {len(detections)}")
    high_conf = sum(1 for d in detections.values() if d["confidence"] == "high")
    print(f"[*] High confidence: {high_conf}, Medium: {len(detections) - high_conf}")


if __name__ == "__main__":
    main()
