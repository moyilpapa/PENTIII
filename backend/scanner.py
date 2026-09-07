"""
scanner.py
Implements the four core assessment modules described in the project docs:

  1. HTTP analysis        (status, headers, cookies, missing-header flags)
  2. Endpoint discovery    (fixed wordlist fuzzing)
  3. JavaScript analysis   (script discovery + regex pattern scanning)
  4. SQL injection testing (error-based, single-quote payload)

Every function returns a plain dict so it can be JSON-serialized straight
into the scan_results table and back out to the React frontend.
"""

import difflib
import hashlib
import re
import time
import uuid
import requests
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

# ---------------------------------------------------------------------------
# Shared config
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Safety controls (configurable, but sane beginner-safe defaults).
# These bound *request volume*, not *result count* -- per the Pent III
# advancement spec, discovered/extracted results are never silently truncated.
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 20
MAX_JS_FILES = 40          # cap on how many linked JS files we download per scan (not on results found)
MAX_CRAWL_LINKS = 100      # bound same-origin HTML discovery; wordlist results remain complete
RATE_LIMIT_DELAY = 0.0     # seconds to sleep between requests; 0 = off, tune up for noisy targets

HEADERS = {"User-Agent": "WebAppSecurityTester/1.0 (authorized-testing-only)"}

# 9.2 HTTP Analysis -- security headers we check for
SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data-injection by restricting allowed content sources.",
    "X-Frame-Options": "Prevents clickjacking by controlling whether the page can be framed.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff').",
    "Strict-Transport-Security": "Forces HTTPS, preventing SSL-stripping downgrade attacks.",
    "Referrer-Policy": "Controls how much referrer information is leaked to other sites.",
    "Permissions-Policy": "Restricts which browser features/APIs the page may use.",
}

# 9.3 Endpoint discovery -- fixed wordlist (expanded; the full list is always
# processed, results are never capped at an arbitrary count).
ENDPOINT_WORDLIST = [
    # admin / management
    "/admin", "/admin/login", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/adminer.php", "/manager/html", "/console",
    # auth
    "/login", "/signin", "/logout", "/register", "/signup", "/auth", "/oauth",
    # config / secrets
    "/.env", "/.env.local", "/.env.production", "/config", "/config.php",
    "/config.json", "/settings.json", "/web.config", "/appsettings.json",
    "/.htaccess", "/.htpasswd",
    # version control / build artifacts
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store",
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    # backups / archives
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sqlite",
    "/database.sql", "/dump.sql", "/site.zip", "/www.zip", "/old", "/old.zip",
    # dev / debug
    "/test", "/dev", "/debug", "/debug.php", "/phpinfo.php", "/info.php",
    "/status", "/health", "/actuator", "/actuator/env", "/trace",
    # API surfaces
    "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger.json",
    "/swagger-ui.html", "/graphql",
    # uploads / file handling
    "/uploads", "/upload", "/files", "/media", "/static/uploads",
    # server metadata
    "/server-status", "/server-info", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt", "/crossdomain.xml",
    # docker / cloud
    "/Dockerfile", "/docker-compose.yml", "/.aws/credentials",
    # logs
    "/logs", "/log", "/error_log", "/access_log",
]

# 9.5 SQLi -- classic error-based detection strings
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "mysql_fetch", "mysqli_fetch",
    "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "sqlite3.operationalerror", "sqlite_error", "pg_query()",
    "postgresql query failed", "odbc sql server driver", "ora-01756",
    "microsoft ole db provider for odbc", "syntax error at or near", "syntax error",
    "unterminated string literal", "near \"'\": syntax error",
]


def _base(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


class _HtmlLinkCollector(HTMLParser):
    """Collect navigational URLs without executing target-side JavaScript."""
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        value = attributes.get("href") if tag in {"a", "link"} else attributes.get("action") if tag == "form" else None
        if value:
            self.urls.append(value)


def discover_same_origin_paths(base_url: str, html: str) -> list[str]:
    """Return normalized, same-host paths discovered in a single HTML page.

    This is deliberately a bounded, passive parser: it does not submit forms,
    execute JavaScript, or leave the registered target's host.
    """
    collector = _HtmlLinkCollector()
    try:
        collector.feed(html)
    except Exception:
        return []

    base = urlparse(base_url)
    paths = []
    seen = set()
    for raw_url in collector.urls:
        candidate = urlparse(urljoin(base_url, raw_url))
        if candidate.scheme not in {"http", "https"} or candidate.hostname != base.hostname:
            continue
        path = candidate.path or "/"
        if candidate.query:
            path = f"{path}?{candidate.query}"
        if path not in seen:
            seen.add(path)
            paths.append(path)
        if len(paths) >= MAX_CRAWL_LINKS:
            break
    return paths


# ---------------------------------------------------------------------------
# 9.2 HTTP Analysis
# ---------------------------------------------------------------------------

def analyze_http(url: str) -> dict:
    url = _base(url)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e), "url": url}

    headers = dict(resp.headers)
    cookies = [
        {
            "name": c.name,
            "secure": c.secure,
            "httponly": "httponly" in [k.lower() for k in c._rest.keys()] if hasattr(c, "_rest") else False,
        }
        for c in resp.cookies
    ]

    flags = []
    for hname, why in SECURITY_HEADERS.items():
        if hname.lower() not in [h.lower() for h in headers.keys()]:
            flags.append({"header": hname, "issue": "missing", "why": why})

    for c in cookies:
        if not c["secure"]:
            flags.append({"header": f"Cookie:{c['name']}", "issue": "missing Secure flag",
                           "why": "Cookie can be sent over unencrypted HTTP."})
        if not c["httponly"]:
            flags.append({"header": f"Cookie:{c['name']}", "issue": "missing HttpOnly flag",
                           "why": "Cookie is readable by JavaScript, increasing XSS impact."})

    return {
        "ok": True,
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "headers": headers,
        "cookies": cookies,
        "flags": flags,
        "server": headers.get("Server", "unknown"),
        "body_snippet": resp.text[:2000],
        "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
        "content_length": len(resp.content),
    }


# ---------------------------------------------------------------------------
# 9.3 Endpoint Discovery
# ---------------------------------------------------------------------------

_SIMILARITY_CAP = 50_000       # cap comparison cost on very large pages
_SIMILARITY_THRESHOLD = 0.93    # tolerate a per-request token/nonce/timestamp;
                                 # calibrated against realistically-sized pages
                                 # (a few hundred bytes and up) -- see
                                 # tests/test_design_fixes.py for the numbers
                                 # behind this choice. A page smaller than a
                                 # real SPA shell would ever be (well under
                                 # ~150 bytes) can still slip past this if a
                                 # random token makes up a large fraction of
                                 # its tiny body -- an acceptable limit, not
                                 # a case any real target is likely to hit.

def _baseline_probe(base: str):
    """Fetches TWO different paths, each guaranteed not to exist, so
    discover_endpoints() has something reliable to compare real candidates
    against.

    Without this, "found" was decided by status code alone (< 400, or
    401/403) -- which breaks completely against any SPA whose client-side
    router has a catch-all route and returns 200 + the same index.html shell
    for literally any path. Every wordlist entry would then look "reachable."

    Two probes, not one: an exact-hash match against a single probe would
    silently fail to catch this on any target whose catch-all page embeds
    something that changes per request -- a CSRF token, a nonce, a
    timestamp in a <meta> tag. Comparing the two probes to each other first
    tells us whether the target's baseline is even stable enough to filter
    against, and gives _matches_baseline() a similarity threshold to fall
    back on instead of requiring byte-for-byte identity.

    Returns None if either probe fails, or if the two probes don't look
    like each other -- in both cases, callers fall back to the old
    status-code-only behavior rather than risk filtering on a baseline that
    isn't actually stable."""
    bodies = []
    status_codes = []
    for _ in range(2):
        probe_path = "/__pentiii_baseline_" + uuid.uuid4().hex[:16]
        try:
            resp = requests.get(base + probe_path, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            return None
        status_codes.append(resp.status_code)
        bodies.append(resp.content[:_SIMILARITY_CAP])

    if status_codes[0] != status_codes[1]:
        return None  # not even consistent with itself -- don't try to filter on it

    stability = difflib.SequenceMatcher(None, bodies[0], bodies[1]).quick_ratio()
    if stability < _SIMILARITY_THRESHOLD:
        return None  # target's "nonexistent path" response is too variable to use as a baseline

    return {
        "status_code": status_codes[0],
        "content": bodies[0],
        "content_hash": hashlib.sha256(bodies[0]).hexdigest(),
    }


def _matches_baseline(baseline, status_code: int, content: bytes) -> bool:
    """True if a response looks like the known-nonexistent baseline: same
    status code, and either a byte-identical body (fast path, the common
    case for a fully static catch-all) or a body that's overwhelmingly
    similar to it (fallback, for a catch-all that embeds something small
    that changes per request -- a token, a timestamp)."""
    if baseline is None or status_code != baseline["status_code"]:
        return False
    truncated = content[:_SIMILARITY_CAP]
    if hashlib.sha256(truncated).hexdigest() == baseline["content_hash"]:
        return True
    return difflib.SequenceMatcher(None, baseline["content"], truncated).quick_ratio() >= _SIMILARITY_THRESHOLD


def discover_endpoints(url: str) -> dict:
    """Runs the complete configured wordlist -- every path is checked and every
    result is kept. Nothing is truncated at an arbitrary count (Pent III
    advancement, Section 3)."""
    base = _base(url).rstrip("/")
    dynamic_paths = []
    try:
        root = requests.get(base, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        content_type = root.headers.get("Content-Type", "").lower()
        if "html" in content_type:
            dynamic_paths = discover_same_origin_paths(base, root.text)
    except requests.exceptions.RequestException:
        # Wordlist discovery still provides a useful result when the landing
        # page cannot be fetched or is not HTML.
        pass

    baseline = _baseline_probe(base)

    candidates = [(path, "wordlist") for path in ENDPOINT_WORDLIST]
    seen_paths = {path for path, _ in candidates}
    candidates.extend((path, "html-link") for path in dynamic_paths if path not in seen_paths)
    results = []
    for path, source in candidates:
        target = base + path
        try:
            resp = requests.get(target, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            is_baseline_match = resp.status_code < 300 and _matches_baseline(baseline, resp.status_code, resp.content)
            exists = (resp.status_code < 400 or resp.status_code in (401, 403)) and not is_baseline_match
            if is_baseline_match:
                assessment = (
                    "This response is byte-identical to a request for a path that does not exist "
                    "on this server -- almost certainly a catch-all response (e.g. an SPA router "
                    "serving its default page for any path), not evidence this specific path exists."
                )
                next_checks = "Not a lead by itself. If this path matters, verify manually with a browser or a tool that understands the app's routing."
                classification = "Soft 404 (catch-all response)"
            elif 300 <= resp.status_code < 400:
                assessment = "Redirect observed; endpoint exposure and authorization are not confirmed."
                next_checks = "Follow the redirect and verify access controls on the destination."
                classification = "Redirect"
            elif resp.status_code in (401, 403):
                assessment = "Access-controlled response observed; authorization behavior requires verification."
                next_checks = "Retest with an authorized session and confirm the intended access policy."
                classification = "Access Controlled"
            elif resp.status_code < 300:
                assessment = "Reachable response observed; this alone does not demonstrate a vulnerability."
                next_checks = "Review authentication, authorization, sensitive data exposure, and input handling."
                classification = "Reachable"
            else:
                assessment = "No accessible endpoint confirmed by this request."
                next_checks = "Validate the response manually if the path is expected to exist."
                classification = "Not Confirmed"
            results.append({
                "path": path,
                "source": source,
                "status_code": resp.status_code,
                "exists": exists,
                "content_length": len(resp.content),
                "url": target,
                "final_url": resp.url,
                "content_type": resp.headers.get("Content-Type", "unknown"),
                "server": resp.headers.get("Server", "unknown"),
                "redirect_location": resp.headers.get("Location", ""),
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:500],
                "classification": classification,
                "assessment": assessment,
                "next_checks": next_checks,
            })
        except requests.exceptions.RequestException as e:
            results.append({"path": path, "source": source, "status_code": None, "exists": False, "error": str(e), "url": target})
        if RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY)

    found = [r for r in results if r.get("exists")]
    return {
        "ok": True,
        "base_url": base,
        "checked": len(results),
        "wordlist_checked": len(ENDPOINT_WORDLIST),
        "html_links_discovered": len(dynamic_paths),
        "baseline_probe_ok": baseline is not None,
        "found": found,
        "all_results": results,
    }


# ---------------------------------------------------------------------------
# 9.4 JavaScript Analysis
# ---------------------------------------------------------------------------

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
# Broadened to capture query strings too (?, =, &, %) so parameterized URLs
# like /product?id=10&category=books are extracted whole, not cut at the "?"
# (Pent III advancement, Section 5 -- "extract parameterized URLs").
INTERESTING_STRING_RE = re.compile(
    r'''(?:["'`])(/[a-zA-Z0-9_\-/.?=&%]{2,200}|https?://[a-zA-Z0-9_\-./?=&%]{4,200})(?:["'`])'''
)
KEY_LOOKING_RE = re.compile(r'(?:api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\']([^"\']{6,60})["\']', re.IGNORECASE)


def analyze_javascript(url: str) -> dict:
    """Static, regex-only JS reconnaissance. No execution, no JS runtime, no
    deobfuscation, no AST analysis. All discovered endpoint-like strings are
    returned -- extraction is not capped at an arbitrary count (Pent III
    advancement, Section 5). MAX_JS_FILES only bounds how many script *files*
    get downloaded per scan, as a request-safety control, and is reported
    transparently via scripts_found vs scripts_scanned."""
    base = _base(url)
    try:
        resp = requests.get(base, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

    script_srcs = list(dict.fromkeys(SCRIPT_SRC_RE.findall(resp.text)))
    to_scan = script_srcs[:MAX_JS_FILES]
    files = []
    all_endpoints = set()
    all_flagged_secrets = []

    for src in to_scan:
        js_url = urljoin(base, src)
        entry = {"src": src, "resolved_url": js_url}
        try:
            jresp = requests.get(js_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            content = jresp.text
            endpoints = sorted(set(INTERESTING_STRING_RE.findall(content)))
            secrets = [m for m in KEY_LOOKING_RE.findall(content)]
            entry.update({"ok": True, "size": len(content), "endpoints_found": endpoints, "possible_secrets": len(secrets)})
            all_endpoints.update(endpoints)
            all_flagged_secrets.extend(secrets)
        except requests.exceptions.RequestException as e:
            entry.update({"ok": False, "error": str(e)})
        files.append(entry)
        if RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY)

    return {
        "ok": True,
        "base_url": base,
        "scripts_found": len(script_srcs),
        "scripts_scanned": len(to_scan),
        "scripts_capped": len(script_srcs) > len(to_scan),
        "files": files,
        "unique_endpoints": sorted(all_endpoints),
        "possible_secrets_flagged": len(all_flagged_secrets),
    }


# ---------------------------------------------------------------------------
# 9.5 SQL Injection Testing (error-based)
# ---------------------------------------------------------------------------

def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_sqli(url: str, param: str) -> dict:
    base = _base(url)
    parsed = urlparse(base)
    existing = parse_qs(parsed.query)
    fallback_value = "1"
    baseline_value = existing.get(param, [fallback_value])[0] or fallback_value
    if baseline_value in ("", "test", "null", "none"):
        baseline_value = fallback_value

    normal_url = _inject_param(base, param, baseline_value)
    injected_url = _inject_param(base, param, baseline_value + "'")

    try:
        normal_resp = requests.get(normal_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        injected_resp = requests.get(injected_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

    body_lower = injected_resp.text.lower()
    matched_signatures = [sig for sig in SQLI_ERROR_SIGNATURES if sig in body_lower]

    vulnerable = len(matched_signatures) > 0 or (
        normal_resp.status_code < 500 and injected_resp.status_code >= 500
    ) or (
        normal_resp.status_code == injected_resp.status_code >= 500 and bool(matched_signatures)
    )

    return {
        "ok": True,
        "parameter": param,
        "normal_url": normal_url,
        "injected_url": injected_url,
        "normal_status": normal_resp.status_code,
        "injected_status": injected_resp.status_code,
        "matched_signatures": matched_signatures,
        "vulnerable": vulnerable,
        "note": (
            "Response contained known SQL error signature(s) and/or a status-code shift -- "
            "classic error-based indicator." if vulnerable else
            "No known SQL error signatures found. This does NOT prove the parameter is safe -- "
            "only that error-based detection found nothing (v1 scope; blind/time-based SQLi is out of scope)."
        ),
    }


# ---------------------------------------------------------------------------
# Pent III advancement: shared Endpoint Collection
#
# Combines the fixed-wordlist Endpoint Discovery results with the JavaScript
# Analysis results into one normalized, deduplicated list, and detects query
# parameters on each URL so the SQL Injection Engine has real targets to test.
# Neither discovery module is modified or made aware of the other -- they stay
# independent; this is purely a merge/normalize step (Section 6/7).
# ---------------------------------------------------------------------------

def normalize_url(base: str, raw: str) -> str:
    """Resolves a relative or absolute URL string against the target's base URL."""
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    return urljoin(base, raw)


def extract_params(url: str) -> list:
    """Returns the query parameter names present on a URL, in order."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def collect_endpoints(target_url: str, endpoint_result: dict, js_result: dict) -> dict:
    """Merges Endpoint Discovery (found paths) + JavaScript Analysis (extracted
    strings) into one normalized, deduplicated endpoint collection, with query
    parameters detected on each entry. No arbitrary count limit is applied."""
    base = _base(target_url)
    seen = {}  # normalized URL -> entry

    def add(raw_url: str, source: str):
        norm = normalize_url(base, raw_url)
        # only keep entries on the same host as the target -- external links
        # (CDNs, analytics, etc.) aren't in-scope for this target's SQLi testing
        if urlparse(norm).netloc != urlparse(base).netloc:
            return
        params = extract_params(norm)
        if norm in seen:
            if source not in seen[norm]["sources"]:
                seen[norm]["sources"].append(source)
        else:
            seen[norm] = {"url": norm, "sources": [source], "parameters": params, "has_parameters": len(params) > 0}

    for r in (endpoint_result or {}).get("all_results", []):
        if r.get("exists") and r.get("url"):
            add(r["url"], "endpoint_discovery")

    for e in (js_result or {}).get("unique_endpoints", []):
        add(e, "javascript_analysis")

    all_entries = sorted(seen.values(), key=lambda e: e["url"])
    parameterized = [e for e in all_entries if e["has_parameters"]]

    return {
        "ok": True,
        "base_url": base,
        "total_endpoints": len(all_entries),
        "parameterized_endpoints": len(parameterized),
        "endpoints": all_entries,
    }
