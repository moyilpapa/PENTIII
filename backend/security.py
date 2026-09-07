"""
security.py
Cross-cutting security controls for the API: authentication and an
SSRF/target-safety guard applied before any scan makes an outbound request.

This tool sends real HTTP requests (and, optionally, shells out to sqlmap)
to whatever URL the caller supplies. Two things follow from that:

  1. The API itself must not be callable by just anyone who can reach the
     port (auth).
  2. The backend must not be usable as an open proxy to probe the operator's
     own internal network / cloud metadata service just because a caller
     asked it to "scan" 169.254.169.254 or 10.0.0.5 (SSRF guard).

Both controls are deliberately simple (single shared API key, IP-range
denylist) because this is a single-operator local security-testing tool,
not a multi-tenant SaaS product. If you deploy this somewhere more exposed,
put real auth (OAuth/SSO) and a network-level egress firewall in front of it
too -- this module is defense in depth, not a substitute for that.

The SSRF guard has two layers:

  - `assert_safe_target()` / `guarded()`: a fast, request-time check that
    resolves the hostname and rejects private/internal addresses before any
    scan work starts. This is what gives the caller an immediate, friendly
    400 with an explanation.
  - `install_connection_guard()`: a second check installed at the socket
    layer itself (patches urllib3's `create_connection`), so *every* TCP
    connection any `requests` call makes during a scan -- not just the
    first one -- is revalidated at the instant it's opened. This is what
    actually closes the gap the first layer can't: a hostname whose DNS
    record changes between the initial check and the real fetch ("DNS
    rebinding"), and a target that 302-redirects to an internal address
    after the original URL passed validation. Without this second layer,
    `requests`'s own DNS resolution (at connect time) and its default
    redirect-following would each independently bypass a URL-level-only
    check.

Both layers share `_is_disallowed_ip()`, so there's one source of truth for
what counts as an unsafe address.
"""

import hmac
import ipaddress
import os
import socket
from functools import wraps
from urllib.parse import urlparse, urlunparse

import urllib3.util.connection as _urllib3_connection
from flask import request, jsonify

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
# A single shared API key, sent as either `X-API-Key: <key>` or
# `Authorization: Bearer <key>`. Set it with:
#   export API_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
#
# ALLOW_NO_AUTH=1 disables this check entirely -- only for local, throwaway
# testing on a machine you fully trust. It is off by default.

# One or more shared API keys, sent as either `X-API-Key: <key>` or
# `Authorization: Bearer <key>`. Set one with:
#   export API_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# Or set several -- comma-separated -- via API_KEYS, so a single caller's key
# can be revoked (removed from the list, server restarted) without having to
# rotate everyone else's:
#   export API_KEYS="key-for-ci,key-for-alice,key-for-bob"
# API_KEYS takes precedence if both are set. Either way, at least one key is
# required unless ALLOW_NO_AUTH=1.
#
# ALLOW_NO_AUTH=1 disables this check entirely -- only for local, throwaway
# testing on a machine you fully trust. It is off by default.


def _load_api_keys():
    raw = os.environ.get("API_KEYS", "").strip()
    if not raw:
        raw = os.environ.get("API_KEY", "").strip()
    return {k.strip() for k in raw.split(",") if k.strip()}


API_KEYS = _load_api_keys()
ALLOW_NO_AUTH = os.environ.get("ALLOW_NO_AUTH", "").strip() == "1"

# Routes that stay open even with auth enabled (no scan capability, no data).
PUBLIC_PATHS = {"/", "/api/health"}


def _extract_key(req) -> str:
    header = req.headers.get("X-API-Key", "")
    if header:
        return header.strip()
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def register_auth(app):
    """Registers a before_request hook enforcing the shared API key(s).

    Fails closed: if no key is configured and ALLOW_NO_AUTH isn't set,
    every request (other than the public health/root routes) is rejected
    with a message explaining how to configure it, rather than silently
    running with no authentication."""

    @app.before_request
    def _check_auth():
        if request.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return None

        if ALLOW_NO_AUTH:
            return None

        if not API_KEYS:
            return jsonify({
                "error": "server not configured",
                "hint": "Set the API_KEY (or API_KEYS, comma-separated for multiple callers) "
                        "environment variable before starting the API "
                        "(e.g. export API_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')), "
                        "or set ALLOW_NO_AUTH=1 for local, single-user, fully-trusted use only.",
            }), 500

        supplied = _extract_key(request)
        # Checked against every configured key rather than short-circuiting
        # on the first match/mismatch: still timing-safe per comparison
        # (hmac.compare_digest), and the key set is small (a handful of
        # callers, not a multi-tenant user table), so the total number of
        # comparisons isn't itself a meaningful side channel here.
        if not supplied or not any(hmac.compare_digest(supplied, k) for k in API_KEYS):
            return jsonify({"error": "unauthorized", "hint": "Send a valid X-API-Key header."}), 401

        return None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# A single shared API key has no per-caller quota by itself -- anyone who
# knows it can otherwise call scan endpoints as fast as they like, including
# hammering the auth check itself to brute-force a key. This is a simple
# in-process sliding-window limiter (no extra dependency, no separate
# service to run -- matches this project's zero-config-SQLite philosophy),
# keyed by client IP so it also throttles pre-auth requests from a given
# source, not just authenticated ones.
#
# Scan routes (/api/scan/...) get their own, lower limit: they trigger real
# outbound HTTP requests (and optionally a sqlmap subprocess), so they're
# far more expensive per call than a /api/targets list.
#
# This is process-local, in-memory state -- it resets on restart and isn't
# shared across multiple worker processes. Fine for the single-operator,
# single-process `python app.py` this project targets; a real multi-worker
# deployment should rate-limit at a reverse proxy instead.

import threading
import time
from collections import defaultdict, deque

RATE_LIMIT_DISABLED = os.environ.get("RATE_LIMIT_DISABLE", "").strip() == "1"
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120") or 120)
RATE_LIMIT_SCAN_PER_MINUTE = int(os.environ.get("RATE_LIMIT_SCAN_PER_MINUTE", "20") or 20)
_RATE_WINDOW_SECONDS = 60

_rate_lock = threading.Lock()
_general_hits = defaultdict(deque)
_scan_hits = defaultdict(deque)


def _prune_and_check(bucket, key, limit, now):
    dq = bucket[key]
    while dq and now - dq[0] > _RATE_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True


def install_rate_limiter(app):
    """Registers a before_request hook enforcing per-IP request limits.
    Registered before register_auth() (see app.py) so repeated bad-key
    attempts are throttled too, not just successfully authenticated calls."""
    if RATE_LIMIT_DISABLED:
        return

    @app.before_request
    def _rate_limit():
        if request.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return None

        client = request.remote_addr or "unknown"
        is_scan = request.path.startswith("/api/scan/")
        limit = RATE_LIMIT_SCAN_PER_MINUTE if is_scan else RATE_LIMIT_PER_MINUTE
        bucket = _scan_hits if is_scan else _general_hits

        with _rate_lock:
            allowed = _prune_and_check(bucket, client, limit, time.monotonic())

        if not allowed:
            return jsonify({
                "error": "rate limited",
                "hint": f"More than {limit} {'scan ' if is_scan else ''}request(s) from this "
                        f"client in the last {_RATE_WINDOW_SECONDS}s. Wait and retry, or raise "
                        f"{'RATE_LIMIT_SCAN_PER_MINUTE' if is_scan else 'RATE_LIMIT_PER_MINUTE'}.",
            }), 429

        return None


# ---------------------------------------------------------------------------
# SSRF / target-safety guard
# ---------------------------------------------------------------------------
# Applied to every URL the backend is about to fetch on the caller's behalf
# (target URLs, sqli parameter URLs, sqlmap targets, etc.) -- not just at
# target-creation time, since the URL that's actually fetched can be
# overridden per-request (see /api/scan/sqli-advanced and /api/scan/sqli-sqlmap).
#
# ALLOW_PRIVATE_TARGETS=1 disables the IP-range checks for legitimate
# internal engagements (e.g. testing an app on your own LAN/VPN) where the
# operator has explicitly decided that's in scope. It does not disable the
# scheme check -- non-HTTP(S) schemes are never a legitimate scan target.

ALLOW_PRIVATE_TARGETS = os.environ.get("ALLOW_PRIVATE_TARGETS", "").strip() == "1"

_DISALLOWED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("169.254.0.0/16"),     # link-local incl. cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),        # multicast
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),           # unique local
    ipaddress.ip_network("fe80::/10"),          # link-local v6
]


class UnsafeTargetError(ValueError):
    pass


def validate_target_url(url: str) -> None:
    """Validate a target at registration time without performing network I/O."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"Unsupported scheme '{parsed.scheme}' -- only http/https targets are allowed.")
    if not parsed.hostname:
        raise UnsafeTargetError("URL has no host to resolve.")


def _is_disallowed_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse it -- treat as unsafe rather than let it through
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    return any(ip in net for net in _DISALLOWED_NETWORKS)


def assert_safe_target(url: str) -> None:
    """Raises UnsafeTargetError if `url` must not be fetched by the backend.

    Checks: scheme is http/https, hostname resolves, and (unless
    ALLOW_PRIVATE_TARGETS=1) none of the resolved addresses fall in a
    private/loopback/link-local/metadata/multicast/reserved range."""
    validate_target_url(url)
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname

    if ALLOW_PRIVATE_TARGETS:
        return

    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as e:
        raise UnsafeTargetError(f"Could not resolve host '{host}': {e}")

    if not addrs:
        raise UnsafeTargetError(f"Could not resolve host '{host}'.")

    for addr in addrs:
        if _is_disallowed_ip(addr):
            raise UnsafeTargetError(
                f"'{host}' resolves to {addr}, which is a private/internal/reserved address. "
                "This tool refuses to scan internal targets by default to prevent SSRF against "
                "the server it runs on. If this is an authorized internal engagement, restart "
                "the API with ALLOW_PRIVATE_TARGETS=1."
            )


def guarded(url_getter):
    """Decorator for Flask view functions: extracts a URL via `url_getter(*args, **kwargs)`
    (called with the same args the view receives) and 400s with a clear message
    if it's unsafe, before the view's body (and therefore any outbound request) runs."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            url = url_getter(*args, **kwargs)
            if url:
                try:
                    assert_safe_target(url)
                except UnsafeTargetError as e:
                    return jsonify({"error": "unsafe target", "detail": str(e)}), 400
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Connection-level SSRF guard (closes DNS-rebinding + redirect bypasses)
# ---------------------------------------------------------------------------
# assert_safe_target() above checks the URL the caller *asked for*, once,
# before a scan starts. It cannot see what a hostname resolves to a few
# hundred milliseconds later when `requests` actually connects (DNS
# rebinding), and it cannot see where a 3xx redirect leads (requests follows
# redirects itself, out of app code's control, unless allow_redirects=False
# is set on every single call site -- easy to miss one).
#
# This guard fixes both by checking at the one point that can't be spoofed
# or skipped: the moment urllib3 is about to open the actual TCP socket.
# That function receives whatever (host, port) it's about to dial, however
# it got there (original request or redirect hop), so re-running the same
# IP-range check there is authoritative regardless of what happened earlier
# in the request lifecycle.


class BlockedConnectionError(OSError):
    """Raised from the patched connection function. Subclasses OSError
    (not UnsafeTargetError/ValueError) on purpose: urllib3's HTTPConnection
    only catches OSError/socket.error around create_connection() and wraps
    it as a NewConnectionError, which requests then surfaces as a normal
    requests.exceptions.ConnectionError. That means every existing
    `except requests.exceptions.RequestException` in scanner.py/sql_engine.py
    already handles this correctly with no changes needed there -- a blocked
    connection just looks like any other failed connection, with our
    message preserved in it."""


_original_create_connection = _urllib3_connection.create_connection
_connection_guard_installed = False


def _guarded_create_connection(address, *args, **kwargs):
    host, port = address
    if ALLOW_PRIVATE_TARGETS:
        return _original_create_connection(address, *args, **kwargs)

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BlockedConnectionError(f"could not resolve host '{host}': {e}")
    if not infos:
        raise BlockedConnectionError(f"could not resolve host '{host}'")

    # Pin to the exact address we just validated instead of letting the
    # original create_connection() re-resolve the hostname a second time.
    # A second, independent lookup is a (narrow but real) TOCTOU window: a
    # DNS answer that flips between our check and the real connect would
    # slip through. Connecting directly to the validated IP -- rather than
    # the hostname -- closes that gap entirely. TLS SNI is unaffected: it's
    # driven by the hostname stored on the connection object, not by the
    # address passed here, so HTTPS to virtual-hosted targets still works.
    for info in infos:
        ip = info[4][0]
        if _is_disallowed_ip(ip):
            raise BlockedConnectionError(
                f"refusing to connect to '{host}' ({ip}): private/internal/reserved "
                "address, blocked by the connection-level SSRF guard. (This check runs "
                "again at connect time, independent of the earlier target validation, "
                "specifically to catch DNS rebinding and redirects to internal targets.)"
            )

    pinned_address = (infos[0][4][0], port)
    return _original_create_connection(pinned_address, *args, **kwargs)


def install_connection_guard():
    """Installs the connection-level guard for the whole process. Patches
    urllib3.util.connection.create_connection, which every `requests` call
    in the app (scanner.py, sql_engine.py) ultimately goes through -- so
    this needs to run once, at startup, and nothing at the call sites needs
    to change. Idempotent; safe to call more than once."""
    global _connection_guard_installed
    if _connection_guard_installed:
        return
    _urllib3_connection.create_connection = _guarded_create_connection
    _connection_guard_installed = True


# ---------------------------------------------------------------------------
# Forward-proxy SSRF guard (for external subprocesses -- sqlmap)
# ---------------------------------------------------------------------------
# install_connection_guard() above only protects HTTP calls THIS Python
# process makes -- it works by patching a function in this process's own
# memory. sqlmap_integration.py's run_sqlmap() doesn't make an HTTP request
# itself; it spawns sqlmap as a completely separate Python process
# (subprocess.run()), with its own interpreter and its own unpatched
# urllib3. The parent process's monkey-patch has no way to reach into a
# child process's memory, so without something else in place, sqlmap's own
# traffic would be validated once (the URL-level assert_safe_target() check
# in app.py, before sqlmap is even launched) and then run completely
# unguarded against DNS rebinding or a mid-scan redirect to an internal
# address, for the entire -- potentially long-running -- scan.
#
# The fix here is the same idea as install_connection_guard(), just moved
# to a place a subprocess *can* reach: a small local HTTP(S) forward proxy,
# passed to sqlmap via --proxy, that applies _is_disallowed_ip() to every
# single connection sqlmap opens through it -- not just the first one. For
# CONNECT (HTTPS), it validates and pins the target IP, then tunnels raw
# bytes -- it never terminates or inspects the TLS session, so sqlmap's
# actual connection to the target is unmodified; the proxy only ever
# decides whether that connection is allowed to happen, exactly like
# _guarded_create_connection does for this process's own requests.

import select
import socketserver
import threading as _threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_PROXY_BIND_HOST = "127.0.0.1"
_ssrf_proxy_port = None
_ssrf_proxy_lock = threading.Lock()


def _validate_and_pin(host, port):
    """Returns a validated, resolved IP for (host, port), applying the same
    policy as _guarded_create_connection (including respecting
    ALLOW_PRIVATE_TARGETS). Raises BlockedConnectionError otherwise."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BlockedConnectionError(f"could not resolve host '{host}': {e}")
    if not infos:
        raise BlockedConnectionError(f"could not resolve host '{host}'")

    if ALLOW_PRIVATE_TARGETS:
        return infos[0][4][0]

    for info in infos:
        ip = info[4][0]
        if _is_disallowed_ip(ip):
            raise BlockedConnectionError(
                f"refusing to connect to '{host}' ({ip}): private/internal/reserved "
                "address, blocked by the sqlmap forward-proxy SSRF guard."
            )
    return infos[0][4][0]


class _SSRFGuardProxyHandler(BaseHTTPRequestHandler):
    """Minimal forward proxy: validates+pins the target IP per connection,
    then relays bytes verbatim. No TLS interception, no caching, no
    features beyond what sqlmap actually needs."""

    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, fmt, *args):
        pass  # sqlmap's own output already reports activity; stay quiet

    def do_CONNECT(self):
        try:
            host, port_str = self.path.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            self.send_error(400, "Bad CONNECT target")
            return
        try:
            ip = _validate_and_pin(host, port)
        except BlockedConnectionError as e:
            self.send_error(403, str(e))
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=self.timeout)
        except OSError as e:
            self.send_error(502, f"could not connect: {e}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._relay(upstream)

    def _handle_plain_http(self):
        # For a plain-HTTP proxy request, self.path is the full target URL.
        parsed = urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or 80
        if not host:
            self.send_error(400, "Bad request target")
            return
        try:
            ip = _validate_and_pin(host, port)
        except BlockedConnectionError as e:
            self.send_error(403, str(e))
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=self.timeout)
        except OSError as e:
            self.send_error(502, f"could not connect: {e}")
            return
        target_path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
        try:
            upstream.sendall(f"{self.command} {target_path} {self.request_version}\r\n".encode("latin-1"))
            for key in self.headers.keys():
                if key.lower() == "proxy-connection":
                    continue
                for value in self.headers.get_all(key, []):
                    upstream.sendall(f"{key}: {value}\r\n".encode("latin-1"))
            upstream.sendall(b"\r\n")
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                upstream.sendall(self.rfile.read(length))
        except OSError:
            upstream.close()
            return
        self._relay(upstream)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle_plain_http

    def _relay(self, upstream_sock):
        sockets = [self.connection, upstream_sock]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                closed = False
                for s in readable:
                    other = upstream_sock if s is self.connection else self.connection
                    try:
                        data = s.recv(65536)
                    except OSError:
                        closed = True
                        break
                    if not data:
                        closed = True
                        break
                    other.sendall(data)
                if closed:
                    break
        finally:
            try:
                upstream_sock.close()
            except OSError:
                pass


class _ThreadingProxyServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def ensure_ssrf_guard_proxy() -> str:
    """Starts the local SSRF-guard forward proxy on first call (idempotent
    -- later calls return the same instance) and returns its
    'http://127.0.0.1:PORT' URL, for passing to sqlmap via --proxy."""
    global _ssrf_proxy_port
    with _ssrf_proxy_lock:
        if _ssrf_proxy_port is not None:
            return f"http://{_PROXY_BIND_HOST}:{_ssrf_proxy_port}"
        server = _ThreadingProxyServer((_PROXY_BIND_HOST, 0), _SSRFGuardProxyHandler)
        _ssrf_proxy_port = server.server_address[1]
        _threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://{_PROXY_BIND_HOST}:{_ssrf_proxy_port}"


# ---------------------------------------------------------------------------
# Deployment-safety check
# ---------------------------------------------------------------------------
# Everything above assumes the process binds to loopback only -- that's what
# makes "single shared API key in localStorage" and "CORS allowlists two
# localhost origins" acceptable tradeoffs. The moment HOST is anything else
# (0.0.0.0, a LAN IP, a public interface), this app is a remote-reachable
# service that can make outbound HTTP requests and optionally shell out to
# sqlmap on the caller's behalf -- so it needs to be *impossible* to end up
# in that state with weak or no auth by accident.

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def check_deployment_safety(host: str, debug: bool = False, tls_enabled: bool = False) -> None:
    """Called once at startup, right before app.run()/the WSGI server binds.
    Refuses to start (raises SystemExit, not just a log line) for
    combinations that are safe on loopback but unsafe the moment the
    process is reachable by anyone other than the machine it runs on.

    This is intentionally stricter than register_auth()'s per-request check:
    that one fails a *request* with a 500 if misconfigured; this one refuses
    to bring the *process* up at all, because on a public/LAN bind a
    single unauthenticated or unencrypted request is already too many --
    there's no "first request after startup" grace period to rely on."""
    if ALLOW_PRIVATE_TARGETS:
        print(
            "[security] NOTE: ALLOW_PRIVATE_TARGETS=1 -- the SSRF guard's IP-range checks are "
            "disabled at both layers (request-time and connection-time). Every scan can reach "
            "private/internal/loopback addresses, including this machine's own services. Only "
            "run with this set for an authorized internal engagement you've explicitly scoped."
        )

    if host in _LOOPBACK_HOSTS:
        return

    if debug:
        raise SystemExit(
            f"Refusing to start: HOST is set to '{host}' (not loopback) while FLASK_DEBUG=1. "
            "Flask's debug mode ships the Werkzeug interactive debugger, which lets anyone who "
            "can reach it execute arbitrary Python on this machine -- it must never be reachable "
            "beyond loopback. Unset FLASK_DEBUG for any non-local deployment."
        )

    if ALLOW_NO_AUTH:
        raise SystemExit(
            f"Refusing to start: HOST is set to '{host}' (not loopback) while ALLOW_NO_AUTH=1. "
            "ALLOW_NO_AUTH is for a machine you fully trust and never expose beyond localhost -- "
            "combined with a non-loopback bind it means anyone who can reach this host can run "
            "scans and shell out to sqlmap with zero authentication. Unset ALLOW_NO_AUTH and set "
            "API_KEY instead."
        )

    if not API_KEYS:
        raise SystemExit(
            f"Refusing to start: HOST is set to '{host}' (not loopback) but no API key is set. "
            "Every request would currently 500 with a setup hint, but on a reachable host that "
            "500 response itself (and the open port) is exposure you don't want by accident. Set "
            "API_KEY (or API_KEYS, comma-separated) before binding to a non-loopback address: "
            "export API_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')"
        )

    if tls_enabled:
        print(
            f"[security] Binding to '{host}' with TLS enabled (TLS_CERT_FILE/TLS_KEY_FILE set) -- "
            "the API key travels encrypted rather than as a plain header. Still double-check:\n"
            "  - This is still a shared secret per key, not per-user accounts with fine-grained "
            "revocation: anyone with a given key has full access under it. Use API_KEYS (plural, "
            "comma-separated) if different callers should be individually revocable.\n"
            "  - ALLOWED_ORIGINS is set to your actual deployed frontend origin(s), not left at "
            "the localhost default."
        )
        return

    print(
        f"[security] WARNING: binding to '{host}', which is reachable beyond this machine.\n"
        "  - The API key is sent as a plain header (X-API-Key / Authorization: Bearer). Set "
        "TLS_CERT_FILE and TLS_KEY_FILE to terminate TLS directly in this process, or put a "
        "reverse proxy (Caddy/nginx/a cloud load balancer) in front doing so -- without one of "
        "those, that key travels in cleartext and can be captured on the network path.\n"
        "  - This is still a shared secret per key, not per-user accounts with fine-grained "
        "revocation: anyone with a given key has full access under it. Use API_KEYS (plural, "
        "comma-separated) if different callers should be individually revocable without "
        "rotating everyone else's key.\n"
        "  - Double-check ALLOWED_ORIGINS is set to your actual deployed frontend origin(s), not "
        "left at the localhost default (CORS will otherwise correctly reject your own frontend)."
    )
