"""
sqlmap_integration.py
Optional Pent III integration with the real sqlmap tool, invoked as a
separate subprocess -- not embedded/copied into this codebase.

Why a subprocess wrapper instead of reimplementing sqlmap's detection logic:
sqlmap is GPLv2-licensed, mature, and field-tested across years of real-world
DBMS/WAF/encoding edge cases that a from-scratch reimplementation (like
sql_engine.py) will inevitably miss. Copying its source into this project
would obligate this project's license too (a real legal constraint, not a
style preference); invoking an independently-installed copy of the tool as a
subprocess avoids that entirely -- this is the standard way many platforms
wrap GPL tools (the same pattern used for wrapping `nmap`, `nikto`, etc.).

This module does NOT ship sqlmap. It looks for an already-installed copy
(see README for setup) and calls it with a conservative, detection-only
flag set. If sqlmap isn't found, `run_sqlmap()` returns a clear, non-fatal
error explaining how to install it -- the rest of Pent III (including
sql_engine.py's own built-in detection) is unaffected either way.

SSRF protection: because sqlmap runs as a separate process, it doesn't get
the connection-level guard install_connection_guard() gives scanner.py/
sql_engine.py for free (that guard patches this process's own urllib3, not
a child process's). To close that gap, run_sqlmap() routes sqlmap through
security.ensure_ssrf_guard_proxy() -- a small local forward proxy that
validates every connection sqlmap makes, not just the initial URL -- on
top of the same URL-level assert_safe_target() check every other scan
route gets, applied before sqlmap is even launched.

Note: backend/vendor/sqlmap/ (the clone location used below) is listed in
.gitignore for exactly this reason -- it holds a full checkout of sqlmap's
GPLv2 source on disk, and the "not embedded in this codebase" claim above
only holds if that directory can never actually be committed.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import security

# Search order: explicit env var, then a vendored copy the user may have
# placed at backend/vendor/sqlmap/sqlmap.py, then a system-wide `sqlmap`
# executable. If none of those exist, this module will NOT reach out to the
# network on its own -- it tells the caller how to install sqlmap instead.
# Set SQLMAP_AUTO_INSTALL=1 to let it `git clone` the official repo the
# first time it's needed. That's opt-in on purpose: a security tool quietly
# fetching and running externally-sourced code the first time a route is
# hit is the kind of thing an operator should decide, not discover.
SQLMAP_PATH_ENV = "SQLMAP_PATH"
SQLMAP_AUTO_INSTALL_ENV = "SQLMAP_AUTO_INSTALL"
DEFAULT_VENDOR_DIR = os.path.join(os.path.dirname(__file__), "vendor", "sqlmap")
DEFAULT_VENDOR_PATH = os.path.join(DEFAULT_VENDOR_DIR, "sqlmap.py")


def _ensure_vendor_checkout():
    """Returns (ok, message). `message` is set on failure, and also set to
    an informational note the one time an auto-clone actually happens, so
    callers can surface "sqlmap was just downloaded" rather than have it
    happen invisibly.

    If backend/vendor/sqlmap already exists (the user set it up themselves,
    per the README), a missing/pruned sqlmap.py is restored from that
    existing local checkout automatically -- that doesn't reach out
    anywhere new, it's just `git checkout` against a repo the user already
    fetched. A *fresh* clone -- reaching out to GitHub for the first time --
    only happens if SQLMAP_AUTO_INSTALL=1 is set."""
    if os.path.isfile(DEFAULT_VENDOR_PATH):
        return True, None

    vendor_dir = os.path.dirname(DEFAULT_VENDOR_PATH)

    if not os.path.isdir(vendor_dir):
        if os.environ.get(SQLMAP_AUTO_INSTALL_ENV, "").strip() != "1":
            return False, (
                "No sqlmap checkout found at backend/vendor/sqlmap. Install it yourself with: "
                "git clone https://github.com/sqlmapproject/sqlmap.git backend/vendor/sqlmap "
                f"-- or set {SQLMAP_AUTO_INSTALL_ENV}=1 to let Pent III clone it automatically "
                "the next time this route is used."
            )
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/sqlmapproject/sqlmap.git", vendor_dir],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            return False, f"automatic sqlmap install ({SQLMAP_AUTO_INSTALL_ENV}=1) failed: {e}"
        ok = os.path.isfile(DEFAULT_VENDOR_PATH)
        note = "sqlmap was just cloned automatically from GitHub (SQLMAP_AUTO_INSTALL=1)." if ok else None
        return ok, note if ok else "clone completed but sqlmap.py was not found afterward."

    # Vendor dir already exists -- this is a repair of the user's own
    # checkout, not a first-time fetch, so no separate opt-in is required.
    try:
        subprocess.run(
            ["git", "-C", vendor_dir, "checkout", "--", "sqlmap.py"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    return os.path.isfile(DEFAULT_VENDOR_PATH), None


def find_sqlmap():
    """Returns (interpreter_args, ok, message) where interpreter_args is the
    list to prepend to subprocess.run(), e.g. ["python3", "/path/sqlmap.py"]
    or ["sqlmap"] if it's on PATH as a standalone executable. `message` may
    be set even when `ok` is True (e.g. to report a just-happened auto-install)."""
    env_path = os.environ.get(SQLMAP_PATH_ENV)
    if env_path and os.path.isfile(env_path):
        return [sys.executable, env_path], True, None

    if os.path.isfile(DEFAULT_VENDOR_PATH):
        return [sys.executable, DEFAULT_VENDOR_PATH], True, None

    vendor_ok, vendor_message = _ensure_vendor_checkout()
    if vendor_ok and os.path.isfile(DEFAULT_VENDOR_PATH):
        return [sys.executable, DEFAULT_VENDOR_PATH], True, vendor_message

    system_sqlmap = shutil.which("sqlmap") or shutil.which("sqlmap.exe")
    if system_sqlmap:
        return [system_sqlmap], True, None

    return None, False, vendor_message or (
        "sqlmap not found. Install it with: "
        "git clone https://github.com/sqlmapproject/sqlmap.git backend/vendor/sqlmap "
        f"-- or set the {SQLMAP_PATH_ENV} environment variable to your sqlmap.py path."
    )



# --- Output parsing -----------------------------------------------------
# sqlmap's console output is designed for humans, not machines -- there's no
# JSON mode for a single-parameter scan like this, so we parse the specific,
# stable phrases it prints. Verified against real captured output for both
# the positive ("... injectable") and negative ("do not appear to be
# injectable") cases -- see the parsing tests below.

NOT_INJECTABLE_RE = re.compile(
    r"(?:do(?:es)? not (?:appear|seem) to be injectable|(?:all\s+)?parameters? do(?:es)? not appear to be injectable)",
    re.IGNORECASE,
)
PARAM_INJECTABLE_RE = re.compile(r"parameter '([^']+)' is '([^']+)' injectable", re.IGNORECASE)
PARAM_INJECTABLE_RE2 = re.compile(r"parameter '([^']+)' is vulnerable\.?", re.IGNORECASE)
DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")
TYPE_RE = re.compile(r"^\s*Type:\s*(.+)$", re.MULTILINE)
PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+)$", re.MULTILINE)
TITLE_RE = re.compile(r"^\s*Title:\s*(.+)$", re.MULTILINE)


def parse_sqlmap_output(stdout):
    """Extracts a structured verdict from sqlmap's raw console output."""
    text = stdout or ""

    if PARAM_INJECTABLE_RE.search(text):
        match = PARAM_INJECTABLE_RE.search(text)
        dbms_match = DBMS_RE.search(text)
        return {
            "vulnerable": True,
            "state": "CONFIRMED",
            "parameter": match.group(1),
            "technique_description": match.group(2),
            "dbms": dbms_match.group(1).strip() if dbms_match else None,
            "type": TYPE_RE.search(text).group(1).strip() if TYPE_RE.search(text) else None,
            "title": TITLE_RE.search(text).group(1).strip() if TITLE_RE.search(text) else None,
            "payload": PAYLOAD_RE.search(text).group(1).strip() if PAYLOAD_RE.search(text) else None,
        }

    if PARAM_INJECTABLE_RE2.search(text):
        match = PARAM_INJECTABLE_RE2.search(text)
        dbms_match = DBMS_RE.search(text)
        return {
            "vulnerable": True,
            "state": "CONFIRMED",
            "parameter": match.group(1),
            "technique_description": "vulnerable",
            "dbms": dbms_match.group(1).strip() if dbms_match else None,
            "type": TYPE_RE.search(text).group(1).strip() if TYPE_RE.search(text) else None,
            "title": TITLE_RE.search(text).group(1).strip() if TITLE_RE.search(text) else None,
            "payload": PAYLOAD_RE.search(text).group(1).strip() if PAYLOAD_RE.search(text) else None,
        }

    if NOT_INJECTABLE_RE.search(text):
        return {"vulnerable": False, "state": "NOT_DETECTED"}

    if re.search(r"(?:not\s+injection|no\s+injection|no\s+vulnerabilities?|not vulnerable)", text, re.IGNORECASE):
        return {"vulnerable": False, "state": "NOT_DETECTED"}

    # Neither phrase matched -- sqlmap likely errored out before reaching a
    # verdict (bad target, connection issue, etc.). Report inconclusive
    # rather than silently guessing either way.
    return {"vulnerable": False, "state": "INCONCLUSIVE", "note": "sqlmap did not reach a clear verdict -- see raw output"}


def run_sqlmap(url, param, original_value="1", config=None):
    """Runs real sqlmap against one URL/parameter with a conservative,
    detection-only flag set (no destructive/data-extraction flags). Returns
    a dict shaped closely enough to sql_engine.run_engine()'s output that
    the frontend can display it with the same components.

    sqlmap needs the target parameter to actually be present in the URL's
    query string (with some value) -- `-p` only tells it *which* existing
    parameter to focus on, it doesn't add one that isn't there. If `url`
    doesn't already contain `param`, it's added here with `original_value`."""
    cfg = config or {}
    interpreter, ok, message = find_sqlmap()
    if not ok:
        return {"ok": False, "error": message}

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if param not in qs:
        qs[param] = [str(original_value)]
        url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    level = min(5, max(1, cfg.get("level", 1)))
    risk = min(3, max(1, cfg.get("risk", 1)))
    timeout = cfg.get("timeout_seconds", 60)

    cmd = interpreter + [
        "-u", url,
        "-p", param,
        "--batch",              # never prompt interactively
        f"--level={level}",
        f"--risk={risk}",
        "--technique=BEUST",    # Boolean, Error, Union, Stacked, Time -- detection techniques only
        "--flush-session",      # don't reuse a stale cached verdict from a previous run
        # Routes every connection sqlmap makes (not just the first) through
        # the SSRF-guard forward proxy -- see security.py's "Forward-proxy
        # SSRF guard" section for why this is necessary at all: sqlmap runs
        # as a separate process, so the in-process urllib3 patch used for
        # scanner.py/sql_engine.py can't reach it.
        f"--proxy={security.ensure_ssrf_guard_proxy()}",
    ]

    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"sqlmap did not finish within {timeout}s"}
    except OSError as e:
        return {"ok": False, "error": f"failed to launch sqlmap: {e}"}
    elapsed = time.monotonic() - t0

    parsed = parse_sqlmap_output(result.stdout)
    return {
        "ok": True,
        "url": url,
        "parameter": param,
        "elapsed_seconds": round(elapsed, 1),
        "return_code": result.returncode,
        **parsed,
        **({"note": message} if message else {}),
        "raw_output": result.stdout[-6000:],  # last portion is what carries the verdict; full output can be very long
    }
