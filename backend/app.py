"""
app.py
Flask API backend for the Web Application Security Tester.

This serves ONLY as a JSON API (the frontend is a separate React/Vite app --
see ../frontend). CORS is enabled for local development.

Run:
    pip install -r requirements.txt
    python app.py
Serves on http://localhost:5050
"""

import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

import database
import scanner
import sql_engine
import security
from severity import derive_severity, SEVERITY_LEVELS

app = Flask(__name__)

# CORS: restricted to an explicit allowlist instead of "*". Configure with a
# comma-separated ALLOWED_ORIGINS env var; defaults to the Vite dev server
# origins only, since this API can trigger outbound scans and shell out to
# sqlmap -- it should never be reachable from an arbitrary web page.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
_allowed_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
CORS(app, origins=_allowed_origins, supports_credentials=False)

# Rate limiting: registered before auth so repeated bad-key guesses from a
# given client are throttled too, not just successfully authenticated calls.
# See security.py's "Rate limiting" section for why (single shared key ->
# no built-in per-caller quota otherwise).
security.install_rate_limiter(app)

# Auth: every /api/* route requires a shared API key unless explicitly
# disabled for local-only use. See security.py for details and setup.
security.register_auth(app)

# SSRF guard, layer 2: the per-route `assert_safe_target` check (via
# `_safe_target_or_error` below) validates the URL a caller supplies before
# a scan starts. This installs the connection-level backstop that
# revalidates at actual connect time -- closing the DNS-rebinding and
# redirect bypasses a URL-only check can't see. See security.py's
# "Connection-level SSRF guard" section for why both layers are needed.
security.install_connection_guard()

# sqlmap execution is a meaningfully bigger blast radius than the rest of the
# app (it's a full external tool, not just a bounded HTTP probe), so it's
# gated behind its own opt-in flag on top of the auth check above.

database.init_db()


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "web-application-security-tester-api",
        "status": "running",
        "note": "This is a JSON API only — there is no page to view here directly. "
                "Open the React frontend (npm run dev in /frontend) to use the UI.",
        "try": "/api/health",
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "not found",
        "hint": "Check the path and method — API routes live under /api/... "
                "and do not accept a trailing slash (e.g. /api/targets, not /api/targets/).",
    }), 404



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def row_to_dict(row):
    return dict(row) if row else None


def save_scan_result(target_id, scan_type, result):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO scan_results (target_id, scan_type, result_json, created_at) VALUES (?, ?, ?, ?)",
        (target_id, scan_type, json.dumps(result), database.now()),
    )
    conn.execute("""
        UPDATE targets
        SET status = CASE
            WHEN EXISTS (SELECT 1 FROM scan_results WHERE target_id = ? AND scan_type = 'http')
             AND EXISTS (SELECT 1 FROM scan_results WHERE target_id = ? AND scan_type = 'endpoints')
             AND EXISTS (SELECT 1 FROM scan_results WHERE target_id = ? AND scan_type = 'javascript')
                THEN 'Complete'
            ELSE 'In Progress'
        END
        WHERE id = ?
    """, (target_id, target_id, target_id, target_id))
    conn.commit()
    conn.close()


def mark_scan_started(target_id):
    conn = database.get_db()
    conn.execute("UPDATE targets SET status = 'In Progress' WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()


def get_target_or_404(target_id):
    conn = database.get_db()
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# 9.1 Target Management
# ---------------------------------------------------------------------------

@app.route("/api/targets", methods=["GET"])
def list_targets():
    conn = database.get_db()
    rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/targets", methods=["POST"])
def create_target():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    try:
        security.validate_target_url(url)
    except security.UnsafeTargetError as e:
        return jsonify({"error": "invalid target", "detail": str(e)}), 400

    conn = database.get_db()
    cur = conn.execute(
        "INSERT INTO targets (name, url, date_added, status) VALUES (?, ?, ?, ?)",
        (name, url, database.now(), "Not Started"),
    )
    conn.commit()
    new_id = cur.lastrowid
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (new_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201


@app.route("/api/targets/<int:target_id>", methods=["GET"])
def get_target(target_id):
    row = get_target_or_404(target_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def delete_target(target_id):
    conn = database.get_db()
    deleted = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,)).rowcount
    conn.commit()
    conn.close()
    if not deleted:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/targets/<int:target_id>/scans", methods=["GET"])
def get_target_scans(target_id):
    conn = database.get_db()
    rows = conn.execute(
        "SELECT * FROM scan_results WHERE target_id = ? ORDER BY id DESC", (target_id,)
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["result_json"] = json.loads(d["result_json"])
        out.append(d)
    return jsonify(out)


# ---------------------------------------------------------------------------
# 9.2 - 9.5 Scan modules
# ---------------------------------------------------------------------------

def _safe_target_or_error(url):
    """Returns None if `url` is safe to fetch, else a (response, status) tuple to return early."""
    try:
        security.assert_safe_target(url)
    except security.UnsafeTargetError as e:
        return jsonify({"error": "unsafe target", "detail": str(e)}), 400
    return None


@app.route("/api/scan/http/<int:target_id>", methods=["POST"])
def scan_http(target_id):
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    unsafe = _safe_target_or_error(target["url"])
    if unsafe:
        return unsafe
    mark_scan_started(target_id)
    result = scanner.analyze_http(target["url"])
    save_scan_result(target_id, "http", result)
    return jsonify(result)


@app.route("/api/scan/endpoints/<int:target_id>", methods=["POST"])
def scan_endpoints(target_id):
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    unsafe = _safe_target_or_error(target["url"])
    if unsafe:
        return unsafe
    mark_scan_started(target_id)
    result = scanner.discover_endpoints(target["url"])
    save_scan_result(target_id, "endpoints", result)
    return jsonify(result)


@app.route("/api/scan/js/<int:target_id>", methods=["POST"])
def scan_js(target_id):
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    unsafe = _safe_target_or_error(target["url"])
    if unsafe:
        return unsafe
    mark_scan_started(target_id)
    result = scanner.analyze_javascript(target["url"])
    save_scan_result(target_id, "javascript", result)
    return jsonify(result)


@app.route("/api/scan/sqli/<int:target_id>", methods=["POST"])
def scan_sqli(target_id):
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True) or {}
    param = (data.get("parameter") or "").strip()
    if not param:
        return jsonify({"error": "parameter is required, e.g. 'id' or 'query'"}), 400
    unsafe = _safe_target_or_error(target["url"])
    if unsafe:
        return unsafe
    mark_scan_started(target_id)
    result = scanner.test_sqli(target["url"], param)
    save_scan_result(target_id, "sqli", result)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Pent III advancement: shared Endpoint Collection + modular SQLi Engine
# ---------------------------------------------------------------------------

@app.route("/api/scan/collect/<int:target_id>", methods=["POST"])
def scan_collect(target_id):
    """Merges the most recent Endpoint Discovery + JavaScript Analysis results
    (re-running both fresh) into one normalized, deduplicated collection with
    query parameters detected -- this feeds the SQLi engine's parameter picker."""
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    unsafe = _safe_target_or_error(target["url"])
    if unsafe:
        return unsafe
    mark_scan_started(target_id)

    endpoint_result = scanner.discover_endpoints(target["url"])
    js_result = scanner.analyze_javascript(target["url"])
    collection = scanner.collect_endpoints(target["url"], endpoint_result, js_result)

    save_scan_result(target_id, "endpoints", endpoint_result)
    save_scan_result(target_id, "javascript", js_result)
    save_scan_result(target_id, "collection", collection)
    return jsonify(collection)


@app.route("/api/scan/sqli-advanced/<int:target_id>", methods=["POST"])
def scan_sqli_advanced(target_id):
    """Runs the modular SQL Injection Engine (baseline + enabled tests +
    confidence scoring) against a specific URL/parameter. Independent from
    the original /api/scan/sqli/<id> route, which is left completely intact."""
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True) or {}
    url = (data.get("url") or target["url"]).strip()
    param = (data.get("parameter") or "").strip()
    original_value = data.get("original_value", "1")
    enabled = data.get("enabled") or {"error": True, "boolean": True, "time": True, "union": True}
    config = data.get("config") or {}

    if not param:
        return jsonify({"error": "parameter is required"}), 400

    unsafe = _safe_target_or_error(url)
    if unsafe:
        return unsafe

    mark_scan_started(target_id)
    try:
        result = sql_engine.run_engine(url, param, original_value, enabled, config)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:  # pragma: no cover - safety net, never crash the API
        return jsonify({"ok": False, "error": f"engine error: {e}"}), 500

    save_scan_result(target_id, "sqli_advanced", result)
    return jsonify(result)


# ---------------------------------------------------------------------------
# 9.6 Finding Management
# ---------------------------------------------------------------------------

def finding_auto_status(data):
    confidence = str(data.get("confidence") or "").lower()
    score = data.get("confidence_score")
    # sqlmap results (sqlmap_integration.run_sqlmap) never populate
    # confidence/confidence_score -- they carry their own verdict in
    # `state` (CONFIRMED/NOT_DETECTED/INCONCLUSIVE), set by
    # parse_sqlmap_output(). Without this check, every sqlmap-confirmed
    # finding fell through to "Unconfirmed" below despite sqlmap -- the
    # more authoritative of the two detection engines -- having already
    # confirmed it.
    if str(data.get("state") or "").upper() == "CONFIRMED":
        return "Confirmed"
    return "Confirmed" if confidence in ("confirmed", "high", "high confidence") or (isinstance(score, (int, float)) and score >= 90) else "Unconfirmed"


def build_auto_findings(target_id):
    conn = database.get_db()
    target = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    rows = conn.execute("SELECT scan_type, result_json FROM scan_results WHERE target_id = ? ORDER BY id DESC", (target_id,)).fetchall()
    conn.close()
    if not target:
        return None

    latest = {}
    for row in rows:
        latest.setdefault(row["scan_type"], json.loads(row["result_json"]))
    findings = []
    base_url = target["url"].rstrip("/")

    http = latest.get("http")
    if http and http.get("ok"):
        for flag in http.get("flags", []):
            findings.append({"id": f"auto-http-{len(findings)}", "target_id": target_id, "name": f"Missing {flag['header']}", "location": http.get("final_url", http.get("url", base_url)), "description": flag.get("why", "A recommended security control was not observed."), "evidence": f"HTTP {http.get('status_code')}; {flag['header']} was not present in the response.", "remediation": f"Configure {flag['header']} according to the application security policy.", "severity": derive_severity("Medium", max_severity="Medium"), "status": "Unconfirmed", "status_mode": "auto", "detection_method": "HTTP response analysis", "confidence": "Medium"})

    endpoints = latest.get("endpoints")
    if endpoints:
        for endpoint in endpoints.get("found", []):
            path = endpoint.get("path", "")
            if path and any(marker in path.lower() for marker in (".env", "backup", ".git", "config")):
                # Confidence now tracks the classification the scanner already
                # computed: a plainly "Reachable" hit is a more meaningful lead
                # than one sitting behind a 401/403 or a redirect, or (now that
                # discover_endpoints() filters obvious soft-404/SPA catch-all
                # responses before this ever runs) one that barely survived.
                classification = endpoint.get("classification", "")
                endpoint_confidence = "Medium" if classification == "Reachable" else "Low"
                findings.append({"id": f"auto-endpoint-{len(findings)}", "target_id": target_id, "name": f"Sensitive endpoint requires review: {path}", "location": endpoint.get("url", f"{base_url}{path}"), "description": "A sensitive-looking endpoint returned a reachable response. This is a review lead, not proof of unauthorized access or data exposure.", "evidence": f"HTTP {endpoint.get('status_code')}; Content-Type: {endpoint.get('content_type', 'unknown')}", "remediation": "Verify authentication, authorization, and whether sensitive content is exposed.", "severity": derive_severity(endpoint_confidence, max_severity="Medium"), "status": "Unconfirmed", "status_mode": "auto", "detection_method": "Endpoint discovery", "confidence": endpoint_confidence})

    javascript = latest.get("javascript")
    if javascript and javascript.get("possible_secrets_flagged", 0):
        js_confidence = "Medium"
        findings.append({"id": "auto-javascript-secrets", "target_id": target_id, "name": "Possible secrets in JavaScript", "location": base_url, "description": "Client-side JavaScript contained strings matching secret-like patterns. The value must be verified before treating it as a credential exposure.", "evidence": f"{javascript['possible_secrets_flagged']} possible secret pattern(s) detected across {javascript.get('scripts_scanned', 0)} script(s).", "remediation": "Remove credentials from client-side code and rotate any exposed secrets.", "severity": derive_severity(js_confidence, max_severity="High"), "status": "Unconfirmed", "status_mode": "auto", "detection_method": "JavaScript pattern analysis", "confidence": js_confidence})

    for scan_type, result in latest.items():
        if scan_type == "sqli" and result.get("vulnerable"):
            sqli_confidence = "High"
            findings.append({"id": "auto-sqli-quick", "target_id": target_id, "name": f"Possible SQL injection: {result.get('parameter', 'parameter')}", "location": result.get("injected_url", base_url), "description": "The injected request reproduced a database-error or server-error signal associated with SQL injection.", "evidence": ", ".join(result.get("matched_signatures", [])) or f"Normal HTTP {result.get('normal_status')}; injected HTTP {result.get('injected_status')}.", "remediation": "Use parameterized queries and validate input server-side.", "severity": derive_severity(sqli_confidence, max_severity="High"), "status": "Unconfirmed", "status_mode": "auto", "detection_method": "Error-based SQLi", "confidence": sqli_confidence})
        if scan_type in ("sqli_advanced", "sqli_sqlmap") and result.get("vulnerable"):
            adv_confidence = result.get("confidence_label", result.get("confidence", "Medium"))
            findings.append({"id": f"auto-{scan_type}", "target_id": target_id, "name": f"SQL injection detected: {result.get('parameter', 'parameter')}", "location": result.get("url", base_url), "description": result.get("summary", "The SQL injection engine reported a positive result."), "evidence": "; ".join(result.get("triggered_methods", [])) or result.get("payload", "Validated scan signal"), "remediation": "Use parameterized queries and validate input server-side.", "severity": derive_severity(adv_confidence, max_severity="High"), "status": finding_auto_status(result), "status_mode": "auto", "detection_method": result.get("detection_method", scan_type), "confidence": adv_confidence})
    return findings

@app.route("/api/findings/<int:target_id>", methods=["GET"])
def list_findings(target_id):
    conn = database.get_db()
    rows = conn.execute(
        "SELECT * FROM findings WHERE target_id = ? ORDER BY "
        "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id DESC",
        (target_id,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/findings/<int:target_id>/auto", methods=["GET"])
def list_auto_findings(target_id):
    findings = build_auto_findings(target_id)
    if findings is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(findings)


@app.route("/api/findings", methods=["POST"])
def create_finding():
    data = request.get_json(force=True) or {}
    required = ["target_id", "name", "severity"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": f"required fields: {', '.join(required)}"}), 400
    if data["severity"] not in SEVERITY_LEVELS:
        return jsonify({"error": f"severity must be one of: {', '.join(SEVERITY_LEVELS)}"}), 400

    conn = database.get_db()
    cur = conn.execute(
        """INSERT INTO findings
           (target_id, name, location, parameter, description, evidence, severity, remediation, status, status_mode, created_at,
            detection_method, http_method, confidence, response_comparison)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["target_id"], data["name"], data.get("location", ""), data.get("parameter", ""),
            data.get("description", ""), data.get("evidence", ""), data["severity"],
            data.get("remediation", ""), finding_auto_status(data) if data.get("status_mode", "auto") == "auto" else data.get("status", "Unconfirmed"), data.get("status_mode", "auto"), database.now(),
            data.get("detection_method", ""), data.get("http_method", "GET"),
            data.get("confidence", ""), json.dumps(data.get("response_comparison")) if data.get("response_comparison") else "",
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (new_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201


@app.route("/api/findings/<int:finding_id>", methods=["DELETE"])
def delete_finding(finding_id):
    conn = database.get_db()
    deleted = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,)).rowcount
    conn.commit()
    conn.close()
    if not deleted:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/findings/<int:finding_id>", methods=["PATCH"])
def update_finding(finding_id):
    data = request.get_json(force=True) or {}
    allowed = ["name", "location", "parameter", "description", "evidence", "severity", "remediation", "status",
               "detection_method", "http_method", "confidence"]
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return jsonify({"error": "no valid fields"}), 400
    if "severity" in fields and fields["severity"] not in SEVERITY_LEVELS:
        return jsonify({"error": f"severity must be one of: {', '.join(SEVERITY_LEVELS)}"}), 400
    conn = database.get_db()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE findings SET {set_clause} WHERE id = ?", (*fields.values(), finding_id))
    conn.commit()
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# 9.7 Reporting
# ---------------------------------------------------------------------------

@app.route("/api/report/<int:target_id>", methods=["GET"])
def get_report(target_id):
    target = get_target_or_404(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404

    conn = database.get_db()
    findings = conn.execute(
        "SELECT * FROM findings WHERE target_id = ? ORDER BY "
        "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id DESC",
        (target_id,),
    ).fetchall()
    scans = conn.execute(
        "SELECT scan_type, created_at FROM scan_results WHERE target_id = ? ORDER BY id DESC",
        (target_id,),
    ).fetchall()
    conn.close()

    findings_list = [dict(f) for f in findings]
    if request.args.get("mode", "manual") == "auto":
        findings_list = build_auto_findings(target_id) or []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings_list:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    return jsonify({
        "target": dict(target),
        "generated_at": database.now(),
        "methodology": [
            "HTTP response analysis (status, headers, cookies) and security-header flagging",
            "Endpoint discovery against a fixed wordlist",
            "JavaScript file discovery and regex-based pattern scanning",
            "Error-based SQL injection testing on a specified parameter",
        ],
        "scans_performed": [dict(s) for s in scans],
        "severity_counts": severity_counts,
        "findings": findings_list,
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "web-application-security-tester-api"})


# Read once at import time -- not inside `if __name__ == "__main__"` -- so
# this check runs no matter how the app is actually served. A real
# deployment should use a production WSGI server (gunicorn/waitress/uwsgi),
# not `python app.py` directly (Flask's own dev server prints exactly this
# warning); those servers import this module rather than executing it as a
# script, and `__name__` is then the module's dotted path, not
# "__main__" -- code gated behind that check silently never runs under
# them. Since check_deployment_safety() raises SystemExit on an unsafe
# combination, running it here means an unsafe config fails the *worker
# process's boot* under gunicorn too, not just a plain `python app.py` run.
#
# Caveat: this app has no way to see a WSGI server's own bind address --
# HOST here only directly controls app.run() below. If you deploy behind
# gunicorn with e.g. `--bind 0.0.0.0:5050`, also set HOST=0.0.0.0 in the
# environment so this check evaluates against how you're actually exposing
# it, not the loopback default.
_host = os.environ.get("HOST", "127.0.0.1").strip()
_debug = os.environ.get("FLASK_DEBUG", "").strip() == "1"

# Opt-in TLS: set both env vars to terminate HTTPS directly in this
# process via app.run() (fine for a small single-operator deployment; a
# higher-traffic one should still prefer a reverse proxy, or gunicorn's
# own --certfile/--keyfile). Leaving either unset falls back to plain
# HTTP, as before -- no behavior change unless you explicitly configure
# this. Under gunicorn, these two env vars aren't wired to anything --
# use gunicorn's own TLS flags instead and just set tls_enabled below to
# match, so the printed guidance is accurate either way.
_tls_cert = os.environ.get("TLS_CERT_FILE", "").strip()
_tls_key = os.environ.get("TLS_KEY_FILE", "").strip()
_ssl_context = (_tls_cert, _tls_key) if _tls_cert and _tls_key else None

security.check_deployment_safety(_host, debug=_debug, tls_enabled=bool(_ssl_context))

if __name__ == "__main__":
    # threaded=True matters even for pure local/single-user use, not just
    # deployment: a scan can legitimately take many seconds (real outbound
    # HTTP per parameter/technique, plus timeouts). Without this, Flask's
    # dev server handles one request at a time, so the whole API --
    # including the frontend just trying to list targets or poll status --
    # would appear to hang for the entire duration of any running scan.
    app.run(host=_host, debug=_debug, port=5050, ssl_context=_ssl_context, threaded=True)
