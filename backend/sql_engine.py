"""
sql_engine.py
Pent III advanced scanner integration layer -- deep SQLi engine.

Central pipeline (Section 49 of the deep-engine upgrade brief):

    REQUEST CONTEXT -> BASELINE -> CONTROLLED MUTATION -> RESPONSE
        -> DIFFERENTIAL ANALYSIS -> TECHNIQUE EVIDENCE -> PARAMETER ATTRIBUTION
        -> VALIDATION -> EVIDENCE CORRELATION -> CONFIDENCE -> FINDING

This module is intentionally separate from scanner.py's `test_sqli` (kept
completely unchanged -- it remains the implementation behind the legacy
"Quick Test" / `/api/scan/sqli/<id>` route) and from endpoint discovery / JS
analysis, which remain independent modules that only *feed* this engine via
scanner.collect_endpoints(). The existing scanner remains the main entry
point; this module only extends what happens once a parameterized endpoint
reaches SQLi testing.

`run_engine(url, param, original_value, enabled, config)` keeps its original
signature and top-level return keys (`confidence`, `vulnerable`, `tests`,
`stages`, ...) for backward compatibility with the existing route and
frontend. New fields (`state`, `evidence`, `stability`, `request_context`,
...) are pure additions.

No exploitation: every payload here is a detection probe. Nothing extracts,
dumps, or modifies data.
"""

import difflib
import re
import statistics
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from scanner import HEADERS

DEFAULT_CONFIG = {
    "request_timeout": 8,       # seconds
    "max_requests": 30,         # hard ceiling on requests this engine run may issue
    "verification_attempts": 2, # >1 enables the retest/validation step per technique
    "timing_threshold": 3.0,    # seconds of extra delay considered significant, floor
    "rate_limit_delay": 0.0,    # seconds to sleep between requests
    "baseline_samples": 2,      # repeated baseline observations for stability/timing variance
    # Request-context overrides (all optional, default to existing GET/query behavior):
    "method": "GET",            # GET | POST
    "parameter_location": "QUERY",  # QUERY | FORM | JSON
    "form_params": {},          # other fields to preserve alongside the tested one (FORM/JSON)
}

# The browser can supply scan settings, but those settings must never turn a
# bounded assessment into an unbounded request generator. Keep the limits in
# the engine (the last line of defence), not only in the React controls.
CONFIG_LIMITS = {
    "request_timeout": (1.0, 30.0),
    "max_requests": (1, 60),
    "verification_attempts": (1, 3),
    "timing_threshold": (0.5, 15.0),
    "rate_limit_delay": (0.0, 5.0),
    "baseline_samples": (1, 3),
}


def normalize_config(config=None):
    """Validate untrusted API configuration and return safe native values."""
    supplied = config or {}
    if not isinstance(supplied, dict):
        raise ValueError("config must be an object")

    normalized = dict(DEFAULT_CONFIG)
    for key, (minimum, maximum) in CONFIG_LIMITS.items():
        value = supplied.get(key, normalized[key])
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a number")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if not minimum <= value <= maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}")
        normalized[key] = int(value) if isinstance(DEFAULT_CONFIG[key], int) else value

    method = str(supplied.get("method", normalized["method"])).upper()
    location = str(supplied.get("parameter_location", normalized["parameter_location"])).upper()
    if method not in {"GET", "POST"}:
        raise ValueError("method must be GET or POST")
    if location not in {"QUERY", "FORM", "JSON"}:
        raise ValueError("parameter_location must be QUERY, FORM, or JSON")
    form_params = supplied.get("form_params", {})
    cookies = supplied.get("cookies", {})
    if not isinstance(form_params, dict) or not isinstance(cookies, dict):
        raise ValueError("form_params and cookies must be objects")

    normalized.update({
        "method": method,
        "parameter_location": location,
        "form_params": {str(key): str(value) for key, value in form_params.items()},
        "cookies": {str(key): str(value) for key, value in cookies.items()},
    })
    return normalized


def normalize_enabled(enabled=None):
    """Accept only the known, explicitly enabled detection techniques."""
    supplied = enabled if enabled is not None else {"error": True, "boolean": True, "time": True, "union": True}
    if not isinstance(supplied, dict):
        raise ValueError("enabled must be an object")
    normalized = {key: bool(supplied.get(key, False)) for key in ("error", "boolean", "time", "union")}
    if not any(normalized.values()):
        raise ValueError("enable at least one detection technique")
    return normalized

# ---------------------------------------------------------------------------
# Technique states (Section 19/22/24). A technique's *state* is the primary,
# human-meaningful classification; the numeric confidence score is supporting
# information layered on top, never the sole definition of vulnerability.
# ---------------------------------------------------------------------------
NOT_DETECTED = "NOT_DETECTED"
INCONCLUSIVE = "INCONCLUSIVE"
LIKELY = "LIKELY"
CONFIRMED = "CONFIRMED"
STATE_RANK = {NOT_DETECTED: 0, INCONCLUSIVE: 1, LIKELY: 2, CONFIRMED: 3}

BOOLEAN_TRUE_SUFFIXES = [
    "' OR '1'='1",
    "' OR 1=1-- -",
    "') OR ('1'='1",
    '" OR "1"="1',
    " OR 1=1#",
    "' OR TRUE-- -",
]
BOOLEAN_FALSE_SUFFIXES = [
    "' AND '1'='2",
    "' AND 1=2-- -",
    "') AND ('1'='2",
    '" AND "1"="2',
    " AND 1=2#",
    "' AND FALSE-- -",
]

TIME_PAYLOADS = [
    "' OR SLEEP({s})-- -",          # MySQL / MariaDB
    "'; SELECT pg_sleep({s})-- -",  # PostgreSQL
    "' OR SLEEP({s})#",             # MySQL, alt comment style
    "' OR BENCHMARK({s}00000,MD5('x'))-- -",
]

UNION_MAX_COLUMNS = 6

# ---------------------------------------------------------------------------
# Structured, per-database-family error taxonomy (Section 11).
# Replaces the flat substring list with signatures carrying real metadata:
# which database family/driver produced it, what category of error it is,
# and how strong a signal it is on its own. scanner.py's flat
# SQLI_ERROR_SIGNATURES list is untouched and still backs the legacy
# Quick Test route -- this taxonomy is additive, used only by the deep engine.
# ---------------------------------------------------------------------------
DB_ERROR_SIGNATURES = [
    # MySQL / MariaDB (MariaDB is a MySQL-compatible fork sharing these
    # message formats in practice, so it's grouped under the same family)
    {"family": "mysql_mariadb", "driver": "mysqli", "category": "syntax_error", "signature": "you have an error in your sql syntax", "strength": "strong"},
    {"family": "mysql_mariadb", "driver": "mysqli", "category": "driver_error", "signature": "mysqli_fetch", "strength": "strong"},
    {"family": "mysql_mariadb", "driver": "mysql_legacy", "category": "driver_error", "signature": "mysql_fetch", "strength": "strong"},
    {"family": "mysql_mariadb", "driver": "pdo_mysql", "category": "driver_error", "signature": "sqlstate[42000]", "strength": "strong"},
    {"family": "mysql_mariadb", "driver": "generic", "category": "driver_warning", "signature": "warning: mysql", "strength": "medium"},
    # PostgreSQL
    {"family": "postgresql", "driver": "pg", "category": "driver_error", "signature": "pg_query()", "strength": "strong"},
    {"family": "postgresql", "driver": "generic", "category": "query_error", "signature": "postgresql query failed", "strength": "strong"},
    {"family": "postgresql", "driver": "generic", "category": "syntax_error", "signature": "syntax error at or near", "strength": "strong"},
    # SQLite
    {"family": "sqlite", "driver": "sqlite3", "category": "driver_error", "signature": "sqlite3.operationalerror", "strength": "strong"},
    {"family": "sqlite", "driver": "generic", "category": "driver_error", "signature": "sqlite_error", "strength": "strong"},
    {"family": "sqlite", "driver": "generic", "category": "syntax_error", "signature": "syntax error", "strength": "strong"},
    {"family": "sqlite", "driver": "generic", "category": "syntax_error", "signature": "near \"'\": syntax error", "strength": "strong"},
    # Microsoft SQL Server / ODBC
    {"family": "mssql", "driver": "odbc", "category": "driver_error", "signature": "odbc sql server driver", "strength": "strong"},
    {"family": "mssql", "driver": "ole_db", "category": "driver_error", "signature": "microsoft ole db provider for odbc", "strength": "strong"},
    {"family": "mssql", "driver": "generic", "category": "syntax_error", "signature": "unclosed quotation mark", "strength": "strong"},
    {"family": "mssql", "driver": "generic", "category": "syntax_error", "signature": "quoted string not properly terminated", "strength": "strong"},
    # Oracle
    {"family": "oracle", "driver": "generic", "category": "driver_error", "signature": "ora-01756", "strength": "strong"},
    # Cross-DB marker -- weaker alone since it can appear without full context
    {"family": "generic", "driver": "generic", "category": "sqlstate_marker", "signature": "sqlstate", "strength": "medium"},
]

STRENGTH_RANK = {"strong": 2, "medium": 1, "weak": 0}


GENERIC_SQL_ERROR_PATTERNS = [
    r"sql syntax.*(mysql|mariadb|postgresql|sqlite|sql server)",
    r"syntax error.*(at or near|in query expression|missing operator|unterminated string literal)",
    r"(unknown column|invalid column|column .* does not exist)",
    r"sqlstate\s*\[|sqlstate\b",
    r"sqlite3\.?operationalerror|sqlite_error|sqlite exception",
    r"odbc sql server driver|sql server.*driver|system\.data\.sqlclient",
    r"(postgresql|mysql|sqlite).*error",
    r"warning.*(mysql|sqlite|postgresql|mssql|sqlsrv)",
]


def detect_db_errors(text):
    """Returns structured evidence for every DB-error signature found in text."""
    if not text:
        return []
    body_lower = text.lower()
    matches = []
    for sig in DB_ERROR_SIGNATURES:
        idx = body_lower.find(sig["signature"])
        if idx != -1:
            context = text[max(0, idx - 40): idx + 80]
            matches.append({**sig, "matched_text": sig["signature"], "context": context.strip()})

    for pattern in GENERIC_SQL_ERROR_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            matches.append({
                "family": "generic",
                "driver": "generic",
                "category": "syntax_error",
                "signature": pattern,
                "strength": "strong",
                "matched_text": pattern,
                "context": text[:250].strip(),
            })
    return matches


def attribute_error(baseline_text, test_text):
    """Section 12 -- a database error is not automatically SQLi evidence
    unless the *mutation* introduced it. Compares the signatures present in
    the baseline against the test response and returns only the ones that
    are genuinely new. A signature already present in the baseline (a
    pre-existing application error, unrelated to the injected parameter) is
    explicitly excluded."""
    baseline_sigs = {m["signature"] for m in detect_db_errors(baseline_text)}
    test_matches = detect_db_errors(test_text)
    introduced = [m for m in test_matches if m["signature"] not in baseline_sigs]
    return introduced, test_matches


# ---------------------------------------------------------------------------
# Request Context (Section 5/6) -- preserves the full request shape a
# mutation is applied to, instead of collapsing it down to just the tested
# parameter. QUERY location preserves this engine's original GET/query-string
# behavior exactly; FORM location POSTs the tested parameter alongside any
# other form fields that must be present for the request to behave as the
# real application expects (e.g. a required "Submit" field).
# ---------------------------------------------------------------------------

@dataclass
class RequestContext:
    url: str
    target_parameter: str
    original_value: str
    method: str = "GET"                 # GET | POST
    parameter_location: str = "QUERY"   # QUERY | FORM | JSON
    form_params: dict = field(default_factory=dict)  # other fields to preserve (FORM/JSON)

    def describe(self):
        return {
            "method": self.method,
            "url": self.url,
            "parameter": self.target_parameter,
            "parameter_location": self.parameter_location,
            "original_value": self.original_value,
        }


class RequestBudget:
    """Tracks how many requests an engine run has issued so a single call to
    run_engine() can never silently balloon into unbounded traffic."""

    def __init__(self, max_requests):
        self.max_requests = max_requests
        self.used = 0

    def spend(self):
        if self.used >= self.max_requests:
            raise RuntimeError(f"Request budget exhausted ({self.max_requests} max for this test run)")
        self.used += 1


def _set_query_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _send(session, ctx, mutated_value, config, budget):
    """Sends one request for the given mutated parameter value, preserving
    the rest of the request context (other form fields, method, location)
    rather than collapsing the request down to just the tested parameter.
    Uses the shared `session` so cookies set by any earlier response in this
    scan (e.g. a session cookie issued on the very first request, or one
    supplied via config["cookies"] for an already-authenticated scan) are
    carried through to every subsequent probe -- without this, a target that
    requires login would show the same "please log in" page for every
    request, making every comparison meaningless and guaranteeing a false
    negative regardless of how good the detection logic is."""
    budget.spend()
    t0 = time.monotonic()
    try:
        if ctx.parameter_location == "FORM":
            data = {**ctx.form_params, ctx.target_parameter: mutated_value}
            resp = session.post(ctx.url, data=data, timeout=config["request_timeout"])
            effective_url = ctx.url
        elif ctx.parameter_location == "JSON":
            data = {**ctx.form_params, ctx.target_parameter: mutated_value}
            resp = session.request(ctx.method, ctx.url, json=data, timeout=config["request_timeout"])
            effective_url = ctx.url
        else:
            effective_url = _set_query_param(ctx.url, ctx.target_parameter, mutated_value)
            if ctx.method == "POST":
                resp = session.post(effective_url, timeout=config["request_timeout"])
            else:
                resp = session.get(effective_url, timeout=config["request_timeout"])
        elapsed = time.monotonic() - t0
        if config.get("rate_limit_delay"):
            time.sleep(config["rate_limit_delay"])
        return {
            "ok": True, "status_code": resp.status_code, "length": len(resp.content),
            "text": resp.text, "elapsed": elapsed, "redirected": resp.url != effective_url,
            "request_url": effective_url,
        }
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e), "elapsed": time.monotonic() - t0}


def compare_responses(baseline, test):
    if not baseline.get("ok") or not test.get("ok"):
        return {
            "status_match": False, "length_delta": None, "length_delta_pct": None,
            "similarity": None, "timing_delta": round((test.get("elapsed", 0) - baseline.get("elapsed", 0)), 3),
            "redirect_changed": None,
        }
    length_delta = test["length"] - baseline["length"]
    length_delta_pct = (abs(length_delta) / baseline["length"] * 100) if baseline["length"] else 0
    similarity = difflib.SequenceMatcher(None, baseline["text"][:4000], test["text"][:4000]).ratio()
    return {
        "status_match": baseline["status_code"] == test["status_code"],
        "length_delta": length_delta,
        "length_delta_pct": round(length_delta_pct, 1),
        "similarity": round(similarity, 3),
        "timing_delta": round(test["elapsed"] - baseline["elapsed"], 3),
        "redirect_changed": baseline["redirected"] != test["redirected"],
    }


def _wants_validation(config):
    return config.get("verification_attempts", 1) > 1


# ---------------------------------------------------------------------------
# Baseline characterization (Section 8/16/17) -- repeated observations
# instead of a single snapshot, so timing analysis has a real variance
# estimate (not just one elapsed number) and content stability is measured
# directly rather than assumed.
# ---------------------------------------------------------------------------

def characterize_baseline(session, ctx, config, budget):
    samples = max(1, config.get("baseline_samples", 2))
    results = []
    for _ in range(samples):
        r = _send(session, ctx, ctx.original_value, config, budget)
        if r["ok"]:
            results.append(r)
    if not results:
        return {"ok": False, "error": "all baseline observations failed"}

    primary = results[0]
    timings = [r["elapsed"] for r in results]
    timing_mean = statistics.mean(timings)
    timing_stdev = statistics.pstdev(timings) if len(timings) > 1 else 0.0

    content_similarity = 1.0
    content_stable = True
    if len(results) >= 2:
        content_similarity = round(
            difflib.SequenceMatcher(None, results[0]["text"][:4000], results[1]["text"][:4000]).ratio(), 3
        )
        content_stable = content_similarity > 0.95

    return {
        **primary,
        "timing_mean": timing_mean,
        "timing_stdev": timing_stdev,
        "timing_samples": [round(t, 3) for t in timings],
        "content_stable": content_stable,
        "content_similarity": content_similarity,
        "db_errors_present": detect_db_errors(primary["text"]),
    }


# ---------------------------------------------------------------------------
# Error-Based Tester (Section 11/12/13) -- structured, attributed
# ---------------------------------------------------------------------------

def _validation_send(session, ctx, mutated_value, config, budget):
    """Like _send(), but for the *optional* validation/retest step only:
    if the request budget is exhausted at this point, that must not blow
    up the whole technique and discard evidence already collected by its
    initial probe -- it should just mean "couldn't verify," exactly like
    any other failed retest (network error, timeout). Without this, a
    technique that already found strong evidence right before hitting
    max_requests would have its entire result lost (see run_engine's
    per-technique try/except), turning a real finding into a false
    negative purely because of when the budget ran out."""
    try:
        return _send(session, ctx, mutated_value, config, budget)
    except RuntimeError as e:
        return {"ok": False, "error": f"validation retest skipped: {e}"}


def error_based_test(session, ctx, config, budget, baseline):
    r = _send(session, ctx, ctx.original_value + "'", config, budget)
    if not r["ok"]:
        return {"method": "Error-Based", "ran": True, "state": INCONCLUSIVE, "triggered": False, "validated": False,
                "evidence": [], "error": r["error"]}

    introduced, all_matches = attribute_error(baseline["text"], r["text"])
    comparison = compare_responses(baseline, r)

    if not introduced:
        generic_status_shift = r["status_code"] >= 500 and baseline.get("status_code", 0) < 500
        generic_sql_error = any(token in r["text"].lower() for token in ["syntax error", "sql syntax", "sqlite3.operationalerror", "unterminated string literal", "sqlstate", "odbc sql server driver"])
        if not generic_status_shift and not generic_sql_error:
            return {
                "method": "Error-Based", "ran": True, "state": NOT_DETECTED, "triggered": False, "validated": False,
                "evidence": [], "comparison": comparison,
                "evidence_note": "No new database error signature introduced by the mutation" + (
                    " (baseline already contains a matching signature -- not attributable to this parameter)" if all_matches else ""
                ),
            }
        return {
            "method": "Error-Based", "ran": True, "state": LIKELY, "triggered": True, "validated": False,
            "evidence": [{"family": "generic", "driver": "generic", "category": "syntax_error", "signature": "syntax_error", "strength": "strong"}], "comparison": comparison,
            "evidence_note": "Response shifted to a 5xx status and the error body contains SQL syntax markers, which is consistent with an injection-triggered query failure",
        }

    strongest = max(introduced, key=lambda m: STRENGTH_RANK.get(m["strength"], 0))
    validated = False
    budget_exhausted = False
    if _wants_validation(config):
        r2 = _validation_send(session, ctx, ctx.original_value + "'", config, budget)
        if r2["ok"]:
            introduced2, _ = attribute_error(baseline["text"], r2["text"])
            validated = any(m["signature"] == strongest["signature"] for m in introduced2)
        else:
            budget_exhausted = "budget" in (r2.get("error") or "").lower()
    else:
        validated = True

    state = CONFIRMED if (validated and strongest["strength"] == "strong") else LIKELY if validated else INCONCLUSIVE

    return {
        "method": "Error-Based", "ran": True, "state": state, "triggered": True, "validated": validated,
        "evidence": introduced,
        "evidence_note": (
            f"Database error introduced by mutation: {strongest['family']}/{strongest['driver']} "
            f"({strongest['category']}, {strongest['strength']} signal)"
            + (" -- reproduced on retest" if validated else
               " -- validation retest skipped (request budget exhausted); evidence kept, unvalidated" if budget_exhausted else
               " -- did not reproduce on retest" if _wants_validation(config) else "")
        ),
        "comparison": comparison, "test_url": r.get("request_url"),
    }


# ---------------------------------------------------------------------------
# Boolean-Based Blind Tester (Section 14/15) -- inferential, capped at LIKELY
# ---------------------------------------------------------------------------

def _boolean_gap(baseline, true_r, false_r):
    cmp_true = compare_responses(baseline, true_r)
    cmp_false = compare_responses(baseline, false_r)
    if cmp_true["similarity"] is None or cmp_false["similarity"] is None:
        return None, cmp_true, cmp_false
    return abs(cmp_true["similarity"] - cmp_false["similarity"]), cmp_true, cmp_false


def boolean_based_test(session, ctx, config, budget, baseline):
    true_payloads = [ctx.original_value + suffix for suffix in BOOLEAN_TRUE_SUFFIXES]
    false_payloads = [ctx.original_value + suffix for suffix in BOOLEAN_FALSE_SUFFIXES]

    true_r = None
    false_r = None
    true_variant = None
    false_variant = None
    for candidate_true, candidate_false in zip(true_payloads, false_payloads):
        r_true = _send(session, ctx, candidate_true, config, budget)
        r_false = _send(session, ctx, candidate_false, config, budget)
        if r_true.get("ok") and r_false.get("ok"):
            true_r, false_r = r_true, r_false
            true_variant, false_variant = candidate_true, candidate_false
            break

    if true_r is None or false_r is None:
        return {"method": "Boolean-Based Blind", "ran": True, "state": INCONCLUSIVE, "triggered": False, "validated": False,
                "evidence": [], "error": (true_r or {}).get("error") or (false_r or {}).get("error") or "no boolean payloads succeeded"}

    gap, cmp_true, cmp_false = _boolean_gap(baseline, true_r, false_r)
    if gap is None:
        return {"method": "Boolean-Based Blind", "ran": True, "state": INCONCLUSIVE, "triggered": False, "validated": False, "evidence": []}

    triggered = gap > 0.08
    if not triggered:
        return {
            "method": "Boolean-Based Blind", "ran": True, "state": NOT_DETECTED, "triggered": False, "validated": False,
            "evidence": [], "evidence_note": "No consistent TRUE/FALSE behavioral difference detected",
            "comparison": {"true_vs_baseline": cmp_true, "false_vs_baseline": cmp_false},
            "payloads_used": {"true": true_variant, "false": false_variant},
        }

    validated = False
    budget_exhausted = False
    if _wants_validation(config):
        true_r2 = _validation_send(session, ctx, true_variant, config, budget)
        false_r2 = _validation_send(session, ctx, false_variant, config, budget)
        if true_r2["ok"] and false_r2["ok"]:
            gap2, _, _ = _boolean_gap(baseline, true_r2, false_r2)
            validated = gap2 is not None and gap2 > 0.08
        else:
            budget_exhausted = "budget" in (true_r2.get("error") or false_r2.get("error") or "").lower()
    else:
        validated = True

    # Boolean evidence is inherently inferential (a content-similarity gap,
    # not a specific, attributable artifact) -- it is deliberately never
    # allowed to reach CONFIRMED on its own, only LIKELY at best.
    state = LIKELY if validated else INCONCLUSIVE

    return {
        "method": "Boolean-Based Blind", "ran": True, "state": state, "triggered": True, "validated": validated,
        "evidence": [{"type": "behavioral_divergence", "similarity_gap": round(gap, 3)}],
        "evidence_note": (
            f"TRUE/FALSE responses diverge (similarity gap {gap:.2f})"
            + (" -- reproduced on retest" if validated else
               " -- validation retest skipped (request budget exhausted); evidence kept, unvalidated" if budget_exhausted else
               " -- did not reproduce on retest" if _wants_validation(config) else "")
        ),
        "comparison": {"true_vs_baseline": cmp_true, "false_vs_baseline": cmp_false},
        "payloads_used": {"true": true_variant, "false": false_variant},
    }


# ---------------------------------------------------------------------------
# Time-Based Blind Tester (Section 16/17) -- validated against baseline
# timing *variance*, not a single elapsed number
# ---------------------------------------------------------------------------

def time_based_test(session, ctx, config, budget, baseline):
    configured_threshold = config.get("timing_threshold", DEFAULT_CONFIG["timing_threshold"])
    baseline_mean = baseline.get("timing_mean", baseline.get("elapsed", 0))
    baseline_stdev = baseline.get("timing_stdev", 0)
    # Required delay must clear both the user's configured threshold AND a
    # safety margin over the baseline's own natural jitter -- a single slow
    # request on a noisy network must never look like injection-induced delay.
    required_delay = max(configured_threshold, 3 * baseline_stdev + 0.5)
    delay_s = max(2, int(required_delay) + 1)

    for template in TIME_PAYLOADS:
        payload = template.format(s=delay_s)
        r = _send(session, ctx, ctx.original_value + payload, config, budget)
        if not r["ok"]:
            continue
        delta = r["elapsed"] - baseline_mean
        if delta >= required_delay:
            validated = False
            budget_exhausted = False
            if _wants_validation(config):
                r2 = _validation_send(session, ctx, ctx.original_value + payload, config, budget)
                if r2["ok"]:
                    validated = (r2["elapsed"] - baseline_mean) >= required_delay
                else:
                    budget_exhausted = "budget" in (r2.get("error") or "").lower()
            else:
                validated = True
            # Time-based evidence is inferential (elapsed time, not a
            # specific artifact) -- capped at LIKELY, never CONFIRMED alone.
            state = LIKELY if validated else INCONCLUSIVE
            return {
                "method": "Time-Based Blind", "ran": True, "state": state, "triggered": True, "validated": validated,
                "evidence": [{"type": "timing_delay", "delay_observed": round(delta, 2), "required_delay": round(required_delay, 2),
                              "baseline_mean": round(baseline_mean, 3), "baseline_stdev": round(baseline_stdev, 3)}],
                "evidence_note": (
                    f"Response delayed by {delta:.2f}s (required {required_delay:.2f}s, accounting for baseline jitter "
                    f"of {baseline_stdev:.2f}s stdev)"
                    + (" -- reproduced on retest" if validated else
                       " -- validation retest skipped (request budget exhausted); evidence kept, unvalidated" if budget_exhausted else
                       " -- did not reproduce on retest" if _wants_validation(config) else "")
                ),
            }
    return {
        "method": "Time-Based Blind", "ran": True, "state": NOT_DETECTED, "triggered": False, "validated": False,
        "evidence": [],
        "evidence_note": f"No response exceeded the required {required_delay:.2f}s delay (baseline mean {baseline_mean:.2f}s, stdev {baseline_stdev:.2f}s)",
    }


# ---------------------------------------------------------------------------
# UNION-Based Analyzer (Section 18) -- explicitly heuristic, never CONFIRMED
# ---------------------------------------------------------------------------

def _looks_like_baseline(baseline, r):
    cmp = compare_responses(baseline, r)
    return cmp["similarity"] is not None and cmp["similarity"] > 0.6 and r["status_code"] < 500, cmp


def union_based_test(session, ctx, config, budget, baseline):
    order_by_results = []
    last_ok_columns = 0
    boundary_r = None

    for n in range(1, UNION_MAX_COLUMNS + 1):
        r = _send(session, ctx, ctx.original_value + f"' ORDER BY {n}-- -", config, budget)
        if not r["ok"]:
            break
        looks_valid, _ = _looks_like_baseline(baseline, r)
        order_by_results.append({"columns": n, "looks_valid": looks_valid, "status_code": r["status_code"]})
        if looks_valid:
            last_ok_columns = n
        else:
            boundary_r = r
            break

    triggered = last_ok_columns >= 1 and len(order_by_results) > last_ok_columns
    if not triggered:
        return {
            "method": "UNION-Based", "ran": True, "state": NOT_DETECTED, "triggered": False, "validated": False,
            "evidence": [], "probe_results": order_by_results,
            "evidence_note": "No column-count boundary detected within the tested range",
        }

    validated = False
    budget_exhausted = False
    if _wants_validation(config) and boundary_r is not None:
        r2 = _validation_send(session, ctx, ctx.original_value + f"' ORDER BY {last_ok_columns + 1}-- -", config, budget)
        if r2["ok"]:
            still_valid2, _ = _looks_like_baseline(baseline, r2)
            validated = not still_valid2
        else:
            budget_exhausted = "budget" in (r2.get("error") or "").lower()
    else:
        validated = True

    # UNION analysis is explicitly heuristic (Section 18): it must never
    # claim CONFIRMED from an ORDER BY boundary alone, regardless of
    # validation -- LIKELY is the ceiling, and only when the boundary
    # reproduces; otherwise it's flagged INCONCLUSIVE/heuristic.
    state = LIKELY if validated else INCONCLUSIVE

    return {
        "method": "UNION-Based", "ran": True, "state": state, "triggered": True, "validated": validated,
        "evidence": [{"type": "column_boundary", "estimated_columns": last_ok_columns, "heuristic": True}],
        "evidence_note": (
            f"Response stopped matching baseline shape after ORDER BY {last_ok_columns + 1}, suggesting {last_ok_columns} "
            f"column(s) -- heuristic, not conclusive on its own"
            + (" -- boundary reproduced on retest" if validated else
               " -- validation retest skipped (request budget exhausted); evidence kept, unvalidated" if budget_exhausted else
               " -- boundary did not reproduce on retest" if _wants_validation(config) else "")
        ),
        "probe_results": order_by_results,
        "estimated_columns": last_ok_columns,
    }


# ---------------------------------------------------------------------------
# Evidence Correlation + Confidence Engine (Section 19/22/23/24/25)
# ---------------------------------------------------------------------------

# Base points reflect how strong each technique's evidence *category*
# inherently is -- a specific, attributable database error is stronger
# evidence than a subtle timing or content-similarity inference.
METHOD_BASE_POINTS = {
    "Error-Based": 55,
    "Boolean-Based Blind": 35,
    "Time-Based Blind": 35,
    "UNION-Based": 20,
}
VALIDATION_BONUS = 15
CORROBORATION_BONUS = 10

CONFIDENCE_BANDS = [
    (90, "Confirmed"),
    (70, "High Confidence"),
    (40, "Potential"),
    (0, "Not Confirmed"),
]


def correlate_state(test_results):
    """Section 19/25 -- techniques are evaluated independently and combined
    by taking the *strongest* individual state, not a vote or a requirement
    that every technique agree. One CONFIRMED technique establishes a
    finding regardless of how many other techniques were inconclusive; a
    weak or inconclusive result from one technique can never erase strong,
    validated evidence from another."""
    ran = [t for t in test_results if t.get("ran")]
    if not ran:
        return NOT_DETECTED
    return max((t.get("state", NOT_DETECTED) for t in ran), key=lambda s: STATE_RANK.get(s, 0))


def confidence_score_v2(test_results, stability=None):
    """Numeric 0-100 score, kept as *supporting* information alongside the
    final state (Section 24) -- it is never used by itself to decide
    vulnerability status; `correlate_state()` does that."""
    triggered = [t for t in test_results if t.get("ran") and t.get("triggered")]
    validated = [t for t in triggered if t.get("validated")]
    unvalidated = [t for t in triggered if not t.get("validated")]

    score = 0
    for t in validated:
        base = METHOD_BASE_POINTS.get(t["method"], 20)
        if t["method"] == "Error-Based" and t.get("evidence"):
            strongest = max((e.get("strength", "medium") for e in t["evidence"]), key=lambda s: STRENGTH_RANK.get(s, 0))
            base = int(base * (1.0 if strongest == "strong" else 0.7))
        score += base + VALIDATION_BONUS
    for t in unvalidated:
        score += METHOD_BASE_POINTS.get(t["method"], 20) // 2

    if len(validated) >= 2:
        score += CORROBORATION_BONUS

    if stability and stability.get("checked") and not stability.get("stable"):
        content_based = {"Boolean-Based Blind", "UNION-Based"}
        penalty = sum(
            (METHOD_BASE_POINTS.get(t["method"], 20) + (VALIDATION_BONUS if t.get("validated") else 0)) // 2
            for t in triggered if t["method"] in content_based
        )
        score = max(0, score - penalty)

    score = max(0, min(100, score))
    label = next(lbl for threshold, lbl in CONFIDENCE_BANDS if score >= threshold)
    return score, label


def to_legacy_confidence(label, any_triggered):
    """Adapter: maps the new scoring back onto the original
    None/Low/Medium/High field so existing findings/report/UI code that
    already reads `result.confidence` keeps working unmodified."""
    if not any_triggered:
        return "None"
    if label in ("Confirmed", "High Confidence"):
        return "High"
    if label == "Potential":
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# State/score reconciliation.
#
# `correlate_state()` and `confidence_score_v2()` are two independently
# computed systems -- the former from each technique's own internal logic,
# the latter from a generic point-sum over triggered/validated flags. They
# were designed to agree, but nothing *enforced* that, so specific
# combinations (particularly a stability-penalty interacting with a
# technique that reached LIKELY/CONFIRMED on its own terms) could produce a
# self-contradicting result: e.g. state=LIKELY (the UI says "vulnerable")
# sitting next to confidence_label="Not Confirmed" and a near-zero score --
# two parts of the same result actively disagreeing with each other.
#
# This reconciles them by construction: the correlated *state* is treated as
# authoritative (per Section 24 of the deep-engine brief -- "the numerical
# score is supporting information, must not be the sole definition of
# vulnerability"), and the numeric score is clamped into the point range
# that's actually consistent with that state before the label is re-derived
# from the clamped score. State and score/label can no longer disagree.
# ---------------------------------------------------------------------------
STATE_SCORE_RANGE = {
    NOT_DETECTED: (0, 39),
    INCONCLUSIVE: (0, 69),
    LIKELY: (70, 89),
    CONFIRMED: (90, 100),
}


def reconcile_score(raw_score, overall_state):
    lo, hi = STATE_SCORE_RANGE.get(overall_state, (0, 100))
    reconciled_score = max(lo, min(hi, raw_score))
    label = next(lbl for threshold, lbl in CONFIDENCE_BANDS if reconciled_score >= threshold)
    return reconciled_score, label


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_engine(url, param, original_value, enabled, config=None):
    """Runs baseline characterization + whichever techniques are enabled, in
    the fixed order: Error-Based -> Boolean-Based -> Time-Based -> UNION-Based,
    respecting a request budget so this can never balloon into uncontrolled
    traffic. `config` may optionally include `method` ("GET"/"POST"),
    `parameter_location` ("QUERY"/"FORM"/"JSON"), `form_params` (dict of other form
    fields to preserve), and `cookies` (dict of cookies to pre-load for an
    already-authenticated scan) -- all default to the original GET/query-string,
    no-cookie behavior when omitted, so existing callers are unaffected.

    A single requests.Session() is used for the entire run, so any cookie
    the target sets on its very first response (e.g. a session cookie) is
    automatically carried through every subsequent probe in this scan --
    without this, a login-gated target would show the same "please log in"
    page to every request, making all comparisons meaningless."""
    cfg = normalize_config(config)
    enabled = normalize_enabled(enabled)
    budget = RequestBudget(cfg["max_requests"])
    stages = []

    session = requests.Session()
    session.headers.update(HEADERS)
    if cfg.get("cookies"):
        session.cookies.update(cfg["cookies"])

    ctx = RequestContext(
        url=url, target_parameter=param, original_value=str(original_value),
        method=cfg.get("method", "GET"), parameter_location=cfg.get("parameter_location", "QUERY"),
        form_params=cfg.get("form_params") or {},
    )

    try:
        baseline = characterize_baseline(session, ctx, cfg, budget)
        stages.append({"stage": "Baseline Request", "status": "Failed" if baseline.get("error") else "Complete"})
    except RuntimeError as e:
        return {"ok": False, "error": str(e), "stages": stages}

    if baseline.get("error"):
        return {"ok": False, "error": baseline["error"], "stages": stages}

    stability = {
        "checked": True,
        "stable": baseline.get("content_stable", True),
        "similarity": baseline.get("content_similarity", 1.0),
    }
    stages.append({
        "stage": "Stability Check",
        "status": "Complete",
        "detail": f"baseline reproducible (similarity {stability['similarity']})" if stability["stable"]
        else f"page content is not stable between identical requests (similarity {stability['similarity']}) -- content-based results discounted",
    })

    test_results = []
    test_fns = [
        ("error", "Error-Based SQLi", error_based_test),
        ("boolean", "Boolean-Based SQLi", boolean_based_test),
        ("time", "Time-Based SQLi", time_based_test),
        ("union", "UNION-Based Analysis", union_based_test),
    ]

    for key, label, fn in test_fns:
        if not enabled.get(key, False):
            stages.append({"stage": label, "status": "Skipped"})
            continue
        try:
            result = fn(session, ctx, cfg, budget, baseline)
            test_results.append(result)
            stages.append({"stage": label, "status": "Complete"})
        except RuntimeError as e:
            stages.append({"stage": label, "status": f"Stopped ({e})"})
            break

    stages.append({"stage": "Response Analysis", "status": "Complete"})

    overall_state = correlate_state(test_results)
    triggered = [t for t in test_results if t.get("ran") and t.get("triggered")]
    validated = [t for t in triggered if t.get("validated")]
    stages.append({
        "stage": "Validation",
        "status": "Complete",
        "detail": f"{len(validated)}/{len(triggered)} triggered result(s) reproduced on retest" if triggered else "no anomalies to validate",
    })

    raw_score, raw_label = confidence_score_v2(test_results, stability)
    score, label_v2 = reconcile_score(raw_score, overall_state)
    legacy_confidence = to_legacy_confidence(label_v2, bool(triggered))
    stages.append({"stage": "Confidence Calculation", "status": "Complete", "detail": f"{score}/100 — {label_v2} (state: {overall_state})"})

    # Section 24/25's core fix: vulnerability is decided by the correlated
    # evidence STATE (LIKELY or CONFIRMED), not by "something triggered".
    vulnerable = overall_state in (LIKELY, CONFIRMED)

    return {
        "ok": True,
        "url": url,
        "http_method": ctx.method,
        "parameter": param,
        "parameter_location": ctx.parameter_location,
        "request_context": ctx.describe(),
        "baseline": {
            "status_code": baseline["status_code"], "length": baseline["length"],
            "elapsed": round(baseline.get("timing_mean", baseline["elapsed"]), 3),
            "timing_stdev": round(baseline.get("timing_stdev", 0), 3),
        },
        "stability": stability,
        "tests": test_results,
        "state": overall_state,
        "triggered_methods": [t["method"] for t in triggered],
        "validated_methods": [t["method"] for t in validated],
        "confidence": legacy_confidence,
        "confidence_score": score,
        "confidence_label": label_v2,
        "vulnerable": vulnerable,
        "requests_used": budget.used,
        "stages": stages,
        "summary": (
            f"State: {overall_state} — {len(triggered)} of {len(test_results)} enabled test(s) triggered, "
            f"{len(validated)} validated (score {score}/100, {label_v2})" if test_results else "No tests were enabled"
        ),
    }
