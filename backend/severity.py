"""
severity.py
Single shared model for turning a detection's confidence into a finding's
severity. Used by every branch of build_auto_findings() in app.py.

Before this, each finding type -- missing headers, endpoint leads, JS
secrets, SQLi (quick), SQLi (advanced/sqlmap) -- hardcoded its own severity
literal independently, in five separate places. Two of those branches
(JS secrets, SQLi advanced) already computed a `confidence` value, but it
never actually influenced `severity`: a Low-confidence SQLi signal and a
High-confidence one both surfaced as "High" severity findings, which
defeats the purpose of tracking confidence at all. Endpoint leads carried a
`classification` (Reachable / Access Controlled / Redirect / ...) that was
computed and displayed but similarly never fed into severity.

The model here is deliberately simple: severity is confidence, capped by how
bad that *category* of finding can plausibly be even in the best case. A
missing security header is never "High" severity no matter how certain we
are it's missing -- it's a hardening gap, not a confirmed exploit. A
possible SQL injection can genuinely be "High" if confidence is High.
"""

SEVERITY_LEVELS = ["Low", "Medium", "High"]


def derive_severity(confidence: str, max_severity: str = "High") -> str:
    """Maps a confidence label to a severity, capped at max_severity.

    confidence: "Low" | "Medium" | "High" -- anything else (missing, or an
        unrecognized label from a scan module) is treated as "Medium" rather
        than silently defaulting to the ceiling.
    max_severity: the highest severity this finding *category* can reach
        regardless of confidence."""
    confidence = confidence if confidence in SEVERITY_LEVELS else "Medium"
    max_severity = max_severity if max_severity in SEVERITY_LEVELS else "High"
    idx = min(SEVERITY_LEVELS.index(confidence), SEVERITY_LEVELS.index(max_severity))
    return SEVERITY_LEVELS[idx]


def is_valid_severity(value) -> bool:
    return value in SEVERITY_LEVELS
