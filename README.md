<<<<<<< HEAD
# Pent III — Web Application Security Tester

A beginner-scope security assessment tool: Flask JSON API backend + React (Vite + Tailwind) frontend.

Built from `Web_Application_Security_Tester_Documentation.md`. The doc specified server-rendered
Flask/Jinja2 templates with no React — this build intentionally uses React for the frontend instead,
talking to Flask purely as a JSON API. All backend scan logic (HTTP analysis, endpoint discovery,
JS scanning, error-based SQLi detection, findings, reporting) matches the doc's Section 9 spec exactly.

## Project structure

```
webapp-security-tester/
├── backend/          Flask API (Python)
│   ├── app.py         routes
│   ├── database.py    SQLite schema + connection helper
│   ├── scanner.py      HTTP / endpoint / JS / SQLi scan logic
│   └── requirements.txt
└── frontend/          React + Vite
    └── src/
        ├── theme.js            design tokens + icon paths (ported from the Figma export)
        ├── api.js              fetch wrapper for the Flask API
        ├── App.jsx             menu bar, primary tab bar, status bar, global state
        ├── components/
        │   ├── figma-ui.jsx     Toolbar/TBtn/Th/Td/PanelLabel/SplitPane/SevBadge primitives
        │   └── Charts.jsx       gradient-filled severity donut (Recharts)
        └── pages/
            ├── DashboardPage.jsx    stat strip, target tree, activity log, findings summary
            ├── TargetsPage.jsx      register/select/delete targets
            ├── HttpPage.jsx         Burp-Repeater-style request/response view
            ├── EndpointsPage.jsx    fixed-wordlist discovery, path detail
            ├── JavaScriptPage.jsx   script discovery + regex pattern table
            ├── SqliPage.jsx         error-based SQLi probes + detail
            ├── FindingsPage.jsx     issue list + detail, full CRUD
            └── ReportsPage.jsx      Preview / Raw Markdown / Summary tabs
```

The UI is a direct port of the project's Figma Make export (dense dark toolbar/table layout,
`#00C49A` teal accent, resizable split panes) — not just its color palette. Every page pulls
real data from the Flask API; none of the mockup's placeholder data made it into the build.

## Pent III advancement (endpoint discovery + SQL injection engine)

This build includes the "Pent III — Complete Security Scanner Advancement":

- **No more 20-result caps.** Endpoint Discovery's wordlist was expanded (~80 paths, grouped by
  category in `scanner.py`) and processes/returns the complete list every time. JavaScript
  Analysis's endpoint extraction is uncapped; only the *number of JS files downloaded per scan*
  is bounded (`MAX_JS_FILES`, a request-safety control, not a result cap — and it's reported
  transparently via `scripts_found` vs `scripts_scanned`).
- **Parameterized URL extraction.** The JS regex now captures full query strings
  (`/product?id=10&category=books`), not just the bare path.
- **Endpoint Collection** (new "Collection (+ JS)" sub-tab on Endpoint Discovery): merges
  wordlist-discovered paths and JS-extracted URLs into one normalized, deduplicated list with
  query parameters detected on each entry — `scanner.collect_endpoints()`.
- **Modular SQL Injection Engine** (`backend/sql_engine.py`, new "Advanced Engine" sub-tab on
  SQLi Test): Baseline Analyzer → Error-Based / Boolean-Based Blind / Time-Based Blind /
  UNION-Based (heuristic, detection-only) → Response Comparator → Validation → Confidence Engine.
  Each technique is independently toggleable, with configurable request timeout, max requests,
  verification attempts, timing threshold, and rate limit — all enforced via a request budget so
  a run can never balloon into uncontrolled traffic.
- **Validation / retesting (sqlmap/ZAP-style).** Every technique — not just timing — now retests
  its own trigger before trusting it: Error-Based re-sends the identical payload and requires the
  error signature to reproduce; Boolean-Based re-checks the TRUE/FALSE divergence; UNION-Based
  re-probes the exact column-count boundary. A single unreproduced anomaly is explicitly kept out
  of the higher confidence bands rather than being reported as a hit.
- **Page stability check**, ported from sqlmap's actual approach (confirmed by reading its real
  source via GitHub, not guessed): before trusting any content-comparison-based technique,
  the baseline is re-fetched once and compared against itself. Pages with rotating ad banners,
  visitor counters, or embedded timestamps look "different" between any two identical requests —
  without this check, that noise reads as a false-positive Boolean/UNION divergence. When the
  page is flagged unstable, Boolean-Based and UNION-Based contributions to the confidence score
  are specifically discounted (Error-Based and Time-Based aren't affected the same way, since
  neither depends on comparing page *content*).
- **Evidence-based 0–100 confidence score.** Each technique contributes points scaled to how
  strong its evidence inherently is (a real database error is stronger evidence than a subtle
  timing gap), plus a validation bonus only if the result reproduced on retest, plus a
  corroboration bonus when two or more independent techniques agree. Maps to
  Confirmed (90–100) / High Confidence (70–89) / Potential (40–69) / Not Confirmed (0–39).
  A `to_legacy_confidence()` adapter maps this back onto the original None/Low/Medium/High field,
  so the findings table, report, and existing frontend code all keep working unmodified — the new
  `confidence_score`/`confidence_label`/`validated_methods` fields are pure additions.
- **The original single-parameter error-based test still exists unchanged** as "Quick Test" —
  nothing was removed, per the advancement brief's Section 20/23.
- Findings gained `detection_method`, `http_method`, and `confidence` fields (existing databases
  are migrated automatically on startup; nothing breaks if you already have a `security_tester.db`
  from before this advancement).

## Running it

You need two terminals — one for the API, one for the UI.

**1. Backend (Flask API on :5050)**

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
export API_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
echo "Your API key: $API_KEY"   # copy this, you'll need it in the frontend
python app.py
```

This creates `backend/security_tester.db` (SQLite) automatically on first run.

**2. Frontend (React dev server on :5173)**

```bash
cd frontend
npm install
npm run dev
```

Open the URL Vite prints (usually `http://localhost:5173`), open the browser console, and run:

```js
import("/src/api.js").then(({ api }) => api.setApiKey("PASTE_YOUR_API_KEY_HERE"))
```

(or just call `localStorage.setItem("apiKey", "...")` directly). The frontend expects the API at
`http://localhost:5050` — that's hardcoded in `frontend/src/api.js` (`BASE` constant) if you need
to change the port.

## Security controls (read this before pointing it at anything)

This tool sends real, unauthenticated-by-the-target HTTP requests (and, optionally, shells out to
sqlmap) at whatever URL you give it. A few guardrails are built in and configured via environment
variables when you start the backend:

| Env var | Default | Purpose |
|---|---|---|
| `API_KEY` | *(unset)* | Shared secret required on every `/api/*` request (`X-API-Key` header). The server refuses to start serving API routes without it unless `ALLOW_NO_AUTH=1` is also set. |
| `API_KEYS` | *(unset)* | Comma-separated list of valid keys, for when more than one caller needs one (CI, a teammate, a script) — each can be revoked individually (remove it from the list, restart) without rotating everyone else's. Takes precedence over `API_KEY` if both are set. |
| `ALLOW_NO_AUTH` | off | Disables the API key check entirely. Only for a machine you fully trust and don't expose beyond localhost — refused outright at startup if combined with a non-loopback `HOST` (see below). |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated CORS allowlist. The API is never `Access-Control-Allow-Origin: *`. If you deploy the frontend anywhere other than localhost, update this to that origin or the API will (correctly) reject it. |
| `ALLOW_PRIVATE_TARGETS` | off | By default, any target/URL that resolves to a private, loopback, link-local, or cloud-metadata address (`10.x`, `127.x`, `169.254.169.254`, etc.) is refused, to stop the API being used as an SSRF proxy against its own host/network. Set this only for an authorized internal engagement where you've deliberately decided that's in scope. |
| `ENABLE_SQLMAP` | off | The `/api/scan/sqli-sqlmap` route (real sqlmap subprocess) is disabled until you explicitly opt in — it's a much bigger blast radius than the rest of the app. |
| `RATE_LIMIT_PER_MINUTE` | `120` | Max requests per client IP per minute on non-scan routes. Applies pre-auth too (by IP), so it also throttles someone guessing at an API key. |
| `RATE_LIMIT_SCAN_PER_MINUTE` | `20` | Lower per-IP limit specifically for `/api/scan/...` routes, since each one triggers real outbound HTTP (and optionally sqlmap). |
| `RATE_LIMIT_DISABLE` | off | Turns rate limiting off entirely. The limiter is in-process/in-memory (no extra service), so it doesn't share state across multiple worker processes — disable it and rate-limit at a reverse proxy instead if you run more than one worker. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | *(unset)* | Set both to terminate HTTPS directly in this Flask process (fine for a small deployment). Leave unset to stay on plain HTTP, as before — a reverse proxy terminating TLS in front is equally valid and more common for anything beyond casual use. |
| `HOST` | `127.0.0.1` | Interface Flask binds to. Everything above is designed around a loopback-only bind. Setting this to anything else (`0.0.0.0`, a LAN/public IP) is checked at startup: it refuses to start at all if combined with `ALLOW_NO_AUTH=1`, `FLASK_DEBUG=1` (the Werkzeug debugger is remote code execution if reachable), or no API key; otherwise it prints a one-time warning about what a non-loopback bind still doesn't give you (see "Deploying beyond localhost" below). |

### Deploying beyond localhost

This app was designed around running on the same machine you're using it from. If you're putting it
somewhere else (a VM, a container, a shared server), the shared-API-key model still works, but only
if you also handle what it doesn't cover on its own:

- **Put TLS in front of it, or set `TLS_CERT_FILE`/`TLS_KEY_FILE`.** Without one of the two, the API
  key travels as a plain header, readable to anyone on the network path.
- **Set `ALLOWED_ORIGINS`** to your deployed frontend's real origin, not the localhost default.
- **Never set `FLASK_DEBUG=1`** on a reachable host — the startup check refuses this for you, but
  don't work around it.
- **Use `API_KEYS` (plural) if more than one caller needs access**, so one can be revoked without
  rotating the rest. It's still a shared-secret model, not a login system with fine-grained
  permissions — for anything beyond a handful of trusted callers, put a real auth layer (OAuth/SSO)
  in front instead.
- **Rate limiting is per-IP and in-process by default** (`RATE_LIMIT_PER_MINUTE` /
  `RATE_LIMIT_SCAN_PER_MINUTE`). If you run more than one worker process, that state isn't shared
  between them — set `RATE_LIMIT_DISABLE=1` and rate-limit at your reverse proxy instead.
- Consider whether `ENABLE_SQLMAP` and `ALLOW_PRIVATE_TARGETS` should stay off in the deployed
  environment even if you use them locally — both widen the blast radius of a leaked key.

The SSRF guard runs at two layers for anything this Python process fetches
directly, and a third for sqlmap specifically:

1. `assert_safe_target()` validates the URL a caller supplies, up front,
   before a scan starts.
2. A socket-connection-level guard (`security.install_connection_guard()`,
   wired up at API startup) revalidates every outbound connection this
   process opens at the moment it's actually opened — including ones
   reached via a redirect, or a hostname whose DNS answer changed between
   the initial check and the real request ("DNS rebinding"). The first
   layer alone can't catch either of those; the two together can.
3. **sqlmap runs as a separate process**, so layer 2's in-process patch
   can't reach it — a subprocess has its own interpreter and its own
   network stack entirely. To cover it, `run_sqlmap()` routes sqlmap
   through a small local forward proxy (`security.ensure_ssrf_guard_proxy()`),
   passed via `--proxy`, which applies the same IP check to every
   connection sqlmap makes for the full duration of the scan — not just
   its first request. It never terminates or inspects TLS; it only decides
   whether a given CONNECT/request target is allowed to be reached.

See `backend/tests/test_ssrf_guard.py` for the regression tests covering
layers 1–2.

**Only ever point this at systems you're authorized to test.** These controls reduce accidental
and drive-by misuse; they don't turn unauthorized scanning into something that's okay to do.

## Using it

1. Go to the **Targets** tab and register a target (name + URL) — **only use targets you're
   authorized to test.** Click a row to select it as the active target.
2. Work through **HTTP Analysis → Endpoint Discovery → JavaScript → SQLi Test** for the active
   target (shown in the menu bar at the top).
3. Any flagged result has an **Add to Findings** button that pre-fills a new finding in the
   Findings tab — fill in severity/remediation and save.
4. **Reports** compiles everything into Preview / Raw Markdown / Summary views — copy the
   markdown or print the Preview tab to PDF via your browser's print dialog.
5. **Dashboard** gives a running overview: stat strip, a live activity log of every scan you've
   run this session, and a findings summary table.

## Test targets

This tool will find little to nothing against secure, well-built sites — that's expected, not a bug
(see the doc's Section 8). Point it at something intentionally vulnerable instead:

- **OWASP Juice Shop**: `docker run -p 3000:3000 bkimminich/juice-shop`
- **DVWA**: `docker run -p 8080:80 vulnerables/web-dvwa`
- Or your own small vulnerable Flask app (recommended in the doc — demonstrates you understand
  both the vulnerability *and* the detection).

## Notes

- CORS is open on the Flask side for local development — tighten this before deploying anywhere
  the API is reachable by anyone other than you.
- The SQLi module is error-based only (v1 scope, per the doc) — a clean result does not prove a
  parameter is safe, only that no known error signature was triggered.
- No automated exploitation happens beyond confirming a flaw is present (e.g. detecting a SQL
  error, not extracting data) — consistent with Section 15 of the doc.

## Daily update — 2026-09-02

- Adjusted the application scrollbar styling to match the darker VS Code-inspired interface without
  changing the original sidebar/nav structure.
- Kept the functional app layout intact while improving the visual polish of scrollable panels and
  content areas.
- Documentation was updated to reflect the latest UI refinement so the current working state is
  captured in the project record.

## Real sqlmap integration (SQLi Test → "sqlmap" sub-tab)

`sql_engine.py`'s detection is a from-scratch reimplementation of common SQLi techniques —
useful and self-contained, but inherently thinner than a tool with years of real-world
refinement. Rather than keep expanding it indefinitely, Pent III can also invoke the actual
sqlmap tool as a subprocess. This is not sqlmap's source code embedded in this project —
that would obligate this project's license too, since sqlmap is GPLv2 — it's this app calling
an independently-installed copy, the same way a scanner might wrap `nmap`.

**Setup** (optional — the rest of Pent III works fully without it):

```bash
git clone https://github.com/sqlmapproject/sqlmap.git backend/vendor/sqlmap
```

Or set the `SQLMAP_PATH` environment variable to wherever your `sqlmap.py` lives. If neither
is present, the "sqlmap" sub-tab returns a clear setup message instead of failing — nothing
else in the app is affected either way. If you'd rather Pent III fetch it for you the first
time it's needed, set `SQLMAP_AUTO_INSTALL=1` — this is opt-in on purpose, since it means the
backend will run a `git clone` of externally-sourced code the first time the sqlmap route is
hit, and that's a decision worth making explicitly rather than having it happen silently.

Verified end-to-end against a real vulnerable Flask app: sqlmap correctly identified SQLite
error-based injection, extracted the exact payload and DBMS, in ~6 requests.
=======
# PENTIII
A web-based security testing platform for discovering and analyzing common web application vulnerabilities, with a focus on automated JavaScript endpoint discovery and SQL injection testing.
>>>>>>> 2fa2016ec46ec2c1ba60c7b3b5750da4315dce71
