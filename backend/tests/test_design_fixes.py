"""
Regression tests for two design-level fixes:

1. Endpoint discovery used to decide "found" by status code alone, so any
   SPA with a client-side-routing catch-all (200 + the same shell for any
   path) would light up most of the wordlist as false "sensitive path"
   leads. discover_endpoints() now probes a guaranteed-nonexistent path
   first and filters any candidate that's byte-identical to it.

2. Severity used to be five independent hardcoded literals across
   build_auto_findings()'s branches, with a `confidence` field that existed
   for some finding types but never actually influenced severity. severity.py
   now provides one shared confidence -> severity mapping, used everywhere.
"""

import threading
import time
import unittest

import requests
from flask import Flask

import scanner
import security
import severity as severity_model


class TestEndpointBaselineFiltering(unittest.TestCase):
    """A dummy 'SPA with a catch-all route' server: every path returns 200
    with the identical body, except one genuinely distinct real path."""
    @classmethod
    def setUpClass(cls):
        # This suite deliberately targets its own local dummy server, same
        # as test_sqli_detection.py -- force ALLOW_PRIVATE_TARGETS on so
        # the connection-level guard (installed by test_ssrf_guard.py, if
        # it ran first in this process) doesn't block these requests.
        cls._original_allow_private = security.ALLOW_PRIVATE_TARGETS
        security.ALLOW_PRIVATE_TARGETS = True

        app = Flask(__name__, static_folder=None)  # avoid Flask's own /static/<path> route
        # intercepting one of our wordlist paths ahead of the catch-all below,
        # which would give a real 404 for a reason unrelated to this test.

        SHELL = "<html><body>spa shell, same for every route</body></html>"

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def catch_all(path):
            # One real, distinguishable endpoint that should NOT be filtered.
            if path == ".env":
                return "DB_PASSWORD=hunter2", 200
            return SHELL, 200

        cls.port = 8766
        cls.thread = threading.Thread(
            target=lambda: app.run(port=cls.port, use_reloader=False), daemon=True
        )
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        for _ in range(50):
            try:
                requests.get(cls.base_url, timeout=0.5)
                break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        security.ALLOW_PRIVATE_TARGETS = cls._original_allow_private

    def test_catch_all_paths_are_not_marked_as_found(self):
        result = scanner.discover_endpoints(self.base_url)
        self.assertTrue(result["baseline_probe_ok"])

        catch_all_hits = [r for r in result["all_results"] if r["path"] != "/.env"]
        # Every path except the real one should be recognized as matching
        # the baseline (soft 404), not counted as a genuine finding.
        for hit in catch_all_hits:
            if hit.get("status_code") is None:
                continue  # network error against this path, unrelated to the filter
            self.assertFalse(
                hit["exists"],
                f"{hit['path']} was marked as existing but is identical to the baseline "
                "(catch-all) response -- the SPA false-positive filter did not catch it.",
            )
            self.assertEqual(hit["classification"], "Soft 404 (catch-all response)")

        found_paths = {r["path"] for r in result["found"]}
        self.assertLess(
            len(found_paths), len(result["all_results"]) / 2,
            "Most of the wordlist was marked as found -- baseline filtering doesn't seem to be working.",
        )

    def test_genuinely_distinct_path_is_still_found(self):
        result = scanner.discover_endpoints(self.base_url)
        found_paths = {r["path"] for r in result["found"]}
        self.assertIn("/.env", found_paths, ".env has genuinely different content and must still be flagged.")


class TestEndpointBaselineFilteringWithNoise(unittest.TestCase):
    """A dummy SPA catch-all that embeds a fresh random token on every
    single response (simulating a CSRF token or nonce rendered into the
    page shell). An exact byte-for-byte match would never fire here --
    this is exactly the gap called out as unfixed after the first version
    of the baseline filter, and this test is what proves it's closed now."""

    @classmethod
    def setUpClass(cls):
        cls._original_allow_private = security.ALLOW_PRIVATE_TARGETS
        security.ALLOW_PRIVATE_TARGETS = True

        app = Flask(__name__, static_folder=None)

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def catch_all(path):
            import secrets
            token = secrets.token_hex(8)
            if path == "admin":
                return f'''<!DOCTYPE html><html><head><meta name="csrf-token" content="{token}">
<title>Admin Panel - User Management</title><link rel="stylesheet" href="/assets/admin-xyz.css"></head>
<body><h1>User Management</h1><table><tr><th>ID</th><th>Email</th><th>Role</th></tr>
<tr><td>1</td><td>admin@example.com</td><td>superuser</td></tr></table>
<form method="post" action="/admin/users/delete"><input name="csrf" value="{token}"></form></body></html>''', 200
            return f'''<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="csrf-token" content="{token}"><title>My App</title>
<link rel="stylesheet" href="/assets/index-abc123.css">
<script type="module" src="/assets/index-def456.js"></script></head>
<body><div id="root"></div><noscript>Enable JavaScript to run this app.</noscript></body></html>''', 200

        cls.port = 8768
        cls.thread = threading.Thread(
            target=lambda: app.run(port=cls.port, use_reloader=False), daemon=True
        )
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        for _ in range(50):
            try:
                requests.get(cls.base_url, timeout=0.5)
                break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        security.ALLOW_PRIVATE_TARGETS = cls._original_allow_private

    def test_noisy_catch_all_is_still_filtered_via_similarity_fallback(self):
        result = scanner.discover_endpoints(self.base_url)
        self.assertTrue(result["baseline_probe_ok"], "baseline should still be usable -- the two probes differ only by an 8-byte token, well within the similarity threshold")

        non_admin_hits = [r for r in result["all_results"] if r["path"] != "/admin"]
        for hit in non_admin_hits:
            if hit.get("status_code") is None:
                continue
            self.assertFalse(
                hit["exists"],
                f"{hit['path']} was marked as existing despite matching the catch-all shell "
                "(aside from its random token) -- the similarity fallback did not catch it.",
            )

    def test_distinct_page_with_its_own_token_is_still_found(self):
        # /admin's markup genuinely differs (not just its token), so it must
        # still clear the similarity threshold and be reported as found.
        result = scanner.discover_endpoints(self.base_url)
        found_paths = {r["path"] for r in result["found"]}
        self.assertIn("/admin", found_paths, "a page with genuinely different content (not just a different token) must still be flagged")



class TestSharedSeverityModel(unittest.TestCase):
    def test_severity_matches_confidence_when_within_cap(self):
        self.assertEqual(severity_model.derive_severity("High", max_severity="High"), "High")
        self.assertEqual(severity_model.derive_severity("Medium", max_severity="High"), "Medium")
        self.assertEqual(severity_model.derive_severity("Low", max_severity="High"), "Low")

    def test_severity_is_capped_regardless_of_confidence(self):
        # A missing-header-style finding: even "High" confidence can't push
        # severity past the category's ceiling.
        self.assertEqual(severity_model.derive_severity("High", max_severity="Medium"), "Medium")
        self.assertEqual(severity_model.derive_severity("Low", max_severity="Medium"), "Low")

    def test_unrecognized_confidence_label_defaults_to_medium_not_the_ceiling(self):
        # Guards against a scan module passing something unexpected and
        # silently getting the highest possible severity as a result.
        self.assertEqual(severity_model.derive_severity("Unknown", max_severity="High"), "Medium")

    def test_is_valid_severity(self):
        for level in severity_model.SEVERITY_LEVELS:
            self.assertTrue(severity_model.is_valid_severity(level))
        self.assertFalse(severity_model.is_valid_severity("Critical"))
        self.assertFalse(severity_model.is_valid_severity(""))


if __name__ == "__main__":
    unittest.main()
