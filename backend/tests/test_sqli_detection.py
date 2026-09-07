import threading
import time
import unittest

import requests
from flask import Flask, request

import scanner
import security
import sql_engine


class TestSqliDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This suite deliberately targets a dummy server on 127.0.0.1 (its
        # own vulnerable test app below) -- a legitimate local/internal
        # target, same as the README's "authorized internal engagement"
        # case. Force ALLOW_PRIVATE_TARGETS on for these tests specifically
        # so they pass regardless of whether test_ssrf_guard's
        # connection-level guard has already been installed in this process
        # (module-level test order shouldn't change behavior either way).
        cls._original_allow_private = security.ALLOW_PRIVATE_TARGETS
        security.ALLOW_PRIVATE_TARGETS = True

        app = Flask(__name__)

        @app.route("/")
        def index():
            value = request.args.get("id", "1")
            try:
                import sqlite3
                con = sqlite3.connect(":memory:")
                con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
                con.execute("INSERT INTO users (name) VALUES ('alice')")
                rows = con.execute("SELECT * FROM users WHERE id = " + value).fetchall()
                return {"rows": rows}, 200
            except Exception as exc:  # pragma: no cover - deliberate trigger for detection tests
                return {"error": str(exc)}, 500

        cls.server = threading.Thread(
            target=lambda: app.run(port=8765, use_reloader=False, debug=False),
            daemon=True,
        )
        cls.server.start()

        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                requests.get("http://127.0.0.1:8765/?id=1", timeout=1)
                break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        security.ALLOW_PRIVATE_TARGETS = cls._original_allow_private

    def test_quick_detector_detects_vulnerable_param(self):
        result = scanner.test_sqli("http://127.0.0.1:8765/?id=1", "id")
        self.assertTrue(result["ok"])
        self.assertTrue(result["vulnerable"], result)

    def test_advanced_engine_detects_vulnerable_param(self):
        result = sql_engine.run_engine(
            "http://127.0.0.1:8765/?id=1",
            "id",
            "1",
            {"error": True, "boolean": False, "time": False, "union": False},
            {},
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["vulnerable"], result)

    def test_engine_rejects_unbounded_request_budget(self):
        with self.assertRaisesRegex(ValueError, "max_requests"):
            sql_engine.normalize_config({"max_requests": 100000})

    def test_engine_rejects_empty_technique_selection(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            sql_engine.normalize_enabled({"error": False})

    def test_html_discovery_keeps_only_same_origin_paths(self):
        html = '''<a href="/docs">Docs</a><form action="/search?q=x"></form>
                  <a href="https://other.example/admin">outside</a><a href="mailto:x@y.test">mail</a>'''
        self.assertEqual(
            scanner.discover_same_origin_paths("https://example.test/root", html),
            ["/docs", "/search?q=x"],
        )


if __name__ == "__main__":
    unittest.main()
