"""
Route-level tests for app.py and the auth middleware in security.py.

Before this file, the only tests in the suite covered SQLi-detection logic
and the SSRF guard -- the API surface itself (auth enforcement, target/
finding CRUD, report generation, and the SSRF/sqlmap gates as seen through
the actual HTTP routes) had zero coverage. These use Flask's test client
against the real `app` object, with an isolated temp SQLite DB so this
suite doesn't touch a real security_tester.db or interfere with other test
modules' data.

security.API_KEYS / ALLOW_NO_AUTH / ALLOW_PRIVATE_TARGETS and app.ENABLE_SQLMAP
are all read as live module attributes at request time (not frozen at
import), so tests can flip them directly per-test instead of needing
separate server processes per config.
"""

import os
import tempfile
import unittest

import app as app_module
import database
import security


class TestAppRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls._original_db_path = database.DB_PATH
        database.DB_PATH = cls.db_path
        database.init_db()

        cls.client = app_module.app.test_client()

        cls._orig_api_keys = list(security.API_KEYS)
        cls._orig_allow_no_auth = security.ALLOW_NO_AUTH
        cls._orig_allow_private = security.ALLOW_PRIVATE_TARGETS
        cls._orig_enable_sqlmap = app_module.ENABLE_SQLMAP

    @classmethod
    def tearDownClass(cls):
        security.API_KEYS = cls._orig_api_keys
        security.ALLOW_NO_AUTH = cls._orig_allow_no_auth
        security.ALLOW_PRIVATE_TARGETS = cls._orig_allow_private
        app_module.ENABLE_SQLMAP = cls._orig_enable_sqlmap
        database.DB_PATH = cls._original_db_path
        os.remove(cls.db_path)
        # Importing app.py runs database.init_db() against the *default*
        # path as a side effect at import time, before we swap DB_PATH
        # above -- clean up that incidental file so running this suite
        # doesn't leave a stray security_tester.db behind.
        try:
            os.remove(cls._original_db_path)
        except OSError:
            pass

    def setUp(self):
        # Baseline for each test: auth required with a known key, private
        # targets allowed (most tests aren't about the SSRF guard itself --
        # that gets its own dedicated test, and its own explicit override).
        security.API_KEYS = ["test-key-123"]
        security.ALLOW_NO_AUTH = False
        security.ALLOW_PRIVATE_TARGETS = True
        app_module.ENABLE_SQLMAP = False

    def auth_headers(self, key=None):
        return {"X-API-Key": security.API_KEYS[0] if key is None else key}

    # ---- Public routes stay open regardless of auth state ----

    def test_health_is_public_without_key(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])

    def test_root_is_public_without_key(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    # ---- Auth enforcement ----

    def test_missing_api_key_config_fails_closed(self):
        security.API_KEYS = []
        resp = self.client.get("/api/targets")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("hint", resp.get_json())

    def test_request_without_key_is_rejected(self):
        resp = self.client.get("/api/targets")
        self.assertEqual(resp.status_code, 401)

    def test_request_with_wrong_key_is_rejected(self):
        resp = self.client.get("/api/targets", headers=self.auth_headers("wrong-key"))
        self.assertEqual(resp.status_code, 401)

    def test_request_with_correct_key_via_x_api_key_header_succeeds(self):
        resp = self.client.get("/api/targets", headers=self.auth_headers())
        self.assertEqual(resp.status_code, 200)

    def test_request_with_correct_key_via_bearer_header_succeeds(self):
        resp = self.client.get(
            "/api/targets", headers={"Authorization": f"Bearer {security.API_KEYS[0]}"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_allow_no_auth_bypasses_key_check(self):
        security.ALLOW_NO_AUTH = True
        resp = self.client.get("/api/targets")
        self.assertEqual(resp.status_code, 200)

    # ---- Target + finding + report lifecycle, through the real routes ----

    def test_target_and_finding_lifecycle(self):
        h = self.auth_headers()

        created = self.client.post(
            "/api/targets", json={"name": "t1", "url": "http://127.0.0.1:1/"}, headers=h
        )
        self.assertEqual(created.status_code, 201)
        target_id = created.get_json()["id"]

        listed = self.client.get("/api/targets", headers=h)
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(t["id"] == target_id for t in listed.get_json()))

        finding = self.client.post(
            "/api/findings",
            json={"target_id": target_id, "name": "Test finding", "severity": "Low"},
            headers=h,
        )
        self.assertEqual(finding.status_code, 201)
        finding_id = finding.get_json()["id"]

        patched = self.client.patch(
            f"/api/findings/{finding_id}", json={"severity": "High"}, headers=h
        )
        self.assertEqual(patched.status_code, 200)
        self.assertEqual(patched.get_json()["severity"], "High")

        report = self.client.get(f"/api/report/{target_id}", headers=h)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.get_json()["severity_counts"]["High"], 1)

        self.assertEqual(
            self.client.delete(f"/api/findings/{finding_id}", headers=h).status_code, 200
        )
        self.assertEqual(
            self.client.delete(f"/api/targets/{target_id}", headers=h).status_code, 200
        )

    def test_unknown_target_returns_404(self):
        resp = self.client.get("/api/targets/999999", headers=self.auth_headers())
        self.assertEqual(resp.status_code, 404)

    def test_create_target_requires_name_and_url(self):
        resp = self.client.post("/api/targets", json={"name": "no-url"}, headers=self.auth_headers())
        self.assertEqual(resp.status_code, 400)

    # ---- SSRF guard enforced at the route level, not just in security.py ----

    def test_scan_route_rejects_private_target_by_default(self):
        security.ALLOW_PRIVATE_TARGETS = False
        h = self.auth_headers()
        created = self.client.post(
            "/api/targets", json={"name": "internal", "url": "http://169.254.169.254/"}, headers=h
        )
        target_id = created.get_json()["id"]

        resp = self.client.post(f"/api/scan/http/{target_id}", headers=h)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "unsafe target")

    # ---- sqlmap route stays off unless explicitly enabled ----

    def test_sqlmap_route_disabled_by_default(self):
        h = self.auth_headers()
        created = self.client.post(
            "/api/targets", json={"name": "t2", "url": "http://example.com/"}, headers=h
        )
        target_id = created.get_json()["id"]

        resp = self.client.post(
            f"/api/scan/sqli-sqlmap/{target_id}", json={"parameter": "id"}, headers=h
        )
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
