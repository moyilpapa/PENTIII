"""
Regression tests for security.py's two-layer SSRF guard.

The bug these tests guard against: assert_safe_target() only validated the
URL the caller supplied, once, before a scan started. Anything that reached
requests.get()/post() by a different path -- a hostname whose DNS answer
changed between the check and the fetch (rebinding), or a 3xx redirect to
an internal address -- sailed through unchecked. install_connection_guard()
fixes this by re-validating at the actual socket-connect layer, which is
the one place neither DNS games nor redirects can route around.
"""

import unittest

import requests

import security


class TestConnectionLevelGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        security.install_connection_guard()
        # Force strict mode for these tests regardless of the process
        # environment or of what other test modules set -- ALLOW_PRIVATE_TARGETS
        # is read as a live module attribute at call time (not frozen at
        # import), so tests can override it directly like this.
        cls._original_allow_private = security.ALLOW_PRIVATE_TARGETS
        security.ALLOW_PRIVATE_TARGETS = False

    @classmethod
    def tearDownClass(cls):
        security.ALLOW_PRIVATE_TARGETS = cls._original_allow_private

    def test_direct_loopback_connection_is_blocked(self):
        """Simulates the bypass scenario directly: a connection reaches a
        private address WITHOUT going through assert_safe_target() first
        (this is what a DNS-rebind or a followed redirect looks like from
        the guard's point of view -- it only ever sees the final address)."""
        with self.assertRaises(requests.exceptions.ConnectionError) as ctx:
            requests.get("http://127.0.0.1:1/", timeout=2)
        self.assertIn("connection-level SSRF guard", str(ctx.exception))

    def test_link_local_metadata_address_is_blocked(self):
        with self.assertRaises(requests.exceptions.ConnectionError) as ctx:
            requests.get("http://169.254.169.254/latest/meta-data/", timeout=2)
        self.assertIn("connection-level SSRF guard", str(ctx.exception))

    def test_url_level_check_still_rejects_private_targets_up_front(self):
        """assert_safe_target() (the fast, friendly, request-time check)
        must keep working too -- the connection-level guard is a backstop,
        not a replacement."""
        with self.assertRaises(security.UnsafeTargetError):
            security.assert_safe_target("http://127.0.0.1:8765/")

    def test_public_hostname_is_not_blocked_by_the_guard(self):
        """A real public address must still be allowed to attempt a
        connection -- the guard must not over-block. (Network failures for
        other reasons, e.g. a sandboxed test runner with no egress, are not
        what this test checks; only that the block reason is never ours.)"""
        try:
            requests.get("http://example.com", timeout=5)
        except requests.exceptions.ConnectionError as e:
            self.assertNotIn("connection-level SSRF guard", str(e))


if __name__ == "__main__":
    unittest.main()
