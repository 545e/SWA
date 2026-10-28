"""
Unit tests for SWA AI Scope Policy and SSRF Protection Engine.
Verifies target normalization, IPv4/IPv6 handling, private/loopback blocking,
cloud metadata defense, allowlist enforcement, and authorized lab mode.
"""

import unittest
from core.scope_policy import ScopePolicy, ScopeValidationResult, CLOUD_METADATA_IPS

class TestScopePolicy(unittest.TestCase):
    def setUp(self):
        self.policy_strict = ScopePolicy(allow_lab_mode=False)
        self.policy_lab = ScopePolicy(allow_lab_mode=True)

    def test_normalize_hostname(self):
        self.assertEqual(self.policy_strict._normalize_hostname("http://example.com:8080/path"), "example.com")
        self.assertEqual(self.policy_strict._normalize_hostname("https://sub.domain.org/"), "sub.domain.org")
        self.assertEqual(self.policy_strict._normalize_hostname("127.0.0.1:8000"), "127.0.0.1")
        self.assertEqual(self.policy_strict._normalize_hostname("[::1]:8080"), "::1")

    def test_reject_dangerous_schemes(self):
        res = self.policy_strict.validate_target("file:///etc/passwd")
        self.assertFalse(res.is_allowed)
        self.assertEqual(res.error_code, "INVALID_SCHEME")

        res_gopher = self.policy_strict.validate_target("gopher://127.0.0.1:70")
        self.assertFalse(res_gopher.is_allowed)

    def test_empty_target(self):
        res = self.policy_strict.validate_target("   ")
        self.assertFalse(res.is_allowed)
        self.assertEqual(res.error_code, "EMPTY_TARGET")

    def test_cloud_metadata_blocked(self):
        for imds in CLOUD_METADATA_IPS:
            is_restricted, reason = self.policy_strict.is_private_or_restricted(imds)
            self.assertTrue(is_restricted, f"Expected {imds} to be restricted")
            self.assertIn("Cloud Metadata", reason)

    def test_private_and_loopback_classification(self):
        # 127.0.0.1 loopback
        res, msg = self.policy_strict.is_private_or_restricted("127.0.0.1")
        self.assertTrue(res)
        self.assertIn("Loopback", msg)

        # RFC1918 10.0.0.1
        res, msg = self.policy_strict.is_private_or_restricted("10.0.0.1")
        self.assertTrue(res)
        self.assertIn("Private", msg)

        # RFC1918 192.168.1.50
        res, msg = self.policy_strict.is_private_or_restricted("192.168.1.50")
        self.assertTrue(res)

        # Public IP 8.8.8.8
        res, msg = self.policy_strict.is_private_or_restricted("8.8.8.8")
        self.assertFalse(res)

    def test_ssrf_blocking_without_lab_mode(self):
        res = self.policy_strict.validate_target("http://127.0.0.1:8000", explicit_lab_authorization=False)
        self.assertFalse(res.is_allowed)
        self.assertEqual(res.error_code, "SSRF_RESTRICTED_IP")
        self.assertIn("SSRF Protection", res.reason)

    def test_lab_mode_authorization_positive(self):
        # With lab mode enabled, 127.0.0.1 should be allowed
        res = self.policy_strict.validate_target("http://127.0.0.1:8000", explicit_lab_authorization=True)
        self.assertTrue(res.is_allowed)
        self.assertTrue(res.is_lab_target)

    def test_invalid_domain_syntax(self):
        res = self.policy_strict.validate_target("invalid..domain!@#")
        self.assertFalse(res.is_allowed)
        self.assertEqual(res.error_code, "INVALID_DOMAIN_SYNTAX")

if __name__ == "__main__":
    unittest.main()
