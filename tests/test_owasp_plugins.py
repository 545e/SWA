"""
Unit tests for SWA AI OWASP Top 10 Security Plugins.
Validates plugin initialization, categories, signature regexes,
and targeted vulnerability detection logic.
"""

import re
import unittest
from plugins.owasp_plugins import (
    PluginA01_BrokenAccessControl,
    PluginA02_CryptographicFailures,
    PluginA03_Injection,
    PluginA04_InsecureDesign,
    PluginA05_SecurityMisconfiguration,
    PluginA06_VulnerableComponents,
    PluginA07_AuthFailures,
    PluginA08_IntegrityFailures,
    PluginA09_LoggingMonitoring,
    PluginA10_SSRF,
    SQL_ERRORS,
    STACK_TRACE_SIGS
)

class TestOwaspPlugins(unittest.TestCase):
    def test_all_10_plugins_instantiate(self):
        plugins = [
            PluginA01_BrokenAccessControl(),
            PluginA02_CryptographicFailures(),
            PluginA03_Injection(),
            PluginA04_InsecureDesign(),
            PluginA05_SecurityMisconfiguration(),
            PluginA06_VulnerableComponents(),
            PluginA07_AuthFailures(),
            PluginA08_IntegrityFailures(),
            PluginA09_LoggingMonitoring(),
            PluginA10_SSRF()
        ]

        self.assertEqual(len(plugins), 10)
        for p in plugins:
            self.assertTrue(p.enabled)
            self.assertIsNotNone(p.plugin_id)
            self.assertIsNotNone(p.owasp_category)
            self.assertTrue(p.plugin_id.startswith("owasp_a"), f"Plugin ID {p.plugin_id} should start with owasp_a")

    def test_sql_error_signatures(self):
        sample_error = "Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        matched = False
        for sig in SQL_ERRORS:
            if re.search(sig, sample_error, re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched, "Expected MySQL syntax error to be matched by SQL_ERRORS")

    def test_stack_trace_signatures(self):
        python_traceback = 'Traceback (most recent call last):\n  File "app.py", line 42, in index\nZeroDivisionError: division by zero'
        matched = False
        for sig in STACK_TRACE_SIGS:
            if re.search(sig, python_traceback):
                matched = True
                break
        self.assertTrue(matched, "Expected Python traceback to match STACK_TRACE_SIGS")

if __name__ == "__main__":
    unittest.main()
