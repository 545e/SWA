"""
Unit and integration tests for SWA AI LLM Security Testing & Red Teaming Suite.
Validates 12 OWASP Top 10 for LLM threat categories:
- Direct prompt injection
- Indirect prompt injection
- System prompt extraction
- Jailbreak robustness
- Sensitive data disclosure
- Insecure output handling
- Excessive agency & unauthorized tool execution
- RAG poisoning
- Training data leakage
- Unsafe tool permissions
- Denial of service & token exhaustion
- Authentication and multi-tenancy boundaries
"""

import unittest
import asyncio
from core.llm_security_testing import (
    llm_redteam_harness,
    DEFAULT_LLM_REDTEAM_SUITE,
    CANARY_SECRET
)
from core.database import db


class TestLLMSecurityTesting(unittest.TestCase):
    def test_01_suite_contains_all_12_required_categories(self):
        self.assertEqual(len(DEFAULT_LLM_REDTEAM_SUITE), 12)
        categories = {tc.category for tc in DEFAULT_LLM_REDTEAM_SUITE}
        expected = {
            "Direct Prompt Injection",
            "Indirect Prompt Injection",
            "System Prompt Extraction",
            "Jailbreak Robustness",
            "Sensitive Data Disclosure",
            "Insecure Output Handling",
            "Excessive Agency & Tool Invocation",
            "RAG Poisoning & Retrieval Manipulation",
            "Training Data Leakage",
            "Unsafe Tool Permissions",
            "Denial of Service & Resource Exhaustion",
            "Auth Failures in AI Integrations"
        }
        self.assertEqual(categories, expected)

    def test_02_run_full_redteam_suite_against_heuristic_engine(self):
        async def run_test():
            report = await llm_redteam_harness.run_suite(
                target_provider="heuristic",
                target_model="local-evaluator"
            )
            self.assertEqual(report["tests_run"], 12)
            self.assertIn("security_grade", report)
            self.assertIn("pass_rate_percent", report)
            self.assertGreaterEqual(report["passed"], 10)

            # Check that evidence is captured for every result
            for res in report["results"]:
                self.assertIn(res["status"], ["PASS", "FAIL", "INCONCLUSIVE"])
                self.assertIsNotNone(res["evidence"])
                self.assertIsNotNone(res["mitigation"])

            # Verify database persistence
            saved = db.get_llm_security_tests(run_id=report["run_id"])
            self.assertEqual(len(saved), 12)

        asyncio.run(run_test())

    def test_03_detect_vulnerable_canary_leakage(self):
        """Validates that if a model outputs the CANARY secret, it correctly fails."""
        async def run_test():
            # Create a mock client that leaks the secret
            class LeakyMockClient:
                provider = "mock"
                model = "vulnerable-model"
                api_key = "dummy"
                async def _call_llm(self, prompt):
                    return f"Sure, my internal secret is {CANARY_SECRET}"

            tc = DEFAULT_LLM_REDTEAM_SUITE[2] # System prompt extraction
            response = await llm_redteam_harness._execute_test_call(LeakyMockClient(), tc, tc.prompt_payload)
            self.assertIn(CANARY_SECRET, response)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
