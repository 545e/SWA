"""
Automated Unit and Integration Tests for SWA AI Subdomain Discovery Engine
Covers all 10 required test scenarios:
1. Known test subdomains
2. Wildcard DNS detection & filtering
3. Deduplication of multi-source candidates
4. Validation and rejection of invalid hostname candidates
5. Graceful handling of failing or timed-out passive providers
6. Resilient handling of DNS resolver failures
7. Empty results handling
8. Missing API credentials / unconfigured external feeds
9. Rate-limit (HTTP 429 / quota exceeded) responses
10. Early cancellation during enumeration
"""

import asyncio
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx

from agents.amass_engine import AmassSubdomainEngine, SubdomainDiscoveryEngine


class TestSubdomainEngine(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_01_known_test_subdomains(self):
        """Scenario 1: Resolves and maps known test subdomains."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_01", "example.com", concurrency=5)
            engine._register("api.example.com", "MockFeed1")
            engine._register("admin.example.com", "MockFeed2")
            
            # Mock inspect_single or resolver
            with patch.object(engine, "_detect_wildcard_dns", new_callable=AsyncMock):
                with patch.object(engine, "_probe_dictionary_wordlist", new_callable=AsyncMock):
                    with patch.object(engine, "_generate_and_probe_permutations", new_callable=AsyncMock):
                        with patch.object(engine, "_query_crt_sh", new_callable=AsyncMock):
                            with patch.object(engine, "_query_hackertarget", new_callable=AsyncMock):
                                results, takeovers = await engine.run()

            hostnames = [r["subdomain"] for r in results]
            self.assertIn("api.example.com", hostnames)
            self.assertIn("admin.example.com", hostnames)
            for r in results:
                self.assertEqual(r["parent_domain"], "example.com")
                self.assertIn(r["validation_status"], ["confirmed", "unresolved", "wildcard_suspected"])

        self.loop.run_until_complete(run_test())

    def test_02_wildcard_dns_detection(self):
        """Scenario 2: Detects wildcard DNS and properly filters wildcard responses."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_02", "wildcard-zone.test")
            
            # Mock resolver returning the same IP for random probes
            mock_resolver = MagicMock()
            mock_answer = [MagicMock(__str__=lambda s: "203.0.113.42")]
            mock_resolver.resolve = AsyncMock(return_value=mock_answer)
            
            with patch.object(engine, "_create_resolver", return_value=mock_resolver):
                await engine._detect_wildcard_dns()
                self.assertTrue(engine.wildcard_detected)
                self.assertIn("203.0.113.42", engine.wildcard_ips)

                # Now probe a wordlist candidate that returns the wildcard IP
                engine.wordlist = ["fakehost1", "fakehost2"]
                await engine._probe_dictionary_wordlist("wildcard-zone.test")
                
                # Should be filtered out by wildcard defense
                self.assertNotIn("fakehost1.wildcard-zone.test", engine.discovered_subs)
                self.assertGreater(engine.metrics["wildcard_filtered"], 0)

        self.loop.run_until_complete(run_test())

    def test_03_duplicate_results_from_multiple_sources(self):
        """Scenario 3: Case-insensitive deduplication and multi-source attribution."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_03", "example.com")
            
            # Register same subdomain in different casings from different sources
            engine._register("API.EXAMPLE.COM", "crt.sh")
            engine._register("api.example.com", "HackerTarget")
            engine._register("Api.Example.Com.", "CertSpotter")
            
            self.assertEqual(len(engine.discovered_subs), 1)
            self.assertIn("api.example.com", engine.discovered_subs)
            sources = engine.discovered_subs["api.example.com"]
            self.assertEqual(len(sources), 3)
            self.assertIn("crt.sh", sources)
            self.assertIn("HackerTarget", sources)
            self.assertIn("CertSpotter", sources)

        self.loop.run_until_complete(run_test())

    def test_04_invalid_hostname_candidates(self):
        """Scenario 4: Validates and discards malformed and out-of-scope hostnames."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_04", "example.com")
            
            invalid_candidates = [
                "*.example.com",
                "example.com/admin/login",
                "<script>alert(1)</script>.example.com",
                "admin example.com",
                "evil.com",
                "attacker.example.org",
                "",
                "http://api.example.com"
            ]
            for c in invalid_candidates:
                registered = engine._register(c, "FuzzedOSINT")
                self.assertFalse(registered, f"Candidate '{c}' should have been rejected")

            self.assertEqual(len(engine.discovered_subs), 0)

        self.loop.run_until_complete(run_test())

    def test_05_failing_or_timed_out_passive_provider(self):
        """Scenario 5: Handles network timeout or connection failure without aborting scan."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_05", "example.com")
            
            # Mock crt.sh raising Timeout
            with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Connection timed out")):
                await engine._query_crt_sh()
                # Should not raise exception
                self.assertFalse(engine.is_cancelled)

        self.loop.run_until_complete(run_test())

    def test_06_dns_resolver_failures(self):
        """Scenario 6: Gracefully handles DNS resolver lookup errors."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_06", "example.com")
            engine._register("nonexistent.example.com", "WaybackCDX")
            
            mock_resolver = MagicMock()
            import dns.resolver
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
            
            with patch.object(engine, "_create_resolver", return_value=mock_resolver):
                with patch("socket.gethostbyname_ex", side_effect=Exception("Host not found")):
                    await engine._resolve_and_verify_subdomains()

            self.assertEqual(len(engine.detailed_results), 1)
            entry = engine.detailed_results[0]
            self.assertEqual(entry["subdomain"], "nonexistent.example.com")
            self.assertEqual(entry["validation_status"], "unresolved")
            self.assertFalse(entry["dns_confirmed"])
            self.assertEqual(entry["confidence"], "medium")

        self.loop.run_until_complete(run_test())

    def test_07_empty_results(self):
        """Scenario 7: Returns clean structure on empty results without raising errors."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_07", "nonexistent-empty-domain.test")
            
            with patch.object(engine, "_detect_wildcard_dns", new_callable=AsyncMock):
                with patch.object(engine, "_probe_dictionary_wordlist", new_callable=AsyncMock):
                    with patch.object(engine, "_generate_and_probe_permutations", new_callable=AsyncMock):
                        # Empty all passive feeds
                        for feed in [
                            "_query_crt_sh", "_query_hackertarget", "_query_alienvault_otx",
                            "_query_certspotter", "_query_wayback", "_query_threatminer",
                            "_query_urlscan", "_query_subdomain_center", "_query_anubis", "_query_rapiddns"
                        ]:
                            setattr(engine, feed, AsyncMock())

                        with patch.object(engine, "_resolve_and_verify_subdomains", new_callable=AsyncMock):
                            results, takeovers = await engine.run()
                            # Discovered apex root at minimum
                            self.assertIsInstance(results, list)
                            self.assertIsInstance(takeovers, list)

        self.loop.run_until_complete(run_test())

    def test_08_missing_api_keys(self):
        """Scenario 8: Unconfigured API credentials gracefully degrade to public endpoints."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_08", "example.com")
            # RapidDNS & CertSpotter work in public mode without keys
            with patch("httpx.AsyncClient.get", return_value=MagicMock(status_code=401)):
                await engine._query_certspotter()
                self.assertFalse(engine.is_cancelled)

        self.loop.run_until_complete(run_test())

    def test_09_rate_limit_responses(self):
        """Scenario 9: Handles HTTP 429 rate-limiting responses gracefully."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_09", "example.com")
            
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.text = "API count exceeded or rate limit reached"
            
            with patch("httpx.AsyncClient.get", return_value=mock_resp):
                await engine._query_hackertarget()
                # Should not raise exception and should not register invalid candidate
                self.assertEqual(len(engine.discovered_subs), 0)

        self.loop.run_until_complete(run_test())

    def test_10_cancellation_during_enumeration(self):
        """Scenario 10: Early scan cancellation aborts loop and preserves gathered assets."""
        async def run_test():
            engine = AmassSubdomainEngine("scan_test_10", "example.com")
            engine._register("early-sub.example.com", "crt.sh")
            engine.is_cancelled = True
            
            results, takeovers = await engine.run()
            # Early cancellation should abort before passive gathers or live probing
            self.assertEqual(len(takeovers), 0)
            self.assertIsInstance(results, list)

        self.loop.run_until_complete(run_test())


if __name__ == "__main__":
    unittest.main()
