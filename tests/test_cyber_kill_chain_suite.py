"""
SWA AI — Cyber Kill Chain Intelligence & Attack Lifecycle Analyzer Test Suite
Comprehensive unit, integration, database, and API tests for all seven stages:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control (C2)
7. Actions on Objectives
Includes correlation, threat intelligence, security controls matrix,
incident management, playbooks, AI analysis fallback, and multi-format reporting.
"""

import os
import unittest
import asyncio
from fastapi.testclient import TestClient

from web.server import app
from core.kill_chain.engine import kill_chain_engine, CyberKillChainEngine
from core.kill_chain.models import (
    KillChainStageEnum,
    SeverityEnum,
    ConfidenceLevelEnum,
    IncidentStatusEnum,
    StageStatusEnum,
    KillChainFinding,
    EvidenceItem,
)
from core.kill_chain.stages.reconnaissance import ReconnaissanceAnalyzer
from core.kill_chain.stages.weaponization import WeaponizationAnalyzer
from core.kill_chain.stages.delivery import DeliveryAnalyzer
from core.kill_chain.stages.exploitation import ExploitationAnalyzer
from core.kill_chain.stages.installation import InstallationAnalyzer
from core.kill_chain.stages.c2 import CommandAndControlAnalyzer
from core.kill_chain.stages.actions import ActionsOnObjectivesAnalyzer
from core.kill_chain.correlation import ThreatCorrelationEngine
from core.kill_chain.threat_intel import ThreatIntelligenceEngine
from core.kill_chain.controls_matrix import SecurityControlMatrix
from core.kill_chain.ai_analyzer import KillChainAIAnalyzer
from core.kill_chain.incident_manager import IncidentManager
from core.kill_chain.reporter import KillChainReportGenerator
from core.kill_chain.db import (
    save_finding,
    get_finding,
    list_findings,
    save_evidence,
    get_evidence,
    list_evidence,
    save_indicator,
    list_indicators,
    save_incident,
    get_incident,
    list_incidents,
)

client = TestClient(app)


class TestCyberKillChainAllSevenStages(unittest.TestCase):
    """Test all 7 stages independently with synthetic security telemetry."""

    def test_01_stage_reconnaissance(self):
        analyzer = ReconnaissanceAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "subdomains": ["api.10.0.1.5", "admin.10.0.1.5", "dev.10.0.1.5"],
            "open_ports": [80, 443, 22, 3306],
            "ssl": {"expired": True, "weak_ciphers": True},
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.RECONNAISSANCE)
        self.assertGreaterEqual(res.findings_count, 2)
        self.assertGreaterEqual(len(res.evidence), 2)
        self.assertIn(res.status, [StageStatusEnum.CRITICAL, StageStatusEnum.HIGH, StageStatusEnum.MEDIUM])
        # Verify MITRE tactic
        self.assertIn("TA0043", analyzer.mitre_tactic)

    def test_02_stage_weaponization(self):
        analyzer = WeaponizationAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "files": [
                {
                    "filename": "payload_stager.exe",
                    "hash": "44d88612fea8a8f36de82e1278abb02f",
                    "reputation_score": 95.0,
                    "threat_actor": "FIN7",
                    "malware_family": "Carbanak",
                    "yara_match": "APT.Weaponized.Stager",
                }
            ],
            "office_documents": [
                {"filename": "invoice.docm", "has_vba_macro": True}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.WEAPONIZATION)
        self.assertGreaterEqual(res.findings_count, 2)
        self.assertTrue(any(f.mitre_technique_id == "T1587.001" for f in res.findings))
        self.assertIn("TA0042", analyzer.mitre_tactic)

    def test_03_stage_delivery(self):
        analyzer = DeliveryAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "emails": [
                {
                    "from": "spoofed@external-attacker.com",
                    "to": "victim@10.0.1.5",
                    "subject": "Direct Deposit Verification Required",
                    "spf": "FAIL",
                    "dmarc": "FAIL",
                    "attachments": ["update.iso"],
                }
            ],
            "urls": [
                {"url": "https://malicious-c2-cdn.xyz/dropper.sh", "status_code": 200, "reputation_score": 90.0, "is_malicious": True}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.DELIVERY)
        self.assertGreaterEqual(res.findings_count, 2)
        self.assertIn("TA0001", analyzer.mitre_tactic)

    def test_04_stage_exploitation(self):
        analyzer = ExploitationAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "findings": [
                {
                    "title": "SQL Injection in Authentication Route",
                    "category": "sqli",
                    "cve": "CVE-2023-34362",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "endpoint": "/api/v1/auth/login",
                    "evidence": "Payload 1' OR '1'='1 caused SQL syntax disclosure.",
                    "tool_source": "SWA OWASP Scanner",
                }
            ],
            "waf_alerts": [
                {"rule_id": "WAF-941100", "client_ip": "203.0.113.42", "payload": "UNION SELECT"}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.EXPLOITATION)
        self.assertEqual(res.status, StageStatusEnum.CRITICAL)
        self.assertGreaterEqual(res.critical_count, 1)
        self.assertIn("TA0002", analyzer.mitre_tactic)

    def test_05_stage_installation(self):
        analyzer = InstallationAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "processes": [
                {
                    "name": "powershell.exe",
                    "pid": 3312,
                    "parent_process": "nginx.exe",
                    "cmdline": "powershell.exe -enc SQBFAFgA",
                }
            ],
            "persistence": [
                {"name": "BackdoorRun", "path": "HKCU\\Run", "target": "C:\\temp\\backdoor.exe"}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.INSTALLATION)
        self.assertGreaterEqual(res.findings_count, 2)
        self.assertIn("TA0003", analyzer.mitre_tactic)

    def test_06_stage_c2(self):
        analyzer = CommandAndControlAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "network_flows": [
                {
                    "src_ip": "10.0.1.5",
                    "dst_ip": "198.51.100.23",
                    "dst_port": 8443,
                    "protocol": "TCP",
                    "count": 50,
                    "interval_seconds": 30,
                    "jitter_pct": 2,
                    "reputation_score": 98.0,
                    "is_c2": True,
                }
            ],
            "dns_tunneling": [
                {"query": "data.exfil.secret.net", "entropy": 4.8, "type": "TXT"}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.COMMAND_AND_CONTROL)
        self.assertEqual(res.status, StageStatusEnum.CRITICAL)
        self.assertGreaterEqual(res.findings_count, 2)
        self.assertIn("TA0011", analyzer.mitre_tactic)

    def test_07_stage_actions_on_objectives(self):
        analyzer = ActionsOnObjectivesAnalyzer()
        telemetry = {
            "target": "10.0.1.5",
            "exfiltration": [
                {
                    "bytes_transferred": 25_000_000,
                    "destination": "https://s3.external-drop.com",
                    "channel": "HTTPS POST",
                    "files": ["customer_records.db"],
                    "is_exfil": True,
                }
            ],
            "ransomware": [
                {"type": "MASS_ENCRYPTION", "details": "Shadow copies purged", "path": "D:\\Shares"}
            ],
            "lateral_movement": [
                {"protocol": "SMB", "user": "SYSTEM", "target_host": "10.0.1.20"}
            ],
        }
        res = analyzer.analyze(telemetry)
        self.assertEqual(res.stage, KillChainStageEnum.ACTIONS_ON_OBJECTIVES)
        self.assertEqual(res.status, StageStatusEnum.CRITICAL)
        self.assertGreaterEqual(res.findings_count, 3)
        self.assertIn("TA0040", analyzer.mitre_tactic)


class TestCorrelationAndScoringMethodology(unittest.TestCase):
    """Test risk calculation, confidence calculation, and multi-stage correlation."""

    def test_independent_risk_and_confidence_calculations(self):
        analyzer = ReconnaissanceAnalyzer()

        # Risk calculation
        risk_high = analyzer.calculate_risk(impact_weight=10.0, likelihood=0.9, asset_criticality=1.5, exposure=1.5)
        risk_low = analyzer.calculate_risk(impact_weight=2.0, likelihood=0.2, asset_criticality=0.8, exposure=0.8)
        self.assertGreater(risk_high, risk_low)
        self.assertLessEqual(risk_high, 100.0)
        self.assertGreaterEqual(risk_low, 0.0)

        # Confidence calculation
        conf_level_high, conf_score_high = analyzer.calculate_confidence(
            evidence_quality=1.0, source_reliability=1.0, corroboration_count=3, completeness=1.0
        )
        conf_level_low, conf_score_low = analyzer.calculate_confidence(
            evidence_quality=0.4, source_reliability=0.5, corroboration_count=0, completeness=0.5
        )
        self.assertEqual(conf_level_high, ConfidenceLevelEnum.CONFIRMED)
        self.assertGreater(conf_score_high, conf_score_low)

    def test_multi_stage_correlation_engine(self):
        correlation_engine = ThreatCorrelationEngine()

        f1 = KillChainFinding(
            id="find_test_1",
            title="Subdomain Exposure",
            stage=KillChainStageEnum.RECONNAISSANCE,
            severity=SeverityEnum.MEDIUM,
            affected_host="10.0.5.1",
            risk_score=45.0,
            confidence_score=80.0,
        )
        f2 = KillChainFinding(
            id="find_test_2",
            title="SQLi in App",
            stage=KillChainStageEnum.EXPLOITATION,
            severity=SeverityEnum.CRITICAL,
            affected_host="10.0.5.1",
            risk_score=95.0,
            confidence_score=90.0,
        )
        f3 = KillChainFinding(
            id="find_test_3",
            title="C2 Beaconing Flow",
            stage=KillChainStageEnum.COMMAND_AND_CONTROL,
            severity=SeverityEnum.HIGH,
            affected_host="10.0.5.1",
            risk_score=88.0,
            confidence_score=85.0,
        )

        paths = correlation_engine.correlate(
            findings=[f1, f2, f3],
            evidence=[],
            indicators=[],
            target_asset="10.0.5.1",
        )

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path.target_asset, "10.0.5.1")
        self.assertEqual(len(path.stages_detected), 3)
        self.assertEqual(path.root_cause_stage, KillChainStageEnum.RECONNAISSANCE)
        self.assertEqual(path.highest_severity, SeverityEnum.CRITICAL)
        self.assertGreater(path.composite_risk_score, 90.0)


class TestThreatIntelligenceAndAIAnalyzer(unittest.TestCase):
    """Test threat intel lookups, caching, and AI analysis fallback."""

    def test_threat_intelligence_caching_and_lookups(self):
        engine = ThreatIntelligenceEngine()

        # CVE Lookup
        res_cve = engine.lookup_indicator("CVE", "CVE-2023-34362")
        self.assertTrue(res_cve["is_malicious"])
        self.assertGreaterEqual(res_cve["reputation_score"], 90.0)
        self.assertIn("MOVEit", res_cve.get("details", {}).get("product", "") or res_cve.get("malware_family", ""))

        # Cached call
        res_cve_cached = engine.lookup_indicator("CVE", "CVE-2023-34362")
        self.assertEqual(res_cve, res_cve_cached)

        # IP Lookup
        res_ip = engine.lookup_indicator("IP", "198.51.100.23")
        self.assertTrue(res_ip["is_malicious"])

        # Provider health check
        health = engine.get_provider_health()
        self.assertGreaterEqual(len(health), 4)

    def test_ai_threat_analysis_seven_questions_fallback(self):
        ai_analyzer = KillChainAIAnalyzer()
        f = KillChainFinding(
            id="test_ai_f1",
            title="Unauthorized System Token Impersonation",
            stage=KillChainStageEnum.ACTIONS_ON_OBJECTIVES,
            severity=SeverityEnum.CRITICAL,
            affected_host="10.0.0.2",
            affected_endpoint="/var/run/secrets",
            risk_score=96.0,
            confidence_score=90.0,
            confidence_level=ConfidenceLevelEnum.CONFIRMED,
            description="Process escalated privileges using token theft.",
            evidence="Token handle duplicated from LSASS PID 640.",
            detection_source="SWA Forensics / EDR",
            remediation="Enforce Credential Guard and isolate host.",
        )

        res = asyncio.run(ai_analyzer.analyze_event(f))
        self.assertIn("answers", res)
        ans = res["answers"]

        # Verify all 7 SOC questions are addressed
        self.assertIn("1_what_happened", ans)
        self.assertIn("2_stage_involved", ans)
        self.assertIn("3_supporting_evidence", ans)
        self.assertIn("4_affected_assets", ans)
        self.assertIn("5_confidence_assessment", ans)
        self.assertIn("6_potential_impact", ans)
        self.assertIn("7_analyst_next_steps", ans)

        # Verify confidence strictly categorized
        self.assertEqual(ans["5_confidence_assessment"]["level"], "CONFIRMED")
        self.assertIn(res["mode"], ["DETERMINISTIC_ENGINE", "AI_AUGMENTED"])


class TestSecurityControlsAndPlaybooks(unittest.TestCase):
    """Test 7x5 matrix calculation and defensive response playbooks."""

    def test_security_controls_coverage_matrix(self):
        matrix_engine = SecurityControlMatrix()
        cov = matrix_engine.get_matrix()

        self.assertIn("overall_coverage_pct", cov)
        self.assertIn("matrix", cov)
        self.assertIn("stage_coverage", cov)
        self.assertGreater(cov["overall_coverage_pct"], 0.0)

        # Verify all 7 stages present
        for stg in KillChainStageEnum:
            self.assertIn(stg.value, cov["matrix"])

    def test_incident_management_and_stage_playbooks(self):
        mgr = IncidentManager()

        # Playbook lookup
        pb = mgr.get_playbook_for_stage("c2")
        self.assertIn("Channel Severance", pb["phase"])
        self.assertEqual(len(pb["steps"]), 5)

        # Create incident
        inc = mgr.create_incident(
            title="Test Multi-Stage Incident",
            severity="HIGH",
            assigned_analyst="SecOps Lead",
            affected_assets=["10.0.1.50"],
            description="Adversary breach campaign",
            stages_involved=["reconnaissance", "delivery"],
            linked_findings=["f1", "f2"],
        )
        self.assertEqual(inc.status, IncidentStatusEnum.NEW)

        # Status transition
        updated = mgr.update_status(inc.id, "INVESTIGATING", notes="Analyst reviewing memory dumps.")
        self.assertEqual(updated.status, IncidentStatusEnum.INVESTIGATING)
        self.assertGreaterEqual(len(updated.audit_trail), 2)


class TestReportingEngineExports(unittest.TestCase):
    """Test generating report deliverables in all 5 formats."""

    def test_multi_format_report_generation(self):
        reporter = KillChainReportGenerator()

        finding = KillChainFinding(
            id="f_rep_1",
            title="Publicly Accessible Redis Datastore",
            stage=KillChainStageEnum.RECONNAISSANCE,
            severity=SeverityEnum.HIGH,
            affected_host="10.0.1.5",
            affected_endpoint="6379",
            risk_score=75.0,
            confidence_score=95.0,
            confidence_level=ConfidenceLevelEnum.CONFIRMED,
            description="Redis listening on 0.0.0.0 without authentication.",
            evidence="INFO command returned redis_version: 7.0.5",
            detection_source="SWA Port Scanner",
            remediation="Bind Redis strictly to 127.0.0.1 and set requirepass.",
        )

        matrix = SecurityControlMatrix().get_matrix()
        pack = reporter.generate_report(
            title="Unit Test Kill Chain Assessment",
            findings=[finding],
            evidence=[],
            attack_paths=[],
            coverage_data=matrix,
            export_formats=["html", "json", "csv", "markdown", "pdf"],
        )

        files = pack.get("files", {})
        self.assertIn("html", files)
        self.assertIn("json", files)
        self.assertIn("csv", files)
        self.assertIn("markdown", files)
        self.assertIn("pdf", files)

        for fmt, path in files.items():
            self.assertTrue(os.path.exists(path), f"File {path} ({fmt}) was not generated!")
            self.assertGreater(os.path.getsize(path), 0, f"File {path} ({fmt}) is empty!")


class TestKillChainAPIEndpoints(unittest.TestCase):
    """Test all REST API endpoints for the Cyber Kill Chain module."""

    def test_api_health_and_overview(self):
        resp = client.get("/api/kill-chain/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("status"), "HEALTHY")

        resp2 = client.get("/api/kill-chain/overview")
        self.assertEqual(resp2.status_code, 200)
        self.assertIn("overall_risk_score", resp2.json())

    def test_api_stages_and_stage_detail(self):
        resp = client.get("/api/kill-chain/stages")
        self.assertEqual(resp.status_code, 200)
        stages = resp.json()
        self.assertEqual(len(stages), 7)

        resp2 = client.get("/api/kill-chain/stages/c2")
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json().get("stage"), "c2")

    def test_api_analyze_and_correlate(self):
        resp = client.post("/api/kill-chain/analyze", json={
            "target": "10.0.2.1",
            "open_ports": [80, 443],
            "subdomains": ["api.10.0.2.1"],
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("status"), "COMPLETED")

        resp_corr = client.post("/api/kill-chain/correlate")
        self.assertEqual(resp_corr.status_code, 200)
        self.assertIsInstance(resp_corr.json(), list)

    def test_api_evidence_and_indicators(self):
        resp = client.post("/api/kill-chain/evidence", json={
            "stage": "reconnaissance",
            "artifact_type": "DNS_A_RECORD",
            "raw_data": "Host resolves to 10.0.2.1",
            "affected_asset": "10.0.2.1",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("id", resp.json())

        resp2 = client.get("/api/kill-chain/evidence")
        self.assertEqual(resp2.status_code, 200)
        self.assertIsInstance(resp2.json(), list)

        resp3 = client.get("/api/kill-chain/intelligence")
        self.assertEqual(resp3.status_code, 200)
        self.assertIn("providers", resp3.json())

    def test_api_incidents_lifecycle(self):
        resp = client.post("/api/kill-chain/incidents", json={
            "title": "API Test Incident",
            "severity": "HIGH",
            "assigned_analyst": "SOC Lead",
            "affected_assets": ["10.0.2.1"],
            "description": "Integration test incident",
            "stages_involved": ["exploitation"],
            "linked_findings": [],
        })
        self.assertEqual(resp.status_code, 200)
        inc_id = resp.json()["id"]

        resp_get = client.get(f"/api/kill-chain/incidents/{inc_id}")
        self.assertEqual(resp_get.status_code, 200)

        resp_patch = client.patch(f"/api/kill-chain/incidents/{inc_id}", json={
            "status": "CONTAINED",
            "notes": "Firewall rules applied."
        })
        self.assertEqual(resp_patch.status_code, 200)
        self.assertEqual(resp_patch.json()["status"], "CONTAINED")

    def test_api_reports_lifecycle(self):
        resp = client.post("/api/kill-chain/reports/generate", json={
            "title": "Automated API Test Report",
            "formats": ["html", "json", "csv", "markdown"],
        })
        self.assertEqual(resp.status_code, 200)
        rep_id = resp.json()["report_id"]

        resp_dl = client.get(f"/api/kill-chain/reports/{rep_id}/download?format=html")
        self.assertEqual(resp_dl.status_code, 200)
        self.assertIn("text/html", resp_dl.headers.get("content-type", ""))


if __name__ == "__main__":
    unittest.main()
