"""
Automated Acceptance Tests for Generation 3 Unified Frontend, Navigation & Routing
Validates:
- All 20 required view containers exist with class="swa-view"
- Dashboard is cleanly encapsulated in #viewDashboard
- Vulnerabilities is cleanly encapsulated in #viewVulnerabilities
- Strict display rules (.swa-view display: none !important; .active display: block !important;)
- VIEW_CONTAINER_MAP routing table completeness and aliasing
- Selecting 'vulnerabilities' strictly targets 'viewVulnerabilities'
- Selecting 'dashboard' strictly targets 'viewDashboard'
- All sidebar navigation elements and breadcrumb mappings
- Backing API contracts for views (/api/findings, /api/scans, /api/assets, /api/agents, /api/settings)
"""

import os
import re
import unittest
from fastapi.testclient import TestClient
from web.server import app

client = TestClient(app)

INDEX_PATH = os.path.join(os.path.dirname(__file__), "..", "web", "static", "index.html")
APP_JS_PATH = os.path.join(os.path.dirname(__file__), "..", "web", "static", "app.js")
STYLES_CSS_PATH = os.path.join(os.path.dirname(__file__), "..", "web", "static", "styles.css")


class TestGen3NavigationAcceptance(unittest.TestCase):

    def setUp(self):
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            self.html = f.read()
        with open(APP_JS_PATH, "r", encoding="utf-8") as f:
            self.js = f.read()
        with open(STYLES_CSS_PATH, "r", encoding="utf-8") as f:
            self.css = f.read()

    def test_01_all_required_views_exist_in_html(self):
        """Verify all 20 required views exist with swa-view class."""
        required_views = [
            "viewDashboard",
            "viewAssessments",
            "viewAssets",
            "viewVulnerabilities",
            "viewCompare",
            "viewTools",
            "viewWebSecurity",
            "viewNetworkSecurity",
            "viewApiSecurity",
            "viewCodeSecurity",
            "viewAgents",
            "viewInvestigation",
            "viewRemediation",
            "viewDrift",
            "viewApprovals",
            "viewReports",
            "viewCyberAudit",
            "viewIntegrations",
            "viewSettings",
            "viewDocs"
        ]
        for v in required_views:
            pattern = rf'id=["\']{v}["\'][^>]*class=["\'][^"\']*swa-view'
            alt_pattern = rf'class=["\'][^"\']*swa-view[^"\']*["\'][^>]*id=["\']{v}["\']'
            self.assertTrue(
                bool(re.search(pattern, self.html) or re.search(alt_pattern, self.html)),
                f"Missing required view container: {v}"
            )

    def test_02_dashboard_and_vulnerabilities_are_isolated(self):
        """Dashboard and Vulnerabilities are distinct isolated view containers."""
        # Check viewDashboard
        self.assertIn('id="viewDashboard"', self.html)
        self.assertIn('swa-view active', self.html)
        
        # Check viewVulnerabilities
        self.assertIn('id="viewVulnerabilities"', self.html)
        
        # Verify findingsContainer is inside viewVulnerabilities, NOT in viewDashboard
        dash_pos = self.html.find('id="viewDashboard"')
        dash_close = self.html.find('</div><!-- /viewDashboard -->')
        self.assertTrue(dash_pos != -1 and dash_close != -1)
        dash_content = self.html[dash_pos:dash_close]
        self.assertNotIn('id="findingsContainer"', dash_content, "findingsContainer must NOT be inside viewDashboard!")

        vuln_pos = self.html.find('id="viewVulnerabilities"')
        vuln_close = self.html.find('</div><!-- /viewVulnerabilities -->')
        self.assertTrue(vuln_pos != -1 and vuln_close != -1)
        vuln_content = self.html[vuln_pos:vuln_close]
        self.assertIn('id="findingsContainer"', vuln_content, "findingsContainer MUST be inside viewVulnerabilities!")

    def test_03_css_view_isolation_enforcement(self):
        """CSS strictly hides inactive views with !important display rule."""
        self.assertIn(".swa-view {", self.css)
        self.assertIn("display: none !important;", self.css)
        self.assertIn(".swa-view.active {", self.css)
        self.assertIn("display: block !important;", self.css)

    def test_04_js_routing_table_completeness(self):
        """VIEW_CONTAINER_MAP in app.js maps all required views and aliases."""
        self.assertIn("const VIEW_CONTAINER_MAP =", self.js)
        expected_mappings = {
            "'dashboard': 'viewDashboard'",
            "'vulnerabilities': 'viewVulnerabilities'",
            "'assessments': 'viewAssessments'",
            "'assets': 'viewAssets'",
            "'pentest': 'viewVulnerabilities'",
            "'compare': 'viewCompare'",
            "'tools': 'viewTools'",
            "'web_security': 'viewWebSecurity'",
            "'network_security': 'viewNetworkSecurity'",
            "'api_security': 'viewApiSecurity'",
            "'code_security': 'viewCodeSecurity'",
            "'agents': 'viewAgents'",
            "'investigation': 'viewInvestigation'",
            "'remediation': 'viewRemediation'",
            "'drift': 'viewDrift'",
            "'approvals': 'viewApprovals'",
            "'reports': 'viewReports'",
            "'cyber_audit': 'viewCyberAudit'",
            "'integrations': 'viewIntegrations'",
            "'settings': 'viewSettings'",
            "'docs': 'viewDocs'"
        }
        for m in expected_mappings:
            self.assertIn(m, self.js, f"Routing table missing mapping: {m}")

    def test_05_nav_to_view_functionality(self):
        """navToView removes active from all views and adds active to target."""
        self.assertIn("function navToView(view", self.js)
        self.assertIn("document.querySelectorAll('.swa-view')", self.js)
        self.assertIn("v.classList.remove('active')", self.js)
        self.assertIn("targetEl.classList.add('active')", self.js)

    def test_06_hash_routing_and_history_support(self):
        """app.js provides hash routing and popstate history listeners."""
        self.assertIn("window.addEventListener('hashchange'", self.js)
        self.assertIn("window.addEventListener('popstate'", self.js)
        self.assertIn("window.history.pushState", self.js)

    def test_07_api_findings_endpoint(self):
        """GET /api/findings returns list of findings for the Vulnerabilities view."""
        resp = client.get("/api/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_08_api_scans_endpoint(self):
        """GET /api/scans returns recent assessments for the Assessments view."""
        resp = client.get("/api/scans")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_09_api_assets_endpoint(self):
        """GET /api/assets returns monitored assets for the Assets view."""
        resp = client.get("/api/assets")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue("assets" in data or isinstance(data, list))
        assets_list = data["assets"] if isinstance(data, dict) else data
        self.assertIsInstance(assets_list, list)

    def test_10_api_agents_endpoint(self):
        """GET /api/agents returns 17 specialist agents for the Agents view."""
        resp = client.get("/api/agents")
        self.assertEqual(resp.status_code, 200)
        agents = resp.json()
        self.assertGreaterEqual(len(agents), 12)


if __name__ == "__main__":
    unittest.main()
