"""
SWA AI Report Generator
Produces industry-standard SARIF 2.1.0, Markdown penetration test reports,
JSON exports, and executive HTML security assessment reports.
"""

import json
from typing import List, Dict, Any
from core.models import ScanJob, VulnerabilityFinding, Severity

class ReportGenerator:
    def __init__(self, scan: ScanJob, findings: List[VulnerabilityFinding]):
        self.scan = scan
        self.findings = findings

    def generate_json(self) -> str:
        data = {
            "swa_version": "2.0-autonomous",
            "scan_id": self.scan.id,
            "target": self.scan.target_url,
            "profile": self.scan.profile.value,
            "started_at": self.scan.started_at,
            "completed_at": self.scan.completed_at,
            "duration_seconds": self.scan.duration_seconds,
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
            "findings": [f.model_dump() for f in self.findings],
            "reconnaissance": self.scan.recon_data.model_dump() if self.scan.recon_data else {}
        }
        return json.dumps(data, indent=2)

    def generate_sarif(self) -> str:
        """SARIF 2.1.0 output compatible with GitHub Advanced Security and DefectDojo."""
        rules = []
        results = []

        rule_index_map = {}
        for f in self.findings:
            rule_id = f.cwe_id or f"SWA-{f.id[:6].upper()}"
            if rule_id not in rule_index_map:
                rule_index = len(rules)
                rule_index_map[rule_id] = rule_index
                rules.append({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else ("warning" if f.severity == Severity.MEDIUM else "note")
                    },
                    "properties": {
                        "cvssScore": f.cvss_score,
                        "owasp": f.owasp_category or "A05:2021"
                    }
                })

            level_map = {
                Severity.CRITICAL: "error",
                Severity.HIGH: "error",
                Severity.MEDIUM: "warning",
                Severity.LOW: "note",
                Severity.INFO: "note"
            }

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index_map[rule_id],
                "level": level_map.get(f.severity, "warning"),
                "message": {"text": f"{f.title} on {f.endpoint}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.endpoint}
                    }
                }],
                "properties": {
                    "poc_curl": f.poc_curl,
                    "remediation": f.remediation_advice
                }
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SWA AI Autonomous Pentesting Engine",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/krishnanmk3/swa-ai",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif_doc, indent=2)

    def generate_markdown(self) -> str:
        s = self.scan
        lines = [
            f"# SWA AI Penetration Test Report",
            f"**Target:** `{s.target_url}`  ",
            f"**Scan ID:** `{s.id}`  ",
            f"**Profile:** `{s.profile.value}`  ",
            f"**Duration:** `{s.duration_seconds or 0}s`  ",
            f"**Completed At:** `{s.completed_at or 'In Progress'}`  ",
            "",
            "## Executive Summary",
            f"An autonomous dynamic security assessment was performed against `{s.target_url}`. "
            f"A total of **{len(self.findings)}** verified security findings were identified with reproducible proofs-of-concept.",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| 🔴 Critical | {sum(1 for f in self.findings if f.severity == Severity.CRITICAL)} |",
            f"| 🟠 High | {sum(1 for f in self.findings if f.severity == Severity.HIGH)} |",
            f"| 🟡 Medium | {sum(1 for f in self.findings if f.severity == Severity.MEDIUM)} |",
            f"| 🔵 Low | {sum(1 for f in self.findings if f.severity == Severity.LOW)} |",
            f"| ⚪ Info | {sum(1 for f in self.findings if f.severity == Severity.INFO)} |",
            "",
            "---",
            "## Detailed Vulnerability Findings",
            ""
        ]

        for i, f in enumerate(self.findings, 1):
            lines.extend([
                f"### {i}. [{f.severity.value}] {f.title}",
                f"- **Endpoint:** `{f.method} {f.endpoint}`",
                f"- **CVSS v3.1 Score:** `{f.cvss_score}` ({f.cvss_vector or 'N/A'})",
                f"- **CWE:** `{f.cwe_id or 'CWE-Unknown'}` | **OWASP:** `{f.owasp_category or 'N/A'}`",
                f"- **Status:** `{'Verified PoC' if f.verified else 'Candidate'}`",
                "",
                f"**Description:**  \n{f.description}",
                "",
                "**Proof of Concept (cURL):**",
                "```bash",
                f.poc_curl or f"curl -i '{f.endpoint}'",
                "```",
                "",
                f"**PoC Technical Verification:**  \n{f.poc_explanation}",
                "",
                "**Remediation Guidance:**  \n" + f.remediation_advice,
                ""
            ])
            if f.remediation_patch:
                lines.extend([
                    "**Remediation Patch / Fix:**",
                    "```",
                    f.remediation_patch,
                    "```",
                    ""
                ])
            lines.append("---")

        return "\n".join(lines)

    def generate_html(self) -> str:
        s = self.scan
        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info = sum(1 for f in self.findings if f.severity == Severity.INFO)

        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            badge_color = {
                Severity.CRITICAL: "#ef4444",
                Severity.HIGH: "#f97316",
                Severity.MEDIUM: "#eab308",
                Severity.LOW: "#3b82f6",
                Severity.INFO: "#94a3b8"
            }.get(f.severity, "#94a3b8")

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background: {badge_color}; color: #fff;">{f.severity.value}</span>
                    <span class="cvss">CVSS {f.cvss_score}</span>
                    <h3 style="margin: 0; display: inline-block;">{i}. {f.title}</h3>
                </div>
                <div class="finding-meta">
                    <strong>Endpoint:</strong> <code>{f.method} {f.endpoint}</code> | 
                    <strong>OWASP:</strong> {f.owasp_category or 'N/A'} | 
                    <strong>CWE:</strong> {f.cwe_id or 'N/A'}
                </div>
                <p>{f.description}</p>
                
                <h4>Proof of Concept (cURL)</h4>
                <pre class="code-box"><code>{f.poc_curl or 'N/A'}</code></pre>

                <h4>Technical Verification</h4>
                <p>{f.poc_explanation or 'Verified via dynamic probe.'}</p>

                <h4>Remediation Guidance</h4>
                <p>{f.remediation_advice}</p>
                {f'<pre class="code-box patch"><code>{f.remediation_patch}</code></pre>' if f.remediation_patch else ''}
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SWA AI Penetration Test Report - {s.target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 36px; border: 1px solid #334155; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        h1, h2, h3, h4 {{ color: #f8fafc; font-weight: 700; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-size: 24px; font-weight: 800; color: #10b981; letter-spacing: 1px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 25px 0; }}
        .stat-card {{ background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .stat-val {{ font-size: 28px; font-weight: 800; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; margin-right: 8px; }}
        .cvss {{ background: #334155; color: #38bdf8; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 700; margin-right: 12px; }}
        .finding-card {{ background: #0f172a; border-radius: 8px; border: 1px solid #334155; padding: 24px; margin-bottom: 24px; }}
        .finding-header {{ display: flex; align-items: center; margin-bottom: 12px; }}
        .finding-meta {{ color: #94a3b8; font-size: 13px; margin-bottom: 14px; }}
        .code-box {{ background: #030712; color: #a5f3fc; padding: 14px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 13px; border: 1px solid #1e293b; }}
        .patch {{ color: #86efac; border-left: 4px solid #10b981; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo">⚡ SWA AI PENTEST REPORT</div>
                <div style="color: #94a3b8; font-size: 14px; margin-top: 4px;">Target: {s.target_url}</div>
            </div>
            <div style="text-align: right; color: #94a3b8; font-size: 13px;">
                Scan ID: {s.id}<br>
                Completed: {s.completed_at or 'In Progress'}<br>
                Duration: {s.duration_seconds or 0}s
            </div>
        </div>

        <h2>Executive Severity Breakdown</h2>
        <div class="stats-grid">
            <div class="stat-card" style="border-top: 4px solid #ef4444;"><div class="stat-val" style="color: #ef4444;">{crit}</div><div>Critical</div></div>
            <div class="stat-card" style="border-top: 4px solid #f97316;"><div class="stat-val" style="color: #f97316;">{high}</div><div>High</div></div>
            <div class="stat-card" style="border-top: 4px solid #eab308;"><div class="stat-val" style="color: #eab308;">{med}</div><div>Medium</div></div>
            <div class="stat-card" style="border-top: 4px solid #3b82f6;"><div class="stat-val" style="color: #3b82f6;">{low}</div><div>Low</div></div>
            <div class="stat-card" style="border-top: 4px solid #94a3b8;"><div class="stat-val" style="color: #94a3b8;">{info}</div><div>Info</div></div>
        </div>

        <h2>Verified Findings ({len(self.findings)})</h2>
        {findings_html if self.findings else '<p style="color: #10b981;">No active vulnerabilities detected during this assessment session.</p>'}
    </div>
</body>
</html>
"""
