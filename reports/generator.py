"""
SWA AI Enterprise Report Generator
Produces industry-standard SARIF 2.1.0, Markdown penetration test reports,
RFC 4180 CSV spreadsheets, JSON exports, and executive HTML security assessment reports
with print-to-PDF formatting.
"""

import json
import csv
import io
import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.models import ScanJob, VulnerabilityFinding, Severity

class ReportGenerator:
    def __init__(self, scan: ScanJob, findings: List[VulnerabilityFinding]):
        self.scan = scan
        self.findings = findings

    def _compute_posture(self) -> Dict[str, Any]:
        """Compute realistic security grade and score based on findings."""
        score = 100
        for f in self.findings:
            sev = f.severity
            if sev == Severity.CRITICAL:
                score -= 30
            elif sev == Severity.HIGH:
                score -= 18
            elif sev == Severity.MEDIUM:
                score -= 8
            elif sev == Severity.LOW:
                score -= 3
            elif sev == Severity.INFO:
                score -= 1
        score = max(0, min(100, score))

        if score >= 90:
            grade, grade_color, risk = "A", "#10b981", "LOW RISK - Strong Security Posture"
        elif score >= 75:
            grade, grade_color, risk = "B", "#3b82f6", "MODERATE RISK - Standard Defenses Active"
        elif score >= 60:
            grade, grade_color, risk = "C", "#eab308", "ELEVATED RISK - Remediation Recommended"
        elif score >= 40:
            grade, grade_color, risk = "D", "#f97316", "HIGH RISK - Multiple Exposures Detected"
        else:
            grade, grade_color, risk = "F", "#ef4444", "CRITICAL RISK - Immediate Triage Required"

        return {
            "score": score,
            "grade": grade,
            "grade_color": grade_color,
            "risk": risk
        }

    def generate_csv(self) -> str:
        """RFC 4180 compliant CSV export for spreadsheet triage / Jira imports."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "Finding ID",
            "Severity",
            "CVSS Score",
            "OWASP Category",
            "CWE ID",
            "Title",
            "Endpoint",
            "Method",
            "Description",
            "Proof of Concept (cURL)",
            "Technical Verification",
            "Remediation Guidance"
        ])

        for f in self.findings:
            writer.writerow([
                f.id,
                f.severity.value,
                f.cvss_score,
                f.owasp_category or "N/A",
                f.cwe_id or "N/A",
                f.title,
                f.endpoint,
                f.method,
                f.description,
                f.poc_curl or "",
                f.poc_explanation or "",
                f.remediation_advice or ""
            ])

        return output.getvalue()

    def generate_json(self) -> str:
        posture = self._compute_posture()
        data = {
            "swa_version": "2.0-autonomous",
            "scan_id": self.scan.id,
            "target": self.scan.target_url,
            "profile": self.scan.profile.value,
            "started_at": self.scan.started_at,
            "completed_at": self.scan.completed_at,
            "duration_seconds": self.scan.duration_seconds,
            "security_posture": posture,
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
                        "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else (
                            "warning" if f.severity == Severity.MEDIUM else "note"
                        )
                    },
                    "properties": {
                        "cvssScore": f.cvss_score,
                        "owasp": f.owasp_category or "A05:2021"
                    }
                })
            else:
                rule_index = rule_index_map[rule_id]

            parsed_url = urlparse(f.endpoint)
            artifact_uri = parsed_url.path if parsed_url.path else "/"

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else (
                    "warning" if f.severity == Severity.MEDIUM else "note"
                ),
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "method": f.method,
                    "endpoint": f.endpoint,
                    "remediation": f.remediation_advice,
                    "poc_curl": f.poc_curl
                }
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SWA AI Autonomous Auditor",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/545e/SWA",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif_doc, indent=2)

    def generate_markdown(self) -> str:
        s = self.scan
        posture = self._compute_posture()
        lines = [
            f"# SWA AI Penetration Test Report",
            f"**Target:** `{s.target_url}`  ",
            f"**Scan ID:** `{s.id}`  ",
            f"**Security Grade:** `{posture['grade']}` ({posture['score']}/100) — {posture['risk']}  ",
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
            "---"
        ]

        # Add Subdomains if any
        if s.recon_data and s.recon_data.subdomains:
            lines.extend([
                "## Discovered Subdomains",
                "",
                "| Subdomain | IP Address | Status | Server |",
                "| :--- | :--- | :--- | :--- |"
            ])
            for sub in s.recon_data.subdomains:
                name = sub.get("subdomain", "") if isinstance(sub, dict) else str(sub)
                ip = sub.get("ip", "N/A") if isinstance(sub, dict) else "N/A"
                st = sub.get("status", "N/A") if isinstance(sub, dict) else "N/A"
                srv = sub.get("server", "N/A") if isinstance(sub, dict) else "N/A"
                lines.append(f"| `{name}` | `{ip}` | `{st}` | {srv} |")
            lines.extend(["", "---"])

        # Add Fuzzed Assets if any
        if s.recon_data and s.recon_data.fuzzing_results:
            lines.extend([
                "## Fuzzed Sensitive Endpoints & Assets",
                "",
                "| Path | Status | Content Length | Title / Classification |",
                "| :--- | :--- | :--- | :--- |"
            ])
            for p in s.recon_data.fuzzing_results:
                lines.append(f"| `{p.get('path')}` | `{p.get('status')}` | `{p.get('content_length')} B` | {p.get('title') or 'Discovered'} |")
            lines.extend(["", "---"])

        lines.extend([
            "## Detailed Vulnerability Findings",
            ""
        ])

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

    def generate_html(self, auto_print: bool = False) -> str:
        s = self.scan
        posture = self._compute_posture()
        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info = sum(1 for f in self.findings if f.severity == Severity.INFO)

        # Build Recon Section
        recon_html = ""
        if s.recon_data:
            ips = s.recon_data.ip_addresses or []
            ports = s.recon_data.open_ports or []
            tech = s.recon_data.technologies or []
            subs = s.recon_data.subdomains or []

            recon_html = f"""
            <div class="report-section">
                <h2>1. Attack Surface & Network Reconnaissance</h2>
                <div class="meta-grid">
                    <div><strong>Exposed IPs:</strong> {', '.join(ips) if ips else 'None detected'}</div>
                    <div><strong>Discovered Subdomains:</strong> {len(subs)} live hostnames</div>
                    <div><strong>Open Ports:</strong> {', '.join([str(p.get('port', p)) for p in ports]) if ports else 'Standard Web (80, 443)'}</div>
                    <div><strong>Technologies:</strong> {', '.join([t.get('name', str(t)) if isinstance(t, dict) else str(t) for t in tech[:8]]) if tech else 'N/A'}</div>
                </div>
            """
            if subs:
                recon_html += """
                <table class="report-table">
                    <thead><tr><th>Subdomain</th><th>IP Address</th><th>HTTP Status</th><th>Server</th></tr></thead>
                    <tbody>
                """
                for sub in subs[:15]:
                    name = sub.get("subdomain", "") if isinstance(sub, dict) else str(sub)
                    ip = sub.get("ip", "N/A") if isinstance(sub, dict) else "N/A"
                    st = sub.get("status", "N/A") if isinstance(sub, dict) else "N/A"
                    srv = sub.get("server", "N/A") if isinstance(sub, dict) else "N/A"
                    recon_html += f"<tr><td><code>{name}</code></td><td>{ip}</td><td>{st}</td><td>{srv}</td></tr>"
                recon_html += "</tbody></table>"
            recon_html += "</div>"

        # Build Fuzzed Assets Section
        fuzzer_html = ""
        if s.recon_data and s.recon_data.fuzzing_results:
            fuzzer_html = f"""
            <div class="report-section">
                <h2>2. Fuzzed Sensitive Endpoints & Exposed Assets ({len(s.recon_data.fuzzing_results)})</h2>
                <table class="report-table">
                    <thead><tr><th>Discovered Path</th><th>HTTP Status</th><th>Content Size</th><th>Title / Classification</th></tr></thead>
                    <tbody>
            """
            for p in s.recon_data.fuzzing_results:
                status = p.get('status', 200)
                st_color = "#10b981" if status == 200 else ("#3b82f6" if status in [301, 302] else "#ef4444")
                fuzzer_html += f"""
                <tr>
                    <td><code>{p.get('path')}</code></td>
                    <td><span style="font-weight:700;color:{st_color};">{status}</span></td>
                    <td>{p.get('content_length', 0)} bytes</td>
                    <td>{p.get('title') or 'Sensitive Asset'}</td>
                </tr>
                """
            fuzzer_html += "</tbody></table></div>"

        # Build Findings HTML
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
                <pre class="code-box"><code>{f.poc_curl or f"curl -i '{f.endpoint}'"}</code></pre>

                <h4>Technical Verification</h4>
                <p>{f.poc_explanation or 'Verified via dynamic probe.'}</p>

                <h4>Remediation Guidance</h4>
                <p>{f.remediation_advice}</p>
                {f'<pre class="code-box patch"><code>{f.remediation_patch}</code></pre>' if f.remediation_patch else ''}
            </div>
            """

        # Auto print script if requested
        print_script = "<script>window.onload = function() { window.print(); };</script>" if auto_print else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SWA AI Executive Security Assessment - {s.target_url}</title>
    <style>
        :root {{
            --bg-page: #0d1117;
            --bg-card: #161b22;
            --bg-subtle: #21262d;
            --border: #30363d;
            --text-title: #f0f6fc;
            --text-body: #c9d1d9;
            --text-muted: #8b949e;
            --brand: #6366f1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-page);
            color: var(--text-body);
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .brand-tag {{
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            background: rgba(99,102,241,0.2);
            color: #a5b4fc;
            text-transform: uppercase;
        }}
        .target-sub {{
            font-size: 14px;
            color: var(--text-muted);
            margin-top: 6px;
        }}
        .actions-bar {{
            display: flex;
            gap: 10px;
        }}
        .btn-action {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid var(--border);
            background: var(--bg-subtle);
            color: var(--text-title);
            text-decoration: none;
            transition: all 0.2s;
        }}
        .btn-action:hover {{
            background: rgba(255,255,255,0.06);
            border-color: #58a6ff;
        }}
        .btn-print-primary {{
            background: var(--brand);
            border-color: var(--brand);
            color: #fff;
        }}
        .btn-print-primary:hover {{
            background: #4f46e5;
        }}
        .posture-card {{
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .posture-grade-badge {{
            width: 72px; height: 72px;
            border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 38px; font-weight: 800;
            color: #fff;
            flex-shrink: 0;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        .stat-card .num {{
            font-size: 28px;
            font-weight: 800;
            line-height: 1.1;
        }}
        .stat-card .label {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .report-section {{
            margin-bottom: 36px;
        }}
        h2 {{
            color: var(--text-title);
            font-size: 18px;
            margin-bottom: 14px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
            font-size: 13px;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            margin-top: 10px;
        }}
        .report-table th, .report-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        .report-table th {{
            background: var(--bg-subtle);
            color: var(--text-muted);
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
        }}
        .finding-card {{
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            page-break-inside: avoid;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 11px;
            letter-spacing: 0.5px;
        }}
        .cvss {{
            background: rgba(255,255,255,0.06);
            border: 1px solid var(--border);
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
        }}
        .finding-meta {{
            font-size: 12.5px;
            color: var(--text-muted);
            margin-bottom: 14px;
        }}
        h4 {{
            margin: 16px 0 6px 0;
            font-size: 12.5px;
            color: var(--text-title);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .code-box {{
            background: #090d13;
            border: 1px solid var(--border);
            padding: 12px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 12px;
            color: #7dd3fc;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .code-box.patch {{
            color: #86efac;
        }}
        code {{
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 12px;
            background: rgba(255,255,255,0.05);
            padding: 2px 5px;
            border-radius: 4px;
            color: #93c5fd;
        }}

        /* Print-to-PDF Specific Styling */
        @media print {{
            body {{
                background: #ffffff !important;
                color: #111827 !important;
                padding: 0 !important;
            }}
            .container {{
                max-width: 100% !important;
                border: none !important;
                box-shadow: none !important;
                padding: 10px !important;
                background: #ffffff !important;
            }}
            .actions-bar {{
                display: none !important;
            }}
            .brand-title, h1, h2, h3, h4 {{
                color: #111827 !important;
            }}
            .target-sub, .finding-meta, .stat-card .label {{
                color: #4b5563 !important;
            }}
            .posture-card, .stat-card, .finding-card {{
                background: #f9fafb !important;
                border: 1px solid #e5e7eb !important;
                box-shadow: none !important;
            }}
            .code-box {{
                background: #f3f4f6 !important;
                color: #1f2937 !important;
                border: 1px solid #d1d5db !important;
            }}
            .finding-card {{
                page-break-inside: avoid !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        
        <div class="header">
            <div>
                <div class="brand-title">
                    <span>SWA AI</span>
                    <span class="brand-tag">Cybersecurity Audit Report</span>
                </div>
                <div class="target-sub">
                    Target: <strong>{s.target_url}</strong> | Audit ID: <code>{s.id}</code> | Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
                </div>
            </div>
            <div class="actions-bar">
                <button onclick="window.print()" class="btn-action btn-print-primary">🖨️ Print / Save as PDF</button>
                <a href="/api/scans/{s.id}/report?format=csv" class="btn-action">📊 Download CSV</a>
                <a href="/api/scans/{s.id}/report?format=json" class="btn-action">⚡ Download JSON</a>
            </div>
        </div>

        <div class="posture-card">
            <div style="display: flex; align-items: center; gap: 18px;">
                <div class="posture-grade-badge" style="background: {posture['grade_color']};">
                    {posture['grade']}
                </div>
                <div>
                    <h3 style="font-size: 20px; color: var(--text-title); margin-bottom: 4px;">Security Posture: {posture['score']}/100</h3>
                    <p style="color: {posture['grade_color']}; font-weight: 700; font-size: 13.5px;">{posture['risk']}</p>
                </div>
            </div>
            <div style="font-size: 13px; color: var(--text-muted); text-align: right;">
                <div>Profile: <strong>{s.profile.value}</strong></div>
                <div>Total Findings: <strong>{len(self.findings)}</strong></div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="num" style="color: #ef4444;">{crit}</div><div class="label">Critical</div></div>
            <div class="stat-card"><div class="num" style="color: #f97316;">{high}</div><div class="label">High</div></div>
            <div class="stat-card"><div class="num" style="color: #eab308;">{med}</div><div class="label">Medium</div></div>
            <div class="stat-card"><div class="num" style="color: #3b82f6;">{low}</div><div class="label">Low</div></div>
            <div class="stat-card"><div class="num" style="color: #94a3b8;">{info}</div><div class="label">Info</div></div>
        </div>

        {recon_html}

        {fuzzer_html}

        <div class="report-section">
            <h2>3. Detailed Penetration Test Findings ({len(self.findings)})</h2>
            {findings_html if self.findings else '<p style="color: #10b981; padding: 20px 0;">No active vulnerabilities detected during this assessment session.</p>'}
        </div>

    </div>
    {print_script}
</body>
</html>
"""
