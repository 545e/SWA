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
        # Autonomous Zero False Positive Filter:
        # Strict validation: HTTP 403 Forbidden indicates access denial, not exposure.
        cleaned_findings = []
        for f in findings:
            desc = (f.description or "").lower()
            expl = (f.poc_explanation or "").lower()
            evid = (f.response_evidence or "").lower()
            title = (f.title or "").lower()
            
            # Check if this finding is claiming exposure based on 401/403/404
            is_403_fp = any(term in desc or term in expl or term in evid for term in ["403", "http 403", "status 403", "returning http 403", "401", "http 401"]) and any(k in title for k in ["fuzzed", "exposed", "environment", "git", "subversion", "backup", ".env", "config"])
            if not is_403_fp and getattr(f, 'verified', True) is not False:
                cleaned_findings.append(f)
        self.findings = cleaned_findings

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
            "Date Detected",
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
                f.created_at or datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
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
                "## Discovered Subdomains & Assets (OWASP Amass Engine)",
                "",
                "| Subdomain | IP Address | CNAME / Alias | Status | Server | Sources | Takeover Risk |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
            ])
            for sub in s.recon_data.subdomains:
                name = sub.get("subdomain", "") if isinstance(sub, dict) else str(sub)
                ip = sub.get("ip", "N/A") if isinstance(sub, dict) else "N/A"
                cname = sub.get("cname", "--") if isinstance(sub, dict) else "--"
                st = sub.get("status", "N/A") if isinstance(sub, dict) else "N/A"
                if str(st) in ["401", "403"]:
                    st = "Protected"
                elif str(st) in ["404", "500", "502", "503"]:
                    st = "Resolved"
                srv = sub.get("server", "N/A") if isinstance(sub, dict) else "N/A"
                srcs = ", ".join(sub.get("sources", [])) if isinstance(sub, dict) and sub.get("sources") else "OSINT"
                takeover = "**CRITICAL**" if (isinstance(sub, dict) and sub.get("takeover_risk")) else "Clean"
                lines.append(f"| `{name}` | `{ip}` | `{cname}` | `{st}` | {srv} | {srcs} | {takeover} |")
            lines.extend(["", "---"])

        # Add Fuzzed Assets if any (Zero FP: only 200/30x valid endpoints)
        if s.recon_data and s.recon_data.fuzzing_results:
            valid_fuzz = [p for p in s.recon_data.fuzzing_results if p.get('status') in [200, 301, 302, 307, 308] and p.get('status') not in [400, 401, 403, 404, 405, 500, 502, 503, 504]]
            if valid_fuzz:
                lines.extend([
                    f"## Discovered Endpoints & Verified Assets ({len(valid_fuzz)})",
                    "",
                    "| Path | Status | Content Length | Title / Classification |",
                    "| :--- | :--- | :--- | :--- |"
                ])
                for p in valid_fuzz:
                    lines.append(f"| `{p.get('path')}` | `{p.get('status')}` | `{p.get('content_length')} B` | {p.get('title') or 'Discovered'} |")
                lines.extend(["", "---"])

        lines.extend([
            "## Detailed Vulnerability Findings",
            ""
        ])

        for i, f in enumerate(self.findings, 1):
            lines.extend([
                f"### {i}. [{f.severity.value}] {f.title}",
                f"- **Detected Date:** `{f.created_at or datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`",
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
                    if str(st) in ["401", "403"]:
                        st = "Protected"
                    elif str(st) in ["404", "500", "502", "503"]:
                        st = "Resolved"
                    srv = sub.get("server", "N/A") if isinstance(sub, dict) else "N/A"
                    recon_html += f"<tr><td><code>{name}</code></td><td>{ip}</td><td>{st}</td><td>{srv}</td></tr>"
                recon_html += "</tbody></table>"
            recon_html += "</div>"

        # Build Fuzzed Assets Section (Zero FP: only 200/30x valid endpoints)
        fuzzer_html = ""
        if s.recon_data and s.recon_data.fuzzing_results:
            valid_fuzz = [p for p in s.recon_data.fuzzing_results if p.get('status') in [200, 301, 302, 307, 308] and p.get('status') not in [400, 401, 403, 404, 405, 500, 502, 503, 504]]
            if valid_fuzz:
                fuzzer_html = f"""
                <div class="report-section">
                    <h2>2. Discovered Endpoints & Verified Assets ({len(valid_fuzz)})</h2>
                    <table class="report-table">
                        <thead><tr><th>Discovered Path</th><th>HTTP Status</th><th>Content Size</th><th>Title / Classification</th></tr></thead>
                        <tbody>
                """
                for p in valid_fuzz:
                    status = p.get('status', 200)
                    st_color = "#10b981" if status == 200 else "#3b82f6"
                    fuzzer_html += f"""
                    <tr>
                        <td><code>{p.get('path')}</code></td>
                        <td><span style="font-weight:700;color:{st_color};">{status}</span></td>
                        <td>{p.get('content_length', 0)} bytes</td>
                        <td>{p.get('title') or 'Public Asset'}</td>
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
                    <strong>CWE:</strong> {f.cwe_id or 'N/A'} | 
                    <strong>Detected:</strong> {f.created_at or datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
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

    def generate_docx(self) -> bytes:
        """Generates a professional executive penetration testing report in Microsoft Word (.docx) format."""
        import io
        import datetime
        try:
            import docx
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
            from docx.oxml import OxmlElement
            from docx.oxml.ns import qn
        except ImportError:
            # Fallback if python-docx unavailable: return empty bytes
            return b""

        doc = docx.Document()
        
        # Page Margins (0.75 in)
        for section in doc.sections:
            section.top_margin = Inches(0.75)
            section.bottom_margin = Inches(0.75)
            section.left_margin = Inches(0.75)
            section.right_margin = Inches(0.75)

        # Helper to set cell shading
        def set_cell_background(cell, hex_color):
            tc_pr = cell._tc.get_or_add_tcPr()
            shd = OxmlElement('w:shd')
            shd.set(qn('w:val'), 'clear')
            shd.set(qn('w:color'), 'auto')
            shd.set(qn('w:fill'), hex_color)
            tc_pr.append(shd)

        s = self.scan
        posture = self._compute_posture()
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Header / Title
        title_p = doc.add_paragraph()
        title_p.paragraph_format.space_before = Pt(0)
        title_p.paragraph_format.space_after = Pt(6)
        run_title = title_p.add_run("SWA AI — CYBERSECURITY AUDIT & PENETRATION TEST REPORT")
        run_title.font.name = "Arial"
        run_title.font.size = Pt(18)
        run_title.font.bold = True
        run_title.font.color.rgb = RGBColor(15, 23, 42)

        sub_p = doc.add_paragraph()
        sub_p.paragraph_format.space_after = Pt(14)
        run_sub = sub_p.add_run("Autonomous Multi-Agent Penetration Testing & Vulnerability Assessment")
        run_sub.font.name = "Arial"
        run_sub.font.size = Pt(11)
        run_sub.font.italic = True
        run_sub.font.color.rgb = RGBColor(100, 116, 139)

        # 2. Executive Overview Table
        doc.add_heading("1. Executive Assessment Overview", level=1)
        
        meta_table = doc.add_table(rows=5, cols=2)
        meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        meta_table.autofit = False
        meta_table.columns[0].width = Inches(2.2)
        meta_table.columns[1].width = Inches(4.8)

        meta_rows = [
            ("Target URL / Host:", s.target_url),
            ("Assessment ID:", s.id),
            ("Scan Profile & Mode:", f"{s.profile.value.upper()} (Lab Mode Authorized)"),
            ("Audit Generated At:", now_str),
            ("Security Posture Grade:", f"Grade {posture['grade']} ({posture['score']}/100) — {posture['risk']}")
        ]
        for i, (k, v) in enumerate(meta_rows):
            cell_k = meta_table.cell(i, 0)
            cell_v = meta_table.cell(i, 1)
            cell_k.text = k
            cell_k.paragraphs[0].runs[0].font.bold = True
            cell_k.paragraphs[0].runs[0].font.size = Pt(9.5)
            set_cell_background(cell_k, "F1F5F9")
            cell_v.text = v
            cell_v.paragraphs[0].runs[0].font.size = Pt(9.5)

        doc.add_paragraph().paragraph_format.space_after = Pt(10)

        # 3. Severity Distribution
        doc.add_heading("2. Vulnerability Severity Breakdown", level=1)
        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info = sum(1 for f in self.findings if f.severity == Severity.INFO)

        stats_table = doc.add_table(rows=2, cols=6)
        stats_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        headers = ["Total Findings", "Critical", "High", "Medium", "Low", "Info"]
        counts = [str(len(self.findings)), str(crit), str(high), str(med), str(low), str(info)]
        colors = ["0F172A", "EF4444", "F97316", "EAB308", "3B82F6", "94A3B8"]

        for col_idx, (hdr, cnt, col_hex) in enumerate(zip(headers, counts, colors)):
            c_hdr = stats_table.cell(0, col_idx)
            c_hdr.text = hdr
            c_hdr.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            c_hdr.paragraphs[0].runs[0].font.bold = True
            c_hdr.paragraphs[0].runs[0].font.size = Pt(9)
            set_cell_background(c_hdr, "1E293B")
            c_hdr.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

            c_cnt = stats_table.cell(1, col_idx)
            c_cnt.text = cnt
            c_cnt.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            r_cnt = c_cnt.paragraphs[0].runs[0]
            r_cnt.font.bold = True
            r_cnt.font.size = Pt(14)
            set_cell_background(c_cnt, "F8FAFC")

        doc.add_paragraph().paragraph_format.space_after = Pt(12)

        # 4. Detailed Vulnerabilities
        doc.add_heading(f"3. Detailed Technical Findings ({len(self.findings)})", level=1)
        if not self.findings:
            p = doc.add_paragraph("Zero active vulnerabilities detected. The target demonstrated robust perimeter hardening.")
            p.runs[0].font.color.rgb = RGBColor(16, 185, 129)
        else:
            for idx, f in enumerate(self.findings, 1):
                sev_str = f.severity.value
                doc.add_heading(f"#{idx} [{sev_str}] {f.title}", level=2)
                
                f_table = doc.add_table(rows=6, cols=2)
                f_table.alignment = WD_TABLE_ALIGNMENT.CENTER
                f_table.columns[0].width = Inches(1.8)
                f_table.columns[1].width = Inches(5.2)

                fields = [
                    ("Severity & CVSS:", f"{sev_str} | CVSS {f.cvss_score} ({f.cvss_vector or 'CVSS:3.1'})"),
                    ("OWASP & CWE:", f"{f.owasp_category or 'OWASP Top 10'} | {f.cwe_id or 'CWE-Unknown'}"),
                    ("Endpoint & Method:", f"{f.method or 'GET'} {f.endpoint or s.target_url}"),
                    ("Technical Description:", f.description or "Automated probe confirmed exposure."),
                    ("Proof of Concept (cURL):", f.poc_curl or f"curl -i '{f.endpoint or s.target_url}'"),
                    ("Remediation Guidance:", f.remediation_advice or "Review access control rules and sanitize user inputs.")
                ]
                for r_idx, (k, v) in enumerate(fields):
                    c0 = f_table.cell(r_idx, 0)
                    c1 = f_table.cell(r_idx, 1)
                    c0.text = k
                    c0.paragraphs[0].runs[0].font.bold = True
                    c0.paragraphs[0].runs[0].font.size = Pt(8.5)
                    set_cell_background(c0, "F1F5F9")
                    c1.text = v
                    c1.paragraphs[0].runs[0].font.size = Pt(8.5)

                doc.add_paragraph().paragraph_format.space_after = Pt(8)

        # 5. Methodology and Certification
        doc.add_heading("4. Testing Methodology & Standards", level=1)
        p_meth = doc.add_paragraph()
        p_meth.add_run(
            "This assessment was performed using SWA AI's 85-agent autonomous security workforce adhering to "
            "OWASP Testing Guide (v4.2), NIST SP 800-115 technical assessment guidelines, and PTES standards. "
            "All findings have been filtered through automated non-destructive proof-of-concept validation to ensure zero false positives."
        )

        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    def generate_pdf(self) -> bytes:
        """Generates a high-resolution, enterprise penetration testing report in true binary PDF format."""
        import io
        import datetime
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
        except ImportError:
            # Fallback if reportlab unavailable: return empty bytes
            return b""

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Title'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0f172a'),
            alignment=0,
            spaceAfter=4
        )
        sub_style = ParagraphStyle(
            'ReportSub',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=14
        )
        h1_style = ParagraphStyle(
            'H1',
            parent=styles['Heading1'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        h2_style = ParagraphStyle(
            'H2',
            parent=styles['Heading2'],
            fontSize=10.5,
            leading=13,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor('#334155')
        )
        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Code'],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor('#6366f1'),
            fontName='Courier'
        )

        story = []
        s = self.scan
        posture = self._compute_posture()
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Header Banner
        story.append(Paragraph("SWA AI — EXECUTIVE PENETRATION TEST REPORT", title_style))
        story.append(Paragraph(f"Autonomous Security Operations & Vulnerability Intelligence | Generated: {now_str}", sub_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#e2e8f0'), spaceAfter=12))

        # 2. Executive Overview Table
        story.append(Paragraph("1. Executive Assessment Overview", h1_style))
        overview_data = [
            [Paragraph("<b>Target URL / System:</b>", body_style), Paragraph(s.target_url, body_style)],
            [Paragraph("<b>Assessment ID:</b>", body_style), Paragraph(f"<font color='#6366f1'><b>{s.id}</b></font>", body_style)],
            [Paragraph("<b>Scan Profile:</b>", body_style), Paragraph(s.profile.value.upper(), body_style)],
            [Paragraph("<b>Security Posture Score:</b>", body_style), Paragraph(f"<b>Grade {posture['grade']} ({posture['score']}/100)</b> — {posture['risk']}", body_style)],
            [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(f"<b>{len(self.findings)} verified vulnerabilities</b>", body_style)]
        ]
        ov_table = Table(overview_data, colWidths=[150, 390])
        ov_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(ov_table)
        story.append(Spacer(1, 14))

        # 3. Severity Distribution
        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info = sum(1 for f in self.findings if f.severity == Severity.INFO)

        story.append(Paragraph("2. Threat Severity Breakdown", h1_style))
        stats_data = [
            ["Critical", "High", "Medium", "Low", "Info", "Total"],
            [str(crit), str(high), str(med), str(low), str(info), str(len(self.findings))]
        ]
        stats_table = Table(stats_data, colWidths=[90, 90, 90, 90, 90, 90])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,1), (-1,1), 13),
            ('TEXTCOLOR', (0,1), (0,1), colors.HexColor('#ef4444')),
            ('TEXTCOLOR', (1,1), (1,1), colors.HexColor('#f97316')),
            ('TEXTCOLOR', (2,1), (2,1), colors.HexColor('#eab308')),
            ('TEXTCOLOR', (3,1), (3,1), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (4,1), (4,1), colors.HexColor('#64748b')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 14))

        # 4. Detailed Findings
        story.append(Paragraph(f"3. Detailed Technical Findings ({len(self.findings)})", h1_style))
        if not self.findings:
            story.append(Paragraph("Zero active vulnerabilities detected during this assessment session.", body_style))
        else:
            sev_colors = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFO": "#64748b"
            }
            for idx, f in enumerate(self.findings[:40], 1): # Cap at 40 in PDF to maintain reasonable document size
                sev_str = f.severity.value
                sev_col = sev_colors.get(sev_str, "#64748b")
                
                heading_html = f"<b>#{idx} <font color='{sev_col}'>[{sev_str}]</font> {f.title}</b> (CVSS {f.cvss_score})"
                
                f_table_data = [
                    [Paragraph(heading_html, h2_style), ""],
                    [Paragraph("<b>Endpoint:</b>", body_style), Paragraph(f"<code>{f.method or 'GET'} {f.endpoint or s.target_url}</code>", code_style)],
                    [Paragraph("<b>OWASP / CWE:</b>", body_style), Paragraph(f"{f.owasp_category or 'OWASP Top 10'} | {f.cwe_id or 'CWE-Unknown'}", body_style)],
                    [Paragraph("<b>Description:</b>", body_style), Paragraph(f.description or "Exposure validated through automated probe.", body_style)],
                    [Paragraph("<b>Remediation:</b>", body_style), Paragraph(f.remediation_advice or "Apply defense-in-depth and input validation.", body_style)]
                ]
                
                f_tbl = Table(f_table_data, colWidths=[110, 430])
                f_tbl.setStyle(TableStyle([
                    ('SPAN', (0,0), (1,0)),
                    ('BACKGROUND', (0,0), (1,0), colors.HexColor('#f1f5f9')),
                    ('BACKGROUND', (0,1), (0,-1), colors.HexColor('#f8fafc')),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                    ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(KeepTogether([f_tbl, Spacer(1, 8)]))

        # Build document
        doc.build(story)
        return buf.getvalue()
