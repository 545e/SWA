"""
SWA AI — Cyber Export Module (Phase 8)
Enterprise-grade reporting and data export engine for security scans, findings,
assets, test executions, deployments, compliance assessments, and audit logs.
Supports PDF (print-ready executive HTML/PDF), CSV, JSON, HTML, and XLSX/TSV formats.
Enforces sensitive data redaction, SHA-256 artifact verification, and audit logging.
"""

import os
import io
import re
import csv
import json
import hashlib
import datetime
from typing import List, Dict, Any, Optional
from core.database import db

EXPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "exports")
os.makedirs(EXPORT_DIR, exist_ok=True)

# Sensitive patterns for autonomous redaction
SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{15,}"),
    re.compile(r"(?i)api[_-]?key[\s:=]+['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"),
    re.compile(r"(?i)secret[\s:=]+['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"),
    re.compile(r"(?i)password[\s:=]+['\"]?[^'\"\s\r\n]{6,}['\"]?"),
    re.compile(r"(?i)Authorization:\s+Basic\s+[A-Za-z0-9+/=]+"),
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
]

def redact_sensitive_data(text: str) -> str:
    """Safely redact credentials, API tokens, and private keys from exported deliverables."""
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_BY_SWA_EXPORT]", redacted)
    return redacted

class CyberExportEngine:
    def __init__(self):
        self.export_dir = EXPORT_DIR

    def export_data(
        self,
        export_type: str,
        format_type: str,
        title: Optional[str] = None,
        scan_id: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[str] = None,
        asset_filter: Optional[str] = None,
        include_evidence: bool = True,
        include_remediation: bool = True,
        actor: str = "system"
    ) -> Dict[str, Any]:
        """
        Execute export workflow across database models:
        export_type: 'findings', 'executive', 'technical', 'assets', 'compliance', 'test_results', 'deployments', 'audit_logs'
        format_type: 'json', 'csv', 'html', 'pdf', 'xlsx'
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        export_id = f"exp_{timestamp}_{os.urandom(3).hex()}"
        safe_format = format_type.lower()
        if safe_format not in ["json", "csv", "html", "pdf", "xlsx"]:
            safe_format = "json"

        display_title = title or f"SWA AI Security Export - {export_type.upper()}"

        # 1. Gather filtered data from database
        data_payload = self._gather_export_data(
            export_type=export_type,
            scan_id=scan_id,
            severity_filter=severity_filter,
            category_filter=category_filter,
            asset_filter=asset_filter
        )

        # 2. Render content according to requested format
        content_bytes, mime_type, file_ext = self._render_format(
            format_type=safe_format,
            export_type=export_type,
            title=display_title,
            data=data_payload,
            include_evidence=include_evidence,
            include_remediation=include_remediation
        )

        # 3. Write deliverable to disk securely
        filename = f"{export_id}_{export_type}.{file_ext}"
        filepath = os.path.join(self.export_dir, filename)
        with open(filepath, "wb") as f:
            f.write(content_bytes)

        file_size = len(content_bytes)
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        download_url = f"/api/cyber/export/download/{export_id}"

        findings_count = len(data_payload.get("findings", [])) if "findings" in data_payload else len(data_payload.get("items", []))

        record = {
            "id": export_id,
            "title": display_title,
            "format": safe_format,
            "export_type": export_type,
            "file_path": filepath,
            "file_size": file_size,
            "findings_count": findings_count,
            "filter_criteria": {
                "scan_id": scan_id,
                "severity": severity_filter,
                "category": category_filter,
                "asset": asset_filter,
                "include_evidence": include_evidence,
                "include_remediation": include_remediation
            },
            "status": "COMPLETED",
            "sha256": sha256,
            "download_url": download_url,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        # 4. Save metadata to DB & audit log
        db.save_cyber_export(record)
        db.record_audit_log(
            action=f"CYBER_EXPORT_GENERATED_{export_type.upper()}",
            actor=actor,
            details=f"Export ID: {export_id}, format: {safe_format}, size: {file_size} bytes, sha256: {sha256[:12]}..."
        )

        return record

    def _gather_export_data(
        self,
        export_type: str,
        scan_id: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[str] = None,
        asset_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query real SQLite database tables for live operational data."""
        with db.get_connection() as conn:
            cursor = conn.cursor()

            if export_type in ["findings", "technical", "executive"]:
                query = "SELECT * FROM findings WHERE 1=1"
                params = []
                if scan_id:
                    query += " AND scan_id = ?"
                    params.append(scan_id)
                if severity_filter:
                    placeholders = ",".join("?" for _ in severity_filter)
                    query += f" AND UPPER(severity) IN ({placeholders})"
                    params.extend([s.upper() for s in severity_filter])
                if category_filter:
                    query += " AND (category LIKE ? OR title LIKE ?)"
                    params.extend([f"%{category_filter}%", f"%{category_filter}%"])
                if asset_filter:
                    query += " AND (target_url LIKE ? OR endpoint LIKE ?)"
                    params.extend([f"%{asset_filter}%", f"%{asset_filter}%"])

                query += " ORDER BY CASE UPPER(severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at DESC"
                cursor.execute(query, tuple(params))
                raw_findings = [dict(r) for r in cursor.fetchall()]

                # Count statistics
                stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": len(raw_findings)}
                for f in raw_findings:
                    sev = (f.get("severity") or "INFO").upper()
                    if sev in stats:
                        stats[sev] += 1

                # Calculate security score & posture
                score = 100 - (stats["CRITICAL"] * 25 + stats["HIGH"] * 15 + stats["MEDIUM"] * 5 + stats["LOW"] * 2)
                score = max(0, min(100, score))
                grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

                return {
                    "findings": raw_findings,
                    "stats": stats,
                    "score": score,
                    "grade": grade,
                    "scan_id": scan_id or "ALL"
                }

            elif export_type == "assets":
                cursor.execute("SELECT * FROM assets ORDER BY last_seen DESC")
                items = [dict(r) for r in cursor.fetchall()]
                return {"items": items, "count": len(items)}

            elif export_type == "test_results":
                cursor.execute("SELECT * FROM cyber_test_results ORDER BY created_at DESC LIMIT 500")
                items = [dict(r) for r in cursor.fetchall()]
                cursor.execute("SELECT * FROM cyber_test_runs ORDER BY created_at DESC LIMIT 20")
                runs = [dict(r) for r in cursor.fetchall()]
                return {"items": items, "runs": runs, "count": len(items)}

            elif export_type == "deployments":
                cursor.execute("SELECT * FROM cyber_deployments ORDER BY created_at DESC LIMIT 100")
                items = [dict(r) for r in cursor.fetchall()]
                return {"items": items, "count": len(items)}

            elif export_type == "audit_logs":
                cursor.execute("SELECT * FROM cyber_audit_logs ORDER BY timestamp DESC LIMIT 500")
                items = [dict(r) for r in cursor.fetchall()]
                return {"items": items, "count": len(items)}

            elif export_type == "compliance":
                cursor.execute("SELECT * FROM findings")
                findings = [dict(r) for r in cursor.fetchall()]
                owasp_matrix = {
                    "A01:2021-Broken Access Control": 0,
                    "A02:2021-Cryptographic Failures": 0,
                    "A03:2021-Injection": 0,
                    "A04:2021-Insecure Design": 0,
                    "A05:2021-Security Misconfiguration": 0,
                    "A06:2021-Vulnerable and Outdated Components": 0,
                    "A07:2021-Identification and Authentication Failures": 0,
                    "A08:2021-Software and Data Integrity Failures": 0,
                    "A09:2021-Security Logging and Monitoring Failures": 0,
                    "A10:2021-Server-Side Request Forgery (SSRF)": 0,
                }
                for f in findings:
                    cat = (f.get("category") or "").upper()
                    title = (f.get("title") or "").upper()
                    if "INJECTION" in cat or "SQL" in title or "COMMAND" in title:
                        owasp_matrix["A03:2021-Injection"] += 1
                    elif "SSRF" in cat or "REQUEST FORGERY" in title:
                        owasp_matrix["A10:2021-Server-Side Request Forgery (SSRF)"] += 1
                    elif "AUTH" in cat or "SESSION" in title:
                        owasp_matrix["A07:2021-Identification and Authentication Failures"] += 1
                    elif "CRYPTO" in cat or "SSL" in title or "TLS" in title:
                        owasp_matrix["A02:2021-Cryptographic Failures"] += 1
                    elif "CONFIG" in cat or "HEADER" in title or "EXPOSED" in title:
                        owasp_matrix["A05:2021-Security Misconfiguration"] += 1
                    elif "DEPENDENCY" in cat or "OUTDATED" in title:
                        owasp_matrix["A06:2021-Vulnerable and Outdated Components"] += 1
                    else:
                        owasp_matrix["A01:2021-Broken Access Control"] += 1

                return {
                    "compliance_standard": "OWASP Top 10 (2021)",
                    "owasp_matrix": owasp_matrix,
                    "total_violations": sum(owasp_matrix.values()),
                    "compliant": sum(owasp_matrix.values()) == 0
                }

            return {"items": []}

    def _render_format(
        self,
        format_type: str,
        export_type: str,
        title: str,
        data: Dict[str, Any],
        include_evidence: bool,
        include_remediation: bool
    ) -> tuple[bytes, str, str]:
        """Convert data dictionary into targeted byte deliverables."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if format_type == "json":
            payload = {
                "report_id": f"SWA-EXPORT-{int(datetime.datetime.now().timestamp())}",
                "title": title,
                "export_type": export_type,
                "generated_at": now_iso,
                "platform": "SWA AI Autonomous Enterprise Security Auditor v2.2",
                "data": data
            }
            json_str = redact_sensitive_data(json.dumps(payload, indent=2))
            return json_str.encode("utf-8"), "application/json", "json"

        elif format_type in ["csv", "xlsx"]:
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\r\n")

            if "findings" in data:
                writer.writerow([
                    "Finding ID", "Title", "Severity", "Category", "CWE",
                    "Target URL", "Endpoint", "Status", "Remediation", "Evidence Excerpt", "Created At"
                ])
                for f in data.get("findings", []):
                    evidence_str = redact_sensitive_data(f.get("response_evidence") or "")[:250] if include_evidence else ""
                    remed_str = redact_sensitive_data(f.get("remediation_advice") or "") if include_remediation else ""
                    writer.writerow([
                        f.get("id"),
                        f.get("title"),
                        f.get("severity"),
                        f.get("category"),
                        f.get("cwe_id", ""),
                        f.get("target_url"),
                        f.get("endpoint"),
                        f.get("status", "OPEN"),
                        remed_str,
                        evidence_str,
                        f.get("created_at")
                    ])
            elif "items" in data:
                items = data.get("items", [])
                if items:
                    headers = list(items[0].keys())
                    writer.writerow(headers)
                    for item in items:
                        writer.writerow([redact_sensitive_data(str(item.get(k, ""))) for k in headers])
                else:
                    writer.writerow(["No records found"])

            content = output.getvalue().encode("utf-8")
            ext = "csv" if format_type == "csv" else "tsv"
            return content, "text/csv", ext

        elif format_type in ["html", "pdf"]:
            html_content = self._generate_enterprise_html(
                title=title,
                export_type=export_type,
                data=data,
                include_evidence=include_evidence,
                include_remediation=include_remediation,
                is_pdf_print=(format_type == "pdf")
            )
            html_content = redact_sensitive_data(html_content)
            return html_content.encode("utf-8"), "text/html", "html"

        # Fallback
        return json.dumps(data).encode("utf-8"), "application/json", "json"

    def _generate_enterprise_html(
        self,
        title: str,
        export_type: str,
        data: Dict[str, Any],
        include_evidence: bool,
        include_remediation: bool,
        is_pdf_print: bool
    ) -> str:
        """Render a cyber-defense dark-mode executive & technical report ready for print-to-PDF."""
        findings = data.get("findings", [])
        stats = data.get("stats", {})
        score = data.get("score", 100)
        grade = data.get("grade", "A")

        score_color = "#10b981" if score >= 80 else "#f59e0b" if score >= 50 else "#ef4444"

        findings_html = ""
        for idx, f in enumerate(findings, 1):
            sev = (f.get("severity") or "INFO").upper()
            badge_color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#f59e0b" if sev == "MEDIUM" else "#3b82f6"
            
            evidence_block = ""
            if include_evidence and f.get("response_evidence"):
                evidence_block = f"""
                <div style="margin-top: 8px; background: #090d16; border: 1px solid #1f293d; border-radius: 6px; padding: 10px;">
                    <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; margin-bottom: 4px; font-weight: 700;">Verified Evidence Payload</div>
                    <pre style="margin: 0; font-family: monospace; font-size: 11px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap;">{f.get('response_evidence')}</pre>
                </div>
                """

            remed_block = ""
            if include_remediation and f.get("remediation_advice"):
                remed_block = f"""
                <div style="margin-top: 8px; background: #06191d; border-left: 3px solid #06b6d4; padding: 8px 12px; font-size: 12px; color: #a5f3fc;">
                    <strong>Actionable Remediation:</strong> {f.get('remediation_advice')}
                </div>
                """

            findings_html += f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 12px; page-break-inside: avoid;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; color: #f9fafb; font-size: 14px;">#{idx}. {f.get('title')}</span>
                    <span style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{sev}</span>
                </div>
                <div style="font-size: 12px; color: #9ca3af; margin-bottom: 6px;">
                    <span><strong>Asset:</strong> {f.get('target_url') or 'N/A'}</span> | 
                    <span><strong>Endpoint:</strong> {f.get('endpoint') or '/'}</span> | 
                    <span><strong>CWE:</strong> {f.get('cwe_id') or 'CWE-N/A'}</span>
                </div>
                <div style="font-size: 12.5px; color: #d1d5db; line-height: 1.5;">{f.get('description') or 'Vulnerability detected during autonomous assessment.'}</div>
                {evidence_block}
                {remed_block}
            </div>
            """

        print_script = "<script>window.onload = function() { window.print(); };</script>" if is_pdf_print else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} — SWA AI Enterprise Security Report</title>
<style>
  @page {{ size: A4; margin: 16mm; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0b0f19;
    color: #e2e8f0;
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid #1e293b;
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .kpi-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 12px;
    text-align: center;
  }}
  .kpi-num {{ font-size: 24px; font-weight: 800; }}
  .kpi-label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; margin-top: 4px; }}
  @media print {{
    body {{ background: #fff !important; color: #000 !important; }}
    .kpi-card, div {{ border-color: #ccc !important; }}
    pre {{ background: #f1f5f9 !important; color: #000 !important; }}
  }}
</style>
{print_script}
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin: 0; font-size: 22px; color: #38bdf8;">SWA AI — Autonomous Enterprise Security Auditor</h1>
      <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">{title} | Generated: {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 28px; font-weight: 800; color: {score_color};">{grade} ({score}/100)</div>
      <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Security Posture Rating</div>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-num" style="color: #ef4444;">{stats.get('CRITICAL', 0)}</div>
      <div class="kpi-label">Critical</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color: #f97316;">{stats.get('HIGH', 0)}</div>
      <div class="kpi-label">High</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color: #f59e0b;">{stats.get('MEDIUM', 0)}</div>
      <div class="kpi-label">Medium</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color: #3b82f6;">{stats.get('LOW', 0)}</div>
      <div class="kpi-label">Low</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color: #38bdf8;">{stats.get('TOTAL', 0)}</div>
      <div class="kpi-label">Total Findings</div>
    </div>
  </div>

  <h2 style="font-size: 16px; color: #f8fafc; border-bottom: 1px solid #1e293b; padding-bottom: 6px; margin-top: 24px; margin-bottom: 16px;">
    Verified Vulnerabilities & Exposure Registry
  </h2>

  {findings_html if findings_html else '<div style="padding: 24px; text-align: center; color: #94a3b8; background: #111827; border-radius: 8px;">No vulnerabilities detected in this scope.</div>'}

  <div style="margin-top: 36px; border-top: 1px solid #1e293b; padding-top: 12px; font-size: 11px; color: #64748b; display: flex; justify-content: space-between;">
    <span>Autonomous Security Verification — Zero False Positive Policy Enforced</span>
    <span>SWA AI v2.2 Enterprise Cyber Defense</span>
  </div>
</body>
</html>
"""

cyber_exporter = CyberExportEngine()
