"""
SWA AI Web Application & REST API Server
Asynchronous FastAPI server with background task dispatch,
WebSocket live feeds, and full report download endpoints.
"""

import os
import asyncio
from typing import List, Optional, Literal
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Response, Query, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.models import ScanJob, ScanConfig, ScanStatus, VulnerabilityFinding, LogEvent
from core.database import db
from core.queue_manager import queue_manager
from agents.orchestrator import SWAOrchestrator
from reports.generator import ReportGenerator
from plugins.plugin_manager import plugin_manager

app = FastAPI(
    title="SWA AI Autonomous Pentesting Engine",
    description="SWA AI agentic red teaming and automated security vulnerability discovery platform.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

@app.post("/api/scans", response_model=ScanJob)
async def launch_scan(config: ScanConfig):
    """
    Launch an autonomous security assessment.
    Takes a domain/URL or IP, creates a background job, and immediately returns.
    All execution happens in the background.
    """
    target = config.target_url.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target URL/domain is required")

    job = ScanJob(
        target_url=target,
        status=ScanStatus.PENDING,
        profile=config.profile,
        config=config
    )
    db.save_scan(job)

    # Launch in background worker
    orchestrator = SWAOrchestrator(job)
    task = asyncio.create_task(orchestrator.execute())
    queue_manager.active_tasks[job.id] = task

    return job

@app.get("/api/scans", response_model=List[ScanJob])
async def list_scans():
    """List all scans with status, duration, and finding counts."""
    return db.list_scans()

@app.get("/api/scans/{scan_id}", response_model=ScanJob)
async def get_scan(scan_id: str):
    """Get scan details, progress, and reconnaissance summary."""
    job = db.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job

@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel an active background scan."""
    success = queue_manager.cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=400, detail="Scan is not running or already completed")
    return {"status": "cancelled", "scan_id": scan_id}

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and all associated findings and logs."""
    success = db.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "scan_id": scan_id}

@app.get("/api/scans/{scan_id}/findings", response_model=List[VulnerabilityFinding])
async def get_scan_findings(scan_id: str):
    """Get all verified vulnerabilities and PoCs discovered for this scan."""
    return db.list_findings(scan_id)

@app.get("/api/findings/{finding_id}", response_model=VulnerabilityFinding)
async def get_finding_detail(finding_id: str):
    """Get full details of a specific finding including PoC cURL and code patch."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@app.get("/api/scans/{scan_id}/logs", response_model=List[LogEvent])
async def get_scan_logs(scan_id: str, limit: int = 500):
    """Retrieve terminal log stream events for a scan."""
    return db.get_logs(scan_id, limit=limit)

@app.get("/api/scans/{scan_id}/report")
async def export_report(scan_id: str, format: Literal["html", "json", "sarif", "markdown"] = "html"):
    """Export complete penetration testing report in HTML, JSON, SARIF 2.1.0, or Markdown."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.list_findings(scan_id)
    generator = ReportGenerator(scan, findings)

    if format == "json":
        return Response(content=generator.generate_json(), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=swa_{scan_id}.json"})
    elif format == "sarif":
        return Response(content=generator.generate_sarif(), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=swa_{scan_id}.sarif"})
    elif format == "markdown":
        return PlainTextResponse(content=generator.generate_markdown(), headers={"Content-Disposition": f"attachment; filename=swa_{scan_id}.md"})
    else:
        return HTMLResponse(content=generator.generate_html())

@app.get("/api/scans/{scan_id}/defenses")
async def get_scan_defenses(scan_id: str):
    """Retrieve automated Blue Team defenses: WAF rules, Suricata/Snort IDS rules, Sigma/SIEM rules, and server hardening configs."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.list_findings(scan_id)
    from core.blue_team_engine import BlueTeamDefenseEngine
    engine = BlueTeamDefenseEngine(scan, findings)
    return engine.generate_all()

class ForensicsPayload(BaseModel):
    raw_logs: Optional[str] = ""
    sample_key: Optional[str] = None

@app.get("/api/forensics/samples")
async def get_forensics_samples():
    """Retrieve pre-built attack investigation log scenarios across operating systems."""
    from core.forensics_engine import ForensicsEngine
    return ForensicsEngine.SAMPLE_LOGS

@app.post("/api/forensics/analyze")
async def analyze_logs(payload: ForensicsPayload):
    """Analyze web and server logs for attack footprints, IoCs, and threat actors across all operating systems."""
    from core.forensics_engine import ForensicsEngine
    raw = payload.raw_logs or ""
    if not raw.strip() and payload.sample_key and payload.sample_key in ForensicsEngine.SAMPLE_LOGS:
        raw = ForensicsEngine.SAMPLE_LOGS[payload.sample_key]["logs"]

    if not raw.strip():
        raise HTTPException(status_code=400, detail="No logs provided for forensic analysis")

    engine = ForensicsEngine(raw)
    return engine.analyze()

@app.get("/api/scans/{scan_id}/forensics")
async def get_scan_forensic_profile(scan_id: str):
    """Generate forensic hunt patterns, expected log footprints, and threat detection queries for scan findings."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.list_findings(scan_id)

    hunt_signatures = []
    for f in findings:
        from urllib.parse import urlparse
        path = urlparse(f.endpoint).path or f.endpoint
        param = f.parameter or ""
        hunt_signatures.append({
            "finding_id": f.id,
            "title": f.title,
            "severity": f.severity,
            "endpoint": path,
            "parameter": param,
            "grep_command": f'grep -iE "{param or path}.*(\\\'|--|union|<script|%2e%2e)" /var/log/nginx/access.log',
            "powershell_command": f'Select-String -Path "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log" -Pattern "{path}"',
            "splunk_query": f'index=web status>=200 uri_path="*{path}*"',
            "elastic_query": f'url.path: "*{path}*" AND (http.response.status_code: [200 TO 599])'
        })

    return {
        "scan_id": scan_id,
        "target": scan.target_url,
        "total_findings": len(findings),
        "threat_hunt_profiles": hunt_signatures
    }


class SettingsPayload(BaseModel):
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_base_url: Optional[str] = None

@app.get("/api/settings")
async def get_settings():
    """Get current configuration and environment status."""
    return {
        "ai_provider": db.get_setting("ai_provider", "auto"),
        "ai_model": db.get_setting("ai_model", "openrouter/z-ai/glm-5.3"),
        "ai_base_url": db.get_setting("ai_base_url", ""),
        "has_api_key": bool(db.get_setting("ai_api_key", "") or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")),
        "default_budget": 10
    }

@app.post("/api/settings")
async def update_settings(settings: SettingsPayload):
    """Persist settings across scans."""
    if settings.ai_provider:
        db.set_setting("ai_provider", settings.ai_provider)
    if settings.ai_model:
        db.set_setting("ai_model", settings.ai_model)
    if settings.ai_base_url is not None:
        db.set_setting("ai_base_url", settings.ai_base_url)
    if settings.ai_api_key:
        db.set_setting("ai_api_key", settings.ai_api_key)
    return {"status": "saved"}

@app.get("/api/plugins")
async def list_plugins():
    """List all registered OWASP Top 10 and security plugins with status."""
    return plugin_manager.list_plugins()

@app.post("/api/plugins/{plugin_id}/toggle")
async def toggle_plugin(plugin_id: str, enabled: Optional[bool] = None):
    """Enable or disable a specific security plugin."""
    success = plugin_manager.toggle_plugin(plugin_id, enabled)
    p = plugin_manager.get_plugin(plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"plugin_id": plugin_id, "enabled": p.enabled}

@app.get("/api/plugins/owasp-matrix")
async def get_owasp_matrix():
    """Retrieve full OWASP Top 10 coverage matrix."""
    return plugin_manager.get_owasp_matrix()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Live WebSocket dispatching real-time scan progress, logs, and discoveries."""
    await websocket.accept()
    q = queue_manager.register_client()
    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        queue_manager.unregister_client(q)
    except Exception:
        queue_manager.unregister_client(q)

# Mount static web UI files
if os.path.exists(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
