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
