"""
SWA AI Async Queue & Event Bus Manager
Handles concurrent background scan jobs and real-time WebSocket subscriber dispatch.
"""

import asyncio
from typing import Dict, Set, Callable, Awaitable, Optional, Any
from core.models import ScanJob, LogEvent, VulnerabilityFinding, ScanStatus
from core.database import db

class QueueManager:
    def __init__(self):
        self.active_tasks: Dict[str, asyncio.Task] = {}
        self.subscribers: Set[asyncio.Queue] = set()
        self.log_subscribers: Dict[str, Set[asyncio.Queue]] = {} # scan_id -> queues

    def register_client(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self.subscribers.add(q)
        return q

    def unregister_client(self, q: asyncio.Queue):
        self.subscribers.discard(q)

    def register_scan_log_client(self, scan_id: str) -> asyncio.Queue:
        if scan_id not in self.log_subscribers:
            self.log_subscribers[scan_id] = set()
        q = asyncio.Queue()
        self.log_subscribers[scan_id].add(q)
        return q

    def unregister_scan_log_client(self, scan_id: str, q: asyncio.Queue):
        if scan_id in self.log_subscribers:
            self.log_subscribers[scan_id].discard(q)
            if not self.log_subscribers[scan_id]:
                del self.log_subscribers[scan_id]

    async def broadcast_event(self, event_type: str, data: Any):
        payload = {"type": event_type, "data": data}
        dead_queues = []
        for q in self.subscribers:
            try:
                q.put_nowait(payload)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            self.subscribers.discard(dq)

    async def emit_log(self, event: LogEvent):
        db.add_log(event)
        # Broadcast to specific scan listeners
        if event.scan_id in self.log_subscribers:
            dead_queues = []
            for q in self.log_subscribers[event.scan_id]:
                try:
                    q.put_nowait({"type": "LOG_EVENT", "data": event.model_dump()})
                except Exception:
                    dead_queues.append(q)
            for dq in dead_queues:
                self.log_subscribers[event.scan_id].discard(dq)
        
        # Also broadcast light event to general subscribers
        await self.broadcast_event("LOG_EVENT", {
            "scan_id": event.scan_id,
            "level": event.level,
            "agent": event.agent,
            "message": event.message,
            "timestamp": event.timestamp
        })

    async def emit_finding(self, finding: VulnerabilityFinding):
        db.add_finding(finding)
        await self.broadcast_event("FINDING_DISCOVERED", {
            "scan_id": finding.scan_id,
            "finding": finding.model_dump()
        })

    async def emit_progress(self, scan_id: str, progress: int, phase: str):
        db.update_scan_progress(scan_id, progress, phase)
        await self.broadcast_event("PROGRESS_UPDATE", {
            "scan_id": scan_id,
            "progress_percent": progress,
            "current_phase": phase
        })

    def cancel_scan(self, scan_id: str) -> bool:
        if scan_id in self.active_tasks:
            task = self.active_tasks[scan_id]
            task.cancel()
            db.update_scan_status(scan_id, ScanStatus.CANCELLED)
            db.update_scan_progress(scan_id, 100, "Cancelled by user")
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.broadcast_event("SCAN_CANCELLED", {"scan_id": scan_id}))
            except RuntimeError:
                pass
            return True
        return False

    def is_scan_running(self, scan_id: str) -> bool:
        return scan_id in self.active_tasks and not self.active_tasks[scan_id].done()

queue_manager = QueueManager()
