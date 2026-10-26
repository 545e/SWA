"""
SWA AI Webhook & Notification Dispatcher
Sends real-time findings and scan completion events to Slack, Discord,
or custom HMAC-signed webhooks.
"""

import hmac
import hashlib
import json
import httpx
from typing import Dict, Any, Optional

class NotificationDispatcher:
    @staticmethod
    async def send_slack_alert(webhook_url: str, title: str, severity: str, endpoint: str, details: str) -> bool:
        """Sends a rich Slack block-kit alert for high/critical findings."""
        if not webhook_url:
            return False

        color_map = {
            "CRITICAL": "#f85149",
            "HIGH": "#f0883e",
            "MEDIUM": "#d29922",
            "LOW": "#58a6ff",
            "INFO": "#8b949e"
        }
        color = color_map.get(severity.upper(), "#6366f1")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 [{severity.upper()}] {title}",
                    "fields": [
                        {"title": "Target Endpoint", "value": f"`{endpoint}`", "short": False},
                        {"title": "Analysis / Impact", "value": details[:300], "short": False}
                    ],
                    "footer": "SWA AI Autonomous Cyber Auditor",
                    "ts": int(__import__("time").time())
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code == 200
        except Exception:
            return False

    @staticmethod
    async def send_custom_webhook(webhook_url: str, event_type: str, data: Dict[str, Any], secret: Optional[str] = None) -> bool:
        """Dispatches an HMAC-SHA256 signed JSON payload to an enterprise SIEM / SOAR endpoint."""
        if not webhook_url:
            return False

        payload_bytes = json.dumps(data, default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-SWA-Event": event_type
        }
        if secret:
            sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
            headers["X-SWA-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(webhook_url, content=payload_bytes, headers=headers)
                return res.status_code in [200, 201, 202, 204]
        except Exception:
            return False
