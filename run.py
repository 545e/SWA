#!/usr/bin/env python3
"""
SWA AI Autonomous Pentesting Platform - Launcher
Execute this script to start the background Web UI on http://127.0.0.1:8000
"""

import sys
import os
import uvicorn

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    banner = """
  ==============================================
   SWA AI - Autonomous Red Team Engine v2.0
   Autonomous Multi-Agent Pentesting Platform
  ==============================================
    """
    print(banner)
    print("[+] Launching SWA AI Security Operations Center Dashboard...")
    print("[+] Web Interface available at: http://127.0.0.1:8000")
    print("[i] Enter any target domain/URL in the UI to launch automated background scans.\n")

    uvicorn.run("web.server:app", host="127.0.0.1", port=8000, log_level="info")
