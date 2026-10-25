#!/usr/bin/env python3
"""
SWA AI Autonomous Pentesting Platform - Launcher
Execute this script to start the background Web UI on http://127.0.0.1:8000
Automatically opens browser and manages port conflicts.
"""

import sys
import os
import socket
import threading
import time
import webbrowser
import uvicorn

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def find_available_port(start_port: int = 8000, max_attempts: int = 10) -> int:
    for p in range(start_port, start_port + max_attempts):
        if not is_port_in_use(p):
            return p
    return start_port

def open_browser(url: str, delay: float = 1.2):
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()

if __name__ == "__main__":
    banner = """
  ==============================================
   SWA AI - Autonomous Cyber Suite v2.1
   Autonomous Multi-Agent Pentesting Platform
  ==============================================
    """
    print(banner)

    host = "127.0.0.1"
    target_port = 8000
    
    # Check if port 8000 is occupied
    actual_port = find_available_port(target_port)
    if actual_port != target_port:
        print(f"[!] Notice: Port {target_port} is currently in use by another process.")
        print(f"[+] Automatically switching to available port: {actual_port}")
    
    server_url = f"http://{host}:{actual_port}"
    print(f"[+] Launching SWA AI Security Operations Center Dashboard...")
    print(f"[✓] Web Interface available at: {server_url}")
    print(f"[+] Opening browser automatically at {server_url} ...")
    print(f"[i] Keep this terminal window open while using SWA.\n")

    # Auto-open browser
    open_browser(server_url)

    # Start Uvicorn
    uvicorn.run("web.server:app", host=host, port=actual_port, log_level="info")
