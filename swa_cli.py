"""
SWA AI CLI & Web Runner
Unified entry point supporting both headless terminal scans
and the real-time background Web Application.
"""

import sys
import os
import argparse
import asyncio
import uvicorn

# Fix Windows terminal UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.models import ScanConfig, ScanJob, ScanProfile, ScanStatus
from core.database import db
from core.queue_manager import queue_manager
from agents.orchestrator import SWAOrchestrator
from reports.generator import ReportGenerator

def print_banner():
    banner = """
  ==============================================
   SWA AI - Autonomous Red Team Engine v2.0
   Autonomous Multi-Agent Pentesting Platform
  ==============================================
    """
    print(banner)

async def run_cli_scan(args):
    print(f"\033[96m[+] Initializing autonomous red team against: {args.target}\033[0m")
    print(f"[+] Scan Profile: {args.profile}")

    config = ScanConfig(
        target_url=args.target,
        profile=ScanProfile(args.profile),
        max_depth=args.depth,
        concurrency=args.concurrency
    )

    job = ScanJob(
        target_url=args.target,
        status=ScanStatus.PENDING,
        profile=config.profile,
        config=config
    )
    db.save_scan(job)

    # Listen to logs and print to terminal
    q = queue_manager.register_client()
    orchestrator = SWAOrchestrator(job)
    scan_task = asyncio.create_task(orchestrator.execute())

    async def log_printer():
        while not scan_task.done():
            try:
                event = await asyncio.wait_for(q.get(), timeout=0.5)
                if event.get("type") == "LOG_EVENT":
                    d = event["data"]
                    color = "\033[92m" if d["level"] == "SUCCESS" else ("\033[91m" if d["level"] in ["ERROR", "FINDING"] else "\033[93m" if d["level"] == "WARN" else "\033[90m")
                    print(f"{color}[{d.get('timestamp')}] [{d.get('agent')}] {d.get('message')}\033[0m")
            except asyncio.TimeoutError:
                pass
            except Exception:
                break

    await asyncio.gather(scan_task, log_printer())
    queue_manager.unregister_client(q)

    # Output summary
    completed_job = db.get_scan(job.id)
    findings = db.list_findings(job.id)
    generator = ReportGenerator(completed_job, findings)

    print("\n\033[92m[✓] Scan Completed Successfully!\033[0m")
    print(f"[+] Duration: {completed_job.duration_seconds}s | Discovered Findings: {len(findings)}")

    if args.export_html:
        with open(args.export_html, "w", encoding="utf-8") as f:
            f.write(generator.generate_html())
        print(f"[+] HTML Report saved: {args.export_html}")

    if args.export_sarif:
        with open(args.export_sarif, "w", encoding="utf-8") as f:
            f.write(generator.generate_sarif())
        print(f"[+] SARIF 2.1.0 saved: {args.export_sarif}")

    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            f.write(generator.generate_json())
        print(f"[+] JSON Report saved: {args.export_json}")

    if args.export_md:
        with open(args.export_md, "w", encoding="utf-8") as f:
            f.write(generator.generate_markdown())
        print(f"[+] Markdown Report saved: {args.export_md}")

    # Return exit code: 0 if clean, 2 if vulnerabilities found
    sys.exit(2 if len(findings) > 0 else 0)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SWA AI Autonomous Penetration Testing Platform")
    parser.add_argument("-t", "--target", type=str, help="Target domain, URL, or IP address")
    parser.add_argument("-p", "--profile", type=str, default="full_red_team", choices=["quick", "full_red_team", "owasp_top10", "api_security", "recon_only"], help="Assessment profile")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency limit")
    parser.add_argument("--web", action="store_true", help="Launch interactive Web Application GUI")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Web host")
    parser.add_argument("--port", type=int, default=8000, help="Web port")
    parser.add_argument("--export-html", type=str, help="Save report as HTML")
    parser.add_argument("--export-sarif", type=str, help="Save report as SARIF 2.1.0")
    parser.add_argument("--export-json", type=str, help="Save report as JSON")
    parser.add_argument("--export-md", type=str, help="Save report as Markdown")

    args = parser.parse_args()

    if args.web or not args.target:
        print(f"\033[92m[⚡] Starting SWA AI Web Server on http://{args.host}:{args.port}\033[0m")
        print(f"[+] Open http://{args.host}:{args.port} in your browser to enter targets and monitor background scans.\n")
        uvicorn.run("web.server:app", host=args.host, port=args.port, reload=False)
    else:
        asyncio.run(run_cli_scan(args))

if __name__ == "__main__":
    main()
