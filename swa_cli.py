"""
SWA AI CLI & Web Runner
Unified entry point supporting autonomous multi-agent red team scans,
on-demand semi-automatic cyber tools, and the real-time background Web Application.
"""


import sys
import os
import argparse
import asyncio
import json
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
   SWA AI - Autonomous Red Team Engine v2.1
   Autonomous & Semi-Automatic Cyber Suite
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
        concurrency=args.concurrency,
        lab_mode=getattr(args, "lab_mode", False),
        enable_sqlmap_lab=getattr(args, "enable_sqlmap", False)
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


    # Return exit code: 0 if clean or if --exit-zero set; 2 if findings discovered
    if getattr(args, "exit_zero", False):
        sys.exit(0)
    sys.exit(2 if len(findings) > 0 else 0)


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SWA AI Autonomous Penetration Testing Platform & Cyber Toolkit")
    
    # Red Team Scan Options
    parser.add_argument("-t", "--target", type=str, help="Target domain, URL, or IP address for full assessment")
    parser.add_argument("-p", "--profile", type=str, default="full_red_team", choices=["quick", "full_red_team", "owasp_top10", "api_security", "recon_only"], help="Assessment profile")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency limit")
    parser.add_argument("--lab-mode", action="store_true", help="Authorize local lab testing (localhost, 127.0.0.1, DVWA, PortSwigger)")
    parser.add_argument("--enable-sqlmap", action="store_true", help="Enable optional non-destructive SQLmap detection on authorized lab targets")
    parser.add_argument("--check-tools", action="store_true", help="Check system availability for Nmap, Nuclei, ZAP, SQLmap, and Native engines")
    parser.add_argument("--exit-zero", action="store_true", help="Always return exit code 0 even if vulnerabilities are found (prevents CI fail)")
    parser.add_argument("--web", action="store_true", help="Launch interactive Web Application GUI")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Web host")
    parser.add_argument("--port", type=int, default=8000, help="Web port")
    parser.add_argument("--export-html", type=str, help="Save report as HTML")
    parser.add_argument("--export-sarif", type=str, help="Save report as SARIF 2.1.0")
    parser.add_argument("--export-json", type=str, help="Save report as JSON")
    parser.add_argument("--export-md", type=str, help="Save report as Markdown")
    
    # Forensics & DFIR
    parser.add_argument("--forensics-log", type=str, help="Analyze local server access log for attack footprints & IoCs (Windows, Linux, macOS)")
    parser.add_argument("--forensics-sample", type=str, choices=["apache_nginx", "windows_iis", "wordpress_brute"], help="Analyze built-in forensic test scenario")
    parser.add_argument("--amass", type=str, help="Run standalone OWASP Amass asset discovery & subdomain takeover scan on domain")
    parser.add_argument("--subdomains", type=str, help="Autonomous multi-source subdomain discovery & asset mapping for domain")
    parser.add_argument("--recursive", action="store_true", help="Enable autonomous multi-tier recursive subdomain discovery")
    parser.add_argument("--export-subs", type=str, help="Export discovered subdomains to file (.txt or .json)")
    
    # Semi-Automatic Cyber Expert Tools
    parser.add_argument("--dns", type=str, help="Resolve DNS records (A, AAAA, MX, TXT, NS, CNAME) and SPF/DMARC posture")
    parser.add_argument("--headers", type=str, help="Audit HTTP security headers and evaluate grade (A+ to F)")
    parser.add_argument("--ssl", type=str, help="Inspect SSL/TLS certificate, cipher suite, issuer, and days to expiration")
    parser.add_argument("--ssl-port", type=int, default=443, help="Port for SSL/TLS inspection (default: 443)")
    parser.add_argument("--ports", type=str, help="Asynchronously probe TCP ports on host")
    parser.add_argument("--port-list", type=str, help="Comma-separated port numbers to probe (e.g. 80,443,8080,8443)")
    parser.add_argument("--whois", type=str, help="Lookup RDAP / IP Threat Intelligence and ASN")
    parser.add_argument("--hash", type=str, help="Calculate cryptographic hashes (MD5, SHA1, SHA256, SHA512, NTLM)")
    parser.add_argument("--jwt", type=str, help="Decode, inspect, and analyze JSON Web Token (JWT)")
    parser.add_argument("--cidr", type=str, help="Calculate CIDR subnet IP range, netmask, wildcard mask, and usable host count")
    parser.add_argument("--probe", type=str, help="Instant single-vector vulnerability probe URL")
    parser.add_argument("--probe-vuln", type=str, default="sqli", choices=["sqli", "xss", "lfi", "cors", "ssrf"], help="Vulnerability type for targeted probe")
    parser.add_argument("--probe-param", type=str, help="Parameter name to probe (defaults to first query param or 'q')")
    parser.add_argument("--revshell", action="store_true", help="Generate authorized penetration testing reverse shell reference templates")
    parser.add_argument("--shell-ip", type=str, default="10.10.14.5", help="LHOST IP for reverse shell generator")
    parser.add_argument("--shell-port", type=int, default=4444, help="LPORT for reverse shell generator")
    parser.add_argument("--shell-type", type=str, default="all", help="Shell type (bash, python3, powershell, netcat_openbsd, all)")
    # Autonomous Continuous Surveillance Daemon
    parser.add_argument("--daemon", action="store_true", help="Run SWA AI as an autonomous background surveillance daemon")
    parser.add_argument("--targets", type=str, default="config/targets.json", help="Path to targets JSON file for autonomous monitoring (default: config/targets.json)")
    parser.add_argument("--interval-hours", type=float, default=12.0, help="Surveillance cycle interval in hours (default: 12.0)")

    # JavaScript Intelligence & GhostJS Secret Scanner
    parser.add_argument("--js-scan", type=str, help="Autonomous JavaScript & Web asset intelligence: scan website and all referenced JS bundles for secrets, endpoints & cloud buckets")
    parser.add_argument("--js-file", type=str, help="Scan local JavaScript, JSON, or HTML file for secrets and endpoints")
    parser.add_argument("--no-active-fetch", action="store_true", help="Disable active fetching of external JS bundles referenced in HTML")
    parser.add_argument("--export-js", type=str, help="Export JavaScript analysis findings to file (.json or .txt)")


    args = parser.parse_args()

    if getattr(args, "check_tools", False):
        from core.scanner_integrations import ScannerIntegrations
        inv = ScannerIntegrations.get_tool_inventory()
        print("\033[96m[+] System Cybersecurity Tool Inventory & Availability:\033[0m\n")
        for tool, meta in inv.items():
            status_color = "\033[92m[INSTALLED]\033[0m" if meta["installed"] else "\033[93m[NOT INSTALLED]\033[0m"
            print(f"  {status_color} {meta['name']}")
            print(f"      Capability: {meta['capability']}")
            if meta["installed"]:
                print(f"      Path: {meta['binary_path']} | Version: {meta.get('version') or 'detected'}")
            else:
                print(f"      Guidance: {meta['install_guide']}")
            print()
        return
    # 0. Autonomous Surveillance Daemon Mode
    if args.daemon:
        from core.autonomous_daemon import AutonomousCyberDaemon
        daemon = AutonomousCyberDaemon(
            targets_file=args.targets,
            interval_hours=args.interval_hours,
            recursive=args.recursive
        )
        try:
            asyncio.run(daemon.start())
        except KeyboardInterrupt:
            print("\n\033[93m[!] Autonomous Cyber Daemon stopped by user.\033[0m")
        return


    # 1. DNS Tool
    if args.dns:
        from core.cyber_tools import DNSLookupTool
        print(f"\033[96m[+] Resolving DNS & Email Security Posture for: {args.dns}\033[0m")
        res = asyncio.run(DNSLookupTool.resolve(args.dns))
        print(f"[+] Domain: {res['domain']}")
        for rtype, vals in res.get("records", {}).items():
            if vals:
                print(f"    - {rtype:<6}: {', '.join(vals)}")
        es = res.get("email_security", {})
        posture_color = "\033[92m" if es.get("posture") == "EXCELLENT" else "\033[93m" if es.get("posture") == "PARTIAL" else "\033[91m"
        print(f"\n[!] Email Spoofing Defense: {posture_color}{es.get('posture')}\033[0m")
        if es.get("spf_record"): print(f"    SPF:   {es['spf_record']}")
        if es.get("dmarc_record"): print(f"    DMARC: {es['dmarc_record']}")
        for note in es.get("notes", []):
            print(f"    Note:  {note}")
        return


    # 2. Security Headers Tool
    if args.headers:
        from core.cyber_tools import SecurityHeadersTool
        print(f"\033[96m[+] Auditing HTTP Security Headers on: {args.headers}\033[0m")
        res = asyncio.run(SecurityHeadersTool.evaluate(args.headers))
        if "error" in res:
            print(f"\033[91m[-] {res['error']}\033[0m")
            return
        grade_color = "\033[92m" if res['grade'] in ['A+', 'A'] else "\033[93m" if res['grade'] in ['B', 'C'] else "\033[91m"
        print(f"\n[✓] Score: {res['score']}/100 | Security Grade: {grade_color}{res['grade']}\033[0m")
        print(f"{'HEADER':<38} {'STATUS':<10} {'WEIGHT':<8}")
        print("-" * 60)
        for h in res.get("security_headers", []):
            color = "\033[92m" if h['status'] == 'PASS' else "\033[91m"
            print(f"{h['header']:<38} {color}{h['status']:<10}\033[0m {h['weight']}")
        if res.get("leakage_headers"):
            print("\n\033[93m[!] Information Disclosure Banners:\033[0m")
            for leak in res["leakage_headers"]:
                print(f"    - {leak['header']}: {leak['value']}")
        return


    # 3. SSL / TLS Tool
    if args.ssl:
        from core.cyber_tools import SSLCertificateTool
        print(f"\033[96m[+] Inspecting SSL/TLS Certificate for: {args.ssl}:{args.ssl_port}\033[0m")
        res = asyncio.run(SSLCertificateTool.inspect(args.ssl, port=args.ssl_port))
        if not res.get("valid"):
            print(f"\033[91m[-] {res.get('error', 'SSL Inspection failed')}\033[0m")
            return
        print(f"[+] Common Name (CN):   {res.get('common_name')}")
        print(f"[+] Issuer CA:          {res.get('issuer_organization') or res.get('issuer')}")
        print(f"[+] TLS Protocol:       {res.get('tls_version')}")
        print(f"[+] Active Cipher:      {res.get('cipher_suite')} ({res.get('cipher_bits')} bits)")
        print(f"[+] Valid From:         {res.get('valid_from')}")
        print(f"[+] Valid Until:        {res.get('valid_to')}")
        days = res.get('days_remaining')
        exp_color = "\033[91m" if res.get('is_expired') or res.get('expiring_soon') else "\033[92m"
        print(f"[!] Expiration Status:  {exp_color}{days} days remaining (Expired: {res.get('is_expired')})\033[0m")
        if res.get("sans"):
            print(f"[+] SANs ({res.get('san_count')} total): {', '.join(res['sans'][:8])}...")
        return


    # 4. Port Prober Tool
    if args.ports:
        from core.cyber_tools import PortProberTool
        port_list = None
        if args.port_list:
            try:
                port_list = [int(p.strip()) for p in args.port_list.split(",") if p.strip()]
            except Exception:
                print("[-] Invalid port list format. Use e.g. 80,443,8080")
                return
        print(f"\033[96m[+] Probing TCP ports on: {args.ports}\033[0m")
        res = asyncio.run(PortProberTool.scan(args.ports, ports=port_list))
        print(f"\n[✓] Port Probe Complete! Open: {res['open_count']} | Closed/Filtered: {res['closed_count']}")
        print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<22} {'BANNER'}")
        print("-" * 65)
        for p in res.get("open_ports", []):
            print(f"\033[92m{p['port']:<8} {p['state']:<10}\033[0m {p['service']:<22} {p.get('banner','')}")
        return


    # 5. WHOIS / IP Intelligence Tool
    if args.whois:
        from core.cyber_tools import WhoisIpTool
        print(f"\033[96m[+] Querying Threat Intelligence & ASN for: {args.whois}\033[0m")
        res = asyncio.run(WhoisIpTool.lookup(args.whois))
        print(f"[+] Query:        {res.get('query')}")
        print(f"[+] Resolved IP:  {res.get('resolved_ip')}")
        print(f"[+] Organization: {res.get('org') or 'N/A'}")
        print(f"[+] ISP / Entity: {res.get('isp') or 'N/A'}")
        print(f"[+] Registry:     {res.get('rdap_source') or 'ARIN/RDAP'}")
        return


    # 6. Cryptography & Hashing Tool
    if args.hash:
        from core.cyber_tools import CryptoEncoderTool
        res = CryptoEncoderTool.calculate_hashes(args.hash)
        print(f"\033[96m[+] Cryptographic Hashes for input string: '{args.hash}'\033[0m")
        print(f"    MD5:    {res['md5']}")
        print(f"    SHA1:   {res['sha1']}")
        print(f"    SHA256: {res['sha256']}")
        print(f"    SHA512: {res['sha512']}")
        print(f"    NTLM:   {res['ntlm']}")
        return


    # 7. JWT Inspector Tool
    if args.jwt:
        from core.cyber_tools import CryptoEncoderTool
        print("\033[96m[+] Inspecting JSON Web Token (JWT)\033[0m")
        res = CryptoEncoderTool.inspect_jwt(args.jwt)
        if "error" in res:
            print(f"\033[91m[-] {res['error']}\033[0m")
            return
        print(f"[+] Algorithm:    {res.get('algorithm')}")
        print(f"[+] Issued At:    {res.get('issued_at') or 'N/A'}")
        print(f"[+] Expires At:   {res.get('expires_at') or 'No expiration set'}")
        print(f"[+] Is Expired:   {res.get('is_expired')}")
        for w in res.get("security_warnings", []):
            print(f"\033[91m[!] WARNING: {w}\033[0m")
        print("\n[+] Decoded Header:")
        print(json.dumps(res.get("header"), indent=2))
        print("\n[+] Decoded Payload:")
        print(json.dumps(res.get("payload"), indent=2))
        return


    # 8. CIDR Subnet Calculator Tool
    if args.cidr:
        from core.cyber_tools import SubnetCalculatorTool
        res = SubnetCalculatorTool.calculate(args.cidr)
        if "error" in res:
            print(f"\033[91m[-] {res['error']}\033[0m")
            return
        print(f"\033[96m[+] Subnet Calculation for: {args.cidr}\033[0m")
        print(f"    IP Version:      {res['version']}")
        print(f"    Network Address: {res['network_address']}")
        print(f"    Broadcast:       {res['broadcast_address']}")
        print(f"    Netmask:         {res['netmask']}")
        print(f"    Wildcard Mask:   {res['wildcard_mask']}")
        print(f"    Usable Range:    {res['first_usable_ip']} - {res['last_usable_ip']}")
        print(f"    Total Hosts:     {res['total_addresses']}")
        print(f"    Usable Hosts:    {res['usable_hosts']}")
        print(f"    Private IP:      {res['is_private']}")
        return


    # 9. Targeted Single-Vector Vulnerability Probe
    if args.probe:
        from core.cyber_tools import TargetedVulnProberTool
        print(f"\033[96m[+] Executing targeted {args.probe_vuln.upper()} probe on: {args.probe}\033[0m")
        res = asyncio.run(TargetedVulnProberTool.probe(args.probe, args.probe_vuln, parameter=args.probe_param))
        if res.get("vulnerable"):
            print(f"\n\033[91m[!] VULNERABILITY CONFIRMED: {res.get('vuln_type')}\033[0m")
            print(f"[+] Endpoint:       {res.get('target_url')}")
            if res.get("parameter"): print(f"[+] Parameter:      {res.get('parameter')}")
            if res.get("poc_curl"): print(f"[+] PoC Command:    {res.get('poc_curl')}")
            if res.get("evidence"): print(f"[+] Evidence:       {res.get('evidence')}")
        else:
            print(f"\n\033[92m[✓] Probing Completed: {res.get('summary', 'No immediate vulnerability detected')}\033[0m")
        return


    # 11. JavaScript Intelligence & GhostJS Secret Scanner
    if args.js_scan or args.js_file:
        from core.js_intelligence import GhostJsAnalyzer
        analyzer = GhostJsAnalyzer()

        if args.js_file:
            print(f"\033[96m[+] Scanning local JavaScript/HTML file: {args.js_file}\033[0m")
            res = analyzer.scan_file(args.js_file)
        else:
            print(f"\033[96m[+] Running Autonomous JavaScript Intelligence on: {args.js_scan}\033[0m")
            print(f"[i] Active JS bundle resolution: {'Disabled' if args.no_active_fetch else 'Enabled'}")
            res = asyncio.run(analyzer.scan_url(args.js_scan, active_fetch_bundles=not args.no_active_fetch))

        if "error" in res and not res.get("secrets"):
            print(f"\033[91m[-] {res['error']}\033[0m")
            return

        s = res.get("summary", {})
        print(f"\n\033[92m[✓] JavaScript Intelligence Scan Completed!\033[0m")
        print(f"[+] Total Scanned Assets: {res.get('scanned_assets_count', 1)}")
        print(f"[!] Discovered Secrets:   {len(res.get('secrets', []))} (Critical: {s.get('critical', 0)}, High: {s.get('high', 0)}, Med: {s.get('medium', 0)}, Low: {s.get('low', 0)})")
        print(f"[+] Discovered Endpoints: {len(res.get('api_endpoints', []))}")
        print(f"[+] Cloud Storage URLs:   {len(res.get('cloud_storage', []))}")
        print(f"[+] Source Map References: {len(res.get('source_maps', []))}")

        if res.get("secrets"):
            print(f"\n\033[91m{'SEVERITY':<10} {'NAME':<32} {'MASKED VALUE':<32} {'LINE':<6} {'SOURCE'}\033[0m")
            print("-" * 110)
            for sec in res["secrets"]:
                sev = sec["severity"]
                sev_color = "\033[91m" if sev in ["CRITICAL", "HIGH"] else "\033[93m"
                src_short = sec["source_url"].split("/")[-1] if "/" in sec["source_url"] else sec["source_url"]
                print(f"{sev_color}{sev:<10}\033[0m {sec['name']:<32} {sec['masked_value']:<32} {sec['line']:<6} {src_short[:25]}")
                if sec.get("snippet"):
                    print(f"    \033[90mSnippet: {sec['snippet'][:90]}\033[0m")

        if res.get("cloud_storage"):
            print(f"\n\033[93m[!] Discovered Cloud Object Storage Buckets:\033[0m")
            for cs in res["cloud_storage"]:
                print(f"    - [{cs['provider']}] {cs['url']}")

        if res.get("source_maps"):
            print(f"\n\033[93m[!] Discovered Source Map References:\033[0m")
            for sm in res["source_maps"]:
                print(f"    - {sm['resolved_url']}")

        if res.get("api_endpoints"):
            print(f"\n\033[96m[+] Discovered Internal / API Endpoints (Top 15):\033[0m")
            for ep in res["api_endpoints"][:15]:
                print(f"    - {ep['path']}")
            if len(res["api_endpoints"]) > 15:
                print(f"    ... and {len(res['api_endpoints']) - 15} more endpoints.")

        if args.export_js:
            with open(args.export_js, "w", encoding="utf-8") as f:
                if args.export_js.endswith(".json"):
                    json.dump(res, f, indent=2)
                else:
                    f.write(f"=== SWA GHOSTJS INTELLIGENCE REPORT ===\n")
                    f.write(f"Target: {res.get('target_url') or args.js_file}\n\n")
                    f.write(f"--- SECRETS ({len(res.get('secrets', []))}) ---\n")
                    for sec in res.get("secrets", []):
                        f.write(f"[{sec['severity']}] {sec['name']}: {sec['masked_value']} (Line {sec['line']}, File: {sec['source_url']})\n")
                    f.write(f"\n--- ENDPOINTS ({len(res.get('api_endpoints', []))}) ---\n")
                    for ep in res.get("api_endpoints", []):
                        f.write(f"{ep['path']} -> {ep['resolved_url']}\n")
            print(f"\n[+] JS Intelligence results exported to: {args.export_js}")
        return

    # 10. Reverse Shell Generator
    if args.revshell:
        from core.cyber_tools import ReverseShellGeneratorTool
        res = ReverseShellGeneratorTool.generate(args.shell_ip, args.shell_port, shell_type=args.shell_type)
        print(f"\033[96m[+] Authorized Pentest Reverse Shell Syntax (LHOST={args.shell_ip}, LPORT={args.shell_port})\033[0m")
        if "command" in res:
            print(f"\n{res['command']}\n")
        else:
            for k, cmd in res.get("templates", {}).items():
                print(f"\n--- {k.upper()} ---")
                print(cmd)
        return


    # 11. Autonomous Multi-Source Subdomain Discovery & Asset Intelligence
    target_sub_domain = args.subdomains or args.amass
    if target_sub_domain:
        from agents.amass_engine import AmassSubdomainEngine
        print(f"\033[96m[+] Launching Autonomous Multi-Source Subdomain Intelligence on: {target_sub_domain}\033[0m")
        print(f"[i] Recursive multi-tier discovery: {'Enabled' if args.recursive else 'Standard'}")
        async def run_amass_cli():
            engine = AmassSubdomainEngine("cli_amass", target_sub_domain, recursive=args.recursive)
            subs, takeovers = await engine.run()
            live_count = sum(1 for s in subs if s.get("status"))
            print(f"\n\033[92m[✓] Subdomain Discovery Completed!\033[0m")
            print(f"[+] Total Discovered Assets: {len(subs)} | Live HTTP/S: {live_count} | Takeover Risks: {len(takeovers)}")
            print(f"\n{'SUBDOMAIN':<38} {'IP ADDRESS':<17} {'STATUS':<8} {'TITLE':<30} {'SOURCES'}")
            print("-" * 115)
            for s in subs:
                src_str = ','.join(s.get('sources', []))[:20]
                status_raw = s.get('status')
                if status_raw:
                    status_col = "\033[92m" if status_raw in [200, 201] else ("\033[93m" if status_raw in [301, 302, 307] else "\033[91m")
                    status_str = f"{status_col}{status_raw}\033[0m"
                else:
                    status_str = "--"
                title_str = (s.get('title') or '')[:28]
                ip_str = s.get('ip') or '--'
                print(f"{s['subdomain']:<38} {ip_str:<17} {status_str:<17} {title_str:<30} {src_str}")
            if takeovers:
                print(f"\n\033[91m[!] CRITICAL: Found {len(takeovers)} Subdomain Takeover Vulnerabilities!\033[0m")
                for to in takeovers:
                    print(f"    - {to.title}: {to.endpoint}")
            if args.export_subs:
                if args.export_subs.endswith('.json'):
                    with open(args.export_subs, 'w', encoding='utf-8') as f:
                        json.dump(subs, f, indent=2)
                else:
                    with open(args.export_subs, 'w', encoding='utf-8') as f:
                        for s in subs:
                            f.write(f"{s['subdomain']}\n")
                print(f"\n[+] Discovered subdomains exported to: {args.export_subs}")
        asyncio.run(run_amass_cli())
        return


    # 12. DFIR Forensics Analysis
    if args.forensics_log or args.forensics_sample:
        from core.forensics_engine import ForensicsEngine
        if args.forensics_sample:
            logs = ForensicsEngine.SAMPLE_LOGS[args.forensics_sample]["logs"]
            print(f"\033[96m[+] Running forensic analysis on built-in scenario: {args.forensics_sample}\033[0m")
        else:
            if not os.path.exists(args.forensics_log):
                print(f"\033[91m[-] Log file not found: {args.forensics_log}\033[0m")
                sys.exit(1)
            with open(args.forensics_log, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()
            print(f"\033[96m[+] Running forensic analysis on log file: {args.forensics_log}\033[0m")


        fe = ForensicsEngine(logs)
        results = fe.analyze()
        s = results["summary"]
        print(f"\n\033[92m[✓] Forensic Analysis Completed!\033[0m")
        print(f"[!] Threat Posture: \033[91m{s['threat_level']}\033[0m - {s['threat_headline']}")
        print(f"[+] Total Lines Analyzed: {s['total_lines_analyzed']}")
        print(f"[+] Attack Footprints Detected: {s['total_attack_footprints']}")
        print(f"[+] Unique Threat Actors: {s['unique_threat_actors']}")
        print("\n\033[93m[!] Identified Footprints by Category:\033[0m")
        for cat, count in results["category_breakdown"].items():
            print(f"    - {cat}: {count}")
        print("\n\033[93m[!] Hostile Threat Actor IPs:\033[0m")
        for actor in results["top_threat_actors"]:
            print(f"    - {actor['ip']} ({actor['incident_count']} requests)")
            print(f"      Linux Drop:   {actor['os_block_linux']}")
            print(f"      Windows Drop: {actor['os_block_windows']}")
        return


    # 13. Web Mode vs CLI Red Team Scan
    if args.web or not args.target:
        print(f"\033[92m[⚡] Starting SWA AI Web Server on http://{args.host}:{args.port}\033[0m")
        print(f"[+] Open http://{args.host}:{args.port} in your browser to enter targets and monitor background scans.\n")
        uvicorn.run("web.server:app", host=args.host, port=args.port, reload=False)
    else:
        asyncio.run(run_cli_scan(args))


if __name__ == "__main__":
    main()
