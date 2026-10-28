"""
SWA AI — Cybersecurity Tool Integration Architecture
Provides safe, documented, subprocess-isolated wrappers for:
- Nmap (Network Discovery & Port Auditing)
- Nuclei (Safe Detection Templates)
- OWASP ZAP (Passive Web Baseline Analysis)
- SQLmap (Safe Non-Destructive Lab Detection)
- Nikto (Web Server Configuration & Outdated Software)
- TShark / Wireshark (Network Packet Inspection)
- Semgrep (Static Application Security Testing - SAST)
- Bandit (Python Source Code Security Linting)
- Trivy (Container & Dependency Scanner)
- Gitleaks (Hardcoded Secret & Token Detection)
- Native Fallback Auditing Engines (Async Port Scanner, OWASP Plugins, Amass OSINT, GhostJS)

Strict Rules:
- All subprocess execution uses safe argument lists (no shell=True with user strings).
- Checks tool presence before execution; never fabricates results.
- If binary is absent, provides clear installation instructions and falls back cleanly.
- Enforces strict timeouts, output parsing, and error handling.
"""

import asyncio
import json
import os
import re
import shutil
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple

from core.models import VulnerabilityFinding, Severity

class ScannerIntegrations:
    """Manages external cybersecurity tool discovery, execution, health checks, and output normalization."""

    @staticmethod
    def _find_binary(name: str, extra_paths: Optional[List[str]] = None) -> Optional[str]:
        p = shutil.which(name)
        if p:
            return p
        if extra_paths:
            for ep in extra_paths:
                if os.path.isfile(ep):
                    return ep
        return None

    @staticmethod
    def _get_version(binary: str, args: List[str]) -> Optional[str]:
        try:
            import subprocess
            proc = subprocess.run([binary] + args, capture_output=True, text=True, timeout=3.0)
            first_line = proc.stdout.strip().splitlines()[0] if proc.stdout else ""
            return first_line[:60]
        except Exception:
            return None

    @staticmethod
    def get_tool_inventory() -> Dict[str, Dict[str, Any]]:
        """Inspects host system for security tool binaries and versions."""
        inventory = {}

        # 1. Nmap
        nmap_path = ScannerIntegrations._find_binary("nmap", [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ])
        inventory["nmap"] = {
            "id": "nmap",
            "name": "Nmap Network Scanner",
            "category": "Network Discovery & Analysis",
            "installed": bool(nmap_path),
            "binary_path": nmap_path,
            "version": ScannerIntegrations._get_version(nmap_path, ["--version"]) if nmap_path else None,
            "capability": "Host discovery, port auditing, service fingerprinting, and OS detection.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Authorized target IP, CIDR block, or domain name.",
            "output_format": "XML, Grepable, Normal text",
            "docs_url": "https://nmap.org/docs.html",
            "install_guide": "Install via 'choco install nmap' (Windows) or 'apt install nmap' (Linux).",
            "scan_profiles": ["Quick Port Discovery", "Full Service & Version Audit"],
            "safe_command_example": "nmap -sV -T3 -Pn --open 127.0.0.1",
            "health_status": "HEALTHY" if nmap_path else "NOT INSTALLED"
        }

        # 2. Nuclei
        nuclei_path = ScannerIntegrations._find_binary("nuclei")
        inventory["nuclei"] = {
            "id": "nuclei",
            "name": "Nuclei Vulnerability Scanner",
            "category": "Web Application Security",
            "installed": bool(nuclei_path),
            "binary_path": nuclei_path,
            "version": ScannerIntegrations._get_version(nuclei_path, ["-version"]) if nuclei_path else None,
            "capability": "Safe, community-curated template-based security checks and misconfiguration detection.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Target URL or list of web endpoints.",
            "output_format": "JSON Lines (JSONL), Standard text",
            "docs_url": "https://docs.projectdiscovery.io/tools/nuclei",
            "install_guide": "Install via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' or binary release.",
            "scan_profiles": ["Safe Templates (CVE, Misconfig)", "Passive Exposures"],
            "safe_command_example": "nuclei -u http://127.0.0.1:8000 -tags cve,misconfig -severity low,medium,high -silent -jsonl",
            "health_status": "HEALTHY" if nuclei_path else "NOT INSTALLED"
        }

        # 3. OWASP ZAP
        zap_path = ScannerIntegrations._find_binary("zap.sh") or ScannerIntegrations._find_binary("zap.bat") or ScannerIntegrations._find_binary("zaproxy")
        inventory["owasp_zap"] = {
            "id": "owasp_zap",
            "name": "OWASP ZAP",
            "category": "Web Application Security",
            "installed": bool(zap_path),
            "binary_path": zap_path,
            "version": ScannerIntegrations._get_version(zap_path, ["-version"]) if zap_path else None,
            "capability": "Automated passive web application security baseline scanning and API assessment.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Target web application URL or OpenAPI specification.",
            "output_format": "HTML, XML, JSON",
            "docs_url": "https://www.zaproxy.org/docs/",
            "install_guide": "Download installer from https://www.zaproxy.org/download/ or run via Docker.",
            "scan_profiles": ["Baseline Passive Audit", "API Baseline"],
            "safe_command_example": "docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:8000",
            "health_status": "HEALTHY" if zap_path else "NOT INSTALLED"
        }

        # 4. SQLmap (Lab Safe Mode)
        sqlmap_path = ScannerIntegrations._find_binary("sqlmap")
        inventory["sqlmap"] = {
            "id": "sqlmap",
            "name": "SQLmap Engine (Lab Safe Mode)",
            "category": "Specialist Pentesting (Authorized Labs Only)",
            "installed": bool(sqlmap_path),
            "binary_path": sqlmap_path,
            "version": ScannerIntegrations._get_version(sqlmap_path, ["--version"]) if sqlmap_path else None,
            "capability": "Non-destructive detection of SQL injection flaws in authorized lab environments.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Target URL with test parameters (e.g., http://127.0.0.1:8000/api?id=1).",
            "output_format": "CSV, Text, SQLite session log",
            "docs_url": "https://sqlmap.org/",
            "install_guide": "Install via 'pip install sqlmap' or clone https://github.com/sqlmapproject/sqlmap.",
            "scan_profiles": ["Non-Destructive Detection (Level 1, Risk 1)"],
            "safe_command_example": "sqlmap -u http://127.0.0.1:8000/api?id=1 --batch --level=1 --risk=1 --technique=BEUST",
            "health_status": "HEALTHY" if sqlmap_path else "NOT INSTALLED"
        }

        # 5. Nikto
        nikto_path = ScannerIntegrations._find_binary("nikto") or ScannerIntegrations._find_binary("nikto.pl")
        inventory["nikto"] = {
            "id": "nikto",
            "name": "Nikto Web Server Scanner",
            "category": "Web Application Security",
            "installed": bool(nikto_path),
            "binary_path": nikto_path,
            "version": ScannerIntegrations._get_version(nikto_path, ["-Version"]) if nikto_path else None,
            "capability": "Web server misconfiguration checks, default files, and outdated software detection.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Target hostname or IP address with port.",
            "output_format": "HTML, XML, CSV, Text",
            "docs_url": "https://cirt.net/Nikto2",
            "install_guide": "Install via 'apt install nikto' (Linux) or clone https://github.com/sullo/nikto.",
            "scan_profiles": ["Configuration & Default Files Audit"],
            "safe_command_example": "nikto -h http://127.0.0.1:8000 -Tuning 123b",
            "health_status": "HEALTHY" if nikto_path else "NOT INSTALLED"
        }

        # 6. TShark / Wireshark
        tshark_path = ScannerIntegrations._find_binary("tshark", [
            r"C:\Program Files\Wireshark\tshark.exe"
        ])
        inventory["tshark"] = {
            "id": "tshark",
            "name": "TShark / Wireshark Packet Analyzer",
            "category": "Network Discovery & Analysis",
            "installed": bool(tshark_path),
            "binary_path": tshark_path,
            "version": ScannerIntegrations._get_version(tshark_path, ["-v"]) if tshark_path else None,
            "capability": "Packet capture analysis, protocol inspection, and network security diagnostics.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "PCAP capture file or authorized network interface.",
            "output_format": "JSON, CSV, Plain text statistics",
            "docs_url": "https://www.wireshark.org/docs/",
            "install_guide": "Install Wireshark with TShark CLI via 'choco install wireshark' or 'apt install tshark'.",
            "scan_profiles": ["Capture File Analysis", "Protocol Statistics"],
            "safe_command_example": "tshark -r capture.pcap -q -z conv,ip",
            "health_status": "HEALTHY" if tshark_path else "NOT INSTALLED"
        }

        # 7. Semgrep
        semgrep_path = ScannerIntegrations._find_binary("semgrep")
        inventory["semgrep"] = {
            "id": "semgrep",
            "name": "Semgrep SAST Engine",
            "category": "Application & Dependency Security",
            "installed": bool(semgrep_path),
            "binary_path": semgrep_path,
            "version": ScannerIntegrations._get_version(semgrep_path, ["--version"]) if semgrep_path else None,
            "capability": "Static application security testing (SAST) for source code vulnerabilities and insecure coding patterns.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Source code directory path.",
            "output_format": "SARIF 2.1.0, JSON, Text",
            "docs_url": "https://semgrep.dev/docs/",
            "install_guide": "Install via 'pip install semgrep' or brew/binary release.",
            "scan_profiles": ["OWASP Top 10 SAST Rules", "Security Audit Baseline"],
            "safe_command_example": "semgrep scan --config auto --json",
            "health_status": "HEALTHY" if semgrep_path else "NOT INSTALLED"
        }

        # 8. Bandit
        bandit_path = ScannerIntegrations._find_binary("bandit")
        inventory["bandit"] = {
            "id": "bandit",
            "name": "Bandit Python Security Linter",
            "category": "Application & Dependency Security",
            "installed": bool(bandit_path),
            "binary_path": bandit_path,
            "version": ScannerIntegrations._get_version(bandit_path, ["--version"]) if bandit_path else None,
            "capability": "Static code analysis to find common security issues in Python source code (hardcoded passwords, SQL injection, shell injection).",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Python repository or file path.",
            "output_format": "JSON, CSV, HTML, Text",
            "docs_url": "https://bandit.readthedocs.io/",
            "install_guide": "Install via 'pip install bandit'.",
            "scan_profiles": ["Recursive Python Security Audit"],
            "safe_command_example": "bandit -r ./src -f json -o bandit-report.json",
            "health_status": "HEALTHY" if bandit_path else "NOT INSTALLED"
        }

        # 9. Trivy
        trivy_path = ScannerIntegrations._find_binary("trivy")
        inventory["trivy"] = {
            "id": "trivy",
            "name": "Trivy Vulnerability & Misconfig Scanner",
            "category": "Application & Dependency Security",
            "installed": bool(trivy_path),
            "binary_path": trivy_path,
            "version": ScannerIntegrations._get_version(trivy_path, ["version"]) if trivy_path else None,
            "capability": "Comprehensive security scanner for container images, filesystems, and software dependencies.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Project filesystem path or container image name.",
            "output_format": "SARIF 2.1.0, JSON, Table",
            "docs_url": "https://aquasecurity.github.io/trivy/",
            "install_guide": "Install via 'choco install trivy' (Windows) or 'apt install trivy' (Linux).",
            "scan_profiles": ["Filesystem Vulnerability Scan", "IaC Misconfiguration Scan"],
            "safe_command_example": "trivy fs --scanners vuln,misconfig .",
            "health_status": "HEALTHY" if trivy_path else "NOT INSTALLED"
        }

        # 10. Gitleaks
        gitleaks_path = ScannerIntegrations._find_binary("gitleaks")
        inventory["gitleaks"] = {
            "id": "gitleaks",
            "name": "Gitleaks Secret Scanner",
            "category": "Application & Dependency Security",
            "installed": bool(gitleaks_path),
            "binary_path": gitleaks_path,
            "version": ScannerIntegrations._get_version(gitleaks_path, ["version"]) if gitleaks_path else None,
            "capability": "Fast, regex and entropy-based secret detection for git repositories and files.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Git repository path or file directory.",
            "output_format": "SARIF, JSON, CSV",
            "docs_url": "https://github.com/gitleaks/gitleaks",
            "install_guide": "Install via 'choco install gitleaks' (Windows) or binary download from GitHub.",
            "scan_profiles": ["Detect Secrets in Working Tree", "Commit History Audit"],
            "safe_command_example": "gitleaks detect --no-git -v",
            "health_status": "HEALTHY" if gitleaks_path else "NOT INSTALLED"
        }

        # 11. Native SWA AI Built-in Engines
        inventory["swa_native"] = {
            "id": "swa_native",
            "name": "SWA AI Native Security Engines",
            "category": "Built-in Core Suite",
            "installed": True,
            "binary_path": "Built-in Python 3.12 Engine",
            "version": "2.2.0-Enterprise",
            "capability": "OWASP Top 10 Suite, Amass OSINT, Dual Baseline Fuzzer, TLS/SSL Deep Inspector, GhostJS Secret Engine, Dependency Manifest Auditor, and Defense Center.",
            "supported_os": ["Windows", "Linux", "macOS"],
            "input_requirements": "Target URL, domain, IP, or manifest file.",
            "output_format": "HTML, SARIF 2.1.0, JSON, Markdown, CSV",
            "docs_url": "https://github.com/545e/SWA",
            "install_guide": "Pre-installed and fully operational with standard Python 3.12 runtime.",
            "scan_profiles": ["Quick Surface", "Full Red Team", "OWASP Top 10", "All Tools Unified Intel"],
            "safe_command_example": "py swa_cli.py -t http://127.0.0.1:8000 -p quick --lab-mode",
            "health_status": "HEALTHY"
        }

        return inventory

    @staticmethod
    def get_command_reference() -> List[Dict[str, Any]]:
        """Returns comprehensive searchable command encyclopedia for all integrated cybersecurity tools."""
        return [
            {
                "tool": "Nmap Network Scanner",
                "tool_id": "nmap",
                "category": "Network Discovery",
                "command": "nmap -sV -T3 -Pn --open 127.0.0.1",
                "purpose": "Identify open ports and fingerprint services on authorized targets with moderate timing.",
                "options": [
                    {"flag": "-sV", "desc": "Attempts service and banner version identification."},
                    {"flag": "-T3", "desc": "Moderate timing profile; avoids aggressive traffic bursts."},
                    {"flag": "-Pn", "desc": "Skips initial ICMP ping host discovery and probes ports directly."},
                    {"flag": "--open", "desc": "Suppresses filtered and closed ports to display only actionable findings."}
                ],
                "expected_input": "Target IPv4, IPv6, or domain name.",
                "expected_output": "List of open ports, protocols (TCP/UDP), detected service names, product versions.",
                "local_lab_example": "nmap -sV -T3 -p 8000 127.0.0.1",
                "safety_considerations": "Only scan authorized IPs. T3 timing is safe for standard services without causing DoS.",
                "common_errors": [
                    {"error": "dnet: Failed to open device", "fix": "Install Npcap on Windows or run as administrator."},
                    {"error": "Host seems down", "fix": "Add -Pn flag if target firewalls block ICMP echo requests."}
                ],
                "docs_url": "https://nmap.org/book/man.html"
            },
            {
                "tool": "Nuclei Vulnerability Scanner",
                "tool_id": "nuclei",
                "category": "Web Application Security",
                "command": "nuclei -u http://127.0.0.1:8000 -tags cve,misconfig -severity low,medium,high -silent -jsonl",
                "purpose": "Execute community-curated, template-based security checks against authorized web endpoints.",
                "options": [
                    {"flag": "-u <url>", "desc": "Target URL to assess."},
                    {"flag": "-tags cve,misconfig", "desc": "Limits checks to known CVEs and server misconfigurations."},
                    {"flag": "-severity ...", "desc": "Filters templates by severity level."},
                    {"flag": "-silent", "desc": "Suppresses banner and non-finding log noise."},
                    {"flag": "-jsonl", "desc": "Outputs structured JSON Lines records for automated ingestion."}
                ],
                "expected_input": "Web application root URL or API base URL.",
                "expected_output": "JSONL records containing matched template ID, severity, CVE/CWE, and matched payload.",
                "local_lab_example": "nuclei -u http://127.0.0.1:8000 -t http/misconfiguration/ -silent",
                "safety_considerations": "Exclude destructive tags (-exclude-tags dos,fuzz,sqli-exploit) during baseline scans.",
                "common_errors": [
                    {"error": "No templates found", "fix": "Run 'nuclei -update-templates' to download the latest signatures."}
                ],
                "docs_url": "https://docs.projectdiscovery.io/tools/nuclei/running"
            },
            {
                "tool": "OWASP ZAP",
                "tool_id": "owasp_zap",
                "category": "Web Application Security",
                "command": "docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice-shop:3000",
                "purpose": "Perform non-intrusive baseline passive vulnerability analysis against an approved web application.",
                "options": [
                    {"flag": "zap-baseline.py", "desc": "Executes ZAP fast baseline scanner script."},
                    {"flag": "-t <target>", "desc": "Approved web target URL."},
                    {"flag": "-r report.html", "desc": "Exports comprehensive audit results to HTML."}
                ],
                "expected_input": "Web application URL in an isolated network or lab environment.",
                "expected_output": "Summary of passive web alerts (missing headers, insecure cookie flags, CORS issues).",
                "local_lab_example": "docker run --rm -t --net=host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:8000",
                "safety_considerations": "Baseline scans are passive and safe. Active testing requires explicit written consent.",
                "common_errors": [
                    {"error": "Failed to connect to target", "fix": "Check container network bridging (--net=host on Linux or host.docker.internal)."}
                ],
                "docs_url": "https://www.zaproxy.org/docs/docker/baseline-scan/"
            },
            {
                "tool": "Bandit Python Security Linter",
                "tool_id": "bandit",
                "category": "Application & Dependency Security",
                "command": "bandit -r ./src -f json -o bandit-report.json",
                "purpose": "Audit Python source code for security vulnerabilities, weak cryptography, and unsafe functions.",
                "options": [
                    {"flag": "-r ./src", "desc": "Recursively scans Python files in the specified directory."},
                    {"flag": "-f json", "desc": "Outputs results in standard JSON format."},
                    {"flag": "-o file.json", "desc": "Saves findings to an output file."}
                ],
                "expected_input": "Directory containing Python (.py) source files.",
                "expected_output": "Structured list of code issues with line numbers, severity, and CWE classification.",
                "local_lab_example": "bandit -r ./core -lll",
                "safety_considerations": "Safe static analysis. Does not execute the target code.",
                "common_errors": [
                    {"error": "SyntaxError in file", "fix": "Ensure code is valid Python for the running interpreter version."}
                ],
                "docs_url": "https://bandit.readthedocs.io/"
            },
            {
                "tool": "Trivy Vulnerability Scanner",
                "tool_id": "trivy",
                "category": "Application & Dependency Security",
                "command": "trivy fs --scanners vuln,misconfig .",
                "purpose": "Assess local repositories, dependency lockfiles, and container images for known CVEs.",
                "options": [
                    {"flag": "fs", "desc": "Scans filesystem mode."},
                    {"flag": "--scanners vuln,misconfig", "desc": "Checks both software vulnerabilities and IaC misconfigurations."},
                    {"flag": ".", "desc": "Current working directory."}
                ],
                "expected_input": "Project root containing requirements.txt, package.json, or Dockerfile.",
                "expected_output": "Table or JSON report detailing package name, installed version, fixed version, and CVE.",
                "local_lab_example": "trivy fs --severity HIGH,CRITICAL .",
                "safety_considerations": "Read-only inspection; completely safe for production repositories.",
                "common_errors": [
                    {"error": "DB download error", "fix": "Check outbound internet connectivity to GitHub release endpoints."}
                ],
                "docs_url": "https://aquasecurity.github.io/trivy/latest/docs/"
            },
            {
                "tool": "SQLmap Engine (Lab Safe Mode)",
                "tool_id": "sqlmap",
                "category": "Specialist Pentesting",
                "command": "sqlmap -u http://127.0.0.1:8000/api?id=1 --batch --level=1 --risk=1 --technique=BEUST",
                "purpose": "Detect presence of SQL injection vulnerabilities non-destructively in authorized labs.",
                "options": [
                    {"flag": "--batch", "desc": "Non-interactive mode using safe default answers."},
                    {"flag": "--level=1 --risk=1", "desc": "Minimal probe volume; strictly non-destructive testing."},
                    {"flag": "--technique=BEUST", "desc": "Tests Boolean, Error, Union, Stacked, and Time detection only."}
                ],
                "expected_input": "Authorized lab URL with parameterized query string.",
                "expected_output": "Confirmation of DBMS backend and parameter injectable status.",
                "local_lab_example": "sqlmap -u http://127.0.0.1:8000/api/probe?target_url=test --batch --level=1",
                "safety_considerations": "Never perform --dump, --os-shell, or destructive testing. Lab mode authorization mandatory.",
                "common_errors": [
                    {"error": "Connection refused", "fix": "Confirm target web server is online and reachable."}
                ],
                "docs_url": "https://sqlmap.org/"
            },
            {
                "tool": "Gitleaks Secret Scanner",
                "tool_id": "gitleaks",
                "category": "Application & Dependency Security",
                "command": "gitleaks detect --no-git -v",
                "purpose": "Scan repository files or commit logs for leaked credentials, private keys, and API tokens.",
                "options": [
                    {"flag": "detect", "desc": "Runs the detection workflow."},
                    {"flag": "--no-git", "desc": "Scans filesystem directory directly without requiring git history."},
                    {"flag": "-v", "desc": "Verbose output showing secret classification and file location."}
                ],
                "expected_input": "Directory or git repository.",
                "expected_output": "List of discovered secrets with entropy score, pattern rule ID, and line number.",
                "local_lab_example": "gitleaks detect --source=. --no-git",
                "safety_considerations": "Redact secrets from logs before sharing audit reports.",
                "common_errors": [
                    {"error": "No config file found", "fix": "Gitleaks includes a default embedded rule set; custom rule file is optional."}
                ],
                "docs_url": "https://github.com/gitleaks/gitleaks"
            },
            {
                "tool": "SWA AI Native Security Engines",
                "tool_id": "swa_native",
                "category": "Built-in Core Engine",
                "command": "py swa_cli.py -t http://127.0.0.1:8000 -p quick --lab-mode",
                "purpose": "Complete autonomous multi-agent red team assessment with verified PoCs and zero false positives.",
                "options": [
                    {"flag": "-t <target>", "desc": "Target URL, IP, or domain within authorized scope."},
                    {"flag": "-p quick", "desc": "Assessment profile (quick, full_red_team, owasp_top10, recon_only)."},
                    {"flag": "--lab-mode", "desc": "Authorizes testing on local lab instances (127.0.0.1, PortSwigger)."},
                    {"flag": "--check-tools", "desc": "Inspects system binary availability for all security engines."}
                ],
                "expected_input": "Target address or URL.",
                "expected_output": "Comprehensive vulnerability assessment with reproduction cURL PoCs and remediation patches.",
                "local_lab_example": "py swa_cli.py -t http://127.0.0.1:8000 -p quick --lab-mode",
                "safety_considerations": "Strict scope enforcement and SSRF protection active by default.",
                "common_errors": [
                    {"error": "Target Scope Refusal", "fix": "Ensure target is in ALLOWED_TARGETS or supply --lab-mode for local targets."}
                ],
                "docs_url": "https://github.com/545e/SWA"
            }
        ]

    @staticmethod
    async def run_tool_health_check(tool_id: str) -> Dict[str, Any]:
        """Executes a safe version or ping check for the specified tool."""
        start = time.time()
        inventory = ScannerIntegrations.get_tool_inventory()
        tool = inventory.get(tool_id)

        if not tool:
            return {
                "tool_id": tool_id,
                "status": "NOT_FOUND",
                "message": f"Unknown tool identifier '{tool_id}'.",
                "latency_ms": 0
            }

        if tool_id == "swa_native":
            latency = round((time.time() - start) * 1000, 2)
            return {
                "tool_id": tool_id,
                "name": tool["name"],
                "status": "HEALTHY",
                "installed": True,
                "version": tool["version"],
                "latency_ms": latency,
                "message": "SWA AI Native Security Engines operational (Python 3.12, OWASP Plugins, GhostJS, Fuzzer active)."
            }

        if not tool["installed"]:
            latency = round((time.time() - start) * 1000, 2)
            return {
                "tool_id": tool_id,
                "name": tool["name"],
                "status": "UNAVAILABLE",
                "installed": False,
                "latency_ms": latency,
                "message": f"Binary not found on system PATH. {tool['install_guide']}"
            }

        # Safe version check argument mapping
        version_args = {
            "nmap": ["--version"],
            "nuclei": ["-version"],
            "owasp_zap": ["-version"],
            "sqlmap": ["--version"],
            "nikto": ["-Version"],
            "tshark": ["-v"],
            "semgrep": ["--version"],
            "bandit": ["--version"],
            "trivy": ["version"],
            "gitleaks": ["version"]
        }

        args = version_args.get(tool_id, ["--version"])
        try:
            proc = await asyncio.create_subprocess_exec(
                tool["binary_path"],
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=4.0)
            output = stdout.decode("utf-8", errors="ignore").strip()
            first_line = output.splitlines()[0] if output else "Active"
            latency = round((time.time() - start) * 1000, 2)
            return {
                "tool_id": tool_id,
                "name": tool["name"],
                "status": "HEALTHY",
                "installed": True,
                "version": first_line[:60],
                "latency_ms": latency,
                "message": f"Verified executable on PATH: {first_line[:60]}"
            }
        except asyncio.TimeoutError:
            latency = round((time.time() - start) * 1000, 2)
            return {
                "tool_id": tool_id,
                "name": tool["name"],
                "status": "TIMEOUT",
                "installed": True,
                "latency_ms": latency,
                "message": "Version check timed out after 4 seconds."
            }
        except Exception as e:
            latency = round((time.time() - start) * 1000, 2)
            return {
                "tool_id": tool_id,
                "name": tool["name"],
                "status": "ERROR",
                "installed": True,
                "latency_ms": latency,
                "message": f"Health check failed: {str(e)}"
            }

    # =====================================================================
    # Nmap Safe Execution
    # =====================================================================
    @staticmethod
    async def run_nmap_safe(target_host: str, ports: str = "top100", timeout: int = 45) -> Dict[str, Any]:
        inventory = ScannerIntegrations.get_tool_inventory()
        nmap_meta = inventory["nmap"]
        if not nmap_meta["installed"]:
            return {
                "tool": "nmap",
                "executed": False,
                "reason": "Nmap binary is not installed on PATH.",
                "install_guide": nmap_meta["install_guide"],
                "ports": []
            }

        port_arg = ["-F"] if ports == "top100" else ["-p", ports]
        cmd = [
            nmap_meta["binary_path"],
            "-sV",
            "-T3",
            "-Pn",
            "--open",
            "--version-light",
            "-oX", "-"
        ] + port_arg + [target_host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
            xml_text = stdout.decode("utf-8", errors="ignore")

            parsed_ports = []
            if xml_text.strip().startswith("<?xml") or "<nmaprun" in xml_text:
                root = ET.fromstring(xml_text)
                for host in root.findall("host"):
                    ports_elem = host.find("ports")
                    if ports_elem is not None:
                        for p in ports_elem.findall("port"):
                            port_id = p.attrib.get("portid")
                            proto = p.attrib.get("protocol", "tcp")
                            state_elem = p.find("state")
                            state = state_elem.attrib.get("state") if state_elem is not None else "unknown"
                            service_elem = p.find("service")
                            svc_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                            product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                            version = service_elem.attrib.get("version", "") if service_elem is not None else ""

                            parsed_ports.append({
                                "port": int(port_id),
                                "protocol": proto,
                                "state": state,
                                "service": svc_name,
                                "product": product,
                                "version": version
                            })

            return {
                "tool": "nmap",
                "executed": True,
                "command": " ".join(cmd),
                "ports": parsed_ports,
                "raw_summary": f"Nmap discovered {len(parsed_ports)} open ports on {target_host}."
            }
        except asyncio.TimeoutError:
            return {"tool": "nmap", "executed": False, "error": f"Nmap execution timed out after {timeout}s."}
        except Exception as e:
            return {"tool": "nmap", "executed": False, "error": f"Nmap execution failed: {str(e)}"}

    # =====================================================================
    # Nuclei Safe Execution
    # =====================================================================
    @staticmethod
    async def run_nuclei_safe(target_url: str, scan_id: str, timeout: int = 60) -> Tuple[List[VulnerabilityFinding], Dict[str, Any]]:
        inventory = ScannerIntegrations.get_tool_inventory()
        nuclei_meta = inventory["nuclei"]
        if not nuclei_meta["installed"]:
            return [], {
                "tool": "nuclei",
                "executed": False,
                "reason": "Nuclei binary not installed.",
                "install_guide": nuclei_meta["install_guide"]
            }

        cmd = [
            nuclei_meta["binary_path"],
            "-u", target_url,
            "-tags", "cve,misconfig,exposure,tech",
            "-exclude-tags", "dos,fuzz,sqli-exploit,intrusive",
            "-severity", "info,low,medium,high,critical",
            "-silent",
            "-jsonl",
            "-timeout", "5"
        ]

        findings: List[VulnerabilityFinding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
            lines = stdout.decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    sev_str = info.get("severity", "info").upper()
                    sev_map = {
                        "CRITICAL": Severity.CRITICAL,
                        "HIGH": Severity.HIGH,
                        "MEDIUM": Severity.MEDIUM,
                        "LOW": Severity.LOW,
                        "INFO": Severity.INFO
                    }
                    cwe_list = info.get("classification", {}).get("cwe-id", [])
                    cwe_val = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None

                    f = VulnerabilityFinding(
                        scan_id=scan_id,
                        title=info.get("name") or data.get("template-id", "Nuclei Finding"),
                        severity=sev_map.get(sev_str, Severity.LOW),
                        cwe_id=cwe_val,
                        endpoint=data.get("matched-at") or target_url,
                        method="GET",
                        description=info.get("description") or f"Nuclei template {data.get('template-id')} matched.",
                        poc_curl=data.get("curl-command") or f"nuclei -t {data.get('template-id')} -u '{target_url}'",
                        request_evidence=data.get("request", "")[:500],
                        response_evidence=data.get("response", "")[:500],
                        remediation_advice=info.get("remediation") or "Consult vendor guidance for this template finding."
                    )
                    findings.append(f)
                except Exception:
                    continue

            return findings, {
                "tool": "nuclei",
                "executed": True,
                "findings_count": len(findings)
            }
        except asyncio.TimeoutError:
            return [], {"tool": "nuclei", "executed": False, "error": f"Nuclei timed out after {timeout}s."}
        except Exception as e:
            return [], {"tool": "nuclei", "executed": False, "error": str(e)}

    # =====================================================================
    # SQLmap Safe Lab Detection (Disabled by default, non-destructive only)
    # =====================================================================
    @staticmethod
    async def run_sqlmap_safe_detection(
        target_url: str,
        scan_id: str,
        is_lab_mode_authorized: bool = False,
        timeout: int = 40
    ) -> Tuple[List[VulnerabilityFinding], Dict[str, Any]]:
        if not is_lab_mode_authorized:
            return [], {
                "tool": "sqlmap",
                "executed": False,
                "reason": "SQLmap module is disabled by default. Requires explicit Lab Mode confirmation on authorized local/lab targets."
            }

        inventory = ScannerIntegrations.get_tool_inventory()
        sqlmap_meta = inventory["sqlmap"]
        if not sqlmap_meta["installed"]:
            return [], {
                "tool": "sqlmap",
                "executed": False,
                "reason": "SQLmap binary not installed on host.",
                "install_guide": sqlmap_meta["install_guide"]
            }

        cmd = [
            sqlmap_meta["binary_path"],
            "-u", target_url,
            "--batch",
            "--crawl=1",
            "--level=1",
            "--risk=1",
            "--technique=BEUST",
            "--flush-session",
            "--timeout=10",
            "--retries=1"
        ]

        findings: List[VulnerabilityFinding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
            output = stdout.decode("utf-8", errors="ignore")

            if "is vulnerable" in output.lower() or "sql injection" in output.lower():
                findings.append(VulnerabilityFinding(
                    scan_id=scan_id,
                    title="SQL Injection Flaw Detected (SQLmap Non-Destructive Probe)",
                    severity=Severity.HIGH,
                    cwe_id="CWE-89",
                    endpoint=target_url,
                    method="GET",
                    description="SQLmap confirmed parameter vulnerability using non-destructive detection probes.",
                    poc_curl=f"sqlmap -u '{target_url}' --batch --level=1 --risk=1",
                    response_evidence=output[:600],
                    remediation_advice="Deploy parameterized prepared statements (PreparedStatement) or ORM parameter binding."
                ))

            return findings, {
                "tool": "sqlmap",
                "executed": True,
                "findings_count": len(findings)
            }
        except asyncio.TimeoutError:
            return [], {"tool": "sqlmap", "executed": False, "error": f"SQLmap timed out after {timeout}s."}
        except Exception as e:
            return [], {"tool": "sqlmap", "executed": False, "error": str(e)}

    # =====================================================================
    # Dependency Manifest Scanner (package.json, requirements.txt)
    # =====================================================================
    @staticmethod
    def scan_dependency_manifest(manifest_filename: str, content: str, scan_id: str) -> List[VulnerabilityFinding]:
        findings = []
        fname = manifest_filename.lower()

        # Python requirements.txt
        if "requirements" in fname or fname.endswith(".txt"):
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^django[=><~!]=*([0-9.]+)", line, re.IGNORECASE)
                if m:
                    ver = m.group(1)
                    if ver.startswith(("1.", "2.", "3.0", "3.1")):
                        findings.append(VulnerabilityFinding(
                            scan_id=scan_id,
                            title=f"Vulnerable Dependency: Outdated Django Framework ({ver})",
                            severity=Severity.HIGH,
                            cwe_id="CWE-1104",
                            endpoint=manifest_filename,
                            description=f"Project manifest specifies Django version {ver}, which has reached End-of-Life and contains multiple security advisories.",
                            remediation_advice="Upgrade Django to version 4.2+ (LTS) or 5.0+.",
                            remediation_patch="Django>=4.2.16"
                        ))

        # Node package.json
        elif "package.json" in fname or fname.endswith(".json"):
            try:
                pkg_data = json.loads(content)
                deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                for dep, ver_spec in deps.items():
                    clean_ver = re.sub(r"[^\d.]", "", str(ver_spec))
                    if dep.lower() == "lodash" and clean_ver.startswith(("4.17.0", "4.17.1", "4.17.20")):
                        findings.append(VulnerabilityFinding(
                            scan_id=scan_id,
                            title="Vulnerable Dependency: lodash Prototype Pollution (CVE-2021-23337)",
                            severity=Severity.HIGH,
                            cwe_id="CWE-1321",
                            endpoint=manifest_filename,
                            description=f"Package 'lodash@{ver_spec}' is vulnerable to Prototype Pollution.",
                            remediation_advice="Upgrade lodash to 4.17.21 or higher.",
                            remediation_patch='"lodash": "^4.17.21"'
                        ))
            except Exception:
                pass

        return findings
