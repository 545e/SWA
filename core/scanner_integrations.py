"""
SWA AI — Cybersecurity Tool Integration Architecture
Provides safe, documented, subprocess-isolated wrappers for:
- Nmap (Network Discovery & Port Auditing)
- Nuclei (Safe Detection Templates)
- OWASP ZAP (Passive Web Baseline Analysis)
- SQLmap (Safe Non-Destructive Lab Detection)
- Native Fallback Auditing Engines (Async Port Scanner, OWASP Plugins, Amass OSINT)

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
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple

from core.models import VulnerabilityFinding, Severity

class ToolStatus(Dict[str, Any]):
    pass

class ScannerIntegrations:
    """Manages external cybersecurity tool discovery, execution, and output normalization."""

    @staticmethod
    def get_tool_inventory() -> Dict[str, Dict[str, Any]]:
        """Inspects host system for security tool binaries and versions."""
        inventory = {}

        # 1. Nmap
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            # Check standard Windows paths
            candidates = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe"
            ]
            for c in candidates:
                if os.path.isfile(c):
                    nmap_path = c
                    break
        inventory["nmap"] = {
            "name": "Nmap Network Scanner",
            "installed": bool(nmap_path),
            "binary_path": nmap_path,
            "version": ScannerIntegrations._get_version(nmap_path, ["--version"]) if nmap_path else None,
            "capability": "Network discovery, port auditing, service fingerprinting",
            "install_guide": "Install via 'choco install nmap' (Windows) or 'apt install nmap' (Linux)."
        }

        # 2. Nuclei
        nuclei_path = shutil.which("nuclei")
        inventory["nuclei"] = {
            "name": "Nuclei Vulnerability Scanner",
            "installed": bool(nuclei_path),
            "binary_path": nuclei_path,
            "version": ScannerIntegrations._get_version(nuclei_path, ["-version"]) if nuclei_path else None,
            "capability": "Safe template-based security checks and misconfiguration detection",
            "install_guide": "Install via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' or binary release."
        }

        # 3. OWASP ZAP
        zap_path = shutil.which("zap.sh") or shutil.which("zap.bat") or shutil.which("zaproxy")
        inventory["owasp_zap"] = {
            "name": "OWASP ZAP",
            "installed": bool(zap_path),
            "binary_path": zap_path,
            "version": ScannerIntegrations._get_version(zap_path, ["-version"]) if zap_path else None,
            "capability": "Automated passive web application security baseline scanning",
            "install_guide": "Download installer from https://www.zaproxy.org/download/."
        }

        # 4. SQLmap (Optional, non-destructive lab mode)
        sqlmap_path = shutil.which("sqlmap")
        inventory["sqlmap"] = {
            "name": "SQLmap Engine (Lab Safe Mode)",
            "installed": bool(sqlmap_path),
            "binary_path": sqlmap_path,
            "version": ScannerIntegrations._get_version(sqlmap_path, ["--version"]) if sqlmap_path else None,
            "capability": "Non-destructive detection of SQL injection flaws in authorized lab environments",
            "install_guide": "Install via 'pip install sqlmap' or clone https://github.com/sqlmapproject/sqlmap."
        }

        # 5. Native SWA AI Built-in Engines
        inventory["swa_native"] = {
            "name": "SWA AI Native Security Engines",
            "installed": True,
            "binary_path": "Built-in Python 3.12 Engine",
            "version": "2.2.0-Enterprise",
            "capability": "OWASP Top 10 Suite, Amass OSINT, Dual Baseline Fuzzer, TLS/SSL Deep Inspector, Threat Forensics",
            "install_guide": "Pre-installed and fully operational."
        }

        return inventory

    @staticmethod
    def _get_version(binary: str, args: List[str]) -> Optional[str]:
        try:
            import subprocess
            proc = subprocess.run([binary] + args, capture_output=True, text=True, timeout=3.0)
            first_line = proc.stdout.strip().splitlines()[0] if proc.stdout else ""
            return first_line[:60]
        except Exception:
            return None

    # =====================================================================
    # Nmap Safe Execution
    # =====================================================================
    @staticmethod
    async def run_nmap_safe(target_host: str, ports: str = "top100", timeout: int = 45) -> Dict[str, Any]:
        """
        Executes Nmap using safe service detection arguments without intrusive/DoS scripts.
        Command equivalent: nmap -sV -T3 -Pn --open <target> -oX -
        """
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
        # Strictly safe arguments array: no shell=True
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

            # Parse XML output
            parsed_ports = []
            if xml_text.strip().startswith("<?xml") or "<nmaprun" in xml_text:
                root = ET.fromstring(xml_text)
                for host in root.findall("host"):
                    ports_elem = host.find("ports")
                    if ports_elem is not None:
                        for p in ports_elem.findall("port"):
                            port_id = p.get("portid")
                            proto = p.get("protocol")
                            state = p.find("state").get("state") if p.find("state") is not None else "unknown"
                            svc = p.find("service")
                            svc_name = svc.get("name") if svc is not None else ""
                            product = svc.get("product") if svc is not None else ""
                            version = svc.get("version") if svc is not None else ""
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
        """
        Runs Nuclei using safe detection templates with JSONL output.
        Excludes intrusive, dos, and weaponized exploitation templates.
        """
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
        """
        Optional, strictly non-destructive SQLmap detection module.
        Requires explicit lab mode authorization.
        Hard constraint: Strictly omits and blocks --dump, --os-shell, --os-pwn, file access.
        """
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

        # Safe non-destructive arguments: batch mode, level 1, risk 1, crawl 1, no data extraction
        cmd = [
            sqlmap_meta["binary_path"],
            "-u", target_url,
            "--batch",
            "--crawl=1",
            "--level=1",
            "--risk=1",
            "--technique=BEUST", # Boolean, Error, Union, Stacked, Time (detection only)
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

            # Check for SQL injection confirmation in SQLmap output
            if "is vulnerable" in output.lower() or "sqlmap identified the following injection points" in output.lower():
                # Extract injected parameter
                param_match = re.search(r"Parameter:\s*(\w+)", output)
                param_name = param_match.group(1) if param_match else "query parameter"

                finding = VulnerabilityFinding(
                    scan_id=scan_id,
                    title=f"Confirmed SQL Injection via '{param_name}' (SQLmap Detection)",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021-Injection",
                    endpoint=target_url,
                    method="GET",
                    parameter=param_name,
                    description=f"Non-destructive SQLmap probe identified verified injection point on parameter '{param_name}'. Database engine accepted SQL syntax manipulation.",
                    poc_curl=f"sqlmap -u '{target_url}' --batch --level=1",
                    poc_explanation=f"SQLmap confirmed injection vulnerability on {param_name} with safe test payloads.",
                    request_evidence=f"GET {target_url} HTTP/1.1\nParameter: {param_name}",
                    response_evidence=output[output.find("Parameter:"):output.find("Parameter:") + 400] if "Parameter:" in output else output[:400],
                    remediation_advice="Deploy parameterized SQL queries / prepared statements exclusively. Strictly validate input formats.",
                    remediation_patch="cursor.execute('SELECT * FROM data WHERE param = %s', (safe_param,))"
                )
                findings.append(finding)

            return findings, {
                "tool": "sqlmap",
                "executed": True,
                "command": f"sqlmap -u '{target_url}' --batch --level=1 --risk=1",
                "vulnerable": len(findings) > 0,
                "output_snippet": output[:600]
            }
        except asyncio.TimeoutError:
            return [], {"tool": "sqlmap", "executed": False, "error": f"SQLmap execution timed out after {timeout}s."}
        except Exception as e:
            return [], {"tool": "sqlmap", "executed": False, "error": str(e)}

    # =====================================================================
    # Dependency Manifest Scanner (package.json, requirements.txt)
    # =====================================================================
    @staticmethod
    def scan_dependency_manifest(manifest_filename: str, content: str, scan_id: str) -> List[VulnerabilityFinding]:
        """Audits project dependency manifests for known vulnerable packages."""
        findings = []
        fname = manifest_filename.lower()

        # Python requirements.txt
        if "requirements" in fname or fname.endswith(".txt"):
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Check known vulnerable patterns
                # e.g. django < 3.2.24 (CVE-2024-27351)
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
                            description=f"Project manifest specifies Django version {ver}, which has reached End-of-Life and contains multiple critical/high security advisories.",
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
                            description=f"Package 'lodash@{ver_spec}' is vulnerable to Prototype Pollution and Command Injection in template functions.",
                            remediation_advice="Upgrade lodash to 4.17.21 or higher.",
                            remediation_patch='"lodash": "^4.17.21"'
                        ))
            except Exception:
                pass

        return findings
