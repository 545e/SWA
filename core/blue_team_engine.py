"""
SWA AI Blue Team Defense & SIEM/IDS Rule Generator
Synthesizes enterprise defensive countermeasures:
- Web Application Firewall (WAF) rules: ModSecurity (OWASP CRS), Cloudflare Expressions, AWS WAF v2, Nginx WAF
- IDS/IPS Signatures: Suricata and Snort 3 rules tailored to discovered threats
- SIEM Detection Rules: Sigma YAML rules, Splunk SPL, Elastic KQL, Microsoft Sentinel
- Infrastructure Hardening: Nginx and Apache security configuration blocks
"""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.models import ScanJob, VulnerabilityFinding, Severity

class BlueTeamDefenseEngine:
    def __init__(self, scan: Optional[ScanJob] = None, findings: Optional[List[VulnerabilityFinding]] = None, target_url: Optional[str] = None):
        self.scan = scan
        self.findings = findings or []
        self.target = target_url or (scan.target_url if scan else "target.local")
        self.parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        self.domain = self.parsed.hostname or self.target.replace("https://", "").replace("http://", "").split("/")[0]

    def generate_all(self) -> Dict[str, Any]:
        waf_rules = self.generate_waf_rules()
        ids_rules = self.generate_ids_signatures()
        siem_rules = self.generate_siem_rules()
        server_hardening = self.generate_server_hardening()

        return {
            "summary": {
                "target": self.domain,
                "total_findings_mitigated": len(self.findings),
                "critical_rules_count": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "generated_waf_rules": len(waf_rules),
                "generated_ids_signatures": len(ids_rules),
                "generated_siem_rules": len(siem_rules),
                "generated_hardening_rules": len(server_hardening)
            },
            "waf_rules": waf_rules,
            "ids_signatures": ids_rules,
            "siem_rules": siem_rules,
            "server_hardening": server_hardening
        }

    @classmethod
    def generate_custom(cls, target_url: str, threat_categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate defensive countermeasures on demand for any domain, IP, or network perimeter."""
        engine = cls(target_url=target_url)
        return engine.generate_all()

    def generate_waf_rules(self) -> List[Dict[str, str]]:
        """Generates ModSecurity (OWASP CRS), Cloudflare WAF, AWS WAF v2, and Nginx WAF rules."""
        rules = []

        # 1. ModSecurity Rule (OWASP CRS 3.3.x compatible)
        sid_counter = 2000001
        modsec_lines = [
            f"# ========================================================",
            f"# SWA AI Automated Blue Team - ModSecurity Ruleset for {self.domain}",
            f"# Generated automatically based on verified security audit",
            f"# ========================================================\n"
        ]

        for f in self.findings:
            rule_id = sid_counter
            sid_counter += 1
            endpoint_path = urlparse(f.endpoint).path or "/"
            param = f.parameter or ""

            if f.severity in [Severity.CRITICAL, Severity.HIGH]:
                if param:
                    modsec_lines.append(
                        f"# Rule {rule_id}: Mitigate {f.title} on parameter '{param}'\n"
                        f"SecRule REQUEST_URI \"@beginsWith {endpoint_path}\" \\\n"
                        f"    \"id:{rule_id},phase:2,deny,status:403,log,auditlog,\\\n"
                        f"    msg:'SWA-WAF: Blocked injection on {param}',\\\n"
                        f"    chain\"\n"
                        f"    SecRule ARGS:{param} \"@rx [\\'\\\"\\;\\-\\-\\(\\)]\" \"t:none,t:urlDecodeUni\"\n"
                    )
                else:
                    modsec_lines.append(
                        f"# Rule {rule_id}: Block unauthorized access to {endpoint_path}\n"
                        f"SecRule REQUEST_URI \"@streq {endpoint_path}\" \\\n"
                        f"    \"id:{rule_id},phase:1,deny,status:403,log,auditlog,\\\n"
                        f"    msg:'SWA-WAF: Restricted asset protection on {endpoint_path}'\"\n"
                    )

        # Baseline Injection & Directory Traversal Protection
        modsec_lines.append(
            f"# Rule {sid_counter}: Generic Path Traversal & Dot-Dot-Slash Defense\n"
            f"SecRule REQUEST_URI|ARGS \"@rx (?:\\.\\./|\\.\\.\\\\)\" \\\n"
            f"    \"id:{sid_counter},phase:2,deny,status:403,log,auditlog,\\\n"
            f"    msg:'SWA-WAF: Directory Traversal sequence blocked'\"\n"
        )
        sid_counter += 1
        modsec_lines.append(
            f"# Rule {sid_counter}: Defensive SQLi Keyword Pattern Interception\n"
            f"SecRule ARGS \"@rx (?i)(?:union\\s+select|select\\s+.*\\s+from|order\\s+by\\s+\\d+|sleep\\(\\d+\\))\" \\\n"
            f"    \"id:{sid_counter},phase:2,deny,status:403,log,auditlog,\\\n"
            f"    msg:'SWA-WAF: Potential SQL Injection query rejected'\"\n"
        )

        rules.append({
            "type": "ModSecurity (OWASP CRS)",
            "filename": "swa_modsecurity.conf",
            "syntax": "apache",
            "content": "\n".join(modsec_lines)
        })

        # 2. Cloudflare WAF Expression Rules
        cf_expressions = []
        for f in self.findings:
            path = urlparse(f.endpoint).path
            if path and path != "/":
                cf_expressions.append(f'(http.request.uri.path eq "{path}")')

        cf_content = "# Cloudflare WAF Custom Firewall Rule (Action: Block)\n"
        if cf_expressions:
            cf_content += " or \n".join(cf_expressions[:10])
            cf_content += "\n or (http.request.uri.path contains \"..\")"
            cf_content += "\n or (http.request.uri.query contains \"1=1\")"
            cf_content += "\n or (http.request.uri.query contains \"UNION SELECT\")"
        else:
            cf_content += '(http.request.uri.path contains "..") or (http.request.uri.query contains "UNION SELECT") or (http.request.uri.path contains "/.env")'

        rules.append({
            "type": "Cloudflare WAF Custom Rules",
            "filename": "cloudflare_waf_expression.txt",
            "syntax": "text",
            "content": cf_content
        })

        # 3. AWS WAF v2 Rule Group (JSON Statement)
        aws_waf_rule = {
            "Name": f"SWA-WAF-DefenseGroup-{self.domain.replace('.', '-')}",
            "Priority": 1,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": f"SWAWafMetric{self.domain.replace('.', '')}"
            },
            "Statement": {
                "OrStatement": {
                    "Statements": [
                        {
                            "ByteMatchStatement": {
                                "SearchString": "..",
                                "FieldToMatch": {"UriPath": {}},
                                "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
                                "PositionalConstraint": "CONTAINS"
                            }
                        },
                        {
                            "ByteMatchStatement": {
                                "SearchString": ".env",
                                "FieldToMatch": {"UriPath": {}},
                                "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                                "PositionalConstraint": "CONTAINS"
                            }
                        },
                        {
                            "ByteMatchStatement": {
                                "SearchString": "union select",
                                "FieldToMatch": {"QueryString": {}},
                                "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}, {"Priority": 1, "Type": "URL_DECODE"}],
                                "PositionalConstraint": "CONTAINS"
                            }
                        }
                    ]
                }
            }
        }
        rules.append({
            "type": "AWS WAF v2 (JSON Statement)",
            "filename": "aws_waf_v2_statement.json",
            "syntax": "json",
            "content": json.dumps(aws_waf_rule, indent=2)
        })

        # 4. Nginx WAF Security Block
        nginx_waf = f"""# Nginx Lightweight WAF & Rate Limiting Module for {self.domain}
limit_req_zone $binary_remote_addr zone=swa_per_ip_limit:10m rate=10r/s;

server {{
    # Enforce request rate limiting
    limit_req zone=swa_per_ip_limit burst=20 nodelay;

    # Deny Malicious Scanners & Bot User-Agents
    if ($http_user_agent ~* (nikto|sqlmap|acunetix|masscan|zgrab|nmap|gobuster)) {{
        return 403;
    }}

    # Block Directory Traversal and Suspicious Query Strings
    if ($query_string ~* "(\\.\\./|union.*select|benchmark\\(|sleep\\()") {{
        return 403;
    }}
}}"""
        rules.append({
            "type": "Nginx WAF Module",
            "filename": "nginx_waf_guard.conf",
            "syntax": "nginx",
            "content": nginx_waf
        })

        return rules

    def generate_ids_signatures(self) -> List[Dict[str, str]]:
        """Generates Suricata and Snort 3 network inspection signatures."""
        signatures = []
        suricata_lines = [
            f"# ----------------------------------------------------",
            f"# SWA AI Blue Team IDS/IPS Rules for Suricata 6.x / 7.x",
            f"# Target: {self.domain}",
            f"# ----------------------------------------------------\n"
        ]

        sid = 3000001
        for f in self.findings:
            endpoint_path = urlparse(f.endpoint).path or "/"
            if f.severity in [Severity.CRITICAL, Severity.HIGH]:
                suricata_lines.append(
                    f"alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ("
                    f"msg:\"SWA-IDS: Inbound Probe against ({f.title[:30]})\"; "
                    f"flow:established,to_server; "
                    f"http.uri; content:\"{endpoint_path}\"; nocase; "
                    f"classtype:web-application-attack; sid:{sid}; rev:1;)"
                )
                sid += 1

        # Generic web attacks
        suricata_lines.append(
            f"alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ("
            f"msg:\"SWA-IDS: Path Traversal Dot-Dot Attempt\"; "
            f"flow:established,to_server; "
            f"http.uri; content:\"/..\"; nocase; "
            f"classtype:web-application-attack; sid:{sid}; rev:1;)"
        )
        sid += 1

        suricata_lines.append(
            f"alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ("
            f"msg:\"SWA-IDS: Sensitive Environment Variables File Probe\"; "
            f"flow:established,to_server; "
            f"http.uri; content:\"/.env\"; nocase; "
            f"classtype:web-application-attack; sid:{sid}; rev:1;)"
        )
        sid += 1

        suricata_lines.append(
            f"alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ("
            f"msg:\"SWA-IDS: SQL Injection Pattern (UNION SELECT)\"; "
            f"flow:established,to_server; "
            f"http.uri; content:\"union\"; nocase; content:\"select\"; nocase; "
            f"classtype:web-application-attack; sid:{sid}; rev:1;)"
        )

        signatures.append({
            "type": "Suricata IDS/IPS Rules",
            "filename": "swa_suricata.rules",
            "syntax": "text",
            "content": "\n".join(suricata_lines)
        })

        # Snort 3 Rules
        snort_lines = [
            f"# ----------------------------------------------------",
            f"# SWA AI Blue Team IDS/IPS Rules for Snort 3",
            f"# Target: {self.domain}",
            f"# ----------------------------------------------------\n",
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] ( msg:"SWA-SNORT: Sensitive .env File Probe"; flow:to_server,established; http_uri; content:"/.env",nocase; sid:4000001; rev:1; )',
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] ( msg:"SWA-SNORT: Directory Traversal Pattern"; flow:to_server,established; http_uri; content:"/..",nocase; sid:4000002; rev:1; )',
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] ( msg:"SWA-SNORT: SQL Injection Keywords"; flow:to_server,established; http_uri; content:"union",nocase; content:"select",nocase; sid:4000003; rev:1; )'
        ]
        signatures.append({
            "type": "Snort 3 Network Signatures",
            "filename": "swa_snort3.rules",
            "syntax": "text",
            "content": "\n".join(snort_lines)
        })

        return signatures

    def generate_siem_rules(self) -> List[Dict[str, str]]:
        """Generates Sigma YAML rules, Splunk SPL, Elastic KQL, and Microsoft Sentinel queries."""
        siem = []
        scan_id_short = self.scan.id[:8] if self.scan else "custom"

        # 1. Sigma Rule YAML
        sigma_yaml = f"""title: Web Application Exploit Attempt Detected ({self.domain})
id: 545e-swa-siem-{scan_id_short}
status: test
description: Detects inbound exploitation attempts matching vulnerabilities identified on {self.domain}.
references:
    - https://github.com/545e/SWA
author: SWA AI Blue Team Defense Center
date: 2026/10/23
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_uri:
        cs-method:
            - 'GET'
            - 'POST'
        cs-uri-stem|contains:
            - '/..'
            - 'etc/passwd'
            - 'win.ini'
            - 'actuator'
            - '.env'
    selection_sqli:
        cs-uri-query|contains:
            - 'UNION'
            - 'SELECT'
            - 'OR 1=1'
            - 'sleep('
    selection_status:
        sc-status:
            - 500
            - 403
    condition: (selection_uri or selection_sqli) and selection_status
falsepositives:
    - Security scanner probes or automated pentest validation
level: high
"""
        siem.append({
            "type": "Sigma Detection Rule (YAML)",
            "filename": "swa_sigma_rule.yml",
            "syntax": "yaml",
            "content": sigma_yaml.strip()
        })

        # 2. Splunk SPL Search Query
        splunk_query = (
            f"# Splunk Search Processing Language (SPL)\n"
            f'index=web_logs host="*{self.domain}*"\n'
            f'| where sc_status>=400\n'
            f'| search (cs_uri_stem="*..*" OR cs_uri_stem="*.env*" OR cs_uri_query="*UNION*" OR cs_uri_query="*SELECT*")\n'
            f'| stats count values(cs_uri_stem) as target_endpoints values(c_ip) as attacker_ips by cs_method, sc_status\n'
            f'| sort - count'
        )
        siem.append({
            "type": "Splunk SPL Query",
            "filename": "splunk_investigation.spl",
            "syntax": "sql",
            "content": splunk_query
        })

        # 3. Elastic (KQL) Query
        elastic_kql = (
            f"# Elastic Lucene / KQL Query for Kibana / Elastic Security\n"
            f'url.domain: "{self.domain}" and (\n'
            f'  url.path: (*..* or *.env* or *backup.sql* or *wp-config*)\n'
            f'  or url.query: (*UNION* or *SELECT* or *sleep* or *<script*)\n'
            f'  or http.response.status_code: 500\n'
            f')'
        )
        siem.append({
            "type": "Elastic KQL Query",
            "filename": "elastic_detection.kql",
            "syntax": "text",
            "content": elastic_kql
        })

        # 4. Microsoft Sentinel KQL Query
        sentinel_kql = (
            f"// Microsoft Sentinel KQL Detection for {self.domain}\n"
            f"W3CIISLog\n"
            f"| where csHost has '{self.domain}'\n"
            f"| where csUriStem has '..' or csUriStem has '.env' or csUriQuery has 'union' or csUriQuery has 'select'\n"
            f"| where scStatus >= 400\n"
            f"| summarize AttackCount = count(), Endpoints = make_set(csUriStem) by cIP, csMethod, bin(TimeGenerated, 5m)\n"
            f"| sort by AttackCount desc"
        )
        siem.append({
            "type": "Microsoft Sentinel KQL",
            "filename": "sentinel_detection.kql",
            "syntax": "text",
            "content": sentinel_kql
        })

        return siem

    def generate_server_hardening(self) -> List[Dict[str, str]]:
        """Generates drop-in Nginx and Apache server hardening configuration blocks."""
        configs = []

        # Nginx Hardening Block
        nginx_conf = f"""# ========================================================
# SWA AI - Nginx Defensive Hardening Configuration
# Host: {self.domain}
# ========================================================

server {{
    listen 443 ssl http2;
    server_name {self.domain};

    # 1. Enforce TLS 1.2 & 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

    # 2. Defensive HTTP Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;

    # 3. Suppress Server Version Disclosure
    server_tokens off;

    # 4. Block HTTP TRACE & TRACK Methods
    if ($request_method ~ ^(TRACE|TRACK)$) {{
        return 405;
    }}

    # 5. Restrict Hidden & Sensitive Files (.env, .git, backups)
    location ~ /\\.(?!well-known) {{
        deny all;
        return 404;
    }}
    location ~* \\.(bak|config|sql|tar|gz|zip)$ {{
        deny all;
        return 404;
    }}
}}
"""
        configs.append({
            "type": "Nginx Security Block",
            "filename": "nginx_hardened.conf",
            "syntax": "nginx",
            "content": nginx_conf.strip()
        })

        # Apache Hardening Block
        apache_conf = f"""# ========================================================
# SWA AI - Apache (.htaccess / httpd.conf) Hardening
# Host: {self.domain}
# ========================================================

<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
</IfModule>

# Disable HTTP TRACE
TraceEnable Off

# Suppress Server Tokens
ServerSignature Off
ServerTokens Prod

# Deny Access to .env, .git, and Sensitive Files
<FilesMatch "^\\.(?!well-known)">
    Require all denied
</FilesMatch>
<FilesMatch "\\.(sql|bak|inc|old)$">
    Require all denied
</FilesMatch>
"""
        configs.append({
            "type": "Apache httpd / .htaccess Hardening",
            "filename": "apache_hardened.conf",
            "syntax": "apache",
            "content": apache_conf.strip()
        })

        return configs
