"""
SWA AI — Cyber Kill Chain Incident Management & Defensive Response Playbooks
Handles complete incident lifecycle management and provides defensive playbooks
tailored to all seven stages of the Lockheed Martin Cyber Kill Chain.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from core.kill_chain.models import (
    KillChainStageEnum,
    IncidentRecord,
    IncidentStatusEnum,
    SeverityEnum,
)
from core.kill_chain.db import (
    save_incident,
    get_incident,
    list_incidents,
    record_audit,
)


class IncidentManager:
    """
    Orchestrates SOC incident workflows and defensive response playbooks.
    """

    PLAYBOOKS: Dict[str, Dict[str, Any]] = {
        "reconnaissance": {
            "title": "Stage 01 — Reconnaissance Defensive Playbook",
            "phase": "Identification & Exposure Reduction",
            "steps": [
                {"step": 1, "action": "Verify External Target Scope", "description": "Confirm asset is within authorized boundary and audit public DNS/WHOIS records."},
                {"step": 2, "action": "Perimeter Port Hardening", "description": "Block all non-essential ingress ports (22, 3389, 3306, 5432, 27017) at firewall."},
                {"step": 3, "action": "Zone Transfer Mitigation", "description": "Disable unauthenticated AXFR zone transfers on all authoritative name servers."},
                {"step": 4, "action": "Mask Service Banners", "description": "Strip Apache/Nginx/IIS version headers to prevent automated version fingerprinting."},
                {"step": 5, "action": "Deploy Canary Port Decoy", "description": "Expose decoy honeypot ports to trip and rate-limit automated scanning bots."},
            ],
            "disruptive": False,
        },
        "weaponization": {
            "title": "Stage 02 — Weaponization Defensive Playbook",
            "phase": "Payload Triage & Signature Ingestion",
            "steps": [
                {"step": 1, "action": "Compute Cryptographic Hashes", "description": "Calculate SHA-256 and MD5 digests for suspicious staged artifacts."},
                {"step": 2, "action": "Query Threat Intelligence", "description": "Cross-reference hash with VirusTotal, MalwareBazaar, and internal repository."},
                {"step": 3, "action": "Static YARA Triage", "description": "Run YARA heuristic rule scanning on sample to identify malware compiler and family."},
                {"step": 4, "action": "Deploy Ingress Block Rule", "description": "Distribute verified malicious file hash to all perimeter gateways and EDR sensors."},
                {"step": 5, "action": "Isolate Staging Storage", "description": "Lock down shared temporary upload buckets or staging directories."},
            ],
            "disruptive": False,
        },
        "delivery": {
            "title": "Stage 03 — Delivery Defensive Playbook",
            "phase": "Containment & Perimeter Filtration",
            "steps": [
                {"step": 1, "action": "Message Search & Purge", "description": "Search email gateway for malicious sender or subject line and purge from all mailboxes."},
                {"step": 2, "action": "Enforce Domain Blocklist", "description": "Block delivery domain and sending IPs at border mail gateways and proxy servers."},
                {"step": 3, "action": "DNS Sinkholing", "description": "Sinkhole all embedded phishing URLs and drive-by download links across corporate DNS."},
                {"step": 4, "action": "User Credential Reset", "description": "Force password change and revoke Active Directory / IdP refresh tokens for recipient."},
                {"step": 5, "action": "Attachment Quarantine", "description": "Block .iso, .lnk, .vbs, and macro-enabled documents at the secure email gateway."},
            ],
            "disruptive": True,
        },
        "exploitation": {
            "title": "Stage 04 — Exploitation Defensive Playbook",
            "phase": "Exploit Containment & Virtual Patching",
            "steps": [
                {"step": 1, "action": "Deploy WAF Virtual Patch", "description": "Apply immediate regex WAF inspection rule blocking exploitation payload pattern."},
                {"step": 2, "action": "Verify CISA KEV Exploitation Status", "description": "Correlate CVE with CISA catalog and prioritize emergency software patching."},
                {"step": 3, "action": "Endpoint Process Isolation", "description": "Suspend web application worker processes exhibiting anomalous crash/error loops."},
                {"step": 4, "action": "Rotate Compromised Secrets", "description": "Invalidate database connection strings and API keys stored on impacted server."},
                {"step": 5, "action": "Input Sanitization Audit", "description": "Deploy parameterized queries or ORM sanitization to eliminate injection root cause."},
            ],
            "disruptive": True,
        },
        "installation": {
            "title": "Stage 05 — Installation Defensive Playbook",
            "phase": "Host Isolation & Persistence Eradication",
            "steps": [
                {"step": 1, "action": "Emergency Host Network Isolation", "description": "Sever host from local network via EDR agent while maintaining SOC telemetry tunnel."},
                {"step": 2, "action": "Terminate Malicious Process Lineage", "description": "Force kill rogue processes and child shells (powershell, cmd, bash, nc)."},
                {"step": 3, "action": "Remove Persistence Anchors", "description": "Delete unauthorized registry Run keys, scheduled tasks, and systemd service units."},
                {"step": 4, "action": "Audit Local User Accounts", "description": "Disable any backdoor accounts created during intrusion window."},
                {"step": 5, "action": "File Integrity Reversion", "description": "Restore altered system binaries from trusted gold master image."},
            ],
            "disruptive": True,
        },
        "c2": {
            "title": "Stage 06 — Command & Control Defensive Playbook",
            "phase": "Channel Severance & Beacon Suppression",
            "steps": [
                {"step": 1, "action": "Terminate Outbound TCP/UDP Socket", "description": "Send immediate TCP RST / UDP drop for connections to remote C2 IP and port."},
                {"step": 2, "action": "Sinkhole C2 Domain", "description": "Redirect domain to internal SOC forensics sinkhole listener."},
                {"step": 3, "action": "Preserve Volatile Memory Dump", "description": "Capture full RAM image of communicating endpoint before rebooting or power cycling."},
                {"step": 4, "action": "Inspect DNS Tunneling Traffic", "description": "Filter high-entropy TXT and anomalous subdomain DNS queries at internal resolvers."},
                {"step": 5, "action": "Correlate Lateral Beaconing", "description": "Scan internal NetFlow logs for secondary endpoints communicating with same C2 node."},
            ],
            "disruptive": True,
        },
        "actions_on_objectives": {
            "title": "Stage 07 — Actions on Objectives Defensive Playbook",
            "phase": "Disaster Containment, Recovery & Forensic Preservation",
            "steps": [
                {"step": 1, "action": "Cut Egress Data Pipelines", "description": "Sever all external bandwidth and revoke cloud storage API tokens to stop exfiltration."},
                {"step": 2, "action": "Halt Ransomware Spread", "description": "Execute network-wide microsegmentation and freeze SMB/NFS file shares."},
                {"step": 3, "action": "Verify Immutable Backup Vaults", "description": "Confirm integrity of air-gapped snapshots and verify no ransomware encryption on backups."},
                {"step": 4, "action": "Revoke All Domain Admin Credentials", "description": "Perform synchronized Kerberos krbtgt account double-reset and reset privileged accounts."},
                {"step": 5, "action": "Notify Legal & Regulatory Teams", "description": "If PII or sensitive data was exfiltrated, engage incident counsel and breach response."},
            ],
            "disruptive": True,
        },
    }

    def create_incident(
        self,
        title: str,
        severity: str,
        assigned_analyst: str,
        affected_assets: List[str],
        description: str,
        stages_involved: List[str],
        linked_findings: List[str],
        linked_evidence: Optional[List[str]] = None,
    ) -> IncidentRecord:
        inc_id = f"inc_{uuid.uuid4().hex[:8]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        stages = []
        for s in stages_involved:
            try:
                stages.append(KillChainStageEnum(s.lower()))
            except Exception:
                pass

        sev_str = severity.upper()
        sev = SeverityEnum[sev_str] if sev_str in SeverityEnum.__members__ else SeverityEnum.HIGH

        # Default containment actions recommended by playbooks
        recs = []
        for s in stages:
            s_val = s.value
            if s_val in self.PLAYBOOKS:
                recs.append(f"{self.PLAYBOOKS[s_val]['title']}: {self.PLAYBOOKS[s_val]['steps'][0]['action']}")

        inc = IncidentRecord(
            id=inc_id,
            title=title,
            severity=sev,
            status=IncidentStatusEnum.NEW,
            assigned_analyst=assigned_analyst or "SOC Analyst",
            affected_assets=affected_assets,
            description=description,
            stages_involved=stages,
            linked_findings=linked_findings,
            linked_evidence=linked_evidence or [],
            containment_recommendations=recs,
            containment_actions_taken=[],
            remediation_notes="",
            audit_trail=[{
                "timestamp": now,
                "actor": assigned_analyst or "SOC Analyst",
                "action": "INCIDENT_CREATED",
                "notes": f"Incident created with severity {sev.value} affecting {affected_assets}.",
            }],
            created_at=now,
            updated_at=now,
        )

        save_incident(inc)
        record_audit("CREATE_INCIDENT", "INCIDENT", inc_id, assigned_analyst, title)
        return inc

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        analyst: str = "SOC Lead",
        notes: str = "",
    ) -> Optional[IncidentRecord]:
        inc = get_incident(incident_id)
        if not inc:
            return None

        stat_str = new_status.upper()
        if stat_str not in IncidentStatusEnum.__members__:
            raise ValueError(f"Invalid incident status: {new_status}")

        inc.status = IncidentStatusEnum[stat_str]
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        inc.updated_at = now

        inc.audit_trail.append({
            "timestamp": now,
            "actor": analyst,
            "action": f"STATUS_TRANSITION_TO_{stat_str}",
            "notes": notes or f"Status changed to {stat_str}.",
        })

        if notes:
            inc.remediation_notes = (inc.remediation_notes + f"\n[{now}] {analyst}: {notes}").strip()

        save_incident(inc)
        record_audit("UPDATE_INCIDENT_STATUS", "INCIDENT", incident_id, analyst, f"Status: {stat_str}")
        return inc

    def get_playbook_for_stage(self, stage: str) -> Dict[str, Any]:
        s = stage.lower()
        if s in self.PLAYBOOKS:
            return self.PLAYBOOKS[s]
        return {
            "title": f"{stage.capitalize()} Defensive Playbook",
            "phase": "General Defense",
            "steps": [{"step": 1, "action": "General Triage", "description": "Review correlated evidence and isolate asset."}],
            "disruptive": False,
        }
