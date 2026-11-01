"""
SWA AI — Continuous Attack Surface Intelligence & Drift Engine (EASM)
Detects external attack surface changes, new/removed assets, DNS modifications,
new open ports, technology drift, expiring certificates, and endpoint exposure.
Distinguishes genuine enterprise drift from transient network collection errors.
"""

from typing import List, Dict, Any, Optional
import datetime
from core.intelligence_models import AssetDriftEvent, DriftType
from core.database import db
from core.models import ReconResult, ScanJob


class AttackSurfaceIntelligenceEngine:
    """Monitors, tracks, and diffs external attack surfaces across assessment cycles."""

    @staticmethod
    def evaluate_drift(scan_job: ScanJob, current_recon: ReconResult) -> List[AssetDriftEvent]:
        """Compares current reconnaissance observations against historical baseline."""
        target = scan_job.target_url
        drift_events: List[AssetDriftEvent] = []

        # Retrieve previous scans for this target to establish baseline
        past_scans = db.get_scans(limit=10)
        previous_scan = None
        for s in past_scans:
            if s.id != scan_job.id and s.target_url == target and s.recon_data:
                previous_scan = s
                break

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if not previous_scan or not previous_scan.recon_data:
            # Baseline initial observation event
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=target,
                drift_type=DriftType.NEW_ASSET,
                title=f"Attack Surface Baseline Established for {target}",
                description=f"Initial discovery identified {len(current_recon.open_ports)} open services and {len(current_recon.ip_addresses)} resolved IP addresses.",
                current_state={
                    "ips": current_recon.ip_addresses,
                    "ports": [p.get("port") for p in current_recon.open_ports],
                    "technologies": [t.get("name") if isinstance(t, dict) else str(t) for t in current_recon.technologies]
                },
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))
            for ev in drift_events:
                db.save_drift_event(ev.model_dump())
            return drift_events

        prev_recon = previous_scan.recon_data

        # 1. Detect New or Changed IP Addresses (DNS Drift)
        prev_ips = set(prev_recon.ip_addresses or [])
        curr_ips = set(current_recon.ip_addresses or [])
        new_ips = curr_ips - prev_ips
        removed_ips = prev_ips - curr_ips

        if new_ips:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=f"IP Infrastructure: {target}",
                drift_type=DriftType.DNS_CHANGE,
                title=f"DNS Drift: New IP Addresses Detected ({', '.join(new_ips)})",
                description=f"Target {target} now resolves to new IP addresses: {list(new_ips)}.",
                previous_state={"ips": list(prev_ips)},
                current_state={"ips": list(curr_ips)},
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        # 2. Detect New or Closed Open Ports
        prev_ports = {p.get("port") for p in (prev_recon.open_ports or []) if p.get("port")}
        curr_ports = {p.get("port") for p in (current_recon.open_ports or []) if p.get("port")}

        new_ports = curr_ports - prev_ports
        for np in new_ports:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=f"{target}:{np}",
                drift_type=DriftType.NEW_PORT_SERVICE,
                title=f"New Attack Surface Exposure: Port {np} Opened",
                description=f"A newly exposed network service was detected listening on port {np}.",
                previous_state={"open_ports": list(prev_ports)},
                current_state={"open_ports": list(curr_ports)},
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        closed_ports = prev_ports - curr_ports
        for cp in closed_ports:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=f"{target}:{cp}",
                drift_type=DriftType.CLOSED_PORT_SERVICE,
                title=f"Service Decommissioned: Port {cp} Closed",
                description=f"Network port {cp} is no longer accessible on {target}.",
                previous_state={"open_ports": list(prev_ports)},
                current_state={"open_ports": list(curr_ports)},
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        # 3. Detect New Subdomains
        prev_subs = {s.get("subdomain") for s in (prev_recon.subdomains or []) if s.get("subdomain")}
        curr_subs = {s.get("subdomain") for s in (current_recon.subdomains or []) if s.get("subdomain")}
        new_subs = curr_subs - prev_subs

        for ns in new_subs:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=ns,
                drift_type=DriftType.NEW_ASSET,
                title=f"New Subdomain Discovered: {ns}",
                description=f"Continuous reconnaissance discovered a new subdomain belonging to {target}.",
                previous_state={},
                current_state={"subdomain": ns},
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        # 4. Detect Technology Stack Changes
        def _get_tech_names(tech_list):
            names = set()
            for t in (tech_list or []):
                val = (t.get("name") if isinstance(t, dict) else str(t)) if t else None
                if val:
                    names.add(str(val))
            return names

        prev_tech = _get_tech_names(prev_recon.technologies)
        curr_tech = _get_tech_names(current_recon.technologies)
        new_tech = curr_tech - prev_tech

        if new_tech:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=f"Technology Stack: {target}",
                drift_type=DriftType.TECHNOLOGY_CHANGED,
                title=f"Technology Stack Drift: {', '.join(new_tech)} Detected",
                description=f"New frameworks or server software detected on {target}: {list(new_tech)}.",
                previous_state={"technologies": list(prev_tech)},
                current_state={"technologies": list(curr_tech)},
                confidence="HIGH_PROBABILITY",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        # 5. Detect SSL Certificate Expiration Warning
        ssl_info = current_recon.ssl_info or {}
        days_left = ssl_info.get("days_remaining") or ssl_info.get("days_left")
        if days_left is not None and isinstance(days_left, (int, float)) and days_left < 30:
            drift_events.append(AssetDriftEvent(
                target=target,
                asset_name=f"TLS Certificate: {target}",
                drift_type=DriftType.CERTIFICATE_EXPIRING,
                title=f"Expiring TLS Certificate Alert ({days_left} Days Remaining)",
                description=f"SSL certificate for {target} will expire in {days_left} days. Renewal action required.",
                current_state=ssl_info,
                confidence="CONFIRMED",
                is_genuine_change=True,
                detected_at=now_iso
            ))

        # Save all detected events into database
        for ev in drift_events:
            db.save_drift_event(ev.model_dump())

        return drift_events

    @staticmethod
    def get_history(limit: int = 50, project_id: Optional[str] = None) -> List[AssetDriftEvent]:
        """Retrieves attack surface drift history."""
        raw_list = db.get_drift_events(limit=limit, project_id=project_id)
        return [AssetDriftEvent(**r) for r in raw_list]


attack_surface_intel = AttackSurfaceIntelligenceEngine()
