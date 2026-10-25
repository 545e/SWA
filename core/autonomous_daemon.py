"""
SWA AI — Autonomous Continuous Attack Surface & Vulnerability Monitor Daemon
Periodically audits target domains, discovers newly spawned subdomains,
tracks attack surface deltas, verifies takeover vulnerabilities,
and maintains persistent historical state.
"""

import asyncio
import datetime
import json
import os
import time
from typing import Dict, List, Any, Optional, Set

from agents.amass_engine import AmassSubdomainEngine
from core.models import ScanConfig, ScanJob, ScanProfile, ScanStatus
from core.database import db
from core.queue_manager import queue_manager
from agents.orchestrator import SWAOrchestrator

class AutonomousCyberDaemon:
    def __init__(self, targets_file: str, interval_hours: float = 12.0, recursive: bool = True):
        self.targets_file = targets_file
        self.interval_seconds = max(60, int(interval_hours * 3600))
        self.recursive = recursive
        self.state_file = os.path.join(os.path.dirname(targets_file), "daemon_state.json")
        self.running = False

    def load_targets(self) -> List[Dict[str, Any]]:
        """Loads target domains and assessment configurations from JSON."""
        if not os.path.exists(self.targets_file):
            # Create default template
            default_targets = [
                {"domain": "example.com", "profile": "quick", "enabled": True}
            ]
            os.makedirs(os.path.dirname(self.targets_file), exist_ok=True)
            with open(self.targets_file, "w", encoding="utf-8") as f:
                json.dump(default_targets, f, indent=2)
            return default_targets

        try:
            with open(self.targets_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Error loading targets file: {e}")
            return []

    def load_previous_state(self) -> Dict[str, Any]:
        """Loads baseline asset snapshots for delta comparison."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_current_state(self, state: Dict[str, Any]):
        """Persists current asset snapshots."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[-] Error saving daemon state: {e}")

    async def run_single_cycle(self):
        """Runs one autonomous surveillance cycle across all enabled targets."""
        targets = self.load_targets()
        previous_state = self.load_previous_state()
        new_state = dict(previous_state)

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"\n\033[96m[⚡] Autonomous Cyber Daemon Cycle Triggered at {timestamp}\033[0m")
        print(f"[+] Active monitored targets: {len(targets)}")

        for t in targets:
            domain = t.get("domain", "").strip()
            if not domain or not t.get("enabled", True):
                continue

            profile = t.get("profile", "quick")
            print(f"\n[+] Autonomous scan starting on: {domain} [Profile: {profile}]")

            # 1. Subdomain Intelligence & Takeover Verification
            engine = AmassSubdomainEngine(
                scan_id=f"daemon_{int(time.time())}",
                base_domain=domain,
                recursive=self.recursive,
                concurrency=25
            )
            subs, takeovers = await engine.run()
            current_hostnames = {s["subdomain"] for s in subs}

            # 2. Compute Attack Surface Delta (New vs Previous)
            prev_hostnames = set(previous_state.get(domain, {}).get("subdomains", []))
            newly_discovered = current_hostnames - prev_hostnames
            stale_removed = prev_hostnames - current_hostnames

            print(f"[✓] {domain}: Total Mapped: {len(subs)} | Live: {sum(1 for s in subs if s.get('status'))}")
            if newly_discovered:
                print(f"\033[92m[!] ATTACK SURFACE EXPANSION DETECTED: {len(newly_discovered)} new assets!\033[0m")
                for sub in list(newly_discovered)[:10]:
                    print(f"    + NEW: {sub}")

            if takeovers:
                print(f"\033[91m[!] CRITICAL: {len(takeovers)} Subdomain Takeovers detected on {domain}!\033[0m")
                for to in takeovers:
                    print(f"    - {to.title}: {to.endpoint}")

            # 3. Trigger Autonomous Vulnerability Assessment Job
            config = ScanConfig(
                target_url=f"https://{domain}",
                profile=ScanProfile(profile) if profile in [p.value for p in ScanProfile] else ScanProfile.QUICK,
                max_depth=2,
                concurrency=5
            )
            job = ScanJob(
                target_url=f"https://{domain}",
                status=ScanStatus.PENDING,
                profile=config.profile,
                config=config
            )
            db.save_scan(job)
            orchestrator = SWAOrchestrator(job)
            await orchestrator.execute()

            # Record state
            new_state[domain] = {
                "last_scanned": timestamp,
                "subdomains": list(current_hostnames),
                "total_assets": len(subs),
                "takeover_count": len(takeovers),
                "newly_added_this_run": list(newly_discovered)
            }

        self.save_current_state(new_state)
        print(f"\n\033[92m[✓] Autonomous cycle complete. Next cycle in {self.interval_seconds // 3600} hours.\033[0m")

    async def start(self):
        """Starts continuous daemon loop."""
        self.running = True
        print(f"\033[92m[⚡] SWA AI Autonomous Surveillance Daemon Started!\033[0m")
        print(f"[+] Monitoring configuration: {self.targets_file}")
        print(f"[+] Frequency: Every {self.interval_seconds / 3600:.1f} hour(s)")
        print(f"[i] Press Ctrl+C in this terminal to stop daemon.\n")

        while self.running:
            try:
                await self.run_single_cycle()
            except Exception as e:
                print(f"\033[91m[-] Daemon cycle encountered error: {e}\033[0m")

            # Sleep until next scheduled cycle
            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break
