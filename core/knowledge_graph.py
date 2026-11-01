"""
SWA AI — Relationship-Based Security Knowledge Graph Engine
Maintains an interconnected graph connecting Organizations, Projects, Domains, Subdomains,
IP Addresses, Network Services, Applications, API Endpoints, Technologies, Certificates,
Vulnerabilities, Findings, Evidence, Mitigations, and Asset Owners.
"""

from typing import List, Dict, Any, Optional
import uuid
import datetime
from urllib.parse import urlparse
from core.intelligence_models import (
    GraphNode,
    GraphEdge,
    GraphNodeType,
    SecurityKnowledgeGraph
)
from core.database import db
from core.models import ScanJob, VulnerabilityFinding, ReconResult


class SecurityKnowledgeGraphEngine:
    """Manages the SWA relationship-based security intelligence knowledge graph."""

    def __init__(self):
        pass

    def ingest_scan(self, scan_job: ScanJob, findings: List[VulnerabilityFinding], recon_data: Optional[ReconResult] = None):
        """Ingests a completed security assessment into the persistent knowledge graph."""
        target = scan_job.target_url
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        project_id = "proj_default"

        # 1. Domain Node
        domain_id = f"dom_{hostname.replace('.', '_')}"
        db.upsert_knowledge_node({
            "id": domain_id,
            "type": GraphNodeType.DOMAIN.value,
            "label": hostname,
            "properties": {"target_url": target, "scheme": parsed.scheme},
            "criticality": "HIGH"
        })

        # Link Project to Domain
        db.upsert_knowledge_edge({
            "id": f"edge_{project_id}_{domain_id}",
            "source_id": project_id,
            "target_id": domain_id,
            "relationship": "OWNS",
            "properties": {"added_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        })

        # 2. Application Node
        app_id = f"app_{hostname.replace('.', '_')}_{port}"
        db.upsert_knowledge_node({
            "id": app_id,
            "type": GraphNodeType.APPLICATION.value,
            "label": f"Web App ({hostname}:{port})",
            "properties": {"base_url": f"{parsed.scheme}://{hostname}:{port}"},
            "criticality": "HIGH"
        })

        db.upsert_knowledge_edge({
            "id": f"edge_{domain_id}_{app_id}",
            "source_id": domain_id,
            "target_id": app_id,
            "relationship": "HOSTS_APPLICATION",
            "properties": {}
        })

        # 3. Ingest Reconnaissance Data (IPs, Open Ports, Technologies, Subdomains, SSL)
        if recon_data:
            # IPs
            for ip in recon_data.ip_addresses:
                ip_id = f"ip_{ip.replace('.', '_').replace(':', '_')}"
                db.upsert_knowledge_node({
                    "id": ip_id,
                    "type": GraphNodeType.IP_ADDRESS.value,
                    "label": ip,
                    "properties": {"ip": ip},
                    "criticality": "MEDIUM"
                })
                db.upsert_knowledge_edge({
                    "id": f"edge_{domain_id}_{ip_id}",
                    "source_id": domain_id,
                    "target_id": ip_id,
                    "relationship": "RESOLVES_TO",
                    "properties": {}
                })

            # Open Ports / Network Services
            for p in recon_data.open_ports:
                port_num = p.get("port")
                service_name = p.get("service", "unknown")
                service_id = f"svc_{hostname.replace('.', '_')}_{port_num}"
                db.upsert_knowledge_node({
                    "id": service_id,
                    "type": GraphNodeType.NETWORK_SERVICE.value,
                    "label": f"{service_name.upper()} (Port {port_num})",
                    "properties": {"port": port_num, "service": service_name, "state": p.get("state", "open")},
                    "criticality": "MEDIUM"
                })
                db.upsert_knowledge_edge({
                    "id": f"edge_{domain_id}_{service_id}",
                    "source_id": domain_id,
                    "target_id": service_id,
                    "relationship": "EXPOSES_SERVICE",
                    "properties": {}
                })

            # Technologies
            for t in (recon_data.technologies or []):
                tech_name = (t.get("name") if isinstance(t, dict) else str(t)) if t else None
                if not tech_name:
                    continue
                tech_id = f"tech_{str(tech_name).lower().replace(' ', '_')}"
                db.upsert_knowledge_node({
                    "id": tech_id,
                    "type": GraphNodeType.TECHNOLOGY.value,
                    "label": str(tech_name),
                    "properties": {"version": t.get("version", "") if isinstance(t, dict) else ""},
                    "criticality": "INFO"
                })
                db.upsert_knowledge_edge({
                    "id": f"edge_{app_id}_{tech_id}",
                    "source_id": app_id,
                    "target_id": tech_id,
                    "relationship": "RUNS_TECHNOLOGY",
                    "properties": {}
                })

            # Subdomains
            for sub in (recon_data.subdomains or [])[:15]:
                sub_name = sub.get("subdomain")
                if sub_name:
                    sub_id = f"sub_{sub_name.replace('.', '_')}"
                    db.upsert_knowledge_node({
                        "id": sub_id,
                        "type": GraphNodeType.SUBDOMAIN.value,
                        "label": sub_name,
                        "properties": {"status": sub.get("status_code") or sub.get("status")},
                        "criticality": "HIGH" if sub.get("takeover_risk") else "LOW"
                    })
                    db.upsert_knowledge_edge({
                        "id": f"edge_{domain_id}_{sub_id}",
                        "source_id": domain_id,
                        "target_id": sub_id,
                        "relationship": "HAS_SUBDOMAIN",
                        "properties": {}
                    })

        # 4. Ingest Findings, Vulnerabilities & Evidence
        for f in findings:
            find_id = f"find_{f.id}"
            db.upsert_knowledge_node({
                "id": find_id,
                "type": GraphNodeType.FINDING.value,
                "label": f.title,
                "properties": {
                    "severity": f.severity.value,
                    "cvss": f.cvss_score,
                    "cwe": f.cwe_id,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "verified": f.verified
                },
                "criticality": f.severity.value
            })

            # Link App to Finding
            db.upsert_knowledge_edge({
                "id": f"edge_{app_id}_{find_id}",
                "source_id": app_id,
                "target_id": find_id,
                "relationship": "AFFECTED_BY_FINDING",
                "properties": {"severity": f.severity.value}
            })

            # Vulnerability / CWE Node
            cwe_label = f.cwe_id or f.owasp_category or "Vulnerability Class"
            vuln_id = f"vuln_{cwe_label.lower().replace(' ', '_').replace('-', '_')}"
            db.upsert_knowledge_node({
                "id": vuln_id,
                "type": GraphNodeType.VULNERABILITY.value,
                "label": cwe_label,
                "properties": {"cwe_id": f.cwe_id, "owasp": f.owasp_category},
                "criticality": f.severity.value
            })
            db.upsert_knowledge_edge({
                "id": f"edge_{find_id}_{vuln_id}",
                "source_id": find_id,
                "target_id": vuln_id,
                "relationship": "CLASSIFIED_AS",
                "properties": {}
            })

            # Evidence Node
            if f.poc_curl or f.request_evidence:
                evid_id = f"evid_{f.id}"
                db.upsert_knowledge_node({
                    "id": evid_id,
                    "type": GraphNodeType.EVIDENCE.value,
                    "label": f"PoC Evidence ({f.id})",
                    "properties": {
                        "curl": f.poc_curl[:200] if f.poc_curl else "",
                        "verification_explanation": f.poc_explanation[:200] if f.poc_explanation else ""
                    },
                    "criticality": "INFO"
                })
                db.upsert_knowledge_edge({
                    "id": f"edge_{find_id}_{evid_id}",
                    "source_id": find_id,
                    "target_id": evid_id,
                    "relationship": "VERIFIED_BY_EVIDENCE",
                    "properties": {}
                })

            # Remediation Node
            if f.remediation_advice:
                rem_id = f"rem_{f.id}"
                db.upsert_knowledge_node({
                    "id": rem_id,
                    "type": GraphNodeType.REMEDIATION.value,
                    "label": f"Fix: {f.title[:30]}...",
                    "properties": {"advice": f.remediation_advice[:200]},
                    "criticality": "INFO"
                })
                db.upsert_knowledge_edge({
                    "id": f"edge_{find_id}_{rem_id}",
                    "source_id": find_id,
                    "target_id": rem_id,
                    "relationship": "RESOLVED_BY",
                    "properties": {}
                })

    def get_full_graph(self) -> SecurityKnowledgeGraph:
        """Returns the complete knowledge graph model."""
        raw = db.get_knowledge_graph()
        nodes = [GraphNode(**n) for n in raw.get("nodes", [])]
        edges = [GraphEdge(**e) for e in raw.get("edges", [])]
        return SecurityKnowledgeGraph(
            nodes=nodes,
            edges=edges,
            summary=raw.get("summary", {})
        )

    def query_exposed_assets(self) -> List[Dict[str, Any]]:
        """Finds all assets with open network services or active findings."""
        graph = self.get_full_graph()
        exposed = []
        for node in graph.nodes:
            if node.type in (GraphNodeType.DOMAIN, GraphNodeType.APPLICATION, GraphNodeType.SUBDOMAIN):
                # Count connected findings and services
                connected_edges = [e for e in graph.edges if e.source_id == node.id or e.target_id == node.id]
                findings_count = sum(1 for e in connected_edges if "FINDING" in e.relationship)
                services_count = sum(1 for e in connected_edges if "SERVICE" in e.relationship)
                if findings_count > 0 or services_count > 0:
                    exposed.append({
                        "node_id": node.id,
                        "label": node.label,
                        "type": node.type.value,
                        "criticality": node.criticality,
                        "connected_findings": findings_count,
                        "connected_services": services_count,
                        "properties": node.properties
                    })
        return exposed

    def query_shared_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Identifies vulnerabilities or CWEs that affect multiple applications or endpoints."""
        graph = self.get_full_graph()
        vuln_nodes = [n for n in graph.nodes if n.type == GraphNodeType.VULNERABILITY]
        shared = []
        for vn in vuln_nodes:
            edges = [e for e in graph.edges if e.target_id == vn.id and e.relationship == "CLASSIFIED_AS"]
            if len(edges) > 1:
                shared.append({
                    "vulnerability_id": vn.id,
                    "label": vn.label,
                    "affected_findings_count": len(edges),
                    "properties": vn.properties
                })
        return shared


knowledge_graph_engine = SecurityKnowledgeGraphEngine()
