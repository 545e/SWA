# SWA AI — Complete API Inventory

**Platform Version:** 2.3.0  
**API Version:** v1  
**Architecture:** FastAPI Asynchronous Core Engine  
**Protocol:** HTTP/1.1, HTTP/2, WebSockets (RFC 6455)  
**Security Status:** Production Hardened • SSRF Protected • RBAC Enforced

---

## 1. System Health & Probes

| Method | Endpoint | Auth | Purpose | Response |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | High-level system health check | `{"status": "HEALTHY", "version": "2.3.0"}` |
| `GET` | `/health/live` | Public | Kubernetes/Docker container liveness probe | `{"status": "ALIVE", "uptime_sec": 42.1}` |
| `GET` | `/health/ready` | Public | System and database readiness probe | `{"status": "READY", "readiness": true}` |
| `GET` | `/health/dependencies` | Public | Component readiness (DB, Agents, Tools, Integrations) | `{"status": "HEALTHY", "dependencies": {...}}` |
| `GET` | `/.well-known/security.txt` | Public | RFC 9116 Vulnerability Disclosure Policy | Plaintext security contact |

---

## 2. API v1 Master Endpoints (`/api/v1/*`)

### Authentication & Access Control
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Public / Key | Authenticate credentials or API key for session token |
| `POST` | `/api/v1/auth/logout` | Session | Invalidate current operator session token |
| `GET` | `/api/v1/auth/session` | Bearer / Key | Retrieve active identity, role, and security context |
| `GET` | `/api/v1/auth/status` | Public | Check authentication mode and active schemes |

### Operators, Tenancy & Projects
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/users` | Analyst+ | List operators and service identities |
| `GET` | `/api/v1/users/me` | Authenticated | Retrieve authenticated user profile |
| `POST` | `/api/v1/users` | Admin | Provision platform operator or service account |
| `GET` | `/api/v1/organizations` | Authenticated | List enterprise tenant organizations |
| `GET` | `/api/v1/workspaces` | Authenticated | List security operations workspaces |
| `POST` | `/api/v1/workspaces` | Admin | Create operational security workspace |
| `GET` | `/api/v1/projects` | Authenticated | List assessment projects within workspace |
| `POST` | `/api/v1/projects` | Admin | Create new scoped assessment project |

### Dashboard & Metrics
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/dashboard/metrics` | Authenticated | Top-level KPI summary, posture score & findings count |
| `GET` | `/api/v1/dashboard/summary` | Authenticated | Live assessment feed, posture grade, agent status |

### Assessments (Scans)
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/assessments` | Authenticated | List all assessment scans with pagination |
| `POST` | `/api/v1/assessments` | Operator+ | Launch autonomous security assessment |
| `GET` | `/api/v1/assessments/{id}` | Authenticated | Retrieve assessment execution status and metadata |
| `POST` | `/api/v1/assessments/{id}/cancel` | Operator+ | Gracefully terminate running assessment job |
| `DELETE`| `/api/v1/assessments/{id}` | Admin | Delete assessment job and associated findings |
| `GET` | `/api/v1/assessments/{id}/findings` | Authenticated | List vulnerability findings discovered by scan |
| `GET` | `/api/v1/assessments/{id}/logs` | Authenticated | Stream telemetry logs and execution steps |

### Assets & Scope Management
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/assets` | Authenticated | List all targets authorized in scope allowlist |
| `POST` | `/api/v1/assets` | Operator+ | Authorize target domain / IP into scope allowlist |
| `GET` | `/api/v1/assets/cloud` | Authenticated | Discovered AWS, Azure, and GCP cloud resources |
| `GET` | `/api/v1/assets/containers` | Authenticated | Discovered container images and workloads |
| `GET` | `/api/v1/assets/exposed` | Authenticated | Exposed external internet perimeter assets |

### Vulnerabilities & Findings
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/vulnerabilities` | Authenticated | Deduplicated vulnerability index across assessments |
| `GET` | `/api/v1/findings` | Authenticated | Granular finding records with severity & status filters |
| `GET` | `/api/v1/findings/{id}` | Authenticated | Deep finding evidence, HTTP request/response & curl PoC |
| `PATCH`| `/api/v1/findings/{id}/status` | Analyst+ | Update lifecycle state (VERIFIED, FALSE_POSITIVE, etc.) |

### Verification & PoC
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/verification/verify` | Operator+ | Execute automated exploit verification against finding |
| `GET` | `/api/v1/verification/poc/{id}` | Authenticated | Generate deterministic curl & python exploit proofs |

### Remediation & Tickets
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/remediation/tickets` | Authenticated | List tracking tickets for discovered vulnerabilities |
| `POST` | `/api/v1/remediation/tickets` | Analyst+ | Create tracking ticket for developer remediation |
| `POST` | `/api/v1/remediation/tickets/{id}/transition` | Analyst+ | Transition ticket state (IN_PROGRESS, RESOLVED) |
| `POST` | `/api/v1/remediation/tickets/{id}/retest` | Operator+ | Trigger automated regression retest |
| `GET` | `/api/v1/remediation/plans` | Authenticated | Retrieve WAF virtual patches & code fixes |

### Security Tools
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/security-tools` | Authenticated | Inventory of all 15 integrated security suites |
| `GET` | `/api/v1/security-tools/catalog`| Authenticated | Capabilities, command flags, and categories |
| `POST` | `/api/v1/security-tools/run` | Operator+ | Execute targeted scanner against authorized target |
| `GET` | `/api/v1/security-tools/health`| Authenticated | Binary availability and local path diagnostics |

### External Integrations Hub
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/integrations/providers`| Authenticated | List all 23 supported third-party providers |
| `GET` | `/api/v1/integrations` | Authenticated | List configured integrations with masked secrets |
| `POST` | `/api/v1/integrations` | Admin | Encrypt and persist provider credentials |
| `POST` | `/api/v1/integrations/test` | Operator+ | Test live network connection to provider API |
| `GET` | `/api/v1/integrations/{id}` | Authenticated | Retrieve single integration configuration |
| `DELETE`| `/api/v1/integrations/{id}` | Admin | Remove provider integration |

### Threat Intelligence
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/threat-intelligence/iocs` | Authenticated | List indicators of compromise (IP, domain, hash) |
| `POST` | `/api/v1/threat-intelligence/enrich` | Authenticated | Multi-provider threat intelligence enrichment |
| `GET` | `/api/v1/threat-intelligence/cisa-kev` | Authenticated | Query CISA Known Exploited Vulnerabilities catalog |
| `GET` | `/api/v1/threat-intelligence/first-epss` | Authenticated | Query FIRST.org EPSS exploit prediction probabilities |

### Autonomous AI Workforce
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/ai/providers` | Authenticated | List AI LLM engines (OpenAI, Anthropic, Gemini, etc.) |
| `GET` | `/api/v1/ai/models` | Authenticated | LLM model catalog with pricing & context windows |
| `GET` | `/api/v1/ai/models/status` | Authenticated | Active AI connection status & health |
| `POST` | `/api/v1/ai/models/test` | Operator+ | Test AI model completion latency |
| `GET` | `/api/v1/ai/agents` | Authenticated | Manifests for all 85 agents across 5 operational tiers |
| `GET` | `/api/v1/ai/agents/summary` | Authenticated | Tier counts and status breakdown |
| `GET` | `/api/v1/ai/agents/{id}` | Authenticated | Agent permission boundary and allowed tools |
| `POST` | `/api/v1/ai/agents/collaborate` | Operator+ | Run collaborative 6-stage multi-agent workflow |
| `GET` | `/api/v1/ai/automation/rules` | Authenticated | Event-driven automation rules |

### Investigations, EASM, Incidents & Approvals
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/investigations` | Authenticated | List active forensic investigations |
| `GET` | `/api/v1/easm/drift` | Authenticated | Attack surface drift detection & asset changes |
| `GET` | `/api/v1/easm/graph` | Authenticated | Attack surface graph nodes and relationships |
| `GET` | `/api/v1/incidents` | Authenticated | Incident response cases |
| `POST` | `/api/v1/incidents` | Analyst+ | Create incident case |
| `GET` | `/api/v1/approvals` | Authenticated | Human-in-the-loop action approval log |
| `GET` | `/api/v1/approvals/pending` | Operator+ | Pending actions requiring operator sign-off |
| `POST` | `/api/v1/approvals/{id}/action` | Admin | Approve or reject gated exploit / probe action |

### Reports & Multi-Format Exports
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/reports/templates` | Authenticated | List 12 enterprise and Nessus-style report templates |
| `POST` | `/api/v1/reports/generate` | Operator+ | Generate report in PDF, HTML, CSV, JSON, Nessus XML |
| `GET` | `/api/v1/reports` | Authenticated | Archive of generated reports |
| `GET` | `/api/v1/exports/formats` | Authenticated | Supported report export formats and MIME types |

### Audit & Governance
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/audit/logs` | Auditor+ | Immutable security audit logs |
| `GET` | `/api/v1/audit/compliance` | Authenticated | OWASP Top 10, NIST CSF, and CIS benchmark matrix |
| `GET` | `/api/v1/system/info` | Authenticated | Host, runtime, and API version metadata |
| `GET` | `/api/v1/system/health` | Authenticated | Subsystem readiness and health overview |
