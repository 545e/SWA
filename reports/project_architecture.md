# SWA AI — System Architecture & Topology
**Report ID:** ARCH-001  
**Project:** SWA AI Autonomous Enterprise Security Auditor  
**Date:** 2026-10-31 07:49:28 UTC  

## 1. Architecture Overview
SWA AI employs an asynchronous, multi-agent cyber defense architecture designed for high-concurrency automated reconnaissance, vulnerability scanning, exploit validation, and compliance reporting.

```
                    ┌─────────────────────────────────┐
                    │     Frontend Web Application    │
                    │   HTML5 / CSS3 / Vanilla JS     │
                    │   WebSocket Live Telemetry      │
                    └────────────────┬────────────────┘
                                     │ HTTP REST / WebSocket (/ws)
                    ┌────────────────▼────────────────┐
                    │      FastAPI Gateway Server     │
                    │   web/server.py (Async Router)  │
                    └───────┬─────────────────┬───────┘
                            │                 │
            ┌───────────────▼──────┐   ┌──────▼──────────────┐
            │   Agents Orchestrator│   │  Core Cyber Engines │
            │   - Recon Agent      │   │  - Cyber Export     │
            │   - Vuln Hunter      │   │  - Cyber Test       │
            │   - Exploit Validator│   │  - Cyber Deploy     │
            │   - Remediation Agent│   │  - Scope Policy     │
            │   - Blue Team Engine │   │  - Tool Registry    │
            └───────────────┬──────┘   └──────┬──────────────┘
                            │                 │
                    ┌───────▼─────────────────▼───────┐
                    │      Database & Storage         │
                    │   Thread-Safe SQLite (WAL)      │
                    │   core/database.py              │
                    └─────────────────────────────────┘
```

## 2. Core Subsystems
- **API Gateway (`web/server.py`)**: Asynchronous FastAPI server exposing 35+ REST endpoints and bidirectional WebSocket streams.
- **Data Persistence Layer (`core/database.py`)**: SQLite with WAL journaling and connection pooling for thread safety.
- **Cyber Export Engine (`core/cyber_export.py`)**: Database-backed report generator with zero false positive filter, credential redaction, and SHA-256 verification.
- **Cyber Test Engine (`core/cyber_test.py`)**: Automated verification engine covering 6 test categories.
- **Cyber Deploy Engine (`core/cyber_deploy.py`)**: 11-stage deployment orchestrator with human approval gates.
- **Scope & SSRF Defense (`core/scope_policy.py`)**: Validates targets against AWS/GCP/Azure IMDS, RFC 1918 private ranges, and lab authorization boundaries.
