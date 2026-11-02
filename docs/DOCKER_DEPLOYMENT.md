# SWA AI — Docker Production & Development Deployment Guide

## Overview
SWA AI provides reproducible, hardened Docker containerization with non-root security execution (`appuser:swa`, UID 10001), healthcheck telemetry, resource limits, and persistent SQLite database volumes.

---

## 1. Quick Production Launch

```bash
# 1. Build and launch in detached mode
docker compose up -d --build

# 2. Inspect running container status
docker compose ps

# 3. Stream real-time logs
docker compose logs -f
```

---

## 2. Docker Architecture & Controls

| Component | Setting / Implementation | Purpose |
| :--- | :--- | :--- |
| **Base Image** | `python:3.12-slim` | Minimal attack surface, fast build times |
| **Security User** | `appuser:swa` (UID 10001) | Non-root principle of least privilege |
| **Persistent Volume** | `swa_ai_persistent_data` -> `/data` | Preserves `swa_data.db` across restarts |
| **Resource Limits** | CPU: 2.0 / Memory: 2048M | Prevents resource starvation on host |
| **Health Check** | `curl -f http://127.0.0.1:8000/health` | Automated orchestration liveness check |
| **Graceful Shutdown**| `stop_grace_period: 15s` | Allows in-flight scans to flush to SQLite |

---

## 3. Local Development with Hot Reload

For developers actively modifying code, use the development compose file which mounts your local codebase:

```bash
docker compose -f docker-compose.dev.yml up --build
```

---

## 4. Container Maintenance & Backup

### Trigger Online Zero-Downtime Database Backup
```bash
docker exec -it swa-ai-cyber-hub python -c "from core.database import db; print(db.backup_database())"
```

### Export Stored Scans and Database
```bash
docker cp swa-ai-cyber-hub:/data/swa_data.db ./local_backup_swa_data.db
```

### Graceful Teardown (Data is Preserved)
```bash
docker compose down
```
*(Volumes are NOT destroyed during `docker compose down`. To remove volumes explicitly, you must specify `-v`)*
