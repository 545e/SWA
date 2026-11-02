# SWA AI — Docker Production Deployment Guide

## Overview
This configuration deploys SWA AI inside a hardened, non-root Docker container (`appuser:swa`, UID 10001) with persistent volume storage for SQLite database records, automated health checking, CPU/memory limits, and log rotation.

---

## 1. Quick Start
```bash
# 1. Copy production environment file
cp deploy/docker/.env.production.example .env

# 2. Build and run via Docker Compose
docker compose -f deploy/docker/docker-compose.prod.yml up -d --build

# 3. Verify container status and healthcheck
docker compose -f deploy/docker/docker-compose.prod.yml ps
```

---

## 2. Essential Commands

| Action | Command |
| :--- | :--- |
| **Inspect Logs** | `docker compose -f deploy/docker/docker-compose.prod.yml logs -f` |
| **Trigger Backup** | `docker exec -it swa-ai-production python -c "from core.database import db; print(db.backup_database())"` |
| **Check Health** | `curl -f http://127.0.0.1:8000/health` |
| **Restart Container**| `docker compose -f deploy/docker/docker-compose.prod.yml restart` |
| **Stop Without Data Loss** | `docker compose -f deploy/docker/docker-compose.prod.yml down` |

> **Note on Data Persistence**: Database records reside in the named volume `swa_ai_production_data` (`/data`). Standard `docker compose down` preserves this volume.
