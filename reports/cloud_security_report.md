# SWA AI — Cloud & Infrastructure Security Report
**Document ID:** SEC-CLOUD-2026-015  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Cloud Deployment Archetypes
SWA AI supports three distinct deployment profiles:
1. **Local Workstation:** Standalone execution via `run.bat` or `python run.py`.
2. **Containerized Execution:** `docker-compose.yml` deploying isolated services with unprivileged user context.
3. **Cloud Native Orchestration:** Helm charts and Kubernetes manifests with read-only root filesystems and non-root UID 10001.
