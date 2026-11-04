# SWA AI — API Deployment & Production Runbook

## 1. Quick Start Local Execution
```powershell
# 1. Activate Python virtual environment
.\venv\Scripts\Activate.ps1

# 2. Install dependencies (FastAPI, Uvicorn, httpx, ReportLab)
pip install -r requirements.txt

# 3. Launch the platform (Default host: 127.0.0.1, Port: 8000)
python run.py
```

## 2. Docker Container Deployment
```bash
# Build production container
docker build -t swa-ai-platform:latest .

# Run with persistent volume for database and reports
docker run -d \
  -p 8000:8000 \
  -e SWA_AUTH_ENABLED=true \
  -e SWA_MASTER_API_KEY="swa_master_key_change_me" \
  -v swa_data:/app/data \
  --name swa-ai \
  swa-ai-platform:latest
```

## 3. Production Readiness & Orchestration Probes
Configure Kubernetes or cloud container orchestrators with the native health probes:
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```
