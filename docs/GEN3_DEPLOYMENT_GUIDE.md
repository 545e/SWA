# SWA AI — Generation 3 Deployment Guide

## 1. Local Windows Deployment

### Prerequisites
- Python 3.10+ (Python 3.12 recommended).
- Git for Windows.

### Quick Start
```powershell
# 1. Clone repository
git clone https://github.com/545e/SWA.git C:\Users\krish\SWA
cd C:\Users\krish\SWA

# 2. Run automated installer or setup venv
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt

# 3. Start SWA AI Server
python run.py
```
Application will be live at `http://127.0.0.1:8000`.

---

## 2. Docker & Container Deployment

### Production Docker Compose
```bash
docker compose up -d --build
```
- Multi-stage build with non-root security user (`appuser`).
- Persistent volume mount on `/app/data` for SQLite database and logs.
- Integrated container health check on `http://127.0.0.1:8000/health`.

---

## 3. Low-Resource Deployment Profile (2 vCPUs, 3 GB RAM)

For edge or constrained VPS deployments:
1. Set `SWA_MAX_CONCURRENT_SCANS=2` in `.env`.
2. Set `SWA_SCAN_CRAWLER_CONCURRENCY=2`.
3. Use external or remote AI API providers (OpenAI, Anthropic, or remote Ollama) to avoid local LLM VRAM/RAM exhaustion.
4. SQLite WAL mode maintains minimal memory footprint (< 120 MB RAM).
