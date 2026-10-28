# SWA AI — Deployment & Production Operations Guide

This guide covers deployment options for SWA AI: bare-metal / virtual machine direct deployment and Docker containerized deployment.

---

## 1. Direct Deployment (Windows & Linux)

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/545e/SWA.git swa-ai
   cd swa-ai
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and set desired options:
   ```bash
   cp .env.example .env
   ```

4. **Launch the Application**:
   - Windows:
     ```cmd
     run.bat
     ```
   - Linux:
     ```bash
     chmod +x run.sh
     ./run.sh
     ```
   - Direct Python command:
     ```bash
     python run.py --host 127.0.0.1 --port 8000
     ```

5. **Verify Health**:
   Navigate to `http://127.0.0.1:8000/api/tools/status` or run:
   ```bash
   curl -s http://127.0.0.1:8000/api/tools/status
   ```

---

## 2. Docker Deployment

SWA AI provides a multi-stage `Dockerfile` and `docker-compose.yml` for isolated container execution.

### Building and Running with Docker Compose:

```bash
docker compose up -d --build
```

### Checking Container Health:

```bash
docker compose ps
docker compose logs -f swa-ai
```

### Docker Compose Configuration (`docker-compose.yml`):
```yaml
version: '3.8'

services:
  swa-ai:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SWA_HOST=0.0.0.0
      - SWA_PORT=8000
      - SWA_LAB_MODE=false
    volumes:
      - swa_data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/tools/status"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  swa_data:
```

---

## 3. Production Hardening Checklist

- [x] **SSRF Protection Active**: Scope policy blocks loopback, private networks, and IMDS metadata.
- [x] **HTTP Security Headers Enforced**: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy active on all endpoints.
- [x] **Subprocess Argument Arrays**: Commands executed without shell string interpolation (`shell=True` prohibited).
- [x] **Rate Limiting & Timeouts**: Strict 5s-60s per-probe timeouts prevent hung processes.
- [x] **No Hardcoded Secrets**: Credentials managed via environment variables.
