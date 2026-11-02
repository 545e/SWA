# SWA AI — Cloud Platform Deployment (Render & Railway)

## 1. Render Deployment (Blueprint)
1. Fork or push your SWA repository to GitHub.
2. Sign in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Select your repository. Render automatically reads [`deploy/platform/render.yaml`](render.yaml) and provisions:
   - Hardened Docker web service.
   - 10GB persistent SSD volume mounted to `/var/data` for database survival.
   - Built-in HTTPS with automatic TLS cert renewal.
   - Automated health checks on `/health`.

## 2. Railway Deployment
1. Install Railway CLI: `npm i -g @railway/cli` or connect via the web interface.
2. Run in the repository root:
   ```bash
   railway login
   railway init
   railway up
   ```
3. Attach a Persistent Volume to `/data` in Railway Project Settings.
4. Set environment variables:
   - `SWA_PORT=8000`
   - `SWA_DB_PATH=/data/swa_data.db`
   - `HEADLESS=1`
