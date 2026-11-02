# SWA AI — Google Cloud Platform (GCP) Deployment Guide

## Deployment Options

### Option 1: Google Cloud Run (Serverless Web + Second Generation Engine)
Cloud Run automatically issues and manages free Google-managed SSL certificates and routes global HTTPS traffic to your container.

```bash
# 1. Set Google Cloud Project
gcloud config set project YOUR_GCP_PROJECT_ID

# 2. Build and push container to Google Artifact Registry
gcloud builds submit --tag gcr.io/YOUR_GCP_PROJECT_ID/swa-ai:latest

# 3. Deploy to Cloud Run
gcloud run deploy swa-ai-hub \
  --image gcr.io/YOUR_GCP_PROJECT_ID/swa-ai:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8000 \
  --memory 2Gi \
  --cpu 2 \
  --min-instances 1 \
  --set-env-vars SWA_HOST=0.0.0.0,SWA_PORT=8000,DOCKER_CONTAINER=1
```

> **Data Persistence on Cloud Run**: Use Google Cloud Filestore (NFS volume) mounted to `/data` in Cloud Run Gen2, or host the SQLite database in an attached Cloud Storage FUSE bucket (`/data`).

### Option 2: Google Compute Engine (GCE VM)
Launch an `e2-standard-2` VM running Ubuntu 22.04 LTS and run `deploy/linux/deploy.sh`.
