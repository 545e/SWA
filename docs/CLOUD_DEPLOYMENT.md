# SWA AI — Multi-Cloud Deployment Guide

This guide details cloud deployment architectures across **Generic Linux VPS**, **Amazon Web Services (AWS)**, **Microsoft Azure**, **Google Cloud Platform (GCP)**, and cloud platforms (**Render / Railway**).

---

## Cloud Deployment Matrix

| Cloud Target | Recommended Architecture | Persistent Storage | TLS / HTTPS | Configuration Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Linux VPS (Ubuntu / Debian / Kali)** | Systemd + Nginx Reverse Proxy | Local Disk (WAL mode) | Certbot / Let's Encrypt | [`deploy/linux/`](../deploy/linux/) |
| **AWS (Amazon Web Services)** | ECS on AWS Fargate | Amazon EFS Mount | AWS ALB + ACM Certificate | [`deploy/aws/`](../deploy/aws/) |
| **Microsoft Azure** | Azure Container Apps | Azure Files Share | Azure Managed TLS Ingress | [`deploy/azure/`](../deploy/azure/) |
| **Google Cloud (GCP)** | Cloud Run (Gen2) / Compute Engine | Cloud Filestore or GCS FUSE | Google Managed HTTPS | [`deploy/gcp/`](../deploy/gcp/) |
| **Render** | Docker Web Service Blueprint | Render Persistent Disk (10GB) | Native Render SSL | [`deploy/platform/render.yaml`](../deploy/platform/render.yaml) |
| **Railway** | Docker Container Service | Railway Volume Mount | Native Railway SSL | [`deploy/platform/railway.json`](../deploy/platform/railway.json) |
| **Self-Hosted On-Prem** | Dedicated Bare Metal / Air-Gapped | NVMe Local Disk + Cron Backup | Internal PKI / Nginx | [`deploy/self-hosted/`](../deploy/self-hosted/) |

---

## 1. Generic Linux VPS Deployment
1. Connect via SSH: `ssh user@your-vps-ip`.
2. Clone repository: `git clone https://github.com/545e/SWA.git /opt/swa-ai`.
3. Run automated deployment:
   ```bash
   cd /opt/swa-ai
   sudo bash deploy/linux/deploy.sh
   ```
4. Configure domain and SSL certificates with Certbot:
   ```bash
   sudo certbot --nginx -d swa.yourdomain.com
   ```

---

## 2. AWS Cloud Deployment
- **Option A (Fargate)**: Register [`deploy/aws/ecs-task-definition.json`](../deploy/aws/ecs-task-definition.json) in your AWS ECS cluster and attach an Amazon EFS mount for `/data`.
- **Option B (EC2)**: Launch a `t3.medium` instance using the cloud-init script [`deploy/aws/ec2-user-data.sh`](../deploy/aws/ec2-user-data.sh).

---

## 3. Microsoft Azure Deployment
- Run the Azure CLI deployment:
  ```bash
  az containerapp create \
    --name swa-ai-hub \
    --resource-group rg-swa \
    --environment env-swa \
    --image YOUR_ACR.azurecr.io/swa-ai:latest \
    --target-port 8000 \
    --ingress external
  ```

---

## 4. Google Cloud Deployment
- Deploy to Cloud Run:
  ```bash
  gcloud run deploy swa-ai-hub \
    --image gcr.io/YOUR_PROJECT/swa-ai:latest \
    --platform managed \
    --port 8000 \
    --memory 2Gi \
    --min-instances 1
  ```

---

## 5. Render Blueprint Deployment
1. Push your repository to GitHub.
2. Create a new **Blueprint** on Render pointing to your repository.
3. Render reads [`deploy/platform/render.yaml`](../deploy/platform/render.yaml) and provisions the service with SSD disk persistence.
