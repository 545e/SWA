# SWA AI — Microsoft Azure Deployment Guide

## Supported Azure Hosting Patterns

### Azure Container Apps (Recommended)
- **Ingress**: Automatic managed TLS certificate with HTTPS termination on port `443` routed to container port `8000`.
- **Persistence**: Mount an Azure Files share to `/data` using Azure Container Apps storage mounts.
- **Health Probes**: Liveness and readiness configured on `/health` and `/ready`.

### Azure Deployment via Azure CLI
```bash
# 1. Create Resource Group & ACR
az group create --name rg-swa-security --location eastus
az acr create --resource-group rg-swa-security --name acrswahub --sku Basic --admin-enabled true

# 2. Build & Push Image
az acr build --registry acrswahub --image swa-ai:latest .

# 3. Create Container Apps Environment with Azure Files Mount
az containerapp env create --name env-swa --resource-group rg-swa-security --location eastus

# 4. Deploy Container App
az containerapp create \
  --name swa-ai-hub \
  --resource-group rg-swa-security \
  --environment env-swa \
  --image acrswahub.azurecr.io/swa-ai:latest \
  --target-port 8000 \
  --ingress external \
  --query properties.configuration.ingress.fqdn
```
