FROM python:3.12-slim

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Create non-root dedicated security user and group
RUN groupadd -r swa && useradd -r -g swa -d /app -s /sbin/nologin -c "SWA System User" swa

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and prepare data directory
COPY . .
RUN mkdir -p /data && chown -R swa:swa /app /data

# Default persistent database location & host configuration
ENV SWA_DB_PATH=/data/swa_data.db
ENV SWA_HOST=0.0.0.0
ENV SWA_PORT=8000
ENV DOCKER_CONTAINER=1

# Run as unprivileged non-root user
USER swa

# Expose Web Interface Port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/api/settings || exit 1

# Run SWA AI
CMD ["python", "run.py"]
