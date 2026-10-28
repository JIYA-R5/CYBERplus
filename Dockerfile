# ==============================================================================
# SentinelAI — Unified Multi-Stage Production Dockerfile
# Provides shared base environment, non-root security isolation, and optimized
# targets for the FastAPI backend, Streamlit dashboard, and telemetry agent.
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Base Runtime & Dependency Layer
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS base

# Standard security and Python runtime performance flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DOCKER_CONTAINER=1 \
    SENTINEL_DB_PATH=/app/data/sentinel.db \
    SENTINEL_MODEL_DIR=/app/models

# Install runtime packages (curl for healthchecks, tshark for packet inspection)
RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl \
    tshark \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group (Least Privilege Security)
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /bin/bash sentinel && \
    (getent group wireshark && usermod -a -G wireshark sentinel || true)

WORKDIR /app

# Copy dependency specifications first to leverage Docker layer caching
COPY requirements.txt requirements-dev.txt ./

# Upgrade pip and install pinned runtime dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-dev.txt

# Copy application source code
COPY . .

# Ensure storage directories exist with proper non-root ownership
RUN mkdir -p /app/data /app/models && \
    chown -R sentinel:sentinel /app


# ------------------------------------------------------------------------------
# Stage 2: FastAPI Application Service Target
# ------------------------------------------------------------------------------
FROM base AS api

# Expose standard FastAPI service port
EXPOSE 8000

# Run as non-root user
USER sentinel

# Container healthcheck querying application health endpoint
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production ASGI server execution (no dev reload mode in container)
CMD ["uvicorn", "api.index:app", "--host", "0.0.0.0", "--port", "8000"]


# ------------------------------------------------------------------------------
# Stage 3: Streamlit SOC Dashboard Target
# ------------------------------------------------------------------------------
FROM base AS dashboard

# Expose standard Streamlit port
EXPOSE 8501

# Run as non-root user
USER sentinel

# Container healthcheck querying Streamlit's internal health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run Streamlit dashboard in headless mode listening on all container interfaces
CMD ["streamlit", "run", "app.py", "--server.port", "8501", "--server.address", "0.0.0.0", "--server.headless", "true"]


# ------------------------------------------------------------------------------
# Stage 4: Endpoint Telemetry Collector Agent Target
# ------------------------------------------------------------------------------
FROM base AS agent

# Run as non-root user
USER sentinel

# Run synthetic collector agent inside container by default
CMD ["python", "agent/agent.py", "--mode", "synthetic", "--api-url", "http://api:8000", "--interval", "15"]


# ------------------------------------------------------------------------------
# Stage 5: Redis Stream Threat Detection Worker Target
# ------------------------------------------------------------------------------
FROM base AS worker

# Run as non-root user
USER sentinel

# Run detection worker consuming from Redis Streams
CMD ["python", "src/workers/detection_worker.py"]

