# ==============================================================================
# Stage 1: Build & Pre-cache Neural Classifier & Embedding Models
# ==============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into wheels directory
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Pre-download models to /opt/models_cache for offline container execution
ENV AEGIS_MODELS_CACHE=/opt/models_cache
ENV HF_HOME=/opt/models_cache
RUN python3 -c "\
import os;\
os.makedirs('/opt/models_cache', exist_ok=True);\
from sentence_transformers import SentenceTransformer;\
print('Pre-caching SentenceTransformer...');\
SentenceTransformer('all-MiniLM-L6-v2', cache_folder='/opt/models_cache');\
print('Models successfully pre-cached.');\
"

# ==============================================================================
# Stage 2: Hardened Runtime Container
# ==============================================================================
FROM python:3.11-slim AS runner

# Create dedicated unprivileged user and group
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -s /sbin/nologin -d /app aegis

WORKDIR /app

# Copy installed python site-packages from builder
COPY --from=builder /root/.local /home/aegis/.local
COPY --from=builder /opt/models_cache /opt/models_cache

# Copy application source code
COPY aegis/ /app/aegis/
COPY config/ /app/config/
COPY pyproject.toml /app/

# Create logs directory with correct permissions
RUN mkdir -p /app/logs /tmp && \
    chown -R aegis:aegis /app /opt/models_cache /tmp

# Configure secure environment
ENV PATH="/home/aegis/.local/bin:${PATH}"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AEGIS_MODELS_CACHE=/opt/models_cache
ENV HF_HOME=/opt/models_cache
ENV AEGIS_AUDIT_LOG_PATH=/app/logs/audit_ledger.jsonl

# Drop to unprivileged non-root user
USER 10001:10001

# Expose Aegis Gateway port
EXPOSE 8000

# Health check via readiness endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/security/readiness', timeout=4)" || exit 1

# Launch Aegis Gateway
CMD ["uvicorn", "aegis.gateway:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
