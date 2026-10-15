# Production Dockerfile for Tether // Agent Hijack Shield
# Explicitly pinned to Python 3.12 slim
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    APP_ENV=production

# Install system dependencies (curl for healthcheck) and create unprivileged security user
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 shield \
    && useradd -u 10001 -g shield -m -s /bin/bash shield

WORKDIR /app

# Create data directory for persistent SQLite database and give shield user ownership
RUN mkdir -p /app/data && chown -R shield:shield /app/data

# Install Python dependencies first for layer caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code with correct ownership
COPY --chown=shield:shield . /app/

# Switch to unprivileged security user
USER shield

EXPOSE 8000

# Native Docker Health Check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/healthz || exit 1

# Bind to Render-provided $PORT or fallback to 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
