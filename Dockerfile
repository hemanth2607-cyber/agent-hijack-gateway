# Production Dockerfile for Agent Hijack Shield (PS-023)
# Explicitly pinned to Python 3.12
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    APP_ENV=production

# Install system dependencies if required and create unprivileged user
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 shield \
    && useradd -u 10001 -g shield -m -s /bin/bash shield

WORKDIR /app

# Install Python dependencies first for caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=shield:shield . /app/

# Switch to unprivileged security user
USER shield

EXPOSE 8000

# Run with uvicorn production server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
