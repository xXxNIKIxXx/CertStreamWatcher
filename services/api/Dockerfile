FROM python:3.11-slim AS builder

WORKDIR /app

COPY ./services/api/requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential python3-dev libffi-dev libssl-dev && \
    python -m pip install --upgrade pip setuptools wheel && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt && \
    rm -rf /var/lib/apt/lists/*

# ── Final stage ──────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY ./services/__init__.py /app/services/__init__.py
COPY ./services/api /app/services/api

ENV PYTHONUNBUFFERED=1

EXPOSE 8080
EXPOSE 9090

# Run with uvicorn for async performance; workers controlled via env
CMD ["python", "-m", "uvicorn", "services.api.main:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--log-level", "info"]
