# Stage 1: Build stage (with Rust)
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies INCLUDING rust
COPY ./services/dashboard/requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
        apt-get update && apt-get install -y --no-install-recommends \
            build-essential python3-dev libffi-dev libssl-dev curl cargo rustc && \
        python -m pip install --upgrade pip setuptools wheel && \
        pip install --prefix=/install --no-cache-dir -r requirements.txt && \
        rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.source="https://github.com/xXxNikixXx/CertStreamWatcher"
LABEL org.opencontainers.image.title="CertStreamWatcher"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description=""

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Stage 2: Final image (no compilers, no rust)
FROM python:3.11-slim

WORKDIR /app

# Runtime deps needed by cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
        libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir gunicorn gevent

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application files
COPY ./services/dashboard .

# Entrypoint
# docker-entrypoint.sh lives in app/dashboard relative to project root
COPY ./services/dashboard/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
