#!/bin/sh
set -e

# defaults for runtime options
: ${WORKERS:=1}
: ${THREADS:=1}
: ${TIMEOUT:=30}

# echo "Running database migrations..."
# if command -v flask >/dev/null 2>&1; then
#     flask db upgrade || echo "migrations failed or not configured, continuing"
# else
#     echo "flask not available in PATH, skipping migrations"
# fi

echo "Starting Gunicorn with gevent worker class..."
exec gunicorn --bind 0.0.0.0:5000 services.dashboard.wsgi:app \
    --worker-class gevent \
    --workers ${WORKERS} --threads ${THREADS} --timeout ${TIMEOUT} \
    --forwarded-allow-ips="*"
