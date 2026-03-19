FROM python:3.11-slim

WORKDIR /app

COPY ./services/collector_new/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the collector package preserving the package hierarchy for relative imports
COPY ./services/__init__.py /app/services/__init__.py
COPY ./services/collector_new /app/services/collector

ENV PYTHONUNBUFFERED=1

# Run as package module so relative imports resolve
CMD ["python", "-m", "services.collector"]
