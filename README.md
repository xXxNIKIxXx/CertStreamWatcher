# CertStreamWatcher

**CertStreamWatcher** is a real-time Certificate Transparency (CT) log monitoring platform. It continuously polls all public CT logs, parses every new X.509 certificate and precertificate, scores them for phishing/typosquatting signals, stores them in ClickHouse, and broadcasts them live over Redis Pub/Sub and WebSocket.

---

## Architecture

### Multi-Node (with Redis)

```
┌─────────────────────────────────────────────────────────────┐
│                     CertStreamWatcher                       │
│                                                             │
│  ┌──────────────────┐    ┌──────────────────────────────┐   │
│  │  Collector(s)    │    │       Dashboard(s)           │   │
│  │  ─────────────   │    │  ─────────────────────────   │   │
│  │  CT Log Polling  │───▶│  Flask Web UI                │   │
│  │  Cert Parsing    │    │  Live Certificate Stream     │   │
│  │  Scoring         │    │  Filter Management           │   │
│  │  Filtering       │    └──────────────────────────────┘   │
│  └────────┬─────────┘                   ▲                   │
│           │                             │                   │
│           ▼                             │                   │
│  ┌─────────────────┐    ┌───────────────────────────────┐   │
│  │     Redis       │────│         API Service           │   │
│  │  Pub/Sub        │    │  REST Endpoints               │   │
│  │  Settings Sync  │    │  Certificate Search           │   │
│  └────────┬────────┘    └───────────────────────────────┘   │
│           │                             ▲                   │
│           ▼                             │                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   ClickHouse                        │    │
│  │          Persistent Certificate Storage             │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Traefik (Reverse Proxy)                             │   │
│  │  Routes :80 → Dashboard   :8081 → API               │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Single-Node (no Redis)

```
┌────────────────────────────────────────────────────┐
│              CertStreamWatcher (Single Node)       │
│                                                    │
│  ┌────────────────┐    ┌─────────────────────────┐ │
│  │   Collector    │    │       Dashboard         │ │
│  │  CT Log Polling│───▶│  Flask Web UI           │ │
│  │  Parsing       │    │  Live Cert Stream (WS)  │ │
│  │  Scoring       │    └─────────────────────────┘ │
│  └───────┬────────┘                ▲               │
│          │ WebSocket :8765         │               │
│          └─────────────────────────               │
│          ▼                                         │
│  ┌─────────────────────────────────────────────┐   │
│  │              ClickHouse                     │   │
│  └─────────────────────────────────────────────┘   │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Traefik (Reverse Proxy)                     │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

### Monitoring Stack

```
  Collector ──┐
  Dashboard ──┤──▶ Grafana Alloy ──▶ Grafana Mimir ──▶ Grafana
  API ─────────┘    (scrapes :8000)   (TSDB)            (Dashboards)
```

---

## Services

| Service | Description | Default Port |
|---------|-------------|-------------|
| **collector** | CT log poller, parser, scorer, broadcaster | `8765` (WS), `8000` (metrics) |
| **web** (dashboard) | Flask web UI, live stream, filter management | `5100` (direct), `5000` (via Traefik) |
| **api** | REST API for certificate search and queries | `8081` (via Traefik) |
| **clickhouse** | Certificate storage | `8123` (HTTP), `9000` (native) |
| **redis** | Pub/Sub backbone (multi-node only) | `6379` |
| **traefik** | Reverse proxy / load balancer | `5000`, `8081`, `8080` |
| **grafana** | Metrics dashboards | `3000` |
| **mimir** | Prometheus-compatible TSDB | `9009` |
| **alloy** | Metrics scraping agent | `1234` (UI) |

---

## Quick Start

### Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2.20
- 4 GB RAM minimum (8 GB recommended for multi-node)
- Ports `5000`, `8081`, `8765`, `3000` available on the host

### Single-Node Deployment

Single-node mode skips Redis entirely. The collector pushes certs directly to the dashboard over a WebSocket connection on `:8765`. Use `docker-compose.single.yml` for this mode.

```bash
# Clone the repository
git clone https://github.com/your-org/certstream-watcher.git
cd certstream-watcher

# Copy and review the filter configuration
cp test/filters/filters.json.example test/filters/filters.json

# Start
docker compose -f docker-compose.single.yml up -d
```

Verify everything is running:

```bash
docker compose -f docker-compose.single.yml ps
docker compose -f docker-compose.single.yml logs -f collector
```

Access the services:
- **Dashboard**: http://localhost:5000
- **Grafana**: http://localhost:3000 (admin / admin)
- **Traefik UI**: http://localhost:8080

### Multi-Node Deployment (with Redis)

Use the default `docker-compose.yml`. Redis is included and the collector can be scaled horizontally.

```bash
# Start all services including Redis
docker compose up -d

# Watch collector logs
docker compose logs -f collector
```

Scale the collector or API horizontally:

```bash
docker compose up -d --scale collector=3 --scale api=2
```

When scaling the collector, set `CT_WORKER_COUNT` and `CT_WORKER_INDEX` to partition the CT log list across replicas, or rely on the built-in DNS-based auto-discovery (see [Worker Sharding](#worker-sharding)).

Access the services:
- **Dashboard**: http://localhost:5000
- **API**: http://localhost:8081
- **Grafana**: http://localhost:3000 (admin / admin)
- **Traefik UI**: http://localhost:8080

---

## Compose Files

### `docker-compose.single.yml` — Single-Node

No Redis. Collector broadcasts directly to the dashboard via WebSocket. Both services have `SINGLE_NODE=1` set.

```yaml
version: '3.8'

services:
  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    container_name: clickhouse
    environment:
      CLICKHOUSE_DB: certstream
      CLICKHOUSE_USER: default
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    ports:
      - "8123:8123"   # HTTP interface
      - "9000:9000"   # Native TCP interface
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    healthcheck:
      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    cap_add:
      - SYS_NICE
    security_opt:
      - seccomp:unconfined

  web:
    image: ghcr.io/xxxnikixxx/certstream-web:latest
    deploy:
      replicas: 1                      # scale dashboard containers freely
    depends_on:
      clickhouse:
        condition: service_healthy
    environment:
      SECRET_KEY: "supersecretkey"
      FLASK_ENV: development
      WORKERS: "1"
      THREADS: "2"
      TIMEOUT: "30"
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      SINGLE_NODE: "1"
      COLLECTOR_WS_URL: ws://collector:8765
    expose:
      - "5000"                         # app traffic via Traefik
    ports:
      - "5100:5000"                    # direct access for testing (optional)
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=5000"
      - "prometheus.path=/metrics"

  traefik:
    image: traefik:v3.3
    restart: unless-stopped
    depends_on:
      - web
      - api
    command:
      - "--api.insecure=true"
      - "--providers.file.filename=/etc/traefik/dynamic.yml"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.api.address=:8081"
    ports:
      - "5000:80"                      # dashboard on :5000
      - "8081:8081"                    # API on :8081
      - "8080:8080"                    # Traefik dashboard (optional)
    volumes:
      - ./services/dashboard/traefik-dynamic.yml:/etc/traefik/dynamic.yml:ro

  api:
    image: ghcr.io/xxxnikixxx/certstream-api:latest
    deploy:
      replicas: 1                      # scale API horizontally
    depends_on:
      clickhouse:
        condition: service_healthy
    environment:
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      CT_API_PORT: "8080"
      CT_API_PROM_PORT: "9090"
      CT_DB_MIN_POOL: "2"
      CT_DB_MAX_POOL: "10"
    expose:
      - "8080"                         # API traffic (via Traefik)
      - "9090"                         # Prometheus metrics
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=9090"
      - "prometheus.path=/metrics"
    restart: unless-stopped

  collector:
    image: ghcr.io/xxxnikixxx/certstream-collector:latest
    container_name: collector
    depends_on:
      clickhouse:
        condition: service_healthy
    environment:
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      CT_FILTER_FILE: /etc/certstream/filters.json
      CT_FILTER_POLL_INTERVAL: "5"
      CT_ENABLE_PROFILING: "1"
      SINGLE_NODE: "1"
    expose:
      - "8000"                         # Prometheus metrics
    ports:
      - "8765:8765"
    volumes:
      - ./test/filters/filters.json:/etc/certstream/filters.json:ro
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./test/grafana:/var/lib/grafana
    ports:
      - "3000:3000"
    restart: unless-stopped
    user: "1001:1001"

  mimir:
    image: grafana/mimir:latest
    container_name: mimir
    restart: unless-stopped
    command: ["-ingester.native-histograms-ingestion-enabled=true", "-config.file=/etc/mimir.yaml"]
    ports:
      - "9009:9009"
    volumes:
      - ./test/mimir/mimir.yaml:/etc/mimir.yaml
      - ./test/mimir/data:/tmp/mimir

  alloy:
    image: grafana/alloy:latest
    container_name: alloy
    restart: unless-stopped
    volumes:
      - ./test/alloy/data:/data-alloy
      - ./test/alloy/config.alloy:/etc/alloy/config.alloy:ro
    command: >
      run --server.http.listen-addr=0.0.0.0:12345
          /etc/alloy/config.alloy
    ports:
      - "1234:12345"   # Alloy UI (optional)

volumes:
  clickhouse_data:
```

### `docker-compose.yml` — Multi-Node (with Redis)

Includes Redis for Pub/Sub and settings sync. The collector has no `container_name` so Docker Compose can scale it freely. API defaults to 2 replicas.

```yaml
version: '3.8'

services:
  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    container_name: clickhouse
    environment:
      CLICKHOUSE_DB: certstream
      CLICKHOUSE_USER: default
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    ports:
      - "8123:8123"   # HTTP interface
      - "9000:9000"   # Native TCP interface
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    healthcheck:
      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    cap_add:
      - SYS_NICE
    security_opt:
      - seccomp:unconfined

  redis:
    image: redis:7-alpine
    container_name: redis
    ports:
      - "6379:6379"

  web:
    image: ghcr.io/xxxnikixxx/certstream-web:latest
    deploy:
      replicas: 1                      # scale dashboard containers freely
    depends_on:
      clickhouse:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      SECRET_KEY: "supersecretkey"
      FLASK_ENV: development
      WORKERS: "1"
      THREADS: "2"
      TIMEOUT: "30"
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      CT_REDIS_URL: redis://redis:6379/0
    expose:
      - "5000"                         # app traffic via Traefik
    ports:
      - "5100:5000"                    # direct access for testing (optional)
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=5000"
      - "prometheus.path=/metrics"

  traefik:
    image: traefik:v3.3
    restart: unless-stopped
    depends_on:
      - web
      - api
    command:
      - "--api.insecure=true"
      - "--providers.file.filename=/etc/traefik/dynamic.yml"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.api.address=:8081"
    ports:
      - "5000:80"                      # dashboard on :5000
      - "8081:8081"                    # API on :8081
      - "8080:8080"                    # Traefik dashboard (optional)
    volumes:
      - ./services/dashboard/traefik-dynamic.yml:/etc/traefik/dynamic.yml:ro

  api:
    image: ghcr.io/xxxnikixxx/certstream-api:latest
    deploy:
      replicas: 2                      # scale API horizontally
    depends_on:
      clickhouse:
        condition: service_healthy
    environment:
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      CT_API_PORT: "8080"
      CT_API_PROM_PORT: "9090"
      CT_DB_MIN_POOL: "2"
      CT_DB_MAX_POOL: "10"
    expose:
      - "8080"                         # API traffic (via Traefik)
      - "9090"                         # Prometheus metrics
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=9090"
      - "prometheus.path=/metrics"
    restart: unless-stopped

  collector:
    image: ghcr.io/xxxnikixxx/certstream-collector:latest
    deploy:
      replicas: 1                      # scale up/down freely
    depends_on:
      clickhouse:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      CT_DB_DSN: clickhouse://default:@clickhouse:8123/certstream
      CT_REDIS_URL: redis://redis:6379/0
      CT_FILTER_FILE: /etc/certstream/filters.json
      CT_FILTER_POLL_INTERVAL: "5"
      CT_ENABLE_PROFILING: "1"
    expose:
      - "8000"                         # Prometheus metrics
    ports:
      - "8765:8765"
    volumes:
      - ./test/filters/filters.json:/etc/certstream/filters.json:ro
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./test/grafana:/var/lib/grafana
    ports:
      - "3000:3000"
    restart: unless-stopped
    user: "1001:1001"

  mimir:
    image: grafana/mimir:latest
    container_name: mimir
    restart: unless-stopped
    command: ["-ingester.native-histograms-ingestion-enabled=true", "-config.file=/etc/mimir.yaml"]
    ports:
      - "9009:9009"
    volumes:
      - ./test/mimir/mimir.yaml:/etc/mimir.yaml
      - ./test/mimir/data:/tmp/mimir

  alloy:
    image: grafana/alloy:latest
    container_name: alloy
    restart: unless-stopped
    volumes:
      - ./test/alloy/data:/data-alloy
      - ./test/alloy/config.alloy:/etc/alloy/config.alloy:ro
    command: >
      run --server.http.listen-addr=0.0.0.0:12345
          /etc/alloy/config.alloy
    ports:
      - "1234:12345"   # Alloy UI (optional)

volumes:
  clickhouse_data:
```

### Key Differences Between Compose Files

| | `docker-compose.single.yml` | `docker-compose.yml` |
|---|---|---|
| Redis | ❌ not included | ✅ `redis:7-alpine` |
| `SINGLE_NODE` | `"1"` on collector + web | not set |
| `CT_REDIS_URL` | not set | `redis://redis:6379/0` |
| `COLLECTOR_WS_URL` | `ws://collector:8765` on web | not set |
| collector `container_name` | `collector` (fixed) | not set (scalable) |
| Settings sync | DB poll only | Redis `ct:settings` channel |

---

## Configuration

All tunables are set via environment variables on the `collector` service.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CT_DB_DSN` | `clickhouse://default:@clickhouse:8123/certstream` | ClickHouse connection DSN |
| `CT_REDIS_URL` | *(unset)* | Redis URL, e.g. `redis://redis:6379/0` |
| `CT_REDIS_DISABLE` | `0` | Set `1` to disable Redis entirely |
| `SINGLE_NODE` | `0` | Set `1` for single-node mode (implies Redis disabled) |
| `CT_BATCH_SIZE` | `500` | Entries fetched per CT log poll cycle |
| `CT_FILTER_FILE` | `filters.json` | Path to the filter rules JSON file |
| `CT_FILTER_POLL_INTERVAL` | `5` | Seconds between filter file reload checks |
| `CT_SETTINGS_POLL_INTERVAL` | `15` | Seconds between DB settings repolls |

### Worker Sharding

| Variable | Default | Description |
|----------|---------|-------------|
| `CT_WORKER_INDEX` | `0` | This worker's index (0-based) |
| `CT_WORKER_COUNT` | `1` | Total number of collector replicas |
| `CT_SERVICE_NAME` | `collector` | DNS service name for auto-discovery |

When neither variable is set and `SINGLE_NODE` is off, the collector auto-discovers its index by resolving the `CT_SERVICE_NAME` DNS name and sorting all peer IP addresses. Scaling with Docker Compose or Kubernetes requires no manual index assignment.

### Network Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_RETRIES` | `5` | Max HTTP retry attempts per CT log request |
| `HTTP_RETRY_BACKOFF` | `1.0` | Base backoff (seconds); doubles each retry |

---

## Filter Rules

Filters are defined in a JSON file (default: `filters.json` / `CT_FILTER_FILE`). The file is **hot-reloaded** without restarting the collector.

### Format

```json
{
  "default_action": "allow",
  "filters": [
    { "field": "dns_names",       "op": "contains", "value": "example.com" },
    { "field": "subject",         "op": "regex",    "value": ".*\\.ru$" },
    { "field": "scripting_score", "op": "gte",      "value": 100 }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Certificate subject DN |
| `issuer` | string | Certificate issuer DN |
| `dns_names` | list | Subject Alternative Names |
| `scripting_score` | int | Phishing/typosquatting score (0–∞) |

### Operators

| Operator | Applies to | Description |
|----------|------------|-------------|
| `contains` | string / list items | Case-insensitive substring match |
| `equals` | string / list items | Case-insensitive exact match |
| `regex` | string / list items | Python `re.search` |
| `gte` / `lte` / `gt` / `lt` / `eq` | `scripting_score` | Numeric comparison |

### `default_action`

- `"allow"` — pass all certs through; a matching rule **blocks** broadcast.
- `"deny"` — block all certs; a matching rule **allows** broadcast.

> **Note:** Filtering only gates broadcasting and WebSocket output. Every parsed certificate is always written to ClickHouse regardless of filter outcome — no data is silently dropped.

---

## Scripting Score

The collector scores each certificate for phishing/brand-impersonation signals before applying filter rules. The score is stored in the `scripting_score` column in ClickHouse and is available as a filter field.

Scoring factors:
- **Keywords** (e.g. `login`, `verify`, `wallet`) — each match adds a configurable weight.
- **Suspicious TLDs** (e.g. `.tk`, `.xyz`, `.pw`) — each match adds 50 points.
- **Unicode confusables** — homograph characters add 10 points each.

---

## Database Schema

Certificates are stored in the `ct_certs` table in ClickHouse:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Auto-generated row ID |
| `log` | String | Source CT log URL |
| `subject` | String | Certificate subject DN |
| `issuer` | String | Certificate issuer DN |
| `not_before` | DateTime64 | Certificate validity start |
| `not_after` | DateTime64 | Certificate validity end |
| `serial_number` | String | Certificate serial number |
| `dns_names` | Array(String) | Subject Alternative Names |
| `fingerprint_sha256` | String | SHA-256 fingerprint (hex) |
| `ct_entry_type` | String | `x509` or `precert` |
| `format` | String | `der` |
| `scripting_score` | Int32 | Phishing score |
| `ts` | DateTime64 | Insertion timestamp |

Partitioned by `toYYYYMM(ts)`, ordered by `(ts, fingerprint_sha256)`.

---

## Metrics

The collector exposes Prometheus metrics on `:8000`. Grafana Alloy scrapes these and forwards them to Mimir.

| Metric | Type | Description |
|--------|------|-------------|
| `ct_entries_processed_total` | Counter | Total CT entries seen |
| `ct_entries_parsed_success_total` | Counter | Successfully parsed certs |
| `ct_parse_failures_total` | Counter | Parse failures |
| `ct_db_writes_total` | Counter | DB write attempts |
| `ct_db_write_errors_total` | Counter | DB write failures |
| `ct_redis_publishes_total` | Counter | Redis publish count |
| `ct_ws_broadcasts_total` | Counter | WebSocket broadcast count |
| `ct_websocket_active_clients` | Gauge | Connected WS clients |
| `ct_total_logs` | Gauge | Number of CT logs polled |
| `ct_log_last_index` | Gauge | Last processed index per log |
| `ct_cert_parse_seconds` | Histogram | Parse latency |
| `ct_db_write_duration_seconds` | Histogram | DB write latency |
| `ct_batch_processing_duration_seconds` | Histogram | Full batch pipeline latency |

---

## WebSocket Stream

The collector exposes a raw WebSocket server on `:8765`. Connect to receive a live JSON stream of filtered certificates:

```json
{
  "log": "https://ct.googleapis.com/logs/argon2024",
  "subject": "CN=example.com",
  "issuer": "CN=Let's Encrypt Authority X3",
  "not_before": "2024-01-01T00:00:00+00:00",
  "not_after": "2024-04-01T00:00:00+00:00",
  "serial_number": "123456789",
  "dns_names": ["example.com", "www.example.com"],
  "fingerprint_sha256": "abcdef...",
  "ct_entry_type": "x509",
  "scripting_score": 0,
  "timestamp": "2024-01-15T12:34:56.789000+00:00"
}
```

---

## Volumes & Persistence

| Volume / Mount | Description |
|----------------|-------------|
| `clickhouse_data` | ClickHouse data (Docker named volume) |
| `./test/filters/filters.json` | Filter rules (bind-mounted, hot-reloaded) |
| `./test/grafana` | Grafana provisioning and dashboard state |
| `./test/mimir` | Mimir config and TSDB data |
| `./test/alloy` | Alloy scrape config |

---

## Development

```bash
# Run a specific service with live logs
docker compose up collector --build

# Rebuild after code changes
docker compose up --build --force-recreate collector

# Open a shell in the running collector
docker compose exec collector bash

# Query ClickHouse directly
docker compose exec clickhouse clickhouse-client \
  --query "SELECT count(), max(ts) FROM certstream.ct_certs"
```

---

## Troubleshooting

**Collector exits immediately**
Check that ClickHouse is healthy before the collector starts. The `depends_on: condition: service_healthy` in the compose file handles this, but manual runs may need a wait.

**No certificates appearing**
CT logs are polled from index 0 on first start and catch up from the live tip. Depending on log size, backfill can take minutes. Watch `ct_log_last_index` in Grafana.

**Redis connection refused**
Ensure `CT_REDIS_URL` is set and the `redis` container is up. Alternatively set `SINGLE_NODE=1` to disable Redis.

**Duplicate log output in console**
Ensure `log.propagate = False` is set for all named loggers (already set in `config.get_logger`). If running under a framework that attaches a root handler, the root logger must not have its own `StreamHandler`.

**High scripting scores on legitimate certs**
Tune keyword weights in `filter_manager.py` or add an `allow` rule for known-good domains.