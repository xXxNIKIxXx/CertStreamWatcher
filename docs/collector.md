# Collector Service — Technical Reference

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Configuration Reference](#3-configuration-reference)
4. [Deployment](#4-deployment)
5. [CT Log Polling](#5-ct-log-polling)
6. [Certificate Parsing](#6-certificate-parsing)
7. [Phishing Score](#7-phishing-score)
8. [Filter Rules](#8-filter-rules)
9. [Database](#9-database)
10. [Redis Integration](#10-redis-integration)
11. [WebSocket Server](#11-websocket-server)
12. [Prometheus Metrics](#12-prometheus-metrics)
13. [Logging](#13-logging)
14. [Troubleshooting](#14-troubleshooting)
15. [Python Dependencies](#15-python-dependencies)

---

## 1. Overview

The **Collector** service is the heart of CertStreamWatcher. It connects to every publicly trusted Certificate Transparency (CT) log, polls for new Merkle tree entries, decodes and parses each X.509 certificate or precertificate, scores it for phishing/brand-impersonation signals, writes it to ClickHouse, and broadcasts it in real-time over both Redis Pub/Sub and a built-in WebSocket server.

The processing pipeline inside each poll cycle is strictly linear:

```
fetch entries  →  parse cert  →  score  →  write DB  →  filter  →  broadcast
```

Scoring always runs before filtering, so every certificate stored in ClickHouse carries a `scripting_score` regardless of whether it was broadcast.

---

## 2. Architecture

### 2.1 Module Overview

| Module | File | Responsibility |
|--------|------|----------------|
| `CertStreamService` | `certstream_service.py` | Main orchestrator — wires all subsystems together, starts poll loop |
| `CTLogPoller` | `ct_logs.py` | Discovers CT logs, runs per-log poll tasks, owns the full pipeline |
| `CertificateParser` | `certificate.py` | Decodes MerkleTreeLeaf blobs, parses DER X.509 / precerts |
| `FilterManager` | `filter_manager.py` | Hot-reloadable rule engine; calls CertScoring for every cert |
| `CertScoring` | `scoring.py` | Keyword / TLD / confusable scoring |
| `DatabaseManager` | `database.py` | Buffered batch inserts into ClickHouse |
| `RedisPublisher` | `redis_client.py` | Async Pub/Sub publisher (optional) |
| `RedisSubscriber` | `redis_subscriber.py` | Receives live settings updates from Redis |
| `WebSocketServer` | `websocket.py` | Broadcasts filtered certs to connected WebSocket clients |
| `MetricsManager` | `metrics.py` | Prometheus metrics; no-op fallback when library absent |
| `config` | `config.py` | Central constants and `get_logger()` factory |

### 2.2 Data Flow

```
                    ┌──────────────────────────────────────────┐
                    │          CT Log (HTTPS)                  │
                    │  GET /ct/v1/get-sth                      │
                    │  GET /ct/v1/get-entries?start=N&end=M    │
                    └─────────────────┬────────────────────────┘
                                      │ raw MerkleTreeLeaf blobs
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │         CertificateParser               │
                    │  parse_leaf_header()                    │
                    │  extract_cert_from_leaf()               │
                    │  parse() / _scan_for_der_cert()         │
                    └─────────────────┬───────────────────────┘
                                      │ cert dict
                            ┌─────────┴───────────┐
                            │    CertScoring      │
                            │    score()          │
                            └─────────┬───────────┘
                                      │ cert dict + scripting_score
                         ┌────────────┴────────────┐
                         │                         │
                         ▼                         ▼
               ┌──────────────────┐    ┌────────────────────┐
               │ DatabaseManager  │    │  FilterManager     │
               │ buffer_cert()    │    │  should_store()    │
               │ flush() (batch)  │    └─────────┬──────────┘
               └──────────────────┘              │ if passes filter
                      ClickHouse                 ▼
                                   ┌─────────────────────────┐
                                   │   RedisPublisher        │
                                   │   publish_batch()       │
                                   ├─────────────────────────┤
                                   │   WebSocketServer       │
                                   │   broadcast_batch()     │
                                   └─────────────────────────┘
```

### 2.3 Subsystem Startup Lifecycle

On startup, `CertStreamService` initialises subsystems in this order:

1. `DatabaseManager.init()` — connects to ClickHouse, creates tables, starts periodic flush task
2. Restore persisted filter settings from `ct_settings` table
3. `RedisPublisher.init()` — connects to Redis (skipped when disabled)
4. `RedisSubscriber.init()` — subscribes to `ct:settings` channel
5. `FilterManager.start()` — launches background file-watcher task
6. Settings poll loop task started (DB re-apply every 15 s)
7. `CTLogPoller.discover_logs()` — fetches and DNS-validates all public CT logs
8. `WebSocketServer.start()` — binds WebSocket port
9. One `asyncio.Task` per CT log launched via `asyncio.gather()`

---

## 3. Configuration Reference

### 3.1 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CT_DB_DSN` | `clickhouse://default:@clickhouse:8123/certstream` | ClickHouse connection DSN. Port 9000 is auto-remapped to 8123. |
| `CT_REDIS_URL` | *(unset)* | Redis URL, e.g. `redis://redis:6379/0`. Leave unset to disable Redis. |
| `CT_REDIS_DISABLE` | `0` | Set `1` to skip all Redis connections unconditionally. |
| `SINGLE_NODE` | `0` | Set `1` for single-node mode. Disables Redis and forces `WORKER_COUNT=1`. |
| `CT_BATCH_SIZE` | `500` | Maximum CT log entries fetched per poll cycle per log. |
| `CT_FILTER_FILE` | `filters.json` | Path to the JSON filter rules file (hot-reloaded). |
| `CT_FILTER_POLL_INTERVAL` | `5` | Seconds between filter file modification checks. |
| `CT_SETTINGS_POLL_INTERVAL` | `15` | Seconds between DB settings re-apply cycles. |
| `CT_WORKER_INDEX` | `0` | This replica's 0-based shard index (multi-node). |
| `CT_WORKER_COUNT` | `1` | Total collector replicas (multi-node). |
| `CT_SERVICE_NAME` | `collector` | DNS service name used for auto worker discovery. |
| `HTTP_RETRIES` | `5` | Maximum HTTP retry attempts per CT log API request. |
| `HTTP_RETRY_BACKOFF` | `1.0` | Base backoff in seconds; doubles on each retry. |

---

## 4. Deployment

### 4.1 Prerequisites

- Docker >= 24 and Docker Compose >= 2.20
- 4 GB RAM minimum (8 GB recommended for multi-node)
- Ports `5000`, `8081`, `8765`, `3000` available on the host

### 4.2 Single-Node Deployment

Single-node mode disables Redis entirely. The collector broadcasts certificates directly to the dashboard via its built-in WebSocket server on port 8765.

```bash
# Clone repository
git clone https://github.com/your-org/certstream-watcher.git
cd certstream-watcher

# Copy the example filter file
cp test/filters/filters.json.example test/filters/filters.json

# Start all services
docker compose -f docker-compose.single.yml up -d

# Follow collector logs
docker compose -f docker-compose.single.yml logs -f collector
```

Key single-node environment variables:

| Variable | Value | Effect |
|----------|-------|--------|
| `SINGLE_NODE` | `1` | Disables Redis, forces `WORKER_COUNT=1` |
| `COLLECTOR_WS_URL` | `ws://collector:8765` | Dashboard connects directly to collector WebSocket |

### 4.3 Multi-Node Deployment

```bash
# Start all services (includes Redis)
docker compose up -d

# Scale collector to 3 replicas (auto-shards CT logs)
docker compose up -d --scale collector=3

# Scale API independently
docker compose up -d --scale api=2
```

### 4.4 Worker Sharding

When running multiple collector replicas, the CT log list is partitioned so each replica processes a disjoint subset of logs. Two mechanisms are supported:

**Manual (explicit):** Set `CT_WORKER_INDEX` and `CT_WORKER_COUNT` on each replica.

**Automatic (DNS-based):** When neither variable is set, the collector resolves the `CT_SERVICE_NAME` DNS name (default: `collector`), collects all peer IP addresses, sorts them, and uses its own position in that sorted list as its index. This works seamlessly with Docker Compose and Kubernetes service DNS.

---

## 5. CT Log Polling

### 5.1 Log Discovery

At startup, `CTLogPoller.discover_logs()` fetches the official CT log list from:

```
https://www.gstatic.com/ct/log_list/v3/log_list.json
```

Each log URL is DNS-validated with a 2-second timeout. Unresolvable logs are skipped and counted in `ct_skipped_unresolvable_logs_total`. The validated list is then partitioned according to the worker sharding configuration.

### 5.2 Poll Cycle

Each CT log runs in its own `asyncio` task. A single poll cycle:

1. Fetch the Signed Tree Head (`GET /ct/v1/get-sth`) to find the current tree size
2. If `tree_size <= last_known_index`, sleep `POLL_INTERVAL` (2 s) and retry
3. Fetch up to `CT_BATCH_SIZE` entries (`GET /ct/v1/get-entries?start=N&end=M`)
4. Run the full parse → score → DB write → filter → broadcast pipeline
5. Update `last_known_index` to `end + 1`
6. If entries were found, sleep `BACKFILL_DELAY` (2 s); otherwise `POLL_INTERVAL` (2 s)

### 5.3 HTTP Retry Logic

All HTTP requests use exponential backoff with up to `HTTP_RETRIES` (default 5) attempts. DNS errors, connection failures, and timeouts trigger retries. Non-retryable errors (e.g. HTTP 4xx) return an empty result immediately.

---

## 6. Certificate Parsing

### 6.1 MerkleTreeLeaf Layout

Each CT log entry contains a base64-encoded `MerkleTreeLeaf` as defined in RFC 6962:

| Byte Offset | Field | Description |
|-------------|-------|-------------|
| `0` | `version` | MerkleTreeLeaf version (always 0) |
| `1` | `leaf_type` | Leaf type (0 = timestamped entry) |
| `2–9` | `timestamp` | Milliseconds since epoch (uint64 big-endian) |
| `10–11` | `entry_type` | 0 = x509Entry, 1 = precertEntry |
| `12–14` | `cert_length` | DER certificate length (uint24, x509 entries only) |
| `15…` | `cert DER` | Raw DER-encoded certificate bytes |

### 6.2 Parsing Strategy

`CertificateParser` uses a multi-stage fallback strategy to maximise parse success:

1. **Direct DER** — Read length from bytes 12–14, attempt to load the DER slice directly
2. **Heuristic scan** — Scan the leaf for ASN.1 `SEQUENCE` (`0x30`) tags from offset 12 onward, extract each definite-length block, try each as a certificate
3. **Embedded DER** — Scan the full blob for embedded DER SEQUENCE blocks (handles precerts with non-standard layouts)
4. **PKCS7/CMS** — Attempt to load as a DER-encoded PKCS7/CMS structure and extract the first enclosed certificate

Precertificate entries (`entry_type = 1`) have their certificate extracted from the `extra_data` field, decoding the RFC 6962 `PrecertChainEntry` structure.

### 6.3 Parsed Certificate Fields

| Field | Source | Notes |
|-------|--------|-------|
| `log` | CT log URL | Source log identifier |
| `subject` | `cert.subject.rfc4514_string()` | Subject Distinguished Name |
| `issuer` | `cert.issuer.rfc4514_string()` | Issuer Distinguished Name |
| `not_before` / `not_after` | `cert.not_valid_before/after_utc` | ISO 8601 UTC strings |
| `serial_number` | `cert.serial_number` | Integer as string |
| `dns_names` | `SubjectAlternativeName` extension | List of DNS SANs |
| `fingerprint_sha256` | `cert.fingerprint(SHA256)` | Lowercase hex |
| `ct_entry_type` | `entry_type` header field | `'x509'` or `'precert'` |
| `format` | hardcoded | Always `'der'` |
| `timestamp` | `datetime.now(UTC)` | Wall-clock time of processing |

---

## 7. Phishing Score

Every certificate is scored by `CertScoring` before being written to ClickHouse. The score is stored in `scripting_score` and is available as a filter criterion.

### 7.1 Scoring Factors

| Factor | Trigger | Points Added |
|--------|---------|-------------|
| Keyword match | `login`, `verify`, `wallet`, `password`, etc. found in subject, issuer, or any SAN | Per-keyword weight (10–25) |
| Suspicious TLD | Domain ends with `.tk`, `.xyz`, `.pw`, `.ga`, `.ml`, `.cf`, etc. | +50 per match |
| Unicode confusable | Homograph character found in any field | +10 per character |

Scores are additive across all fields. A typical phishing certificate targeting a bank login page might score 75–200+.

### 7.2 Customising Scoring

Keywords, TLD list, and confusables map are defined in `FilterManager._load_scripting_config()`. Edit that method or load from a file or environment variable to tune scoring for your use case.

---

## 8. Filter Rules

### 8.1 Filter File Format

Filter rules are defined in a JSON file. The path defaults to `filters.json` and can be overridden with `CT_FILTER_FILE`. Changes are **hot-reloaded** without restarting.

```json
{
  "default_action": "allow",
  "filters": [
    { "field": "dns_names",       "op": "contains", "value": "paypal" },
    { "field": "subject",         "op": "regex",    "value": ".*\\.ru$" },
    { "field": "scripting_score", "op": "gte",      "value": 150 }
  ]
}
```

### 8.2 Supported Fields and Operators

| Field | Type | Available Operators |
|-------|------|---------------------|
| `subject` | string | `contains`, `equals`, `regex` |
| `issuer` | string | `contains`, `equals`, `regex` |
| `dns_names` | list | `contains`, `equals`, `regex` (applied to each item) |
| `scripting_score` | integer | `gte`, `lte`, `gt`, `lt`, `eq` |

### 8.3 `default_action` Semantics

| `default_action` | No rules match | A rule matches |
|-----------------|----------------|----------------|
| `allow` (default) | Certificate is broadcast | Certificate is **blocked** from broadcast |
| `deny` | Certificate is **blocked** | Certificate is broadcast |

> **Important:** Filtering only gates broadcasting. Every certificate is **always** written to ClickHouse regardless of filter outcome — no data is silently dropped.

### 8.4 Settings Persistence and Sync

When filter settings are updated (via file, Redis, or API), they are persisted to the `ct_settings` table in ClickHouse and published to the `ct:settings` Redis channel. Other collector and dashboard replicas subscribe to that channel and re-apply the new settings within seconds. A fallback poll loop re-applies DB settings every `CT_SETTINGS_POLL_INTERVAL` (15 s) to handle Redis restarts.

---

## 9. Database

### 9.1 ClickHouse Schema

```sql
CREATE TABLE IF NOT EXISTS ct_certs (
    id                 UUID DEFAULT generateUUIDv4(),
    log                String,
    subject            String,
    issuer             String,
    not_before         DateTime64(3, 'UTC'),
    not_after          DateTime64(3, 'UTC'),
    serial_number      String,
    dns_names          Array(String),
    fingerprint_sha256 String,
    ct_entry_type      String,
    format             String,
    scripting_score    Int32 DEFAULT 0,
    ts                 DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (ts, fingerprint_sha256)
PARTITION BY toYYYYMM(ts)
```

### 9.2 Buffered Writes

Certificates are never written one-by-one. They are appended to an in-memory buffer protected by an `asyncio.Lock`, then flushed in a single `INSERT` statement in two cases:

- **Periodic flush** — a background task flushes every `DB_FLUSH_INTERVAL` seconds (default 5 s)
- **Per-batch flush** — `CTLogPoller` calls `DatabaseManager.flush()` once after processing each batch of CT log entries

Each flush opens a fresh ClickHouse HTTP connection via `clickhouse-connect`, performs the bulk `INSERT`, and closes the connection.

### 9.3 Column Migrations

On startup, `DatabaseManager._migrate_columns()` checks `system.columns` and adds any columns introduced after initial deployment (`ct_entry_type`, `format`, `scripting_score`). This makes zero-downtime upgrades safe.

---

## 10. Redis Integration

### 10.1 Certificate Publishing (`ct:certs`)

When Redis is enabled, every broadcast-eligible certificate is published as a JSON message to the `ct:certs` Pub/Sub channel using a pipeline for efficiency. Dashboards and other consumers subscribe to this channel to receive the live stream.

### 10.2 Settings Synchronisation (`ct:settings`)

Filter rule updates are published to the `ct:settings` channel. The `RedisSubscriber` in each service instance receives these messages and re-applies the new settings to the in-memory `FilterManager` without a restart.

### 10.3 Disabling Redis

Set `SINGLE_NODE=1` or `CT_REDIS_DISABLE=1` to disable all Redis connections. In single-node mode the collector broadcasts exclusively over its built-in WebSocket server.

---

## 11. WebSocket Server

The collector runs a `websockets`-based server on port `8765` (configurable via `WEBSOCKET_PORT`). Clients connect and receive a live stream of JSON certificate objects.

### 11.1 Message Format

```json
{
  "log": "https://ct.googleapis.com/logs/argon2024",
  "subject": "CN=example.com",
  "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
  "not_before": "2024-01-01T00:00:00+00:00",
  "not_after":  "2024-04-01T00:00:00+00:00",
  "serial_number": "123456789",
  "dns_names": ["example.com", "www.example.com"],
  "fingerprint_sha256": "abcdef...",
  "ct_entry_type": "x509",
  "scripting_score": 0,
  "timestamp": "2024-01-15T12:34:56.789000+00:00"
}
```

---

## 12. Prometheus Metrics

The collector exposes Prometheus metrics on `:8000/metrics`. When `prometheus_client` is not installed all metric calls are silently no-ops.

| Metric | Type | Description |
|--------|------|-------------|
| `ct_entries_processed_total` | Counter | Total CT log entries seen |
| `ct_entries_parsed_success_total` | Counter | Successfully parsed certificates |
| `ct_parse_failures_total` | Counter | Certificate parse failures |
| `ct_extraction_failures_total` | Counter | Leaf extraction failures |
| `ct_poll_errors_total` | Counter | Unhandled errors during poll cycles |
| `ct_skipped_unresolvable_logs_total` | Counter | CT logs skipped due to DNS failure |
| `ct_db_writes_total` | Counter | DB write attempts |
| `ct_db_write_errors_total` | Counter | DB write failures |
| `ct_redis_publishes_total` | Counter | Redis publish count |
| `ct_redis_publish_errors_total` | Counter | Redis publish failures |
| `ct_ws_broadcasts_total` | Counter | WebSocket broadcast count |
| `ct_ws_broadcast_errors_total` | Counter | WS delivery failures to individual clients |
| `ct_websocket_active_clients` | Gauge | Currently connected WebSocket clients |
| `ct_total_logs` | Gauge | Number of CT logs being polled |
| `ct_log_last_index{log}` | Gauge | Last processed tree index per CT log |
| `ct_db_available` | Gauge | 1 = ClickHouse connected, 0 = not |
| `ct_redis_available` | Gauge | 1 = Redis connected, 0 = not |
| `ct_db_buffer_size` | Gauge | Rows currently buffered for DB insertion |
| `ct_cert_parse_seconds` | Histogram | Per-certificate parse latency |
| `ct_db_write_duration_seconds` | Histogram | ClickHouse batch insert latency |
| `ct_batch_processing_duration_seconds` | Histogram | Full pipeline latency per batch |
| `ct_http_request_duration_seconds` | Histogram | CT log API request latency |

---

## 13. Logging

All modules use named loggers created via `config.get_logger(name)`. The factory sets `propagate=False` on each logger to prevent duplicate output when a root-level `StreamHandler` is also active.

| Logger Name | Module |
|-------------|--------|
| `CTStreamService` | `certstream_service.py` |
| `CTStreamService.CTLogs` | `ct_logs.py` |
| `CTStreamService.Certificate` | `certificate.py` |
| `CTStreamService.FilterManager` | `filter_manager.py` |
| `CTStreamService.Database` | `database.py` |
| `CTStreamService.Redis` | `redis_client.py` |
| `CTStreamService.RedisSubscriber` | `redis_subscriber.py` |
| `CTStreamService.WebSocket` | `websocket.py` |
| `CTStreamService.Metrics` | `metrics.py` |

Log level is `INFO` by default. At `DEBUG` level the parser emits parsed certificate details and base64 DER blob previews on failure.

---

## 14. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| No certs appearing after startup | Backfill from index 0 in progress | Wait several minutes; watch `ct_log_last_index` in Grafana |
| ClickHouse connection refused | Container not yet healthy | Check `depends_on` health condition; wait for `service_healthy` |
| Redis connection refused | `CT_REDIS_URL` not set or redis container down | Set `CT_REDIS_URL` or use `SINGLE_NODE=1` |
| Duplicate log lines in console | Root logger also has a `StreamHandler` | Ensure `get_logger()` is used everywhere (sets `propagate=False`) |
| High parse failure rate | Unusual CT log entry format | Check `ct_parse_failures_by_log_total`; review DER preview in DEBUG logs |
| `scripting_score` always 0 | `FilterManager.should_store()` not called before DB write | Verify `filter_manager` is wired in `CTLogPoller` constructor |
| Settings not propagating to replicas | Redis not running or wrong channel | Check `ct:settings` channel; verify `RedisSubscriber` is initialised |
| Collector OOM with many logs | Too many concurrent poll tasks | Reduce `CT_BATCH_SIZE` or increase container memory limit |

---

## 15. Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `aiohttp` | >=3.9 | Async HTTP client for CT log API requests |
| `cryptography` | >=42 | DER certificate parsing (x509, SHA-256, SAN) |
| `clickhouse-connect` | >=0.7 | ClickHouse HTTP client with batch insert support |
| `redis[asyncio]` | >=5.0 | Async Redis Pub/Sub publisher and subscriber |
| `websockets` | >=12 | Built-in WebSocket server |
| `prometheus_client` | >=0.20 | Prometheus metrics exposition (optional) |