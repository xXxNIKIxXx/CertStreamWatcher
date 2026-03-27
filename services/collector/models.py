
# Import all models from shared.models
from services.shared.models import Base, CTLog, CTLogSlice, CTLogSource, CTLogOperator, CTCert, CTSetting


# ---------------------------------------------------------------------------
# ClickHouse DDL
# ---------------------------------------------------------------------------

def create_all_clickhouse_tables(engine):
    import sqlalchemy

    ct_logs_sql = '''
    CREATE TABLE IF NOT EXISTS ct_logs (
        id                      UUID    DEFAULT generateUUIDv4(),
        operator_id             UUID,
        description             String,
        log_id                  String,
        key                     String,
        url                     String,
        mmd                     Int32,
        state                   String,
        temporal_interval_start DateTime64(3, 'UTC'),
        temporal_interval_end   DateTime64(3, 'UTC'),
        status                  String,
        is_tiled                UInt8   DEFAULT 0,
        submission_url          String,
        monitoring_url          String,
        added_at                DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    ct_log_operators_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_operators (
        id       UUID DEFAULT generateUUIDv4(),
        name     String,
        email    Array(String),
        added_at DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    ct_log_sources_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_sources (
        id                String,
        url               String,
        name              String,
        enabled           UInt8,
        added_at          DateTime64(3, 'UTC'),
        last_polled       DateTime64(3, 'UTC'),
        backlog           Int32,
        freshness_seconds Int32,
        error_count       Int32,
        status            String,
        is_tiled          UInt8 DEFAULT 0
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    ct_certs_sql = '''
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
    ) ENGINE = MergeTree()
    ORDER BY (ts, fingerprint_sha256)
    PARTITION BY toYYYYMM(ts)
    '''

    ct_settings_sql = '''
    CREATE TABLE IF NOT EXISTS ct_settings (
        key   String,
        value String,
        ts    DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (key, ts)
    '''

    # ReplacingMergeTree(updated_at) keeps the latest row per (id, slice_start)
    # after background merges.  New progress is written as INSERT rows; the
    # in-process Python cache in DatabaseManager prevents duplicate slice
    # creation so row count stays bounded.
    ct_log_slices_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_slices (
        id            String,
        slice_start   UInt64  DEFAULT 0,
        slice_end     UInt64  DEFAULT 0,
        current_index UInt64  DEFAULT 0,
        worker_id     String  DEFAULT '',
        status        String  DEFAULT 'pending',
        updated_at    DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree(updated_at)
    PRIMARY KEY (id, slice_start)
    ORDER BY (id, slice_start)
    TTL updated_at + INTERVAL 7 DAY
    '''

    with engine.connect() as conn:
        conn.execute(sqlalchemy.text(ct_logs_sql))
        conn.execute(sqlalchemy.text(ct_log_operators_sql))
        conn.execute(sqlalchemy.text(ct_log_sources_sql))
        conn.execute(sqlalchemy.text(ct_certs_sql))
        conn.execute(sqlalchemy.text(ct_settings_sql))
        conn.execute(sqlalchemy.text(ct_log_slices_sql))