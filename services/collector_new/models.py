from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()



class CTLog(Base):
    """
    SQLAlchemy model for ct_logs table, matching the web app/database schema exactly.
    Progress fields (current_index, log_length) moved to CTLogProgress.
    """
    __tablename__ = 'ct_logs'
    id = Column(String, primary_key=True)
    operator_id = Column(String)
    description = Column(String)
    log_id = Column(String)  # Unique log identifier (base64 or similar)
    key = Column(String)     # Public key (PEM or base64)
    url = Column(String)
    mmd = Column(Integer)
    state = Column(String)   # JSON-encoded state
    temporal_interval_start = Column(String)  # Store as string for ISO8601 compatibility
    temporal_interval_end = Column(String)    # Store as string for ISO8601 compatibility
    status = Column(String)
    is_tiled = Column(Boolean, default=False)
    submission_url = Column(String)
    monitoring_url = Column(String)
    added_at = Column(String, default=lambda: datetime.datetime.utcnow().isoformat(sep=' '))

    def __repr__(self):
        return (
            f"<CTLog(id={self.id}, operator_id={self.operator_id}, description={self.description}, "
            f"log_id={self.log_id}, key={self.key}, url={self.url}, mmd={self.mmd}, state={self.state}, "
            f"temporal_interval_start={self.temporal_interval_start}, temporal_interval_end={self.temporal_interval_end}, "
            f"status={self.status}, is_tiled={self.is_tiled}, submission_url={self.submission_url}, "
            f"monitoring_url={self.monitoring_url}, added_at={self.added_at})>"
        )


# New table for progress tracking with TTL
class CTLogProgress(Base):
    """
    Tracks current_index and log_length for each log, with TTL for old rows.
    Only one row per log is kept (id is primary key).
    TTL is set to 24 hours for old rows (ClickHouse).
    """
    __tablename__ = 'ct_log_progress'
    id = Column(String, primary_key=True)  # log id (same as CTLog.id)
    current_index = Column(Integer)
    log_length = Column(Integer)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return (
            f"<CTLogProgress(id={self.id}, current_index={self.current_index}, "
            f"log_length={self.log_length}, updated_at={self.updated_at})>"
        )

class CTLogSource(Base):
    """
    SQLAlchemy model for ct_log_sources table, matching the web app/database schema exactly.
    """
    __tablename__ = 'ct_log_sources'
    id = Column(String, primary_key=True)
    url = Column(String)
    name = Column(String)
    enabled = Column(Boolean)
    added_at = Column(DateTime)
    last_polled = Column(DateTime)
    backlog = Column(Integer)
    freshness_seconds = Column(Integer)
    error_count = Column(Integer)
    status = Column(String)
    is_tiled = Column(Boolean, default=False)

    def __repr__(self):
        return (
            f"<CTLogSource(id={self.id}, url={self.url}, name={self.name}, enabled={self.enabled}, "
            f"added_at={self.added_at}, last_polled={self.last_polled}, backlog={self.backlog}, "
            f"freshness_seconds={self.freshness_seconds}, error_count={self.error_count}, "
            f"status={self.status}, is_tiled={self.is_tiled})>"
        )

class CTLogOperator(Base):
    """
    SQLAlchemy model for ct_log_operators table, matching the web app/database schema exactly.
    """
    __tablename__ = 'ct_log_operators'
    id = Column(String, primary_key=True)
    name = Column(String)
    email = Column(String)  # Store as JSON-encoded array of strings
    added_at = Column(DateTime)

    def __repr__(self):
        return (
            f"<CTLogOperator(id={self.id}, name={self.name}, email={self.email}, "
            f"added_at={self.added_at})>"
        )

class CTCert(Base):
    """
    SQLAlchemy model for ct_certs table, matching the web app/database schema exactly.
    """
    __tablename__ = 'ct_certs'
    id = Column(String, primary_key=True)
    log = Column(String)
    subject = Column(String)
    issuer = Column(String)
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    serial_number = Column(String)
    dns_names = Column(String)  # Store as JSON-encoded array of strings
    fingerprint_sha256 = Column(String)
    ct_entry_type = Column(String)
    format = Column(String)
    scripting_score = Column(Integer, default=0)
    ts = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return (
            f"<CTCert(id={self.id}, log={self.log}, subject={self.subject}, issuer={self.issuer}, "
            f"not_before={self.not_before}, not_after={self.not_after}, serial_number={self.serial_number}, "
            f"dns_names={self.dns_names}, fingerprint_sha256={self.fingerprint_sha256}, "
            f"ct_entry_type={self.ct_entry_type}, format={self.format}, scripting_score={self.scripting_score}, "
            f"ts={self.ts})>"
        )

class CTSetting(Base):
    """
    SQLAlchemy model for ct_settings table, matching the web app/database schema exactly.
    """
    __tablename__ = 'ct_settings'
    key = Column(String, primary_key=True)
    value = Column(String)
    ts = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return (
            f"<CTSetting(key={self.key}, value={self.value}, ts={self.ts})>"
        )

# Migration/creation script for ClickHouse tables
def create_all_clickhouse_tables(engine):
    import sqlalchemy
    # ct_logs table
    ct_logs_sql = '''
    CREATE TABLE IF NOT EXISTS ct_logs (
        id UUID DEFAULT generateUUIDv4(),
        operator_id UUID,
        description String,
        log_id String,
        key String,
        url String,
        mmd Int32,
        state String,
        temporal_interval_start DateTime64(3, 'UTC'),
        temporal_interval_end DateTime64(3, 'UTC'),
        current_index UInt64 DEFAULT 0,
        log_length UInt64 DEFAULT 0,
        status String,
        is_tiled UInt8 DEFAULT 0,
        submission_url String,
        monitoring_url String,
        added_at DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    # ct_log_operators table
    ct_log_operators_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_operators (
        id UUID DEFAULT generateUUIDv4(),
        name String,
        email Array(String),
        added_at DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    # ct_log_sources table (full schema)
    ct_log_sources_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_sources (
        id String,
        url String,
        name String,
        enabled UInt8,
        added_at DateTime64(3, 'UTC'),
        last_polled DateTime64(3, 'UTC'),
        backlog Int32,
        freshness_seconds Int32,
        error_count Int32,
        status String,
        is_tiled UInt8 DEFAULT 0
    ) ENGINE = MergeTree()
    ORDER BY (added_at, id)
    PARTITION BY toYYYYMM(added_at)
    '''

    # ct_certs table
    ct_certs_sql = '''
    CREATE TABLE IF NOT EXISTS ct_certs (
        id UUID DEFAULT generateUUIDv4(),
        log String,
        subject String,
        issuer String,
        not_before DateTime64(3, 'UTC'),
        not_after DateTime64(3, 'UTC'),
        serial_number String,
        dns_names Array(String),
        fingerprint_sha256 String,
        ct_entry_type String,
        format String,
        scripting_score Int32 DEFAULT 0,
        ts DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (ts, fingerprint_sha256)
    PARTITION BY toYYYYMM(ts)
    '''

    # ct_settings table
    ct_settings_sql = '''
    CREATE TABLE IF NOT EXISTS ct_settings (
        key String,
        value String,
        ts DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree()
    ORDER BY (key, ts)
    '''

    # ct_log_progress table with TTL (DateTime for TTL)
    ct_log_progress_sql = '''
    CREATE TABLE IF NOT EXISTS ct_log_progress (
        id String,
        current_index UInt64 DEFAULT 0,
        log_length UInt64 DEFAULT 0,
        updated_at DateTime DEFAULT now()
    ) ENGINE = MergeTree()
    PRIMARY KEY id
    TTL updated_at + INTERVAL 24 HOUR
    '''

    with engine.connect() as conn:
        conn.execute(sqlalchemy.text(ct_logs_sql))
        conn.execute(sqlalchemy.text(ct_log_operators_sql))
        conn.execute(sqlalchemy.text(ct_log_sources_sql))
        conn.execute(sqlalchemy.text(ct_certs_sql))
        conn.execute(sqlalchemy.text(ct_settings_sql))
        conn.execute(sqlalchemy.text(ct_log_progress_sql))