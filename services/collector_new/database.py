from .config import get_logger
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from .models import Base, CTLog
import asyncio
import sqlalchemy

logger = get_logger("CTStreamService.DatabaseManager")


class DatabaseManager:
    def __init__(self, db_url: str):
        self.engine = create_engine(
            db_url,
            echo=False,
            future=True,
            # Use a proper connection pool instead of the default NullPool.
            # pool_size: number of persistent connections kept open.
            # max_overflow: extra connections allowed beyond pool_size under load.
            # pool_pre_ping: validate connections before checkout to avoid stale ones.
            # pool_recycle: recycle connections older than 30 min to avoid server-side
            #               timeouts silently dropping them.
            poolclass=QueuePool,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=1800,
        )
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    async def init(self):
        from .models import create_all_clickhouse_tables
        create_all_clickhouse_tables(self.engine)
        await self._auto_migrate_all_models()

    async def _auto_migrate_all_models(self):
        def _migrate():
            insp = sqlalchemy.inspect(self.engine)
            for table in Base.metadata.sorted_tables:
                table_name = table.name
                try:
                    db_columns = [col['name'] for col in insp.get_columns(table_name)]
                except Exception:
                    continue
                for col in table.columns:
                    if col.name not in db_columns:
                        ch_type = self._sa_type_to_clickhouse(col.type)
                        default = self._get_column_default(col)
                        alter = (
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {col.name} {ch_type}{default}"
                        )
                        with self.engine.connect() as conn:
                            conn.execute(sqlalchemy.text(alter))
                            conn.commit()
        await asyncio.to_thread(_migrate)

    def _sa_type_to_clickhouse(self, sa_type):
        import sqlalchemy as sa
        if isinstance(sa_type, sa.String):
            return "String"
        if isinstance(sa_type, sa.Integer):
            return "Int32"
        if isinstance(sa_type, sa.Boolean):
            return "UInt8"
        if isinstance(sa_type, sa.DateTime):
            return "DateTime"
        if isinstance(sa_type, sa.Float):
            return "Float64"
        return "String"

    def _get_column_default(self, col):
        if col.default is not None and col.default.arg is not None:
            val = col.default.arg
            if isinstance(val, bool):
                val = int(val)
            return f" DEFAULT {val}"
        return ""

    async def get_log_sources(self) -> list[CTLog]:
        def _query():
            with self.Session() as session:
                return session.query(CTLog).all()
        return await asyncio.to_thread(_query)

    async def update_log_index(self, log_id: str, current_index: int):
        """Update current_index for a log via raw ClickHouse ALTER ... UPDATE."""
        def _update():
            with self.Session() as session:
                sql = (
                    f"ALTER TABLE ct_logs "
                    f"UPDATE current_index = {current_index} "
                    f"WHERE log_id = '{log_id}'"
                )
                session.execute(sqlalchemy.text(sql))
                session.commit()
        await asyncio.to_thread(_update)

    async def close(self):
        """Dispose the connection pool, closing all pooled connections."""
        def _dispose():
            self.engine.dispose()
        await asyncio.to_thread(_dispose)


# ---------------------------------------------------------------------------
# Scoped progress writer – keeps one session per worker task and accumulates
# updates in memory, flushing them in a single transaction every N calls.
# ---------------------------------------------------------------------------

class ProgressWriter:
    """
    Batches CTLogProgress upserts so the event loop is not hammered with one
    DB round-trip per batch.

    Usage (one instance per long-lived task):

        writer = ProgressWriter(db_manager, flush_every=10)
        writer.record(log_id, end_index)   # cheap, in-memory only
        await writer.flush_if_due()        # issues one SQL call when threshold hit
        await writer.flush()               # force-flush at end of task / log

    flush_every controls the write amplification vs. freshness trade-off:
    higher = fewer DB round-trips; lower = more up-to-date persisted state.
    """

    def __init__(self, db_manager: DatabaseManager, flush_every: int = 10):
        self._db = db_manager
        self._flush_every = flush_every
        # log_id -> (current_index, log_length)  -- pending writes
        self._pending: dict[str, tuple[int | None, int | None]] = {}
        self._call_count: int = 0

    def record(
        self,
        log_id: str,
        current_index: int | None = None,
        log_length: int | None = None,
    ) -> None:
        """Stage an update in memory. Does NOT touch the database."""
        prev = self._pending.get(log_id, (None, None))
        self._pending[log_id] = (
            current_index if current_index is not None else prev[0],
            log_length    if log_length   is not None else prev[1],
        )
        self._call_count += 1

    async def flush_if_due(self) -> None:
        """Flush only when the configured threshold has been reached."""
        if self._call_count >= self._flush_every:
            await self.flush()

    async def flush(self) -> None:
        """Write all pending updates in a single transaction and clear the queue."""
        if not self._pending:
            return

        snapshot = dict(self._pending)
        self._pending.clear()
        self._call_count = 0

        def _write():
            import datetime
            from .models import CTLogProgress
            with self._db.Session() as session:
                for log_id, (current_index, log_length) in snapshot.items():
                    progress = (
                        session.query(CTLogProgress)
                        .filter_by(id=log_id)
                        .first()
                    )
                    if not progress:
                        progress = CTLogProgress(id=log_id)
                        session.add(progress)

                    changed = False
                    if current_index is not None and progress.current_index != current_index:
                        progress.current_index = current_index
                        changed = True
                    if log_length is not None and progress.log_length != log_length:
                        progress.log_length = log_length
                        changed = True
                    if changed:
                        progress.updated_at = datetime.datetime.utcnow()

                # One commit covers the whole batch
                session.commit()

        await asyncio.to_thread(_write)
        logger.debug(
            f"ProgressWriter: flushed {len(snapshot)} log(s) in one transaction."
        )