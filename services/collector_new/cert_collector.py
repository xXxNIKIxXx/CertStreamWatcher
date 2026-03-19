from .models import CTLog, CTLogProgress
from .config import get_logger, BATCH_SIZE
from .database import ProgressWriter

import asyncio
import time

logger = get_logger("CertCollector")


async def collect_log_forever(log: CTLog, db=None):
    """
    Drives one CT log to completion, then polls for new work.

    A single ProgressWriter is created for the lifetime of this task so that:
      - Progress reads reuse the pooled connections from DatabaseManager.
      - Progress writes are accumulated in memory and flushed in one
        transaction every FLUSH_EVERY batches (or when the log is caught up).
    """
    FLUSH_EVERY = 10  # batches between DB flushes – tune to taste

    writer = ProgressWriter(db, flush_every=FLUSH_EVERY) if db is not None else None

    stats = {
        "total": 0,
        "start_time": time.monotonic(),
    }

    while True:
        made_progress = False

        while True:
            more = await _collect_batch(log, db=db, writer=writer, stats=stats)
            if not more:
                break
            made_progress = True
            await asyncio.sleep(0)  # yield, but keep draining

        # Force-flush any remaining staged writes when we hit the idle state
        if writer is not None:
            await writer.flush()

        if made_progress:
            await asyncio.sleep(0)
        else:
            await asyncio.sleep(5.0)


async def collect_all_logs_dynamic(db, poll_interval: int = 30):
    """
    Periodically refreshes the log list from the database and manages one
    asyncio Task per active log.  New logs get a task; removed logs are
    cancelled.
    """
    log_tasks: dict[str, asyncio.Task] = {}

    while True:
        def _get_logs():
            with db.Session() as session:
                return session.query(CTLog).all()

        logs = await asyncio.to_thread(_get_logs)
        log_ids = {log.id for log in logs}

        # Start tasks for new / dead logs
        for log in logs:
            if log.id not in log_tasks or log_tasks[log.id].done():
                log_tasks[log.id] = asyncio.create_task(
                    collect_log_forever(log, db=db),
                    name=f"collector-{log.id}",
                )

        # Cancel tasks for logs that disappeared from the DB
        for log_id in list(log_tasks):
            if log_id not in log_ids:
                log_tasks[log_id].cancel()
                del log_tasks[log_id]

        await asyncio.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _read_progress(log_id: str, db) -> tuple[int, int]:
    """Return (current_index, log_length) from ct_log_progress."""
    def _query():
        with db.Session() as session:
            progress = (
                session.query(CTLogProgress)
                .filter_by(id=log_id)
                .first()
            )
            if progress:
                return progress.current_index or 0, progress.log_length or 0
            return 0, 0

    return await asyncio.to_thread(_query)


async def _collect_batch(
    log: CTLog,
    db=None,
    writer: ProgressWriter | None = None,
    batch_size: int = BATCH_SIZE,
    stats: dict | None = None,
) -> bool:
    """
    Process one batch of certificates for *log*.

    Returns True if more work remains, False when the log is caught up.
    All DB progress writes go through *writer* so they are batched.
    """
    log_id  = log.id
    log_url = log.url

    current_index = 0
    log_length    = 0

    if db is not None:
        current_index, log_length = await _read_progress(log_id, db)

    if log_length <= current_index:
        logger.info(
            f"[{log_id}] Up to date "
            f"(current_index={current_index}, log_length={log_length})"
        )
        return False

    end_index = min(current_index + batch_size, log_length)
    parsed    = end_index - current_index

    # Emit a rate-of-progress log line
    if stats is not None:
        stats["total"] += parsed
        elapsed = time.monotonic() - stats["start_time"]
        if elapsed > 0:
            per_sec  = stats["total"] / elapsed
            per_min  = per_sec * 60
            per_hour = per_sec * 3600
        else:
            per_sec = per_min = per_hour = 0
        logger.debug(
            f"[{log_id}] {current_index} -> {end_index} / {log_length} | "
            f"{per_sec:.1f}/s  {per_min:.0f}/min  {per_hour:.0f}/hr"
        )
    else:
        logger.debug(
            f"[{log_id}] {current_index} -> {end_index} / {log_length}"
        )

    if log.is_tiled:
        logger.debug(f"[{log_id}]   (tiled – checkpoint endpoint)")
    else:
        logger.debug(f"[{log_id}]   (standard get-entries endpoint)")

    # Stage the progress update; the writer decides when to flush.
    if writer is not None and end_index != current_index:
        writer.record(log_id, current_index=end_index)
        await writer.flush_if_due()
    elif db is not None and end_index != current_index:
        # Fallback: no writer supplied – write directly (original behaviour)
        import datetime
        def _update():
            with db.Session() as session:
                progress = (
                    session.query(CTLogProgress)
                    .filter_by(id=log_id)
                    .first()
                )
                if not progress:
                    progress = CTLogProgress(id=log_id)
                    session.add(progress)
                progress.current_index = end_index
                progress.updated_at    = datetime.datetime.utcnow()
                session.commit()
        await asyncio.to_thread(_update)

    return end_index < log_length