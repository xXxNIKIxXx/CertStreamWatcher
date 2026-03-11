"""Statistics and analytics endpoints (ClickHouse backend)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from datetime import datetime
from typing import Optional

from ..models import (
    StatsResponse,
    TopIssuersResponse,
    IssuerCount,
    TimeseriesResponse,
    TimeseriesPoint,
)

router = APIRouter(prefix="/stats", tags=["Statistics"])


def _get_db():
    from ..main import db
    return db


# ClickHouse interval unit map for timeseries
_INTERVAL_UNITS = {
    "second": "SECOND", "seconds": "SECOND",
    "minute": "MINUTE", "minutes": "MINUTE",
    "hour": "HOUR",    "hours": "HOUR",
    "day": "DAY",      "days": "DAY",
    "week": "WEEK",    "weeks": "WEEK",
    "month": "MONTH",  "months": "MONTH",
}


def _parse_interval(interval: str) -> str:
    """Convert e.g. '1 hour', '5 minutes' to ClickHouse 'N UNIT' string."""
    parts = interval.strip().split()
    if len(parts) == 2:
        n, unit = parts
        ch_unit = _INTERVAL_UNITS.get(unit.lower())
        if ch_unit and n.isdigit():
            return f"{n} {ch_unit}"
    return "1 HOUR"


@router.get(
    "",
    response_model=StatsResponse,
    summary="Database statistics",
    description="Aggregate statistics about the certificate collection.",
)
async def get_stats(db=Depends(_get_db)):
    row = await db.fetchrow(
        """
        SELECT
            count()                                                AS total_certificates,
            uniq(issuer)                                           AS unique_issuers,
            uniq(subject)                                          AS unique_subjects,
            min(ts)                                                AS earliest_cert,
            max(ts)                                                AS latest_cert,
            countIf(ts >= now() - INTERVAL 1 HOUR)                AS certs_last_hour,
            countIf(ts >= now() - INTERVAL 24 HOUR)               AS certs_last_24h
        FROM ct_certs
        """,
        endpoint="stats",
    )
    if not row:
        return StatsResponse()
    return StatsResponse(**row)

# ---------------------------------------------------------------------------
# Top issuers
# ---------------------------------------------------------------------------

@router.get(
    "/analytics/top-issuers",
    response_model=TopIssuersResponse,
    summary="Top certificate issuers",
)
async def top_issuers(
    limit: int = Query(10, ge=1, le=100),
    db=Depends(_get_db),
):
    rows = await db.fetch(
        "SELECT issuer, count() AS cnt FROM ct_certs "
        "GROUP BY issuer ORDER BY cnt DESC LIMIT {lim:UInt32}",
        {"lim": limit},
        endpoint="top_issuers",
    )
    return TopIssuersResponse(
        data=[IssuerCount(issuer=r["issuer"], count=r["cnt"]) for r in rows]
    )


# ---------------------------------------------------------------------------
# Timeseries (cert volume over time)
# ---------------------------------------------------------------------------

@router.get(
    "/analytics/timeseries",
    response_model=TimeseriesResponse,
    summary="Certificate volume over time",
    description="Bucket certificates by time interval for charting.",
)
async def cert_timeseries(
    interval: str = Query(
        "1 hour",
        description="Interval expression, e.g. '5 minutes', '1 hour', '1 day'",
    ),
    since: Optional[datetime] = Query(None, description="Start of time range"),
    until: Optional[datetime] = Query(None, description="End of time range"),
    db=Depends(_get_db),
):
    ch_interval = _parse_interval(interval)

    conditions: list[str] = []
    params: dict = {}
    idx = 0

    if since:
        params[f"p{idx}"] = since
        conditions.append(f"ts >= {{p{idx}:DateTime64(3)}}")
        idx += 1
    if until:
        params[f"p{idx}"] = until
        conditions.append(f"ts <= {{p{idx}:DateTime64(3)}}")
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    sql = (
        f"SELECT toStartOfInterval(ts, INTERVAL {ch_interval}) AS bucket, "
        f"count() AS cnt "
        f"FROM ct_certs {where} "
        f"GROUP BY bucket ORDER BY bucket"
    )

    rows = await db.fetch(sql, params, endpoint="cert_timeseries")
    return TimeseriesResponse(
        data=[TimeseriesPoint(bucket=r["bucket"], count=r["cnt"]) for r in rows],
        interval=ch_interval,
    )
