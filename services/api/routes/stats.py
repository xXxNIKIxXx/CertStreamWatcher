"""Statistics and analytics endpoints (ClickHouse backend)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..models import StatsResponse

router = APIRouter(prefix="/stats", tags=["Statistics"])


def _get_db():
    from ..main import db
    return db


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
