"""Certificate query endpoints (ClickHouse backend)."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from ..config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from ..models import (
    CertificateListResponse,
    CertificateOut,
    PaginationMeta,
    TopIssuersResponse,
    IssuerCount,
    TimeseriesResponse,
    TimeseriesPoint,
)

router = APIRouter(prefix="/certificates", tags=["Certificates"])


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


# ---------------------------------------------------------------------------
# List / search
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=CertificateListResponse,
    summary="List certificates",
    description=(
        "Paginated list of certificates with optional filtering by subject, "
        "issuer, domain (dns_names array) and time range."
    ),
)
async def list_certificates(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Results per page"),
    subject: Optional[str] = Query(None, description="Filter by subject (ilike)"),
    issuer: Optional[str] = Query(None, description="Filter by issuer (ilike)"),
    domain: Optional[str] = Query(None, description="Filter by DNS name (exact array element match)"),
    fingerprint: Optional[str] = Query(None, description="Exact SHA-256 fingerprint"),
    since: Optional[datetime] = Query(None, description="Certificates logged after this time"),
    until: Optional[datetime] = Query(None, description="Certificates logged before this time"),
    sort: str = Query("ts", description="Sort column", regex="^(ts|subject|issuer|not_before|not_after)$"),
    order: str = Query("desc", description="Sort order", regex="^(asc|desc)$"),
    db=Depends(_get_db),
):
    conditions: list[str] = []
    params: dict = {}
    idx = 0

    if subject:
        params[f"p{idx}"] = f"%{subject}%"
        conditions.append(f"ilike(subject, {{p{idx}:String}})")
        idx += 1
    if issuer:
        params[f"p{idx}"] = f"%{issuer}%"
        conditions.append(f"ilike(issuer, {{p{idx}:String}})")
        idx += 1
    if domain:
        params[f"p{idx}"] = domain
        conditions.append(f"has(dns_names, {{p{idx}:String}})")
        idx += 1
    if fingerprint:
        params[f"p{idx}"] = fingerprint
        conditions.append(f"fingerprint_sha256 = {{p{idx}:String}}")
        idx += 1
    if since:
        params[f"p{idx}"] = since
        conditions.append(f"ts >= {{p{idx}:DateTime64(3)}}")
        idx += 1
    if until:
        params[f"p{idx}"] = until
        conditions.append(f"ts <= {{p{idx}:DateTime64(3)}}")
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    allowed_sort = {"ts", "subject", "issuer", "not_before", "not_after"}
    sort_col = sort if sort in allowed_sort else "ts"
    sort_dir = "ASC" if order == "asc" else "DESC"
    offset = (page - 1) * page_size

    count_sql = f"SELECT count() FROM ct_certs {where}"
    total = await db.fetchval(count_sql, params, endpoint="list_certificates") or 0

    data_sql = (
        f"SELECT * FROM ct_certs {where} "
        f"ORDER BY {sort_col} {sort_dir} "
        f"LIMIT {page_size} OFFSET {offset}"
    )
    try:
        rows = await db.fetch(data_sql, params, endpoint="list_certificates")
        print(rows)
        certs = []
        for r in rows:
            try:
                certs.append(_row_to_cert(r))
            except Exception as cert_exc:
                import logging
                logging.getLogger("api.certificates").exception(f"Failed to parse cert row: {r}\n{cert_exc}")
        total_pages = max(1, math.ceil(total / page_size))
        return CertificateListResponse(
            data=certs,
            meta=PaginationMeta(
                page=page,
                page_size=page_size,
                total=total,
                total_pages=total_pages,
            ),
        )
    except Exception as exc:
        import logging
        logging.getLogger("api.certificates").exception(f"list_certificates failed: {exc}")
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="Internal Server Error")


# ---------------------------------------------------------------------------
# Single certificate by UUID
# ---------------------------------------------------------------------------

@router.get(
    "/{cert_id}",
    response_model=CertificateOut,
    summary="Get certificate by UUID",
)
async def get_certificate(cert_id: str, db=Depends(_get_db)):
    from fastapi import HTTPException

    row = await db.fetchrow(
        "SELECT * FROM ct_certs WHERE id = {id:UUID}",
        {"id": cert_id},
        endpoint="get_certificate",
    )
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return _row_to_cert(row)


# ---------------------------------------------------------------------------
# Search by fingerprint
# ---------------------------------------------------------------------------

@router.get(
    "/fingerprint/{sha256}",
    response_model=CertificateListResponse,
    summary="Find certificates by SHA-256 fingerprint",
)
async def find_by_fingerprint(sha256: str, db=Depends(_get_db)):
    rows = await db.fetch(
        "SELECT * FROM ct_certs WHERE fingerprint_sha256 = {fp:String} ORDER BY ts DESC",
        {"fp": sha256},
        endpoint="find_by_fingerprint",
    )
    certs = [_row_to_cert(r) for r in rows]
    return CertificateListResponse(
        data=certs,
        meta=PaginationMeta(
            page=1, page_size=len(certs), total=len(certs), total_pages=1
        ),
    )


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_cert(row: dict) -> CertificateOut:
    dns_names = row.get("dns_names")
    if isinstance(dns_names, str):
        import json
        try:
            dns_names = json.loads(dns_names)
        except Exception:
            dns_names = [dns_names]
    elif dns_names is None:
        dns_names = []
    id_val = row.get("id", None)
    try:
        if id_val is not None:
            id_val = str(id_val)
    except Exception as e:
        import logging
        logging.getLogger("api.certificates").exception(f"Failed to convert id to string: {id_val} ({type(id_val)}) - {e}")
        id_val = None
    return CertificateOut(
        id=id_val,
        log=row.get("log", None),
        subject=row.get("subject", None),
        issuer=row.get("issuer", None),
        not_before=row.get("not_before", None),
        not_after=row.get("not_after", None),
        serial_number=row.get("serial_number", None),
        dns_names=dns_names,
        fingerprint_sha256=row.get("fingerprint_sha256", None),
        ts=row.get("ts", None),
        ct_entry_type=row.get("ct_entry_type", None),
        format=row.get("format", None),
    )



def _get_db():
    """Dependency – injected at app startup via ``router.state``."""
    from ..main import db
    return db


# ---------------------------------------------------------------------------
# List / search
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=CertificateListResponse,
    summary="List certificates",
    description=(
        "Paginated list of certificates with optional filtering by subject, "
        "issuer, domain (dns_names) and time range."
    ),
)
async def list_certificates(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Results per page"),
    subject: Optional[str] = Query(None, description="Filter by subject (ILIKE)"),
    issuer: Optional[str] = Query(None, description="Filter by issuer (ILIKE)"),
    domain: Optional[str] = Query(None, description="Filter by DNS name (JSONB contains)"),
    fingerprint: Optional[str] = Query(None, description="Exact SHA-256 fingerprint"),
    since: Optional[datetime] = Query(None, description="Certificates logged after this time"),
    until: Optional[datetime] = Query(None, description="Certificates logged before this time"),
    sort: str = Query("ts", description="Sort column", regex="^(ts|subject|issuer|not_before|not_after)$"),
    order: str = Query("desc", description="Sort order", regex="^(asc|desc)$"),
    db=Depends(_get_db),
):
    # Build dynamic WHERE clause
    conditions: list[str] = []
    params: list = []
    idx = 1

    if subject:
        conditions.append(f"subject ILIKE ${idx}")
        params.append(f"%{subject}%")
        idx += 1
    if issuer:
        conditions.append(f"issuer ILIKE ${idx}")
        params.append(f"%{issuer}%")
        idx += 1
    if domain:
        conditions.append(f"dns_names @> ${idx}::jsonb")
        params.append(json.dumps([domain]))
        idx += 1
    if fingerprint:
        conditions.append(f"fingerprint_sha256 = ${idx}")
        params.append(fingerprint)
        idx += 1
    if since:
        conditions.append(f"ts >= ${idx}")
        params.append(since)
        idx += 1
    if until:
        conditions.append(f"ts <= ${idx}")
        params.append(until)
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Allowed sort columns (prevent injection even though we validate via regex)
    allowed_sort = {"ts", "subject", "issuer", "not_before", "not_after"}
    sort_col = sort if sort in allowed_sort else "ts"
    sort_dir = "ASC" if order == "asc" else "DESC"

    # Count query
    count_sql = f"SELECT COUNT(*) FROM ct_certs {where}"
    total = await db.fetchval(count_sql, *params, endpoint="list_certificates") or 0

    # Data query
    offset = (page - 1) * page_size
    data_sql = (
        f"SELECT * FROM ct_certs {where} "
        f"ORDER BY {sort_col} {sort_dir} "
        f"LIMIT ${idx} OFFSET ${idx + 1}"
    )
    rows = await db.fetch(data_sql, *params, page_size, offset, endpoint="list_certificates")

    certs = [_row_to_cert(r) for r in rows]
    total_pages = max(1, math.ceil(total / page_size))
    return CertificateListResponse(
        data=certs,
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        ),
    )


# ---------------------------------------------------------------------------
# Single certificate
# ---------------------------------------------------------------------------

@router.get(
    "/{cert_id}",
    response_model=CertificateOut,
    summary="Get certificate by ID",
)
async def get_certificate(cert_id: int, db=Depends(_get_db)):
    from fastapi import HTTPException

    row = await db.fetchrow(
        "SELECT * FROM ct_certs WHERE id = $1", cert_id, endpoint="get_certificate"
    )
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return _row_to_cert(row)


# ---------------------------------------------------------------------------
# Search by fingerprint
# ---------------------------------------------------------------------------

@router.get(
    "/fingerprint/{sha256}",
    response_model=CertificateListResponse,
    summary="Find certificates by SHA-256 fingerprint",
)
async def find_by_fingerprint(sha256: str, db=Depends(_get_db)):
    rows = await db.fetch(
        "SELECT * FROM ct_certs WHERE fingerprint_sha256 = $1 ORDER BY ts DESC",
        sha256,
        endpoint="find_by_fingerprint",
    )
    certs = [_row_to_cert(r) for r in rows]
    return CertificateListResponse(
        data=certs,
        meta=PaginationMeta(
            page=1, page_size=len(certs), total=len(certs), total_pages=1
        ),
    )


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
        "SELECT issuer, COUNT(*) AS cnt FROM ct_certs "
        "GROUP BY issuer ORDER BY cnt DESC LIMIT $1",
        limit,
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
        description="PostgreSQL interval expression (e.g. '5 minutes', '1 hour', '1 day')",
    ),
    since: Optional[datetime] = Query(None, description="Start of time range"),
    until: Optional[datetime] = Query(None, description="End of time range"),
    db=Depends(_get_db),
):
    conditions = []
    params: list = []
    idx = 1

    if since:
        conditions.append(f"ts >= ${idx}")
        params.append(since)
        idx += 1
    if until:
        conditions.append(f"ts <= ${idx}")
        params.append(until)
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Use date_trunc-style bucketing with a safe interval
    # We sanitize the interval string by only allowing alphanumeric + space
    safe_interval = "".join(c for c in interval if c.isalnum() or c == " ")

    sql = (
        f"SELECT date_trunc('hour', ts) - "
        f"  (EXTRACT(epoch FROM date_trunc('hour', ts))::int "
        f"   %% EXTRACT(epoch FROM interval '{safe_interval}')::int) "
        f"  * interval '1 second' AS bucket, "
        f"COUNT(*) AS cnt "
        f"FROM ct_certs {where} "
        f"GROUP BY bucket ORDER BY bucket"
    )

    rows = await db.fetch(sql, *params, endpoint="cert_timeseries")
    return TimeseriesResponse(
        data=[TimeseriesPoint(bucket=r["bucket"], count=r["cnt"]) for r in rows],
        interval=safe_interval,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_cert(row) -> CertificateOut:
    dns_names = row.get("dns_names")
    if isinstance(dns_names, str):
        dns_names = json.loads(dns_names)
    return CertificateOut(
        id=row["id"],
        log=row.get("log"),
        subject=row.get("subject"),
        issuer=row.get("issuer"),
        not_before=row.get("not_before"),
        not_after=row.get("not_after"),
        serial_number=row.get("serial_number"),
        dns_names=dns_names,
        fingerprint_sha256=row.get("fingerprint_sha256"),
        ts=row.get("ts"),
        ct_entry_type=row.get("ct_entry_type"),
        format=row.get("format"),
    )
